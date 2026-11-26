"""Tamper-evident audit log: every entry commits to the previous one with SHA-256.

`record()` only adds the entry to the caller's transaction (it never commits), so the audited
action and its audit row become durable atomically. Chain order is the `seq` order.

Limits, by design: the chain detects modified, deleted (except trailing) and reordered rows.
Truncating the tail, or rewriting the whole table consistently, needs an external anchor.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session as DbSession

from audidash_server import clock
from audidash_server.models import AuditEntry

GENESIS_HASH = "0" * 64
# Arbitrary application-wide key for the PostgreSQL advisory lock that serializes writers.
_CHAIN_LOCK_KEY = 0x41554449  # "AUDI"
_FORBIDDEN_KEY_PARTS = ("password", "secret", "token", "totp", "code", "evidence")


def _check_details(value: Any) -> None:
    """Reject keys that look like secrets, at any nesting depth."""
    if isinstance(value, dict):
        for key, inner in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
                raise ValueError(f"audit details key {key!r} may carry a secret")
            _check_details(inner)
    elif isinstance(value, list | tuple):
        for inner in value:
            _check_details(inner)


def _canonical(
    *,
    at: datetime,
    actor_user_id: uuid.UUID | None,
    actor_device_id: uuid.UUID | None,
    action: str,
    target: str | None,
    details: dict[str, Any],
) -> str:
    payload = {
        "at": at.astimezone(UTC).isoformat(timespec="microseconds"),
        "actor_user_id": str(actor_user_id) if actor_user_id is not None else None,
        "actor_device_id": str(actor_device_id) if actor_device_id is not None else None,
        "action": action,
        "target": target,
        "details": details,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _row_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _entry_hash(entry: AuditEntry) -> str:
    return _row_hash(
        entry.prev_hash,
        _canonical(
            at=entry.at,
            actor_user_id=entry.actor_user_id,
            actor_device_id=entry.actor_device_id,
            action=entry.action,
            target=entry.target,
            details=entry.details,
        ),
    )


def _lock_chain(db: DbSession) -> None:
    # PostgreSQL: a transaction-scoped advisory lock makes read-last/insert serial across
    # writers. SQLite (dev only) has a single writer; concurrent writers fail with
    # SQLITE_BUSY instead of forking the chain.
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _CHAIN_LOCK_KEY})


def record(
    db: DbSession,
    *,
    action: str,
    actor_user_id: uuid.UUID | None,
    actor_device_id: uuid.UUID | None,
    target: str,
    details: dict[str, Any],
) -> AuditEntry:
    """Append an entry to the chain inside the caller's transaction (no commit)."""
    _check_details(details)
    at = clock.now()
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    _lock_chain(db)
    db.flush()  # make this transaction's own earlier entries visible to the read below
    last = db.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).first()
    prev_hash = last.row_hash if last is not None else GENESIS_HASH
    canonical = _canonical(
        at=at,
        actor_user_id=actor_user_id,
        actor_device_id=actor_device_id,
        action=action,
        target=target,
        details=details,
    )
    entry = AuditEntry(
        at=at,
        actor_user_id=actor_user_id,
        actor_device_id=actor_device_id,
        action=action,
        target=target,
        details=details,
        prev_hash=prev_hash,
        row_hash=_row_hash(prev_hash, canonical),
    )
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: DbSession) -> int | None:
    """Return the first `seq` whose link or content is wrong, or None if the chain is intact."""
    expected_prev = GENESIS_HASH
    rows = db.scalars(select(AuditEntry).order_by(AuditEntry.seq).execution_options(yield_per=1000))
    for entry in rows:
        if entry.prev_hash != expected_prev or entry.row_hash != _entry_hash(entry):
            return int(entry.seq)
        expected_prev = entry.row_hash
    return None
