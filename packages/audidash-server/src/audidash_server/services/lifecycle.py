"""Finding status transitions: every change (manual or from ingestion) is one guarded UPDATE.

The guard lives in SQL (`WHERE id = :id AND status = :status_read_just_now`), never in a
read-modify-write on ORM attributes, so a stale writer (an ingest that loaded its rows before an
analyst set `accepted_risk`) cannot overwrite a newer state: its UPDATE matches no row.

Callers own the transaction: nothing here commits.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from datetime import datetime

from audidash_core.findings import FindingStatus
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from audidash_server import clock
from audidash_server.models import FindingEvent, FindingRecord

# Manual state machine (spec §7): target status -> statuses it may be entered from.
MANUAL_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.acknowledged: frozenset({FindingStatus.open}),
    FindingStatus.resolved: frozenset({FindingStatus.open, FindingStatus.acknowledged}),
    FindingStatus.false_positive: frozenset({FindingStatus.open, FindingStatus.acknowledged}),
    FindingStatus.accepted_risk: frozenset({FindingStatus.open, FindingStatus.acknowledged}),
    FindingStatus.open: frozenset(
        {
            FindingStatus.resolved,
            FindingStatus.false_positive,
            FindingStatus.accepted_risk,
            FindingStatus.auto_resolved,
        }
    ),
}
JUSTIFICATION_REQUIRED = frozenset({FindingStatus.false_positive, FindingStatus.accepted_risk})


def try_transition(
    db: DbSession,
    finding_id: uuid.UUID,
    *,
    to_status: FindingStatus,
    allowed_from: Collection[FindingStatus],
    user_id: uuid.UUID | None,
    run_id: uuid.UUID | None,
    justification: str | None,
    at: datetime | None = None,
) -> FindingStatus | None:
    """Move a finding to `to_status` if its *current database* status is in `allowed_from`.

    Returns the status it actually moved from (also recorded in the `FindingEvent`), or None when
    the finding is missing or in a disallowed state (nothing written). The UPDATE re-checks the
    status that was read, so a concurrent change between read and write also yields None.
    """
    db.flush()  # pending ORM changes first: the UPDATE below bypasses the unit of work
    current = db.scalar(select(FindingRecord.status).where(FindingRecord.id == finding_id))
    if current is None or current not in allowed_from:
        return None
    when = at or clock.now()
    result = db.execute(
        update(FindingRecord)
        .where(FindingRecord.id == finding_id, FindingRecord.status == current)
        .values(
            status=to_status,
            status_changed_at=when,
            status_changed_by=user_id,
            justification=justification,
        )
        .execution_options(synchronize_session=False)
    )
    # The UPDATE bypassed loaded instances: make them re-read the row on next access.
    loaded = db.identity_map.get(db.identity_key(FindingRecord, finding_id))
    if loaded is not None:
        db.expire(loaded, ["status", "status_changed_at", "status_changed_by", "justification"])
    if result.rowcount != 1:  # type: ignore[attr-defined]  # CursorResult at runtime
        return None
    db.add(
        FindingEvent(
            finding_id=finding_id,
            run_id=run_id,
            user_id=user_id,
            from_status=current,
            to_status=to_status,
            justification=justification,
            at=when,
        )
    )
    db.flush()
    return current


def transition(
    db: DbSession,
    finding_id: uuid.UUID,
    *,
    to_status: FindingStatus,
    allowed_from: Collection[FindingStatus],
    user_id: uuid.UUID | None,
    run_id: uuid.UUID | None,
    justification: str | None,
    at: datetime | None = None,
) -> bool:
    """Boolean form of `try_transition`."""
    moved = try_transition(
        db,
        finding_id,
        to_status=to_status,
        allowed_from=allowed_from,
        user_id=user_id,
        run_id=run_id,
        justification=justification,
        at=at,
    )
    return moved is not None
