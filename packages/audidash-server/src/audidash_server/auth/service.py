"""Password + TOTP verification shared by the dashboard login form and the API token endpoint.

One code path, so lockout, timing equalization, replay protection and auditing cannot drift
between the two front doors. Rate limiting stays with the callers (it needs the request).

Transaction contract: every failure path records its audit row and COMMITS here. On success
the counters are reset, the TOTP step is claimed and the `login.success` row is added, but
nothing is committed: the caller adds its session/token row and commits once.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session as DbSession

from audidash_server import audit, clock
from audidash_server.auth import passwords
from audidash_server.auth.lockout import (
    MAX_FAILED_LOGINS,
    clear_failures_if_unlocked,
    record_failure,
)
from audidash_server.auth.totp import decrypt_totp_secret, totp_match_step
from audidash_server.models import User
from audidash_server.textguard import NUL

logger = logging.getLogger(__name__)

MAX_USERNAME_CHARS = 64
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class LoginOutcome(StrEnum):
    ok = "ok"
    invalid = "invalid"
    # Correct password, but the account has no TOTP yet (only reported when TOTP is required).
    totp_not_enrolled = "totp_not_enrolled"


@dataclass(frozen=True)
class LoginResult:
    outcome: LoginOutcome
    user: User | None = None
    totp_enrolled: bool = False


def audit_username(username: str) -> str:
    """Bounded, control-character-free copy of a submitted username for the audit log."""
    return _CONTROL_CHARS.sub("?", username[:MAX_USERNAME_CHARS])


def _totp_step(user: User, code: str, secret_key: str) -> int | None:
    """Matching, not-yet-used TOTP step for an enrolled user, else None."""
    if user.totp_secret_enc is None:
        return None
    try:
        secret = decrypt_totp_secret(user.totp_secret_enc, secret_key)
    except ValueError:
        logger.warning("TOTP secret of user %s cannot be decrypted (secret key changed?)", user.id)
        return None
    step = totp_match_step(secret, code)
    if step is None or (user.totp_last_step is not None and step <= user.totp_last_step):
        return None
    return step


def _claim_totp_step(db: DbSession, user: User, step: int) -> bool:
    """Atomically record `step` as used; False if it (or a later one) was already used."""
    result = db.execute(
        update(User)
        .where(User.id == user.id)
        .where(or_(User.totp_last_step.is_(None), User.totp_last_step < step))
        .values(totp_last_step=step)
        .execution_options(synchronize_session=False)
    )
    claimed: int = getattr(result, "rowcount", 0)
    if claimed == 1:
        user.totp_last_step = step
    return claimed == 1


def authenticate(
    db: DbSession,
    *,
    username: str,
    password: str,
    totp_code: str,
    secret_key: str,
    actor_device_id: uuid.UUID | None = None,
    require_totp: bool = False,
) -> LoginResult:
    """Check credentials with lockout, timing equalization, TOTP replay guard and auditing."""

    def audit_failure(reason: str = "invalid") -> None:
        audit.record(
            db,
            action="login.failure",
            actor_user_id=None,
            actor_device_id=actor_device_id,
            target="login",
            details={"username": audit_username(username), "reason": reason},
        )

    def fail_rolled_back() -> LoginResult:
        """Race losers: their transaction was rolled back; still leave an audit row."""
        db.rollback()
        audit_failure()
        db.commit()
        return LoginResult(LoginOutcome.invalid)

    def fail_counted(user_id: uuid.UUID | None) -> LoginResult:
        """Every failure path does the same DB work: one counted UPDATE and a commit."""
        if record_failure(db, user_id, now):
            logger.warning("account %s locked after %d failures", user_id, MAX_FAILED_LOGINS)
        # Same transaction as the counter UPDATE; never says which factor failed.
        audit_failure()
        db.commit()
        return LoginResult(LoginOutcome.invalid)

    now = clock.now()
    user = None
    # A NUL-bearing name cannot exist (PostgreSQL would reject the query): plain failure.
    if len(username) <= MAX_USERNAME_CHARS and NUL not in username:
        user = db.scalars(select(User).where(User.username == username)).first()
    if user is None or user.disabled:
        passwords.verify_password(passwords.dummy_hash(), password)  # equalize timing
        return fail_counted(None)

    password_ok = passwords.verify_password(user.password_hash, password)
    enrolled = user.totp_secret_enc is not None
    step = _totp_step(user, totp_code, secret_key) if enrolled else None
    if user.locked_until is not None and user.locked_until > now:
        return fail_counted(None)  # attempts while locked are not counted
    if not password_ok or (enrolled and step is None):
        return fail_counted(user.id)
    if require_totp and not enrolled:
        audit_failure("totp_not_enrolled")
        db.commit()
        return LoginResult(LoginOutcome.totp_not_enrolled, user)

    if not clear_failures_if_unlocked(db, user.id, now):
        return fail_rolled_back()  # a concurrent attempt locked the account meanwhile
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
    if step is not None and not _claim_totp_step(db, user, step):
        return fail_rolled_back()  # a concurrent login consumed this code first
    audit.record(
        db,
        action="login.success",
        actor_user_id=user.id,
        actor_device_id=actor_device_id,
        target=user.username,
        details={"second_factor_enrolled": enrolled},
    )
    return LoginResult(LoginOutcome.ok, user, enrolled)
