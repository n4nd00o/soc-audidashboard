"""Account lockout bookkeeping done SQL-side, so concurrent attempts cannot lose updates.

Every helper issues its UPDATEs in the caller's transaction; the caller commits.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import or_, update
from sqlalchemy.orm import Session as DbSession

from audidash_server.models import User

MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)


def record_failure(db: DbSession, user_id: uuid.UUID | None, now: datetime) -> bool:
    """Atomically count one failed attempt; return True if this attempt locked the account.

    `user_id=None` runs the same statement against a non-existent id, so failure paths for
    unknown, disabled or already-locked accounts do equivalent database work (timing).
    """
    target = user_id if user_id is not None else uuid.uuid4()
    count = db.execute(
        update(User)
        .where(User.id == target)
        .values(failed_logins=User.failed_logins + 1)
        .returning(User.failed_logins)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    if count is None or count < MAX_FAILED_LOGINS:
        return False
    # Guarded: only the attempt that still sees >= MAX (after row locking) sets the lock.
    locked = db.execute(
        update(User)
        .where(User.id == target, User.failed_logins >= MAX_FAILED_LOGINS)
        .values(locked_until=now + LOCKOUT, failed_logins=0)
        .execution_options(synchronize_session=False)
    )
    return int(getattr(locked, "rowcount", 0)) == 1


def clear_failures_if_unlocked(db: DbSession, user_id: uuid.UUID, now: datetime) -> bool:
    """Reset the counter on success, but only if no lock is in force at this instant.

    Closes the race where a guess read `locked_until IS NULL` before a concurrent attempt
    set the lock: that guess cannot complete a login.
    """
    result = db.execute(
        update(User)
        .where(User.id == user_id)
        .where(or_(User.locked_until.is_(None), User.locked_until <= now))
        .values(failed_logins=0, locked_until=None)
        .execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0)) == 1
