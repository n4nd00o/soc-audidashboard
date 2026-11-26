"""Retention purge: drop runs and findings that aged out of ``retention_days``."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session as DbSession

from audidash_server import clock
from audidash_server.models import FindingEvent, FindingRecord, Run


@dataclass(frozen=True)
class PurgeResult:
    cutoff: datetime
    runs: int
    findings: int
    events: int


def purge(db: DbSession, retention_days: int, *, dry_run: bool = False) -> PurgeResult:
    """Delete runs finished, and findings last seen, before ``now - retention_days``.

    Does not commit. Events of purged findings are removed explicitly (not only via the FK
    cascade, which SQLite does not enforce by default); references to purged runs are nulled.
    """
    cutoff = clock.now() - timedelta(days=retention_days)
    old_findings = select(FindingRecord.id).where(FindingRecord.last_seen < cutoff)
    old_runs = select(Run.id).where(Run.finished_at < cutoff)
    events = (
        db.scalar(
            select(func.count())
            .select_from(FindingEvent)
            .where(FindingEvent.finding_id.in_(old_findings))
        )
        or 0
    )
    findings = (
        db.scalar(
            select(func.count()).select_from(FindingRecord).where(FindingRecord.last_seen < cutoff)
        )
        or 0
    )
    runs = db.scalar(select(func.count()).select_from(Run).where(Run.finished_at < cutoff)) or 0
    if not dry_run:
        db.execute(delete(FindingEvent).where(FindingEvent.finding_id.in_(old_findings)))
        db.execute(delete(FindingRecord).where(FindingRecord.last_seen < cutoff))
        db.execute(
            update(FindingRecord)
            .where(FindingRecord.last_run_id.in_(old_runs))
            .values(last_run_id=None)
        )
        db.execute(
            update(FindingEvent).where(FindingEvent.run_id.in_(old_runs)).values(run_id=None)
        )
        db.execute(delete(Run).where(Run.finished_at < cutoff))
    return PurgeResult(cutoff=cutoff, runs=runs, findings=findings, events=events)
