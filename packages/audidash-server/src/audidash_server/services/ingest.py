"""Run ingestion: validate against the asset, upsert findings by fingerprint, auto-resolve.

Lifecycle rules (spec §7 / §12.3):
- a fingerprint seen for the first time becomes an `open` finding (event None -> open);
- a fingerprint seen again refreshes `last_seen`/`last_run_id` and its descriptive fields;
  if it was `auto_resolved` it is re-opened (event auto_resolved -> open). Every other state,
  manual ones included, is left alone;
- only when the run status is `ok`: `open`/`acknowledged` findings of the same
  (asset, plugin) that the run did not report become `auto_resolved` (event recorded).
  `resolved`, `false_positive` and `accepted_risk` are never changed automatically.
- idempotent on `run_id`: the same device re-uploading gets the stored summary back.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from audidash_core.catalog import Trust
from audidash_core.findings import Finding, FindingStatus, fingerprint
from audidash_core.runner import RunResult, RunStatus
from audidash_core.scoring import ScoredFinding, asset_score
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from audidash_server import audit, clock
from audidash_server.models import Asset, Device, FindingEvent, FindingRecord, Run, User

AUTO_RESOLVABLE = (FindingStatus.open, FindingStatus.acknowledged)
_MAX_PLUGIN_ID = 128
_MAX_PLUGIN_VERSION = 64


class IngestError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class IngestOutcome:
    created: bool  # False: idempotent replay of an earlier upload
    summary: dict[str, Any]


def _replay(db: DbSession, run_id: uuid.UUID, device: Device) -> IngestOutcome | None:
    existing = db.get(Run, run_id)
    if existing is None:
        return None
    if existing.device_id != device.id or existing.ingest_summary is None:
        raise IngestError(409, "run_id already used by another device")
    return IngestOutcome(created=False, summary=dict(existing.ingest_summary))


def _validate(result: RunResult, asset: Asset) -> Trust | None:
    accepted = {asset.name} | ({asset.address} if asset.address else set())
    if result.target not in accepted:
        raise IngestError(422, "result target does not match the asset's address or name")
    for finding in result.findings:
        if finding.target not in accepted:
            raise IngestError(
                422, f"finding {finding.id!r} target does not match the asset's address or name"
            )
    if not 0 < len(result.plugin_id) <= _MAX_PLUGIN_ID:
        raise IngestError(422, "plugin_id length out of range")
    if not 0 < len(result.plugin_version) <= _MAX_PLUGIN_VERSION:
        raise IngestError(422, "plugin_version length out of range")
    if result.manifest_sha256 is not None and len(result.manifest_sha256) != 64:
        raise IngestError(422, "manifest_sha256 must be 64 hex characters")
    if result.started_at.tzinfo is None or result.finished_at.tzinfo is None:
        raise IngestError(422, "started_at/finished_at must carry a timezone")
    try:
        return Trust(result.trust) if result.trust is not None else None
    except ValueError:
        raise IngestError(422, "unknown trust tier") from None


def _apply(record: FindingRecord, finding: Finding) -> None:
    record.title = finding.title
    record.severity = finding.severity
    record.category = finding.category
    record.evidence = finding.evidence
    record.recommendation = finding.recommendation
    record.references = list(finding.references)


def ingest_run(
    db: DbSession,
    *,
    run_id: uuid.UUID,
    asset_name: str,
    result: RunResult,
    device: Device,
    user: User,
) -> IngestOutcome:
    """Store one run and its findings; commits. Raises IngestError on rejection."""
    replay = _replay(db, run_id, device)
    if replay is not None:
        return replay
    asset = db.scalars(select(Asset).where(Asset.name == asset_name)).first()
    if asset is None:
        raise IngestError(422, f"unknown asset {asset_name[:128]!r}")
    trust = _validate(result, asset)
    now = clock.now()

    db.add(
        Run(
            id=run_id,
            device_id=device.id,
            user_id=user.id,
            asset_id=asset.id,
            plugin_id=result.plugin_id,
            plugin_version=result.plugin_version,
            manifest_sha256=result.manifest_sha256 or "",
            trust=trust,
            status=result.status,
            reason=result.reason,
            started_at=result.started_at,
            finished_at=result.finished_at,
            warnings=list(result.warnings),
            received_at=now,
        )
    )
    try:
        db.flush()  # claims run_id before any finding references it
    except IntegrityError:
        db.rollback()  # a concurrent upload of the same run_id won
        replay = _replay(db, run_id, device)
        if replay is None:
            raise
        return replay

    events: list[FindingEvent] = []

    def event(rec: FindingRecord, before: FindingStatus | None, after: FindingStatus) -> None:
        events.append(
            FindingEvent(
                finding_id=rec.id, run_id=run_id, from_status=before, to_status=after, at=now
            )
        )

    reported: dict[str, Finding] = {}
    for finding in result.findings:  # a repeated fingerprint within one run counts once
        fp = fingerprint(result.plugin_id, finding.id, str(asset.id), finding.item_key)
        reported[fp] = finding
    known: dict[str, FindingRecord] = {}
    if reported:
        query = select(FindingRecord).where(FindingRecord.fingerprint.in_(list(reported)))
        known = {rec.fingerprint: rec for rec in db.scalars(query)}

    new = updated = auto_resolved = 0
    for fp, finding in reported.items():
        rec = known.get(fp)
        if rec is None:
            rec = FindingRecord(
                id=uuid.uuid4(),
                fingerprint=fp,
                asset_id=asset.id,
                plugin_id=result.plugin_id,
                finding_id=finding.id,
                item_key=finding.item_key or "",
                status=FindingStatus.open,
                first_seen=now,
                last_seen=now,
                last_run_id=run_id,
            )
            _apply(rec, finding)
            db.add(rec)
            event(rec, None, FindingStatus.open)
            new += 1
            continue
        _apply(rec, finding)
        rec.last_seen = now
        rec.last_run_id = run_id
        if rec.status is FindingStatus.auto_resolved:
            rec.status = FindingStatus.open
            rec.status_changed_at = now
            rec.status_changed_by = None
            event(rec, FindingStatus.auto_resolved, FindingStatus.open)
        updated += 1

    try:
        db.flush()  # finding rows first: events reference them
    except IntegrityError:
        db.rollback()  # a concurrent run created the same fingerprint first
        raise IngestError(409, "concurrent upload for this asset; retry") from None

    if result.status is RunStatus.ok:
        stale = db.scalars(
            select(FindingRecord).where(
                FindingRecord.asset_id == asset.id,
                FindingRecord.plugin_id == result.plugin_id,
                FindingRecord.status.in_(AUTO_RESOLVABLE),
            )
        )
        for rec in stale:
            if rec.fingerprint in reported:
                continue
            event(rec, rec.status, FindingStatus.auto_resolved)
            rec.status = FindingStatus.auto_resolved
            rec.status_changed_at = now
            rec.status_changed_by = None
            auto_resolved += 1

    db.add_all(events)
    scored = [
        ScoredFinding(severity=r.severity, category=r.category, status=r.status)
        for r in db.scalars(select(FindingRecord).where(FindingRecord.asset_id == asset.id))
    ]
    summary: dict[str, Any] = {
        "run_id": str(run_id),
        "new": new,
        "updated": updated,
        "auto_resolved": auto_resolved,
        "asset_score": asset_score(scored, asset.criticality),
    }
    run = db.get(Run, run_id)
    assert run is not None  # noqa: S101 - inserted above in this transaction
    run.ingest_summary = summary
    audit.record(
        db,
        action="run.ingest",
        actor_user_id=user.id,
        actor_device_id=device.id,
        target=str(run_id),
        details={
            "asset_id": str(asset.id),
            "plugin_id": result.plugin_id,
            "status": str(result.status),
            "new": new,
            "updated": updated,
            "auto_resolved": auto_resolved,
        },
    )
    db.commit()
    return IngestOutcome(created=True, summary=summary)
