"""Asset registry queries: one findings query feeds every row's score (no N+1)."""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass

from audidash_core.manifest import TargetType
from audidash_core.scoring import Band, Criticality, ScoredFinding, asset_score, band
from sqlalchemy import exists, select
from sqlalchemy.orm import Session as DbSession

from audidash_server.models import Asset, FindingRecord, Run
from audidash_server.web.queries import COUNTED

CRITICALITY_LABELS: dict[Criticality, str] = {
    Criticality.low: "Baixa",
    Criticality.medium: "Média",
    Criticality.high: "Alta",
}


@dataclass(frozen=True)
class AssetListRow:
    id: uuid.UUID
    name: str
    address: str | None
    asset_type: TargetType
    criticality: Criticality
    tags: list[str]
    score: float
    band: Band
    open_count: int


def list_assets(db: DbSession, only: uuid.UUID | None = None) -> list[AssetListRow]:
    """Assets with score, band and open-finding count; highest score first, then name."""
    assets_query = select(Asset)
    findings_query = select(
        FindingRecord.asset_id,
        FindingRecord.severity,
        FindingRecord.category,
        FindingRecord.status,
    )
    if only is not None:
        assets_query = assets_query.where(Asset.id == only)
        findings_query = findings_query.where(FindingRecord.asset_id == only)

    by_asset: dict[uuid.UUID, list[ScoredFinding]] = defaultdict(list)
    open_counts: dict[uuid.UUID, int] = defaultdict(int)
    for asset_id, severity, category, status in db.execute(findings_query).all():
        by_asset[asset_id].append(ScoredFinding(severity, category, status))
        if status in COUNTED:
            open_counts[asset_id] += 1

    rows = [
        AssetListRow(
            id=a.id,
            name=a.name,
            address=a.address,
            asset_type=a.asset_type,
            criticality=a.criticality,
            tags=list(a.tags or []),
            score=(s := asset_score(by_asset.get(a.id, []), a.criticality)),
            band=band(s),
            open_count=open_counts.get(a.id, 0),
        )
        for a in db.scalars(assets_query)
    ]
    rows.sort(key=lambda r: (-r.score, r.name))
    return rows


def is_referenced(db: DbSession, asset_id: uuid.UUID) -> bool:
    """True when any finding or run still points at the asset."""
    has_finding = exists().where(FindingRecord.asset_id == asset_id)
    has_run = exists().where(Run.asset_id == asset_id)
    return bool(db.scalar(select(has_finding | has_run)))
