"""Overview-page queries: pure functions over a SQLAlchemy `Session`.

Scores always come from `audidash_core.scoring`; nothing here re-implements the formula.
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.scoring import (
    Band,
    Criticality,
    ScoredFinding,
    asset_score,
    band,
    global_score,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from audidash_server.models import Asset, FindingEvent, FindingRecord

COUNTED = (FindingStatus.open, FindingStatus.acknowledged)
STALE_AFTER = timedelta(days=90)
TREND_DAYS = 30
SUSPICIOUS_LIMIT = 10
TOP_ASSETS = 5

BAND_LABELS: dict[Band, str] = {
    Band.low: "Baixo",
    Band.moderate: "Moderado",
    Band.high: "Alto",
    Band.critical: "Crítico",
}
SEVERITY_LABELS: dict[Severity, str] = {
    Severity.info: "Info",
    Severity.low: "Baixa",
    Severity.medium: "Média",
    Severity.high: "Alta",
    Severity.critical: "Crítica",
}
SEVERITY_ORDER = (Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info)

# SVG geometry (viewBox units).
GAUGE_CX, GAUGE_CY, GAUGE_R = 100.0, 100.0, 80.0
TREND_W, TREND_H, TREND_PAD = 300.0, 90.0, 8.0


@dataclass(frozen=True)
class AssetRow:
    id: uuid.UUID
    name: str
    criticality: Criticality
    score: float
    band: Band
    counted: int


@dataclass(frozen=True)
class SuspiciousRow:
    id: uuid.UUID
    title: str
    asset_name: str
    severity: Severity
    first_seen: datetime


@dataclass(frozen=True)
class TrendPoint:
    day: date
    score: float


@dataclass(frozen=True)
class Overview:
    global_score: float
    band: Band
    severity_counts: list[tuple[Severity, int]]
    counted_total: int
    suspicious: list[SuspiciousRow]
    top_assets: list[AssetRow]
    trend: list[TrendPoint]
    trend_polyline: str
    gauge_path: str
    stale_count: int


def gauge_path(score: float) -> str:
    """SVG arc path of the filled part of a semicircle gauge (empty string for 0)."""
    clamped = max(0.0, min(100.0, score))
    if clamped <= 0:
        return ""
    angle = math.pi * (1.0 - clamped / 100.0)
    x = GAUGE_CX + GAUGE_R * math.cos(angle)
    y = GAUGE_CY - GAUGE_R * math.sin(angle)
    start_x = GAUGE_CX - GAUGE_R
    return f"M {start_x:.2f} {GAUGE_CY:.2f} A {GAUGE_R:.0f} {GAUGE_R:.0f} 0 0 1 {x:.2f} {y:.2f}"


def trend_polyline(points: list[TrendPoint]) -> str:
    """`points` attribute for an SVG polyline: x spans the width, y is 0-100 inverted."""
    n = len(points)
    step = (TREND_W - 2 * TREND_PAD) / (n - 1) if n > 1 else 0.0
    coords = []
    for i, p in enumerate(points):
        x = TREND_PAD + i * step
        y = TREND_PAD + (1.0 - max(0.0, min(100.0, p.score)) / 100.0) * (TREND_H - 2 * TREND_PAD)
        coords.append(f"{x:.2f},{y:.2f}")
    return " ".join(coords)


def _global(
    by_asset: dict[uuid.UUID, list[ScoredFinding]], criticality: dict[uuid.UUID, Criticality]
) -> float:
    return global_score(
        (asset_score(by_asset.get(aid, []), crit), crit) for aid, crit in criticality.items()
    )


def severity_counts(db: DbSession) -> list[tuple[Severity, int]]:
    rows = db.execute(
        select(FindingRecord.severity, func.count())
        .where(FindingRecord.status.in_(COUNTED))
        .group_by(FindingRecord.severity)
    ).all()
    found = {sev: n for sev, n in rows}
    return [(sev, found.get(sev, 0)) for sev in SEVERITY_ORDER]


def daily_trend(
    db: DbSession,
    now: datetime,
    criticality: dict[uuid.UUID, Criticality],
    days: int = TREND_DAYS,
) -> list[TrendPoint]:
    """Global score at the end of each of the last `days` UTC days (today = up to `now`).

    Status history is rebuilt from `FindingEvent` (a finding with no events is assumed to have
    held its current status since `first_seen`); severity, category and asset criticality are
    the current values. One pass over the time-sorted events plus one scoring per day:
    O(events + days x findings), fine for demo scale.
    """
    today = now.astimezone(UTC).date()
    findings = {
        row.id: row
        for row in db.execute(
            select(
                FindingRecord.id,
                FindingRecord.asset_id,
                FindingRecord.severity,
                FindingRecord.category,
                FindingRecord.status,
                FindingRecord.first_seen,
            )
        ).all()
    }
    timeline: list[tuple[datetime, uuid.UUID, FindingStatus]] = [
        (e.at, e.finding_id, e.to_status)
        for e in db.execute(
            select(FindingEvent.finding_id, FindingEvent.to_status, FindingEvent.at)
        ).all()
        if e.finding_id in findings
    ]
    with_events = {fid for _, fid, _ in timeline}
    timeline.extend(
        (f.first_seen, f.id, f.status) for f in findings.values() if f.id not in with_events
    )
    timeline.sort(key=lambda item: item[0])

    state: dict[uuid.UUID, FindingStatus] = {}
    idx = 0
    points: list[TrendPoint] = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        day_end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=UTC)
        while idx < len(timeline) and timeline[idx][0] < day_end:
            _, fid, status = timeline[idx]
            state[fid] = status
            idx += 1
        by_asset: dict[uuid.UUID, list[ScoredFinding]] = defaultdict(list)
        for fid, status in state.items():
            f = findings[fid]
            by_asset[f.asset_id].append(ScoredFinding(f.severity, f.category, status))
        points.append(TrendPoint(day, _global(by_asset, criticality)))
    return points


def build_overview(db: DbSession, now: datetime) -> Overview:
    assets = db.scalars(select(Asset)).all()
    criticality = {a.id: a.criticality for a in assets}
    names = {a.id: a.name for a in assets}

    rows = db.execute(
        select(
            FindingRecord.asset_id,
            FindingRecord.severity,
            FindingRecord.category,
            FindingRecord.status,
        )
    ).all()
    by_asset: dict[uuid.UUID, list[ScoredFinding]] = defaultdict(list)
    counted_by_asset: dict[uuid.UUID, int] = defaultdict(int)
    for asset_id, severity, category, status in rows:
        by_asset[asset_id].append(ScoredFinding(severity, category, status))
        if status in COUNTED:
            counted_by_asset[asset_id] += 1

    score = _global(by_asset, criticality)
    asset_rows = [
        AssetRow(
            id=aid,
            name=names[aid],
            criticality=crit,
            score=(s := asset_score(by_asset.get(aid, []), crit)),
            band=band(s),
            counted=counted_by_asset.get(aid, 0),
        )
        for aid, crit in criticality.items()
    ]
    asset_rows.sort(key=lambda r: (-r.score, r.name))

    suspicious = [
        SuspiciousRow(f.id, f.title, names.get(f.asset_id, "?"), f.severity, f.first_seen)
        for f in db.scalars(
            select(FindingRecord)
            .where(
                FindingRecord.category == Category.suspicious,
                FindingRecord.status.in_(COUNTED),
            )
            .order_by(FindingRecord.first_seen.desc(), FindingRecord.title)
            .limit(SUSPICIOUS_LIMIT)
        )
    ]
    stale = db.scalar(
        select(func.count())
        .select_from(FindingRecord)
        .where(FindingRecord.status.in_(COUNTED), FindingRecord.last_seen < now - STALE_AFTER)
    )
    counts = severity_counts(db)
    trend = daily_trend(db, now, criticality)
    return Overview(
        global_score=score,
        band=band(score),
        severity_counts=counts,
        counted_total=sum(n for _, n in counts),
        suspicious=suspicious,
        top_assets=asset_rows[:TOP_ASSETS],
        trend=trend,
        trend_polyline=trend_polyline(trend),
        gauge_path=gauge_path(score),
        stale_count=stale or 0,
    )
