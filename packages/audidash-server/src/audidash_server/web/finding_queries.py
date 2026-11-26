"""Findings page queries: filtered, paginated list and the detail history."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode, urlsplit

from audidash_core.findings import Category, FindingStatus, Severity
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session as DbSession

from audidash_server import clock
from audidash_server.models import Asset, FindingEvent, FindingRecord, User
from audidash_server.textguard import filter_text
from audidash_server.web.queries import COUNTED, SEVERITY_LABELS, SEVERITY_ORDER, STALE_AFTER

PAGE_SIZE = 50
STATUS_ALL = "all"
STATUS_LABELS: dict[FindingStatus, str] = {
    FindingStatus.open: "Aberto",
    FindingStatus.acknowledged: "Reconhecido",
    FindingStatus.resolved: "Resolvido",
    FindingStatus.auto_resolved: "Resolvido automaticamente",
    FindingStatus.false_positive: "Falso positivo",
    FindingStatus.accepted_risk: "Risco aceito",
}
CATEGORY_LABELS: dict[Category, str] = {
    Category.misconfiguration: "Configuração incorreta",
    Category.vulnerability: "Vulnerabilidade",
    Category.suspicious: "Suspeito",
    Category.compliance: "Conformidade",
}
_TRUE = {"1", "true", "on", "yes"}


@dataclass(frozen=True)
class Filters:
    asset: uuid.UUID | None = None
    severity: Severity | None = None
    category: Category | None = None
    status: str = ""  # "" = open+acknowledged, STATUS_ALL, or a FindingStatus value
    plugin: str = ""
    stale: bool = False
    page: int = 1

    def params(self, page: int | None = None) -> str:
        """Query string (no leading '?') that reproduces these filters, for pagination links."""
        items: dict[str, str] = {}
        if self.asset:
            items["asset"] = str(self.asset)
        if self.severity:
            items["severity"] = self.severity.value
        if self.category:
            items["category"] = self.category.value
        if self.status:
            items["status"] = self.status
        if self.plugin:
            items["plugin"] = self.plugin
        if self.stale:
            items["stale"] = "1"
        target = self.page if page is None else page
        if target > 1:
            items["page"] = str(target)
        return urlencode(items)


def _enum[E: (Severity, Category)](kind: type[E], raw: str | None) -> E | None:
    try:
        return kind(raw) if raw else None
    except ValueError:
        return None  # invalid filter values are ignored, never an error page


def parse_filters(params: Mapping[str, str]) -> Filters:
    try:
        asset = uuid.UUID(params.get("asset", "")) if params.get("asset") else None
    except ValueError:
        asset = None
    status = params.get("status", "")
    if status != STATUS_ALL and status not in {s.value for s in FindingStatus}:
        status = ""
    try:
        page = max(1, int(params.get("page", "1")))
    except ValueError:
        page = 1
    return Filters(
        asset=asset,
        severity=_enum(Severity, params.get("severity")),
        category=_enum(Category, params.get("category")),
        status=status,
        plugin=filter_text(params.get("plugin")),
        stale=params.get("stale", "").lower() in _TRUE,
        page=min(page, 100_000),
    )


@dataclass(frozen=True)
class FindingRow:
    id: uuid.UUID
    title: str
    severity: Severity
    category: Category
    status: FindingStatus
    asset_name: str
    plugin_id: str
    last_seen: datetime
    stale: bool


@dataclass(frozen=True)
class FindingPage:
    rows: list[FindingRow]
    total: int
    page: int
    pages: int


def _severity_rank() -> object:
    return case(
        *[(FindingRecord.severity == s, i) for i, s in enumerate(SEVERITY_ORDER)],
        else_=len(SEVERITY_ORDER),
    )


def _is_stale(last_seen: datetime) -> bool:
    return _aware(last_seen) < clock.now() - STALE_AFTER


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=clock.now().tzinfo)


def list_findings(db: DbSession, f: Filters) -> FindingPage:
    conditions = []
    if f.asset:
        conditions.append(FindingRecord.asset_id == f.asset)
    if f.severity:
        conditions.append(FindingRecord.severity == f.severity)
    if f.category:
        conditions.append(FindingRecord.category == f.category)
    if f.status == "":
        conditions.append(FindingRecord.status.in_(COUNTED))
    elif f.status != STATUS_ALL:
        conditions.append(FindingRecord.status == FindingStatus(f.status))
    if f.plugin:
        conditions.append(FindingRecord.plugin_id == f.plugin)
    if f.stale:
        conditions.append(FindingRecord.last_seen < clock.now() - STALE_AFTER)

    total = db.scalar(select(func.count()).select_from(FindingRecord).where(*conditions)) or 0
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(f.page, pages)
    query = (
        select(FindingRecord, Asset.name)
        .join(Asset, Asset.id == FindingRecord.asset_id)
        .where(*conditions)
        .order_by(_severity_rank(), FindingRecord.last_seen.desc(), FindingRecord.id)  # type: ignore[arg-type]
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    )
    rows = [
        FindingRow(
            id=rec.id,
            title=rec.title,
            severity=rec.severity,
            category=rec.category,
            status=rec.status,
            asset_name=name,
            plugin_id=rec.plugin_id,
            last_seen=rec.last_seen,
            stale=_is_stale(rec.last_seen),
        )
        for rec, name in db.execute(query).all()
    ]
    return FindingPage(rows=rows, total=total, page=page, pages=pages)


def filter_options(db: DbSession) -> tuple[list[tuple[uuid.UUID, str]], list[str]]:
    assets = [(a, n) for a, n in db.execute(select(Asset.id, Asset.name).order_by(Asset.name))]
    plugins = list(
        db.scalars(select(FindingRecord.plugin_id).distinct().order_by(FindingRecord.plugin_id))
    )
    return assets, plugins


@dataclass(frozen=True)
class HistoryRow:
    at: datetime
    from_status: FindingStatus | None
    to_status: FindingStatus
    actor: str | None  # None: automatic (ingestion)
    justification: str | None


def history(db: DbSession, finding_id: uuid.UUID) -> list[HistoryRow]:
    query = (
        select(FindingEvent, User.username)
        .outerjoin(User, User.id == FindingEvent.user_id)
        .where(FindingEvent.finding_id == finding_id)
        .order_by(FindingEvent.at.desc(), FindingEvent.id)
    )
    return [
        HistoryRow(e.at, e.from_status, e.to_status, name, e.justification)
        for e, name in db.execute(query).all()
    ]


@dataclass(frozen=True)
class Reference:
    text: str
    url: str | None  # set only for http(s) links


def reference_links(references: list[str]) -> list[Reference]:
    """References as text; only well-formed http(s) URLs become links."""
    out: list[Reference] = []
    for raw in references:
        text = str(raw)
        url: str | None = None
        if text == text.strip() and not any(c.isspace() or ord(c) < 32 for c in text):
            try:
                parts = urlsplit(text)
            except ValueError:
                parts = None
            if parts is not None and parts.scheme in ("http", "https") and parts.netloc:
                url = text
        out.append(Reference(text, url))
    return out


__all__ = [
    "CATEGORY_LABELS",
    "SEVERITY_LABELS",
    "SEVERITY_ORDER",
    "STATUS_ALL",
    "STATUS_LABELS",
]
