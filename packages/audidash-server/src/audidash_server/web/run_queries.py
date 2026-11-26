"""Runs page and plugin-allowlist queries."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode

from audidash_core.catalog import Trust
from audidash_core.runner import RunStatus
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from audidash_server.models import Asset, Device, Run, User, VerifiedPlugin
from audidash_server.web.paging import PAGE_SIZE, page_count, parse_page

STATUS_LABELS: dict[RunStatus, str] = {
    RunStatus.ok: "OK",
    RunStatus.error: "Erro",
    RunStatus.timeout: "Tempo esgotado",
    RunStatus.blocked: "Bloqueado",
}
TRUST_LABELS: dict[Trust, str] = {
    Trust.official: "Oficial",
    Trust.verified: "Verificado",
    Trust.community: "Comunidade",
}


@dataclass(frozen=True)
class RunFilters:
    asset: uuid.UUID | None = None
    plugin: str = ""
    status: RunStatus | None = None
    page: int = 1

    def params(self, page: int | None = None) -> str:
        items: dict[str, str] = {}
        if self.asset:
            items["asset"] = str(self.asset)
        if self.plugin:
            items["plugin"] = self.plugin
        if self.status:
            items["status"] = self.status.value
        target = self.page if page is None else page
        if target > 1:
            items["page"] = str(target)
        return urlencode(items)


def parse_run_filters(params: Mapping[str, str]) -> RunFilters:
    try:
        asset = uuid.UUID(params["asset"]) if params.get("asset") else None
    except ValueError:
        asset = None
    try:
        status = RunStatus(params["status"]) if params.get("status") else None
    except ValueError:
        status = None  # invalid filter values are ignored, never an error page
    return RunFilters(
        asset=asset,
        plugin=params.get("plugin", "")[:128],
        status=status,
        page=parse_page(params.get("page")),
    )


@dataclass(frozen=True)
class RunRow:
    id: uuid.UUID
    asset_name: str
    plugin_id: str
    plugin_version: str
    trust: Trust | None
    status: RunStatus
    new: int | None
    updated: int | None
    auto_resolved: int | None
    device_name: str | None
    username: str | None
    received_at: datetime


@dataclass(frozen=True)
class RunPage:
    rows: list[RunRow]
    total: int
    page: int
    pages: int


def _count(summary: dict[str, object] | None, key: str) -> int | None:
    value = (summary or {}).get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def list_runs(db: DbSession, f: RunFilters) -> RunPage:
    conditions = []
    if f.asset:
        conditions.append(Run.asset_id == f.asset)
    if f.plugin:
        conditions.append(Run.plugin_id == f.plugin)
    if f.status:
        conditions.append(Run.status == f.status)
    total = db.scalar(select(func.count()).select_from(Run).where(*conditions)) or 0
    pages = page_count(total)
    page = min(f.page, pages)
    query = (
        select(Run, Asset.name, Device.name, User.username)
        .join(Asset, Asset.id == Run.asset_id)
        .outerjoin(Device, Device.id == Run.device_id)
        .outerjoin(User, User.id == Run.user_id)
        .where(*conditions)
        .order_by(Run.received_at.desc(), Run.id)
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    )
    rows = [
        RunRow(
            id=run.id,
            asset_name=asset_name,
            plugin_id=run.plugin_id,
            plugin_version=run.plugin_version,
            trust=run.trust,
            status=run.status,
            new=_count(run.ingest_summary, "new"),
            updated=_count(run.ingest_summary, "updated"),
            auto_resolved=_count(run.ingest_summary, "auto_resolved"),
            device_name=device_name,
            username=username,
            received_at=run.received_at,
        )
        for run, asset_name, device_name, username in db.execute(query).all()
    ]
    return RunPage(rows=rows, total=total, page=page, pages=pages)


def run_filter_options(db: DbSession) -> tuple[list[tuple[uuid.UUID, str]], list[str]]:
    assets = [
        (aid, name)
        for aid, name in db.execute(
            select(Asset.id, Asset.name)
            .where(Asset.id.in_(select(Run.asset_id)))
            .order_by(Asset.name)
        )
    ]
    plugins = list(db.scalars(select(Run.plugin_id).distinct().order_by(Run.plugin_id)))
    return assets, plugins


# --- plugins seen in runs, grouped by manifest ------------------------------------------


@dataclass(frozen=True)
class PluginGroup:
    plugin_id: str
    version: str
    manifest_sha256: str
    trusts: list[Trust]  # every tier reported for this manifest, strongest claim first
    unreported: bool  # some run carried no trust tier
    last_run_at: datetime
    runs: int
    verified: bool


_TRUST_ORDER = [Trust.official, Trust.verified, Trust.community]


@dataclass
class _Acc:
    trusts: set[Trust]
    unreported: bool
    last: datetime
    runs: int


def plugin_groups(db: DbSession) -> list[PluginGroup]:
    verified = set(db.scalars(select(VerifiedPlugin.manifest_sha256)))
    grouped = db.execute(
        select(
            Run.plugin_id,
            Run.plugin_version,
            Run.manifest_sha256,
            Run.trust,
            func.max(Run.received_at),
            func.count(),
        ).group_by(Run.plugin_id, Run.plugin_version, Run.manifest_sha256, Run.trust)
    ).all()
    merged: dict[tuple[str, str, str], _Acc] = {}
    for plugin_id, version, digest, trust, last, count in grouped:
        acc = merged.setdefault((plugin_id, version, digest), _Acc(set(), False, last, 0))
        if trust is None:
            acc.unreported = True
        else:
            acc.trusts.add(trust)
        acc.last = max(acc.last, last)
        acc.runs += count
    groups = [
        PluginGroup(
            plugin_id=key[0],
            version=key[1],
            manifest_sha256=key[2],
            trusts=sorted(acc.trusts, key=_TRUST_ORDER.index),
            unreported=acc.unreported,
            last_run_at=acc.last,
            runs=acc.runs,
            verified=key[2] in verified,
        )
        for key, acc in merged.items()
    ]
    groups.sort(key=lambda g: (g.plugin_id, g.version, g.manifest_sha256))
    return groups
