import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.manifest import TargetType
from audidash_core.scoring import (
    Criticality,
    ScoredFinding,
    asset_score,
    band,
    global_score,
)
from audidash_server.models import Asset, FindingEvent, FindingRecord, Role
from audidash_server.web import queries
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session as DbSession

HTML = {"Accept": "text/html"}
NOW = datetime(2026, 11, 25, 12, 0, 10, tzinfo=UTC)  # same instant as the frozen_clock fixture


def _asset(name: str, crit: Criticality) -> Asset:
    return Asset(
        id=uuid.uuid4(),
        name=name,
        asset_type=TargetType.linux,
        criticality=crit,
        tags=[],
        created_at=NOW - timedelta(days=60),
    )


def _finding(
    asset: Asset,
    title: str,
    severity: Severity,
    category: Category,
    status: FindingStatus,
    *,
    first_seen_days: int = 10,
    last_seen_days: int = 0,
) -> tuple[FindingRecord, list[FindingEvent]]:
    record = FindingRecord(
        id=uuid.uuid4(),
        fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
        asset_id=asset.id,
        plugin_id="p",
        finding_id=title,
        title=title,
        severity=severity,
        category=category,
        status=status,
        first_seen=NOW - timedelta(days=first_seen_days),
        last_seen=NOW - timedelta(days=last_seen_days),
    )
    events = [
        FindingEvent(
            finding_id=record.id,
            from_status=None,
            to_status=FindingStatus.open,
            at=record.first_seen,
        )
    ]
    if status is not FindingStatus.open:
        events.append(
            FindingEvent(
                finding_id=record.id,
                from_status=FindingStatus.open,
                to_status=status,
                at=NOW - timedelta(days=5),
            )
        )
    return record, events


class Seeded:
    def __init__(self) -> None:
        self.web = _asset("web-01", Criticality.high)
        self.db = _asset("db-01", Criticality.low)
        self.findings: list[FindingRecord] = []
        self.events: list[FindingEvent] = []
        specs: list[tuple[Asset, str, Severity, Category, FindingStatus, int, int]] = [
            (self.web, "RCE", Severity.critical, Category.vulnerability, FindingStatus.open, 20, 0),
            (
                self.web,
                "Beacon",
                Severity.high,
                Category.suspicious,
                FindingStatus.acknowledged,
                8,
                0,
            ),
            (
                self.web,
                "Old fix",
                Severity.medium,
                Category.misconfiguration,
                FindingStatus.resolved,
                20,
                6,
            ),
            (self.web, "Banner", Severity.info, Category.compliance, FindingStatus.open, 3, 0),
            (
                self.db,
                "Weak TLS",
                Severity.low,
                Category.misconfiguration,
                FindingStatus.open,
                12,
                0,
            ),
            (self.db, "Cron", Severity.medium, Category.suspicious, FindingStatus.open, 120, 100),
        ]
        for asset, title, sev, cat, status, first, last in specs:
            rec, evs = _finding(
                asset, title, sev, cat, status, first_seen_days=first, last_seen_days=last
            )
            self.findings.append(rec)
            self.events.extend(evs)

    def persist(self, db: DbSession) -> None:
        db.add_all([self.web, self.db])
        db.flush()
        db.add_all(self.findings)
        db.flush()
        db.add_all(self.events)
        db.commit()

    def scored(self, asset: Asset, as_of: datetime | None = None) -> list[ScoredFinding]:
        out: list[ScoredFinding] = []
        for rec in self.findings:
            if rec.asset_id != asset.id:
                continue
            status = rec.status
            if as_of is not None:
                hist = [e for e in self.events if e.finding_id == rec.id and e.at < as_of]
                if not hist:
                    continue
                status = max(hist, key=lambda e: e.at).to_status
            out.append(ScoredFinding(rec.severity, rec.category, status))
        return out

    def global_score(self, as_of: datetime | None = None) -> float:
        return global_score(
            [
                (asset_score(self.scored(a, as_of), a.criticality), a.criticality)
                for a in (self.web, self.db)
            ]
        )


@pytest.fixture
def seeded(app_client: TestClient) -> Seeded:
    data = Seeded()
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        data.persist(s)
    return data


def _login(client: TestClient, make_user: Any, login: Any, frozen_clock: Any, role: Role) -> None:
    user = make_user(f"u-{role.value}", role)
    r = login(user.username, user.password, user.code(frozen_clock.current))
    assert r.status_code == 303


def test_queries_match_scoring(app_client: TestClient, seeded: Seeded, frozen_clock: Any) -> None:
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        ov = queries.build_overview(s, NOW)
    expected = seeded.global_score()
    assert ov.global_score == expected
    assert ov.band is band(expected)
    counts = dict(ov.severity_counts)
    assert counts[Severity.critical] == 1
    assert counts[Severity.high] == 1
    assert counts[Severity.medium] == 1  # the resolved medium is not counted
    assert counts[Severity.low] == 1
    assert counts[Severity.info] == 1
    assert ov.stale_count == 1
    assert [s.title for s in ov.suspicious] == ["Beacon", "Cron"]  # newest first
    assert [a.name for a in ov.top_assets] == ["web-01", "db-01"]
    assert ov.top_assets[0].score == asset_score(seeded.scored(seeded.web), Criticality.high)
    assert ov.top_assets[1].score == asset_score(seeded.scored(seeded.db), Criticality.low)


def test_trend_reconstructed_from_events(
    app_client: TestClient, seeded: Seeded, frozen_clock: Any
) -> None:
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        ov = queries.build_overview(s, NOW)
    assert len(ov.trend) == 30
    assert ov.trend[-1].day == NOW.date()
    assert ov.trend[-1].score == seeded.global_score()
    assert ov.trend[0].day == NOW.date() - timedelta(days=29)
    # Day -10 (end of day): the "Old fix" finding was still open there.
    day = NOW.date() - timedelta(days=10)
    end = datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(days=1)
    point = next(p for p in ov.trend if p.day == day)
    assert point.score == seeded.global_score(end)
    assert point.score != ov.trend[-1].score
    assert ov.trend_polyline.count(",") == 30


def test_empty_database(app_client: TestClient) -> None:
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        ov = queries.build_overview(s, NOW)
    assert ov.global_score == 0.0
    assert ov.suspicious == [] and ov.top_assets == [] and ov.stale_count == 0
    assert all(p.score == 0.0 for p in ov.trend)


def test_page_shows_scoring_numbers(
    app_client: TestClient, seeded: Seeded, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _login(app_client, make_user, login, frozen_clock, Role.viewer)
    r = app_client.get("/", headers=HTML)
    assert r.status_code == 200
    score = seeded.global_score()
    match = re.search(r'id="global-score"[^>]*>\s*([0-9.]+)\s*<', r.text)
    assert match and match.group(1) == f"{score:.2f}"
    labels = {"low": "Baixo", "moderate": "Moderado", "high": "Alto", "critical": "Crítico"}
    assert labels[band(score).value] in r.text
    assert "Beacon" in r.text and "web-01" in r.text and "db-01" in r.text
    web_score = asset_score(seeded.scored(seeded.web), Criticality.high)
    assert f"{web_score:.2f}" in r.text
    assert "<polyline" in r.text and "<table" in r.text  # SVG trend + hidden data table


def test_page_is_csp_clean(
    app_client: TestClient, seeded: Seeded, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _login(app_client, make_user, login, frozen_clock, Role.admin)
    html = app_client.get("/", headers=HTML).text
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"<style", html)
    assert not re.search(r"\sstyle\s*=", html)
    assert not re.search(r"<[^>]+\son[a-z]+\s*=", html, re.IGNORECASE)
    assert not re.search(r"https?://(?!www\.w3\.org)", html)  # no external resources
    assert 'src="/static/js/htmx.min.js"' in html and 'src="/static/js/app.js"' in html
    assert 'name="htmx-config"' in html and "includeIndicatorStyles" in html
    assert "chart.umd" not in html  # no charting library


@pytest.mark.parametrize(
    ("role", "admin_links"),
    [(Role.admin, True), (Role.analyst, False), (Role.viewer, False)],
)
def test_nav_by_role(
    app_client: TestClient,
    make_user: Any,
    login: Any,
    frozen_clock: Any,
    role: Role,
    admin_links: bool,
) -> None:
    _login(app_client, make_user, login, frozen_clock, role)
    r = app_client.get("/", headers=HTML)
    assert r.status_code == 200
    for label in ("Visão geral", "Ativos", "Achados", "Execuções", "Plugins", "Dispositivos"):
        assert label in r.text
    assert ("Usuários" in r.text) is admin_links
    assert ("Auditoria" in r.text) is admin_links
    assert re.search(r'<a[^>]*aria-current="page"[^>]*>\s*Visão geral', r.text)
    assert "<nav" in r.text and "<main" in r.text and "<header" in r.text


def test_unauthenticated_redirects(app_client: TestClient) -> None:
    r = app_client.get("/", headers=HTML, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_static_app_js_served(app_client: TestClient) -> None:
    r = app_client.get("/static/js/app.js")
    assert r.status_code == 200
    assert "localStorage" in r.text and "try" in r.text


def test_trend_reads_events_in_a_deterministic_order(
    app_client: TestClient, seeded: Seeded, frozen_clock: Any
) -> None:
    statements: list[str] = []

    def capture(conn: Any, cursor: Any, statement: str, *_: Any) -> None:
        statements.append(" ".join(statement.split()))

    engine = app_client.app.state.engine  # type: ignore[attr-defined]
    event.listen(engine, "before_cursor_execute", capture)
    try:
        with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
            queries.build_overview(s, NOW)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    prefix = "SELECT finding_events.finding_id, finding_events.to_status, finding_events.at "
    (events_sql,) = [q for q in statements if q.startswith(prefix)]
    assert events_sql.endswith("ORDER BY finding_events.at, finding_events.id")
