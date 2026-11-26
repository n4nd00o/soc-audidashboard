import re
import uuid
from datetime import UTC, datetime
from html import escape
from typing import Any

import pytest
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus
from audidash_core.scoring import Criticality, ScoredFinding, asset_score, band
from audidash_server.models import (
    Asset,
    AuditEntry,
    FindingRecord,
    Role,
    Run,
)
from fastapi.testclient import TestClient
from sqlalchemy import select

HTML = {"Accept": "text/html"}
HX = {"HX-Request": "true"}
NOW = datetime(2026, 11, 25, 12, 0, 10, tzinfo=UTC)
XSS = '<script>alert("x")</script>'


def _login(client: TestClient, make_user: Any, login: Any, clock: Any, role: Role) -> str:
    user = make_user(f"u-{role.value}", role)
    assert login(user.username, user.password, user.code(clock.current)).status_code == 303
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/", headers=HTML).text)
    assert match
    return match.group(1)


def _form(**over: str) -> dict[str, str]:
    data = {
        "name": "srv-01",
        "address": "10.0.0.1",
        "asset_type": "linux",
        "criticality": "high",
        "tags": "prod, db",
    }
    data.update(over)
    return data


def _assets(client: TestClient) -> list[Asset]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(Asset).order_by(Asset.name)))


def _audit(client: TestClient, action: str) -> list[AuditEntry]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(AuditEntry).where(AuditEntry.action == action)))


def _seed_asset(
    client: TestClient, name: str = "web-01", crit: Criticality = Criticality.high
) -> Asset:
    asset = Asset(
        id=uuid.uuid4(),
        name=name,
        address="10.1.1.1",
        asset_type=TargetType.linux,
        criticality=crit,
        tags=["a"],
        created_at=NOW,
    )
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(asset)
        s.commit()
    return asset


def _seed_finding(
    client: TestClient, asset: Asset, severity: Severity, status: FindingStatus
) -> None:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(
            FindingRecord(
                id=uuid.uuid4(),
                fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
                asset_id=asset.id,
                plugin_id="p",
                finding_id=f"f-{uuid.uuid4().hex[:6]}",
                title="t",
                severity=severity,
                category=Category.vulnerability,
                status=status,
                first_seen=NOW,
                last_seen=NOW,
            )
        )
        s.commit()


def _seed_run(client: TestClient, asset: Asset) -> None:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(
            Run(
                id=uuid.uuid4(),
                asset_id=asset.id,
                plugin_id="p",
                plugin_version="1",
                manifest_sha256="0" * 64,
                status=RunStatus.ok,
                started_at=NOW,
                finished_at=NOW,
                warnings=[],
                received_at=NOW,
            )
        )
        s.commit()


@pytest.mark.parametrize("role", [Role.admin, Role.analyst])
def test_create_edit_delete_per_writer_role(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, role: Role
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, role)
    page = app_client.get("/assets/new", headers=HTML)
    assert page.status_code == 200

    r = app_client.post("/assets", data={**_form(), "csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    (asset,) = _assets(app_client)
    assert (asset.name, asset.address, asset.asset_type, asset.criticality, asset.tags) == (
        "srv-01",
        "10.0.0.1",
        TargetType.linux,
        Criticality.high,
        ["prod", "db"],
    )
    created = _audit(app_client, "asset.create")
    assert len(created) == 1 and created[0].actor_user_id is not None
    assert created[0].target == "srv-01"

    assert app_client.get(f"/assets/{asset.id}/edit", headers=HTML).status_code == 200
    r = app_client.post(
        f"/assets/{asset.id}",
        data={**_form(name="srv-02", criticality="low", tags=""), "csrf_token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    (asset,) = _assets(app_client)
    assert (asset.name, asset.criticality, asset.tags) == ("srv-02", Criticality.low, [])
    (updated,) = _audit(app_client, "asset.update")
    assert updated.details["changed"] == ["criticality", "name", "tags"]
    assert "srv-01" not in str(updated.details)

    r = app_client.post(
        f"/assets/{asset.id}/delete", data={"csrf_token": token}, follow_redirects=False
    )
    assert r.status_code == 303
    assert _assets(app_client) == []
    (deleted,) = _audit(app_client, "asset.delete")
    assert deleted.target == "srv-02" and deleted.actor_user_id is not None


def test_viewer_can_list_but_not_mutate(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    asset = _seed_asset(app_client)
    token = _login(app_client, make_user, login, frozen_clock, Role.viewer)
    page = app_client.get("/assets", headers=HTML)
    assert page.status_code == 200 and "web-01" in page.text
    assert "/assets/new" not in page.text and "/delete" not in page.text

    calls = [
        ("get", "/assets/new", None),
        ("post", "/assets", _form()),
        ("get", f"/assets/{asset.id}/edit", None),
        ("post", f"/assets/{asset.id}", _form(name="hacked")),
        ("post", f"/assets/{asset.id}/delete", {}),
    ]
    for method, path, data in calls:
        r = (
            app_client.get(path, headers=HTML)
            if method == "get"
            else app_client.post(path, data={**(data or {}), "csrf_token": token})
        )
        assert r.status_code == 403, path
        assert r.json() == {"detail": "Forbidden"}, path
    (unchanged,) = _assets(app_client)
    assert unchanged.name == "web-01"
    assert _audit(app_client, "asset.create") == []


def test_unauthenticated_is_redirected(app_client: TestClient) -> None:
    r = app_client.get("/assets", headers=HTML, follow_redirects=False)
    assert r.status_code in (303, 401)
    assert app_client.post("/assets", data=_form()).status_code in (303, 401)


def test_missing_or_bad_csrf_is_403_and_state_unchanged(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    asset = _seed_asset(app_client)
    _login(app_client, make_user, login, frozen_clock, Role.admin)
    assert app_client.post("/assets", data=_form()).status_code == 403
    assert app_client.post("/assets", data={**_form(), "csrf_token": "nope"}).status_code == 403
    assert app_client.post(f"/assets/{asset.id}", data=_form(name="x")).status_code == 403
    assert app_client.post(f"/assets/{asset.id}/delete").status_code == 403
    bad = {"HX-CSRF-Token": "nope"}
    assert app_client.post(f"/assets/{asset.id}/delete", headers=bad).status_code == 403
    (unchanged,) = _assets(app_client)
    assert unchanged.name == "web-01"
    assert _audit(app_client, "asset.update") == [] and _audit(app_client, "asset.delete") == []


def test_duplicate_name_shows_message(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _seed_asset(app_client, "web-01")
    other = _seed_asset(app_client, "web-02")
    token = _login(app_client, make_user, login, frozen_clock, Role.admin)
    r = app_client.post("/assets", data={**_form(name="web-01"), "csrf_token": token})
    assert r.status_code == 422
    assert "Já existe um ativo com esse nome" in r.text
    r = app_client.post(
        f"/assets/{other.id}", data={**_form(name="web-01"), "csrf_token": token}, headers=HX
    )
    assert r.status_code == 422
    assert "Já existe um ativo com esse nome" in r.text
    assert [a.name for a in _assets(app_client)] == ["web-01", "web-02"]
    # Saving an asset under its own unchanged name is not a duplicate.
    r = app_client.post(
        f"/assets/{other.id}",
        data={**_form(name="web-02", criticality="low"), "csrf_token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303


def test_validation_errors_rerender_form(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, Role.analyst)
    for bad in (
        _form(name=""),
        _form(name="a\x07b"),
        _form(name="x" * 129),
        _form(asset_type="amiga"),
        _form(criticality="extreme"),
        _form(tags=",".join(f"t{i}" for i in range(33))),
        _form(address="x" * 256),
    ):
        r = app_client.post("/assets", data={**bad, "csrf_token": token})
        assert r.status_code == 422, bad
        assert 'class="error"' in r.text
        assert "<form" in r.text
    assert _assets(app_client) == []
    assert _audit(app_client, "asset.create") == []


def test_blank_address_stored_as_none(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, Role.admin)
    r = app_client.post(
        "/assets", data={**_form(address="  "), "csrf_token": token}, follow_redirects=False
    )
    assert r.status_code == 303
    assert _assets(app_client)[0].address is None


def test_delete_refused_when_referenced(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    with_findings = _seed_asset(app_client, "with-findings")
    with_runs = _seed_asset(app_client, "with-runs")
    _seed_finding(app_client, with_findings, Severity.high, FindingStatus.resolved)
    _seed_run(app_client, with_runs)
    token = _login(app_client, make_user, login, frozen_clock, Role.admin)
    for asset in (with_findings, with_runs):
        r = app_client.post(
            f"/assets/{asset.id}/delete", data={"csrf_token": token}, follow_redirects=False
        )
        assert r.status_code == 409
        assert "Não é possível excluir" in r.text
        r = app_client.post(f"/assets/{asset.id}/delete", headers={**HX, "HX-CSRF-Token": token})
        assert r.status_code == 409
        assert "Não é possível excluir" in r.text
    assert len(_assets(app_client)) == 2
    assert _audit(app_client, "asset.delete") == []


def test_htmx_flows(app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any) -> None:
    asset = _seed_asset(app_client)
    token = _login(app_client, make_user, login, frozen_clock, Role.analyst)
    hx = {**HX, "HX-CSRF-Token": token}

    edit = app_client.get(f"/assets/{asset.id}/edit", headers=hx)
    assert edit.status_code == 200
    assert "<html" not in edit.text and f'id="asset-{asset.id}"' in edit.text

    r = app_client.post(f"/assets/{asset.id}", data=_form(name="renamed"), headers=hx)
    assert r.status_code == 200
    assert "<html" not in r.text and "renamed" in r.text and f'id="asset-{asset.id}"' in r.text
    assert _assets(app_client)[0].name == "renamed"

    r = app_client.post("/assets", data=_form(name="new-one"), headers=hx)
    assert r.status_code == 200 and r.headers["HX-Redirect"] == "/assets"
    assert [a.name for a in _assets(app_client)] == ["new-one", "renamed"]

    r = app_client.post(f"/assets/{asset.id}/delete", headers=hx)
    assert r.status_code == 200 and r.text == ""
    assert [a.name for a in _assets(app_client)] == ["new-one"]


def test_unknown_asset_is_404(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, Role.admin)
    ghost = uuid.uuid4()
    assert app_client.get(f"/assets/{ghost}/edit", headers=HTML).status_code == 404
    assert (
        app_client.post(f"/assets/{ghost}", data={**_form(), "csrf_token": token}).status_code
        == 404
    )
    assert app_client.post(f"/assets/{ghost}/delete", data={"csrf_token": token}).status_code == 404


def test_list_scores_match_scoring_and_sort(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    web = _seed_asset(app_client, "web-01", Criticality.high)
    db = _seed_asset(app_client, "db-01", Criticality.low)
    _seed_asset(app_client, "a-empty", Criticality.medium)
    _seed_finding(app_client, web, Severity.critical, FindingStatus.open)
    _seed_finding(app_client, web, Severity.high, FindingStatus.acknowledged)
    _seed_finding(app_client, web, Severity.medium, FindingStatus.resolved)
    _seed_finding(app_client, db, Severity.low, FindingStatus.open)
    _login(app_client, make_user, login, frozen_clock, Role.viewer)
    html = app_client.get("/assets", headers=HTML).text

    web_score = asset_score(
        [
            ScoredFinding(Severity.critical, Category.vulnerability, FindingStatus.open),
            ScoredFinding(Severity.high, Category.vulnerability, FindingStatus.acknowledged),
            ScoredFinding(Severity.medium, Category.vulnerability, FindingStatus.resolved),
        ],
        Criticality.high,
    )
    db_score = asset_score(
        [ScoredFinding(Severity.low, Category.vulnerability, FindingStatus.open)], Criticality.low
    )
    assert f"{web_score:.2f}" in html and f"{db_score:.2f}" in html
    assert band(web_score).value in html
    assert html.index("web-01") < html.index("db-01") < html.index("a-empty")
    row = re.search(rf'<tr id="asset-{web.id}".*?</tr>', html, re.S)
    assert row
    assert f"{web_score:.2f}" in row.group(0)
    assert re.search(r'data-label="Abertos">2<', row.group(0))  # open + acknowledged
    assert "Alta" in row.group(0)


def test_xss_escaped_in_list_and_forms(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, Role.admin)
    app_client.post(
        "/assets",
        data={**_form(name=XSS, address=XSS, tags=XSS), "csrf_token": token},
        follow_redirects=False,
    )
    (asset,) = _assets(app_client)
    pages = [
        app_client.get("/assets", headers=HTML).text,
        app_client.get(f"/assets/{asset.id}/edit", headers=HTML).text,
        app_client.get(f"/assets/{asset.id}/edit", headers={**HTML, **HX}).text,
    ]
    for html in pages:
        assert XSS not in html
        assert escape(XSS) in html or escape(XSS, quote=False) in html or "&lt;script&gt;" in html
    r = app_client.post(
        f"/assets/{asset.id}/delete", data={"csrf_token": "x"}, follow_redirects=False
    )
    assert r.status_code == 403


def test_nav_links_to_assets(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _login(app_client, make_user, login, frozen_clock, Role.viewer)
    html = app_client.get("/assets", headers=HTML).text
    assert 'href="/assets" aria-current="page"' in html
