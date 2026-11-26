import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import audidash_server
import pytest
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality
from audidash_server.models import Asset, AuditEntry, FindingEvent, FindingRecord, Role, User
from audidash_server.services import lifecycle
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

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


def _asset(client: TestClient, name: str = "web-01") -> Asset:
    asset = Asset(
        id=uuid.uuid4(),
        name=name,
        address="10.1.1.1",
        asset_type=TargetType.linux,
        criticality=Criticality.high,
        tags=[],
        created_at=NOW,
    )
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(asset)
        s.commit()
    return asset


def _finding(
    client: TestClient,
    asset: Asset,
    *,
    title: str = "t",
    severity: Severity = Severity.high,
    category: Category = Category.vulnerability,
    status: FindingStatus = FindingStatus.open,
    plugin_id: str = "p",
    last_seen: datetime = NOW,
    evidence: str = "",
    references: list[str] | None = None,
) -> uuid.UUID:
    fid = uuid.uuid4()
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(
            FindingRecord(
                id=fid,
                fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
                asset_id=asset.id,
                plugin_id=plugin_id,
                finding_id=f"f-{fid.hex[:6]}",
                title=title,
                severity=severity,
                category=category,
                evidence=evidence,
                recommendation="rec",
                references=references or [],
                status=status,
                first_seen=NOW,
                last_seen=last_seen,
            )
        )
        s.commit()
    return fid


def _get(client: TestClient, fid: uuid.UUID) -> FindingRecord:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        rec: FindingRecord | None = s.get(FindingRecord, fid)
        assert rec is not None
        return rec


def _events(client: TestClient, fid: uuid.UUID) -> list[FindingEvent]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(FindingEvent).where(FindingEvent.finding_id == fid)))


def _audit(client: TestClient, action: str) -> list[AuditEntry]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(AuditEntry).where(AuditEntry.action == action)))


def _post(client: TestClient, fid: uuid.UUID, csrf: str | None, **data: str) -> Any:
    if csrf is not None:
        data["csrf_token"] = csrf
    return client.post(f"/findings/{fid}/status", data=data, follow_redirects=False)


@pytest.fixture
def analyst(app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any) -> str:
    return _login(app_client, make_user, login, frozen_clock, Role.analyst)


# --- list ---------------------------------------------------------------------------------


def test_list_defaults_to_counted_statuses(app_client: TestClient, analyst: str) -> None:
    a = _asset(app_client)
    _finding(app_client, a, title="aberto-x")
    _finding(app_client, a, title="reconhecido-x", status=FindingStatus.acknowledged)
    _finding(app_client, a, title="resolvido-x", status=FindingStatus.resolved)
    body = app_client.get("/findings", headers=HTML).text
    assert "aberto-x" in body and "reconhecido-x" in body
    assert "resolvido-x" not in body
    assert "resolvido-x" in app_client.get("/findings?status=all").text
    only = app_client.get("/findings?status=resolved").text
    assert "resolvido-x" in only and "aberto-x" not in only


def test_list_filters(app_client: TestClient, analyst: str) -> None:
    a1, a2 = _asset(app_client, "web-01"), _asset(app_client, "db-01")
    old = NOW - timedelta(days=120)
    _finding(app_client, a1, title="crit-x", severity=Severity.critical)
    _finding(app_client, a1, title="cat-x", category=Category.compliance)
    _finding(app_client, a2, title="asset2-x")
    _finding(app_client, a1, title="plug-x", plugin_id="other.plugin")
    _finding(app_client, a1, title="stale-x", last_seen=old)

    def titles(query: str) -> str:
        return str(app_client.get(f"/findings?{query}").text)

    sev = titles("severity=critical")
    assert "crit-x" in sev and "cat-x" not in sev
    cat = titles("category=compliance")
    assert "cat-x" in cat and "crit-x" not in cat
    by_asset = titles(f"asset={a2.id}")
    assert "asset2-x" in by_asset and "crit-x" not in by_asset
    plug = titles("plugin=other.plugin")
    assert "plug-x" in plug and "crit-x" not in plug
    stale = titles("stale=1")
    assert "stale-x" in stale and "crit-x" not in stale


def test_list_ignores_invalid_filter_values(app_client: TestClient, analyst: str) -> None:
    _finding(app_client, _asset(app_client), title="ok-x")
    r = app_client.get("/findings?severity=nope&asset=not-a-uuid&page=zzz&status=bogus")
    assert r.status_code == 200 and "ok-x" in r.text


def test_list_pagination_and_stable_order(app_client: TestClient, analyst: str) -> None:
    a = _asset(app_client)
    _finding(app_client, a, title="LOWSEV-x", severity=Severity.low, last_seen=NOW)
    for i in range(54):
        _finding(
            app_client,
            a,
            title=f"HIGH-{i:02d}-x",
            severity=Severity.high,
            last_seen=NOW - timedelta(minutes=i),
        )
    first = app_client.get("/findings").text
    second = app_client.get("/findings?page=2").text
    assert len(re.findall(r"HIGH-\d\d-x", first)) == 50
    assert "HIGH-00-x" in first and first.index("HIGH-00-x") < first.index("HIGH-01-x")
    assert "LOWSEV-x" not in first
    assert len(re.findall(r"HIGH-\d\d-x", second)) == 4 and "LOWSEV-x" in second
    assert second.index("HIGH-50-x") < second.index("LOWSEV-x")
    assert 'href="/findings?page=2"' in first


def test_list_htmx_returns_fragment_and_form_degrades(app_client: TestClient, analyst: str) -> None:
    _finding(app_client, _asset(app_client), title="frag-x")
    full = app_client.get("/findings", headers=HTML).text
    frag = app_client.get("/findings?severity=high", headers=HX).text
    assert "<html" in full and "<html" not in frag and "frag-x" in frag
    restore = app_client.get("/findings", headers={**HX, "HX-History-Restore-Request": "true"})
    assert "<html" in restore.text
    assert re.search(r'<form[^>]*method="get"[^>]*action="/findings"', full)
    assert 'hx-push-url="true"' in full


def test_list_requires_login(app_client: TestClient) -> None:
    r = app_client.get("/findings", headers=HTML, follow_redirects=False)
    assert r.status_code in (303, 401)


# --- detail -------------------------------------------------------------------------------


def test_detail_escapes_and_links_only_http(app_client: TestClient, analyst: str) -> None:
    a = _asset(app_client)
    fid = _finding(
        app_client,
        a,
        title=XSS,
        evidence=f"line1\n{XSS}",
        references=[
            "javascript:alert(1)",
            "https://example.com/a?x=1&y=2",
            f"see {XSS}",
            "data:text/html,<b>",
        ],
    )
    body = app_client.get(f"/findings/{fid}").text
    assert XSS not in body and "&lt;script&gt;" in body
    assert re.search(r"<pre[^>]*>line1\n&lt;script&gt;", body)
    assert 'href="https://example.com/a?x=1&amp;y=2"' in body
    assert 'rel="noopener noreferrer"' in body
    assert 'href="javascript:' not in body and 'href="data:' not in body
    assert "javascript:alert(1)" in body  # shown as plain text
    assert "rec" in body


def test_detail_404(app_client: TestClient, analyst: str) -> None:
    assert app_client.get(f"/findings/{uuid.uuid4()}").status_code == 404


def test_detail_history_shows_actor(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client))
    assert _post(app_client, fid, analyst, to="acknowledged").status_code == 303
    body = app_client.get(f"/findings/{fid}").text
    assert "u-analyst" in body and "Reconhecido" in body


def test_viewer_sees_no_actions_and_cannot_post(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    csrf = _login(app_client, make_user, login, frozen_clock, Role.viewer)
    fid = _finding(app_client, _asset(app_client), title="v-x")
    page = app_client.get(f"/findings/{fid}")
    assert page.status_code == 200 and "v-x" in page.text
    assert "/status" not in page.text
    assert app_client.get("/findings").status_code == 200
    r = _post(app_client, fid, csrf, to="acknowledged")
    assert r.status_code == 403
    assert _get(app_client, fid).status is FindingStatus.open
    assert _events(app_client, fid) == [] and _audit(app_client, "finding.status_change") == []


# --- lifecycle actions --------------------------------------------------------------------


def test_post_without_csrf_forbidden(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client))
    assert _post(app_client, fid, None, to="acknowledged").status_code == 403
    assert _post(app_client, fid, "wrong", to="acknowledged").status_code == 403
    assert _get(app_client, fid).status is FindingStatus.open
    assert _events(app_client, fid) == []


def test_analyst_sees_actions(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client))
    page = app_client.get(f"/findings/{fid}").text
    assert f'action="/findings/{fid}/status"' in page
    assert 'name="to" value="acknowledged"' in page


@pytest.mark.parametrize("role", [Role.admin, Role.analyst])
def test_status_change_records_event_and_audit(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, role: Role
) -> None:
    csrf = _login(app_client, make_user, login, frozen_clock, role)
    fid = _finding(app_client, _asset(app_client))
    r = _post(app_client, fid, csrf, to="accepted_risk", justification="controle compensatório")
    assert r.status_code == 303 and r.headers["location"] == f"/findings/{fid}"
    rec = _get(app_client, fid)
    assert rec.status is FindingStatus.accepted_risk
    assert rec.justification == "controle compensatório"
    assert rec.status_changed_at is not None and rec.status_changed_by is not None
    (event,) = _events(app_client, fid)
    assert (event.from_status, event.to_status) == (FindingStatus.open, FindingStatus.accepted_risk)
    assert event.user_id == rec.status_changed_by and event.run_id is None
    assert event.justification == "controle compensatório"
    (entry,) = _audit(app_client, "finding.status_change")
    assert entry.details == {
        "from": "open",
        "to": "accepted_risk",
        "finding_id": str(fid),
        "has_justification": True,
    }
    assert "compensat" not in str(entry.details) and "compensat" not in str(entry.target)


def test_audit_never_contains_evidence_or_justification(
    app_client: TestClient, analyst: str
) -> None:
    fid = _finding(app_client, _asset(app_client), evidence="SEGREDO-EVID")
    _post(app_client, fid, analyst, to="resolved")
    (entry,) = _audit(app_client, "finding.status_change")
    assert entry.details["has_justification"] is False
    assert "SEGREDO-EVID" not in repr(entry.details)


@pytest.mark.parametrize("to", ["false_positive", "accepted_risk"])
@pytest.mark.parametrize("justification", ["", "   ", "x" * 1001, "bad\x00char", "bad\x1bchar"])
def test_justification_required_and_validated(
    app_client: TestClient, analyst: str, to: str, justification: str
) -> None:
    fid = _finding(app_client, _asset(app_client))
    r = _post(app_client, fid, analyst, to=to, justification=justification)
    assert r.status_code == 422
    assert _get(app_client, fid).status is FindingStatus.open
    assert _events(app_client, fid) == [] and _audit(app_client, "finding.status_change") == []


def test_justification_boundary_accepted(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client))
    assert (
        _post(app_client, fid, analyst, to="false_positive", justification="x" * 1000).status_code
        == 303
    )
    assert _get(app_client, fid).status is FindingStatus.false_positive


@pytest.mark.parametrize(
    ("start", "to", "ok"),
    [
        (FindingStatus.open, "acknowledged", True),
        (FindingStatus.open, "resolved", True),
        (FindingStatus.acknowledged, "resolved", True),
        (FindingStatus.acknowledged, "false_positive", True),
        (FindingStatus.resolved, "open", True),
        (FindingStatus.false_positive, "open", True),
        (FindingStatus.accepted_risk, "open", True),
        (FindingStatus.auto_resolved, "open", True),
        (FindingStatus.acknowledged, "acknowledged", False),
        (FindingStatus.acknowledged, "open", False),
        (FindingStatus.open, "open", False),
        (FindingStatus.open, "auto_resolved", False),
        (FindingStatus.resolved, "acknowledged", False),
        (FindingStatus.resolved, "accepted_risk", False),
        (FindingStatus.auto_resolved, "resolved", False),
        (FindingStatus.open, "bogus", False),
    ],
)
def test_transition_matrix(
    app_client: TestClient, analyst: str, start: FindingStatus, to: str, ok: bool
) -> None:
    fid = _finding(app_client, _asset(app_client), status=start)
    r = _post(app_client, fid, analyst, to=to, justification="motivo")
    if ok:
        assert r.status_code == 303
        assert _get(app_client, fid).status.value == to
        assert len(_events(app_client, fid)) == 1
    else:
        assert r.status_code == 409
        assert _get(app_client, fid).status is start
        assert _events(app_client, fid) == []


def test_reopen_clears_justification(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client))
    _post(app_client, fid, analyst, to="false_positive", justification="motivo")
    _post(app_client, fid, analyst, to="open")
    rec = _get(app_client, fid)
    assert rec.status is FindingStatus.open and rec.justification is None
    assert [e.to_status for e in _events(app_client, fid)].count(FindingStatus.open) == 1


def test_unknown_finding_404(app_client: TestClient, analyst: str) -> None:
    assert _post(app_client, uuid.uuid4(), analyst, to="acknowledged").status_code == 404


def test_htmx_success_returns_lifecycle_fragment(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client))
    r = app_client.post(
        f"/findings/{fid}/status",
        data={"to": "acknowledged"},
        headers={**HX, "HX-CSRF-Token": analyst},
    )
    assert r.status_code == 200 and "<html" not in r.text
    assert 'id="finding-lifecycle"' in r.text and "Reconhecido" in r.text


def test_htmx_errors_render_fragment_with_message(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client))
    headers = {**HX, "HX-CSRF-Token": analyst}
    r = app_client.post(f"/findings/{fid}/status", data={"to": "false_positive"}, headers=headers)
    assert r.status_code == 422 and "<html" not in r.text and 'role="alert"' in r.text
    r = app_client.post(f"/findings/{fid}/status", data={"to": "auto_resolved"}, headers=headers)
    assert r.status_code == 409 and 'role="alert"' in r.text


def test_nonhtmx_error_rerenders_full_page(app_client: TestClient, analyst: str) -> None:
    fid = _finding(app_client, _asset(app_client), title="full-x")
    r = _post(app_client, fid, analyst, to="false_positive")
    assert r.status_code == 422 and "<html" in r.text and "full-x" in r.text


def test_app_js_has_response_error_listener() -> None:
    js = (Path(audidash_server.__file__).parent / "static/js/app.js").read_text("utf-8")
    assert "htmx:responseError" in js and 'role", "status"' in js
    assert "style." not in js.replace("element.style", "")  # no inline-style manipulation


# --- stale writers vs manual state --------------------------------------------------------


def _seed_db_finding(db: DbSession, status: FindingStatus) -> uuid.UUID:
    asset = Asset(
        id=uuid.uuid4(),
        name="a",
        asset_type=TargetType.linux,
        criticality=Criticality.low,
        tags=[],
        created_at=NOW,
    )
    fid = uuid.uuid4()
    db.add(asset)
    db.flush()
    db.add(
        FindingRecord(
            id=fid,
            fingerprint=uuid.uuid4().hex * 2,
            asset_id=asset.id,
            plugin_id="p",
            finding_id="f",
            title="t",
            severity=Severity.low,
            category=Category.vulnerability,
            status=status,
            first_seen=NOW,
            last_seen=NOW,
        )
    )
    db.commit()
    return fid


def test_transition_guard_refuses_disallowed_current_status(db_session: DbSession) -> None:
    fid = _seed_db_finding(db_session, FindingStatus.accepted_risk)
    stale = db_session.get(FindingRecord, fid)
    assert stale is not None
    ok = lifecycle.transition(
        db_session,
        fid,
        to_status=FindingStatus.auto_resolved,
        allowed_from={FindingStatus.open, FindingStatus.acknowledged},
        user_id=None,
        run_id=None,
        justification=None,
    )
    db_session.commit()
    assert ok is False
    assert db_session.scalars(select(FindingEvent)).all() == []
    db_session.refresh(stale)
    assert stale.status is FindingStatus.accepted_risk


def test_transition_uses_actual_from_status_in_event(db_session: DbSession) -> None:
    fid = _seed_db_finding(db_session, FindingStatus.acknowledged)
    user = User(
        id=uuid.uuid4(),
        username="x",
        password_hash="h",  # noqa: S106 - placeholder, never verified
        role=Role.analyst,
        failed_logins=0,
        created_at=NOW,
    )
    db_session.add(user)
    db_session.flush()
    assert lifecycle.transition(
        db_session,
        fid,
        to_status=FindingStatus.resolved,
        allowed_from={FindingStatus.open, FindingStatus.acknowledged},
        user_id=user.id,
        run_id=None,
        justification="ok",
    )
    db_session.commit()
    (event,) = db_session.scalars(select(FindingEvent)).all()
    assert (event.from_status, event.to_status) == (
        FindingStatus.acknowledged,
        FindingStatus.resolved,
    )


def test_stale_auto_resolve_does_not_overwrite_accepted_risk(
    make_api_user: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_ingest import ASSET, _by_finding_id, _result, _upload  # noqa: PLC0415
    from test_ingest import _finding as f

    api = make_api_user()
    assert api.post("/api/v1/assets", ASSET).status_code == 201
    _upload(api, _result([f("A-1"), f("B-2")]))
    original = lifecycle.try_transition

    def racing(db: DbSession, finding_id: uuid.UUID, **kwargs: Any) -> Any:
        rec = db.get(FindingRecord, finding_id)
        assert rec is not None
        if rec.finding_id == "B-2":  # an analyst commits accepted_risk after ingest loaded rows
            db.execute(
                update(FindingRecord)
                .where(FindingRecord.id == finding_id)
                .values(status=FindingStatus.accepted_risk, justification="analyst")
                .execution_options(synchronize_session=False)
            )
        return original(db, finding_id, **kwargs)

    monkeypatch.setattr(lifecycle, "try_transition", racing)
    r = _upload(api, _result([f("A-1")]))
    assert r.status_code == 201
    assert r.json()["auto_resolved"] == 0
    b2 = _by_finding_id(api.client)["B-2"]
    assert b2.status is FindingStatus.accepted_risk and b2.justification == "analyst"
    with api.client.app.state.sessionmaker() as s:
        to_auto = [
            e
            for e in s.scalars(select(FindingEvent).where(FindingEvent.finding_id == b2.id))
            if e.to_status is FindingStatus.auto_resolved
        ]
    assert to_auto == []


def test_list_orders_by_severity_rank_not_alphabetically(
    app_client: TestClient, analyst: str
) -> None:
    a = _asset(app_client)
    # Newest last_seen on the lowest severity, so neither recency nor name order can pass.
    for i, sev in enumerate(
        [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
    ):
        _finding(
            app_client, a, title=f"RANK-{sev.value}-x", severity=sev,
            last_seen=NOW - timedelta(days=10 - i),
        )  # fmt: skip
    body = app_client.get("/findings").text
    assert re.findall(r"RANK-(\w+)-x", body) == ["critical", "high", "medium", "low", "info"]


def test_detail_reference_edge_cases(app_client: TestClient, analyst: str) -> None:
    fid = _finding(
        app_client,
        _asset(app_client),
        references=[
            " javascript:x",
            "java	script:x",
            "//evil.example/x",
            "HTTP://ok.example/x",
            "data:text/html,x",
        ],
    )
    body = app_client.get(f"/findings/{fid}").text
    assert 'href="HTTP://ok.example/x"' in body
    assert body.count('rel="noopener noreferrer"') == 1
    for bad in ("javascript:", "java	script", "//evil", "data:"):
        assert f'href="{bad}' not in body and f'href=" {bad}' not in body


def test_list_page_clamping(app_client: TestClient, analyst: str) -> None:
    a = _asset(app_client)
    for i in range(51):
        _finding(app_client, a, title=f"P-{i:02d}-x")
    assert "página 1 de 2" in app_client.get("/findings?page=-5").text
    assert "página 2 de 2" in app_client.get("/findings?page=999999").text
    assert "página 1 de 2" in app_client.get("/findings?page=abc").text
    assert "página 1 de 2" in app_client.get("/findings?page=0").text
