"""NUL (0x00) must never reach the database: PostgreSQL text columns reject it with a 500.

The autouse `_pg_like_nul_guard` fixture (conftest) makes SQLite fail the same way, so every
test here exercises the real boundary on both backends (the CI PostgreSQL job runs them too).
"""

import re
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality
from audidash_server.models import Asset, AuditEntry, Device, FindingRecord, Role, Run, User
from fastapi.testclient import TestClient
from sqlalchemy import select

HTML = {"Accept": "text/html"}
NOW = datetime(2026, 11, 25, 12, 0, 10, tzinfo=UTC)
ASSET = {"name": "srv1", "address": "srv1.local", "asset_type": "linux", "criticality": "high"}
GENERIC_ERROR = "Usuário, senha ou código inválidos."


def _rows(client: TestClient, model: Any) -> list[Any]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(model)).all())


def _result(**over: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": "A-1",
        "title": "title",
        "severity": "high",
        "category": "misconfiguration",
        "target": "srv1.local",
        "evidence": "",
        "recommendation": "",
        "references": [],
        "item_key": None,
    }
    finding.update(over.pop("finding", {}))
    result = {
        "plugin_id": "linux-baseline",
        "plugin_version": "1.2.0",
        "target": "srv1.local",
        "status": "ok",
        "reason": None,
        "findings": [finding],
        "warnings": [],
        "started_at": "2026-11-25T11:59:00Z",
        "finished_at": "2026-11-25T12:00:00Z",
        "stderr_tail": "",
        "manifest_sha256": "a" * 64,
        "trust": "official",
    }
    result.update(over)
    return result


@pytest.fixture
def api(make_api_user: Any) -> Any:
    user = make_api_user()
    assert user.post("/api/v1/assets", ASSET).status_code == 201
    return user


# --- ingestion ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("result", "field"),
    [
        (_result(finding={"title": "bad\x00title"}), "result.findings.0.title"),
        (_result(finding={"evidence": "e\x00"}), "result.findings.0.evidence"),
        (_result(finding={"recommendation": "\x00"}), "result.findings.0.recommendation"),
        (_result(finding={"item_key": "/etc/\x00x"}), "result.findings.0.item_key"),
        (_result(finding={"references": ["ok", "r\x00"]}), "result.findings.0.references.1"),
        (_result(warnings=["fine", "w\x00"]), "result.warnings.1"),
        (_result(status="error", reason="boom\x00", findings=[]), "result.reason"),
        (_result(stderr_tail="tail\x00"), "result.stderr_tail"),
    ],
)
def test_ingest_rejects_nul_naming_the_field(
    api: Any, frozen_clock: Any, result: dict[str, Any], field: str
) -> None:
    r = api.post("/api/v1/runs", {"run_id": str(uuid.uuid4()), "asset": "srv1", "result": result})
    assert r.status_code == 422, r.text
    assert r.json() == {"detail": f"{field} must not contain NUL (0x00) characters"}
    assert _rows(api.client, Run) == [] and _rows(api.client, FindingRecord) == []


def test_ingest_rejects_nul_in_asset_name(api: Any, frozen_clock: Any) -> None:
    body = {"run_id": str(uuid.uuid4()), "asset": "srv1\x00", "result": _result()}
    r = api.post("/api/v1/runs", body)
    assert r.status_code == 422
    assert r.json() == {"detail": "asset must not contain NUL (0x00) characters"}


def test_ingest_without_nul_still_accepted(api: Any, frozen_clock: Any) -> None:
    body = {"run_id": str(uuid.uuid4()), "asset": "srv1", "result": _result()}
    assert api.post("/api/v1/runs", body).status_code == 201


def test_api_asset_create_rejects_nul(make_api_user: Any) -> None:
    api = make_api_user()
    r = api.post("/api/v1/assets", {**ASSET, "name": "srv\x00"})
    assert r.status_code == 422
    assert _rows(api.client, Asset) == []


# --- login --------------------------------------------------------------------------------


def _failure_audits(client: TestClient) -> list[AuditEntry]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        query = select(AuditEntry).where(AuditEntry.action == "login.failure")
        return list(s.scalars(query))


def test_web_login_username_with_nul_is_a_normal_failure(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user("alice", Role.admin)
    r = login("alice\x00", u.password, u.code(frozen_clock.current))
    assert r.status_code == 401 and GENERIC_ERROR in r.text
    audits = _failure_audits(app_client)
    assert len(audits) == 1
    assert audits[0].details["username"] == "alice?"


def test_api_login_username_with_nul_is_a_normal_failure(
    app_client: TestClient, make_user: Any, enroll_device: Any, frozen_clock: Any
) -> None:
    u = make_user("alice", Role.admin)
    device = enroll_device()
    r = app_client.post(
        "/api/v1/auth/token",
        json={"username": "\x00" * 10, "password": u.password, "totp": "000000"},
        headers=device.headers,
    )
    assert r.status_code == 401
    assert r.json() == {"detail": "invalid credentials"}
    assert _failure_audits(app_client)[0].details["username"] == "?" * 10


# --- dashboard filters and forms ----------------------------------------------------------


def _session(client: TestClient, make_user: Any, login: Any, clock: Any, role: Role) -> str:
    user = make_user(f"u-{role.value}", role)
    assert login(user.username, user.password, user.code(clock.current)).status_code == 303
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/", headers=HTML).text)
    assert match
    return match.group(1)


def _seed_asset_and_finding(client: TestClient) -> tuple[Asset, FindingRecord]:
    asset = Asset(
        id=uuid.uuid4(),
        name="web-01",
        address="10.1.1.1",
        asset_type=TargetType.linux,
        criticality=Criticality.high,
        tags=["a"],
        created_at=NOW,
    )
    rec = FindingRecord(
        id=uuid.uuid4(),
        fingerprint="f" * 64,
        asset_id=asset.id,
        plugin_id="p",
        finding_id="F-1",
        title="t",
        severity=Severity.high,
        category=Category.vulnerability,
        status=FindingStatus.open,
        first_seen=NOW,
        last_seen=NOW,
    )
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        s.add(asset)
        s.flush()
        s.add(rec)
        s.commit()
    return asset, rec


@pytest.mark.parametrize("path", ["/findings", "/runs"])
def test_filter_value_with_nul_is_ignored(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, path: str
) -> None:
    _session(app_client, make_user, login, frozen_clock, Role.viewer)
    _seed_asset_and_finding(app_client)
    r = app_client.get(path, params={"plugin": "p\x00"}, headers=HTML)
    assert r.status_code == 200
    if path == "/findings":
        assert "/findings/" in r.text  # the filter was dropped: the finding is listed


@pytest.mark.parametrize(
    "over",
    [{"name": "srv\x00"}, {"address": "10.0.0.1\x00"}, {"tags": "prod, d\x00b"}],
)
def test_asset_forms_reject_nul(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, over: dict[str, str]
) -> None:
    csrf = _session(app_client, make_user, login, frozen_clock, Role.analyst)
    form = {"name": "srv-01", "address": "10.0.0.1", "asset_type": "linux"}
    form |= {"criticality": "high", "tags": "prod", "csrf_token": csrf} | over
    assert app_client.post("/assets", data=form, headers=HTML).status_code == 422
    asset, _ = _seed_asset_and_finding(app_client)
    r = app_client.post(f"/assets/{asset.id}", data=form, headers=HTML)
    assert r.status_code == 422
    assert [a.name for a in _rows(app_client, Asset)] == ["web-01"]


def test_justification_with_nul_rejected(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    csrf = _session(app_client, make_user, login, frozen_clock, Role.analyst)
    _, rec = _seed_asset_and_finding(app_client)
    r = app_client.post(
        f"/findings/{rec.id}/status",
        data={"to": "accepted_risk", "justification": "ok\x00", "csrf_token": csrf},
        headers=HTML,
    )
    assert r.status_code == 422
    assert _rows(app_client, FindingRecord)[0].status is FindingStatus.open


def test_user_creation_with_nul_rejected(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    csrf = _session(app_client, make_user, login, frozen_clock, Role.admin)
    r = app_client.post(
        "/users",
        data={
            "username": "bob\x00",
            "role": "viewer",
            "password": "Another-Str0ng-Passphrase",
            "csrf_token": csrf,
        },
        headers=HTML,
    )
    assert r.status_code == 422
    assert "\x00" not in r.text
    assert [u.username for u in _rows(app_client, User)] == ["u-admin"]


def test_device_token_name_with_nul_rejected(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    csrf = _session(app_client, make_user, login, frozen_clock, Role.admin)
    r = app_client.post(
        "/devices/tokens", data={"name": "lap\x00top", "csrf_token": csrf}, headers=HTML
    )
    assert r.status_code == 422
    assert "\x00" not in r.text


def test_enroll_device_name_with_nul_rejected(
    app_client: TestClient, issue_enrollment_token: Any, csr: Any
) -> None:
    r = app_client.post(
        "/enroll",
        json={"token": issue_enrollment_token(), "device_name": "x\x00", "csr_pem": csr().decode()},
    )
    assert r.status_code == 422
    assert _rows(app_client, Device) == []
