"""Runs, plugin allowlist, devices, users and audit pages (+ GET /api/v1/verified)."""

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from audidash_core.catalog import Trust
from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus
from audidash_core.scoring import Criticality
from audidash_server import audit
from audidash_server.auth.passwords import verify_password
from audidash_server.models import (
    Asset,
    AuditEntry,
    Device,
    EnrollmentToken,
    Role,
    Run,
    User,
    VerifiedPlugin,
)
from audidash_server.services.enrollment import token_sha256
from audidash_server.web.routes_users import _removes_last_admin
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

HTML = {"Accept": "text/html"}
NOW = datetime(2026, 11, 25, 12, 0, 10, tzinfo=UTC)
XSS = '<script>alert("x")</script>'
ESCAPED = "&lt;script&gt;alert("
HASH_A = "a" * 64
HASH_B = "b" * 64
TEST_PASSWORD = "Corr3ct-Horse-Battery-Staple"  # noqa: S105 - what make_user assigns


def _login(client: TestClient, make_user: Any, login: Any, clock: Any, role: Role) -> str:
    user = make_user(f"u-{role.value}", role)
    assert login(user.username, user.password, user.code(clock.current)).status_code == 303
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/", headers=HTML).text)
    assert match
    return match.group(1)


@pytest.fixture
def admin(app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any) -> str:
    return _login(app_client, make_user, login, frozen_clock, Role.admin)


def _db(client: TestClient) -> Any:
    return client.app.state.sessionmaker()  # type: ignore[attr-defined]


def _all(client: TestClient, model: Any) -> list[Any]:
    with _db(client) as s:
        return list(s.scalars(select(model)))


def _audit(client: TestClient, action: str) -> list[AuditEntry]:
    with _db(client) as s:
        return list(s.scalars(select(AuditEntry).where(AuditEntry.action == action)))


def _asset(client: TestClient, name: str = "srv-1") -> Asset:
    asset = Asset(
        id=uuid.uuid4(),
        name=name,
        address=None,
        asset_type=TargetType.linux,
        criticality=Criticality.high,
        tags=[],
        created_at=NOW,
    )
    with _db(client) as s:
        s.add(asset)
        s.commit()
    return asset


def _run(
    client: TestClient,
    asset: Asset,
    *,
    plugin_id: str = "linux-baseline",
    version: str = "1.0.0",
    digest: str = HASH_A,
    trust: Trust | None = Trust.official,
    status: RunStatus = RunStatus.ok,
    received_at: datetime = NOW,
    device_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    summary: dict[str, Any] | None = None,
) -> Run:
    run = Run(
        id=uuid.uuid4(),
        device_id=device_id,
        user_id=user_id,
        asset_id=asset.id,
        plugin_id=plugin_id,
        plugin_version=version,
        manifest_sha256=digest,
        trust=trust,
        status=status,
        started_at=NOW,
        finished_at=NOW,
        warnings=[],
        received_at=received_at,
        ingest_summary=summary,
    )
    with _db(client) as s:
        s.add(run)
        s.commit()
    return run


def _post(client: TestClient, path: str, token: str | None, **data: str) -> Any:
    if token is not None:
        data["csrf_token"] = token
    return client.post(path, data=data, follow_redirects=False)


# ------------------------------------------------------------------------------- runs


def test_runs_list_shows_columns_counts_device_and_user(
    app_client: TestClient, admin: str, enroll_device: Any
) -> None:
    device = enroll_device("lap-1")
    asset = _asset(app_client)
    owner = _all(app_client, User)[0]
    summary = {"new": 3, "updated": 2, "auto_resolved": 1, "asset_score": 5.0}
    _run(
        app_client,
        asset,
        trust=Trust.verified,
        status=RunStatus.error,
        device_id=device.id,
        user_id=owner.id,
        summary=summary,
    )
    r = app_client.get("/runs", headers=HTML)
    assert r.status_code == 200
    body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))
    for needle in ("srv-1", "linux-baseline", "1.0.0", "Verificado", "Erro", "lap-1", "u-admin"):
        assert needle in body
    assert re.search(r'data-label="Novos">3<', r.text)
    assert re.search(r'data-label="Atualizados">2<', r.text)
    assert re.search(r'data-label="Resolvidos auto\.">1<', r.text)
    assert "2026-11-25 12:00" in body


def test_runs_without_summary_or_trust_render_dashes(app_client: TestClient, admin: str) -> None:
    _run(app_client, _asset(app_client), trust=None, summary=None)
    r = app_client.get("/runs", headers=HTML)
    assert r.status_code == 200
    assert 'data-label="Novos">—<' in r.text and 'data-label="Confiança">—<' in r.text


def _results(page: str) -> str:
    """The runs table only (the filter form lists every asset and plugin name too)."""
    return page.split('<table class="data runs">', 1)[1] if "<table" in page else ""


def test_runs_filters_and_ordering(app_client: TestClient, admin: str) -> None:
    a1, a2 = _asset(app_client, "alpha"), _asset(app_client, "beta")
    _run(app_client, a1, plugin_id="plug-one", received_at=NOW)
    _run(
        app_client,
        a2,
        plugin_id="plug-two",
        status=RunStatus.timeout,
        received_at=NOW + timedelta(hours=1),
    )
    full = _results(app_client.get("/runs", headers=HTML).text)
    assert full.index("beta") < full.index("alpha")  # newest first
    by_asset = _results(app_client.get(f"/runs?asset={a1.id}", headers=HTML).text)
    assert "plug-one" in by_asset and "plug-two" not in by_asset
    by_plugin = _results(app_client.get("/runs?plugin=plug-two", headers=HTML).text)
    assert "beta" in by_plugin and "alpha" not in by_plugin
    by_status = _results(app_client.get("/runs?status=timeout", headers=HTML).text)
    assert "plug-two" in by_status and "plug-one" not in by_status
    junk = app_client.get("/runs?status=nope&asset=zzz&page=-4", headers=HTML)
    assert junk.status_code == 200  # invalid filters are ignored


def test_runs_paginate_by_50(app_client: TestClient, admin: str) -> None:
    asset = _asset(app_client)
    for i in range(51):
        _run(app_client, asset, version=f"1.0.{i}", received_at=NOW + timedelta(minutes=i))
    first = app_client.get("/runs", headers=HTML).text
    assert "51 execução(ões) · página 1 de 2" in first
    assert first.count("<tr>") == 51  # header + 50 rows
    assert "/runs?page=2" in first
    second = app_client.get("/runs?page=2", headers=HTML).text
    assert second.count("<tr>") == 2 and "1.0.0<" in second


def test_runs_escape_plugin_and_asset(app_client: TestClient, admin: str) -> None:
    _run(app_client, _asset(app_client, "<b>x</b>"), plugin_id=XSS, version=XSS)
    page = app_client.get("/runs", headers=HTML).text
    assert XSS not in page and ESCAPED in page and "<b>x</b>" not in page


def test_runs_requires_login(app_client: TestClient) -> None:
    assert app_client.get("/runs", headers=HTML, follow_redirects=False).status_code in (303, 401)


# ---------------------------------------------------------------------------- plugins


def test_plugins_grouped_by_id_version_manifest(app_client: TestClient, admin: str) -> None:
    asset = _asset(app_client)
    _run(app_client, asset, trust=Trust.official, received_at=NOW)
    _run(app_client, asset, trust=Trust.official, received_at=NOW + timedelta(hours=2))
    _run(app_client, asset, trust=Trust.community, received_at=NOW + timedelta(hours=1))
    _run(app_client, asset, version="2.0.0", digest=HASH_B, trust=None)
    page = app_client.get("/plugins", headers=HTML).text
    rows = re.findall(r"<tr>.*?</tr>", page.split("Lista de verificados")[0], re.S)[1:]
    assert len(rows) == 2
    first = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", rows[0]))
    assert "linux-baseline 1.0.0" in first and HASH_A in first
    assert "Oficial, Comunidade" in first and " 3 " in first
    assert "2026-11-25 14:00" in first  # last run time
    assert "não informada" in re.sub(r"<[^>]+>", " ", rows[1])


def test_plugins_verify_and_unverify_persist_with_audit(app_client: TestClient, admin: str) -> None:
    _run(app_client, _asset(app_client))
    r = _post(app_client, "/plugins/verify", admin, manifest_sha256=HASH_A)
    assert r.status_code == 303
    (row,) = _all(app_client, VerifiedPlugin)
    assert (row.manifest_sha256, row.plugin_id, row.version) == (HASH_A, "linux-baseline", "1.0.0")
    assert row.approved_by is not None and row.approved_at is not None
    (entry,) = _audit(app_client, "plugin.verify")
    assert entry.details["manifest_sha256"] == HASH_A and entry.target == "linux-baseline"
    page = app_client.get("/plugins", headers=HTML).text
    assert "Remover verificação" in page and "u-admin" in page
    # idempotent: a second verify neither duplicates nor re-audits
    assert _post(app_client, "/plugins/verify", admin, manifest_sha256=HASH_A).status_code == 303
    assert (
        len(_all(app_client, VerifiedPlugin)) == 1 and len(_audit(app_client, "plugin.verify")) == 1
    )

    r = _post(app_client, "/plugins/unverify", admin, manifest_sha256=HASH_A)
    assert r.status_code == 303
    assert _all(app_client, VerifiedPlugin) == []
    (gone,) = _audit(app_client, "plugin.unverify")
    assert gone.details["manifest_sha256"] == HASH_A
    with _db(app_client) as s:
        assert audit.verify_chain(s) is None


def test_plugins_verify_rejects_bad_or_unseen_hash(app_client: TestClient, admin: str) -> None:
    _run(app_client, _asset(app_client))
    assert _post(app_client, "/plugins/verify", admin, manifest_sha256="A" * 64).status_code == 422
    assert _post(app_client, "/plugins/verify", admin, manifest_sha256="zz").status_code == 422
    assert _post(app_client, "/plugins/verify", admin, manifest_sha256=HASH_B).status_code == 404
    assert _post(app_client, "/plugins/unverify", admin, manifest_sha256=HASH_B).status_code == 404
    assert _all(app_client, VerifiedPlugin) == []


def test_plugins_runs_without_manifest_cannot_be_verified(
    app_client: TestClient, admin: str
) -> None:
    _run(app_client, _asset(app_client), digest="")
    page = app_client.get("/plugins", headers=HTML).text
    assert "Marcar como verificado" not in page
    assert _post(app_client, "/plugins/verify", admin, manifest_sha256="").status_code == 422


def test_plugins_csrf_enforced(app_client: TestClient, admin: str) -> None:
    _run(app_client, _asset(app_client))
    assert _post(app_client, "/plugins/verify", None, manifest_sha256=HASH_A).status_code == 403
    assert _post(app_client, "/plugins/verify", "bad", manifest_sha256=HASH_A).status_code == 403
    assert _all(app_client, VerifiedPlugin) == []


@pytest.mark.parametrize("role", [Role.analyst, Role.viewer])
def test_plugins_non_admin_forbidden_to_mutate_and_sees_no_buttons(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, role: Role
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, role)
    _run(app_client, _asset(app_client))
    for path in ("/plugins/verify", "/plugins/unverify"):
        assert _post(app_client, path, token, manifest_sha256=HASH_A).status_code == 403
    page = app_client.get("/plugins", headers=HTML)
    assert page.status_code == 200 and "Marcar como verificado" not in page.text
    assert _all(app_client, VerifiedPlugin) == []


def test_plugins_escape_ids(app_client: TestClient, admin: str) -> None:
    _run(app_client, _asset(app_client), plugin_id=XSS, version=XSS)
    page = app_client.get("/plugins", headers=HTML).text
    assert XSS not in page and ESCAPED in page


def test_verified_api_returns_allowlist(make_api_user: Any, app_client: TestClient) -> None:
    viewer = make_api_user("vic", Role.viewer)
    r = viewer.get("/api/v1/verified")
    assert r.status_code == 200 and r.json() == {"manifest_sha256": []}
    with _db(app_client) as s:
        for digest, pid in ((HASH_B, "b-plugin"), (HASH_A, "a-plugin")):
            s.add(
                VerifiedPlugin(manifest_sha256=digest, plugin_id=pid, version="1", approved_at=NOW)
            )
        s.commit()
    assert viewer.get("/api/v1/verified").json() == {"manifest_sha256": [HASH_A, HASH_B]}


def test_verified_api_requires_device_and_bearer(
    make_api_user: Any, app_client: TestClient
) -> None:
    api = make_api_user("vic", Role.viewer)
    assert app_client.get("/api/v1/verified").status_code == 401
    assert app_client.get("/api/v1/verified", headers=api.device.headers).status_code == 401


# ---------------------------------------------------------------------------- devices


def _command(page: str) -> str:
    match = re.search(r'<pre class="evidence" id="enroll-command">(.*?)</pre>', page, re.S)
    assert match, "enrolment command missing"
    return match.group(1).replace("&#34;", '"').replace("&amp;", "&")


def test_create_token_shows_command_once(app_client: TestClient, admin: str, settings: Any) -> None:
    r = _post(app_client, "/devices/tokens", admin, name="laptop-ana")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    cmd = _command(r.text)
    ca = app_client.app.state.ca.fingerprint_sha256()  # type: ignore[attr-defined]
    m = re.fullmatch(
        r"audidash enroll --server (\S+) --api (\S+) --token=(\S+) --name laptop-ana "
        r"--ca-fingerprint (\S+)",
        cmd,
    )
    assert m, cmd
    assert m.group(1) == "https://testserver" and m.group(2) == "https://testserver:9443"
    token, fingerprint = m.group(3), m.group(4)
    assert fingerprint == ca
    (row,) = _all(app_client, EnrollmentToken)
    assert row.token_sha256 == token_sha256(token)
    assert row.used_at is None
    (entry,) = _audit(app_client, "enrollment_token.create")
    assert entry.target == "laptop-ana" and token not in str(entry.details)
    # never shown again, and never stored in clear
    assert token not in app_client.get("/devices", headers=HTML).text
    assert token not in str(_all(app_client, AuditEntry)[-1].details)


def test_token_ttl_is_24_hours(app_client: TestClient, admin: str, frozen_clock: Any) -> None:
    _post(app_client, "/devices/tokens", admin, name="laptop-ana")
    (row,) = _all(app_client, EnrollmentToken)
    assert row.expires_at == frozen_clock.current + timedelta(hours=24)


def test_command_uses_public_urls_from_settings(
    app_client: TestClient, admin: str, settings: Any
) -> None:
    app_client.app.state.settings = settings.model_copy(  # type: ignore[attr-defined]
        update={
            "public_dashboard_url": "https://soc.example.org:8443",
            "public_api_url": "https://soc.example.org:9443",
        }
    )
    cmd = _command(_post(app_client, "/devices/tokens", admin, name="x1 box").text)
    assert "--server https://soc.example.org:8443 --api https://soc.example.org:9443" in cmd
    assert '--name "x1 box"' in cmd


@pytest.mark.parametrize(
    "name", ["", "   ", "a;rm -rf /", "$(id)", "line\nbreak", "-lead", "x" * 129]
)
def test_token_rejects_unsafe_device_names(app_client: TestClient, admin: str, name: str) -> None:
    r = _post(app_client, "/devices/tokens", admin, name=name)
    assert r.status_code == 422 and "inválido" in r.text
    assert "audidash enroll" not in r.text
    assert _all(app_client, EnrollmentToken) == []
    assert _audit(app_client, "enrollment_token.create") == []


def test_token_list_shows_status_and_consuming_device_never_token(
    app_client: TestClient, admin: str, frozen_clock: Any, csr: Any
) -> None:
    cmd = _command(_post(app_client, "/devices/tokens", admin, name="laptop-ana").text)
    token = re.search(r"--token=(\S+)", cmd).group(1)  # type: ignore[union-attr]
    page = app_client.get("/devices", headers=HTML).text
    assert "Não usado" in page
    r = app_client.post(
        "/enroll",
        json={"token": token, "device_name": "laptop-ana", "csr_pem": csr().decode()},
    )
    assert r.status_code == 201
    page = app_client.get("/devices", headers=HTML).text
    tokens_part = page.split("Tokens de inscrição")[1]
    assert (
        "Usado" in tokens_part and "laptop-ana" in tokens_part and "2026-11-25 12:00" in tokens_part
    )
    assert token not in page and token_sha256(token) not in page
    with _db(app_client) as db:  # an issued-but-expired token
        owner = db.scalars(select(User)).one()
        db.add(
            EnrollmentToken(
                token_sha256="c" * 64,
                created_by=owner.id,
                expires_at=frozen_clock.current - timedelta(minutes=1),
            )
        )
        db.commit()
    assert "Expirado" in app_client.get("/devices", headers=HTML).text


def test_revoke_device_persists_audits_and_blocks_api(
    app_client: TestClient, admin: str, make_api_user: Any, frozen_clock: Any
) -> None:
    api = make_api_user("bob", Role.analyst)
    assert api.get("/api/v1/assets").status_code == 200
    r = _post(app_client, f"/devices/{api.device.id}/revoke", admin)
    assert r.status_code == 303 and r.headers["location"] == "/devices"
    with _db(app_client) as s:
        device = s.get(Device, api.device.id)
        assert device is not None and device.revoked_at == frozen_clock.current
    (entry,) = _audit(app_client, "device.revoke")
    assert entry.target == str(api.device.id) and entry.details["device_name"] == "bob-laptop"
    assert api.get("/api/v1/assets").status_code == 401
    assert "Revogado" in app_client.get("/devices", headers=HTML).text
    # repeating is harmless and not re-audited
    assert _post(app_client, f"/devices/{api.device.id}/revoke", admin).status_code == 303
    assert len(_audit(app_client, "device.revoke")) == 1


def test_revoke_unknown_device_404(app_client: TestClient, admin: str) -> None:
    assert _post(app_client, f"/devices/{uuid.uuid4()}/revoke", admin).status_code == 404


def test_device_mutations_need_csrf(app_client: TestClient, admin: str, enroll_device: Any) -> None:
    device = enroll_device("lap-1")
    assert _post(app_client, f"/devices/{device.id}/revoke", None).status_code == 403
    assert _post(app_client, "/devices/tokens", "bad", name="x-box").status_code == 403
    with _db(app_client) as s:
        found = s.get(Device, device.id)
        assert found is not None and found.revoked_at is None
    assert len(_all(app_client, EnrollmentToken)) == 1  # only the one enroll_device issued


@pytest.mark.parametrize("role", [Role.analyst, Role.viewer])
def test_devices_non_admin_cannot_mutate_and_sees_no_tokens(
    app_client: TestClient,
    make_user: Any,
    login: Any,
    frozen_clock: Any,
    enroll_device: Any,
    role: Role,
) -> None:
    device = enroll_device("lap-1")
    token = _login(app_client, make_user, login, frozen_clock, role)
    assert _post(app_client, "/devices/tokens", token, name="x-box").status_code == 403
    assert _post(app_client, f"/devices/{device.id}/revoke", token).status_code == 403
    page = app_client.get("/devices", headers=HTML)
    assert page.status_code == 200 and "lap-1" in page.text
    assert "Tokens de inscrição" not in page.text and "Revogar" not in page.text
    with _db(app_client) as s:
        found = s.get(Device, device.id)
        assert found is not None and found.revoked_at is None


def test_devices_escape_names(app_client: TestClient, admin: str, enroll_device: Any) -> None:
    device = enroll_device("lap-1")
    with _db(app_client) as s:
        s.execute(update(Device).where(Device.id == device.id).values(name=XSS))
        s.commit()
    page = app_client.get("/devices", headers=HTML).text
    assert XSS not in page and ESCAPED in page


# ----------------------------------------------------------------------------- users


def _user(client: TestClient, name: str) -> User:
    with _db(client) as s:
        found: User = s.scalars(select(User).where(User.username == name)).one()
        s.expunge(found)
        return found


def test_create_user_persists_hashed_password_without_totp(
    app_client: TestClient, admin: str, login: Any
) -> None:
    r = _post(app_client, "/users", admin, username="carol", role="analyst", password=TEST_PASSWORD)
    assert r.status_code == 303 and r.headers["location"] == "/users"
    carol = _user(app_client, "carol")
    assert carol.role is Role.analyst and carol.totp_secret_enc is None and not carol.disabled
    assert carol.password_hash != TEST_PASSWORD and verify_password(
        carol.password_hash, TEST_PASSWORD
    )
    (entry,) = _audit(app_client, "user.create")
    assert entry.target == "carol" and entry.details["role"] == "analyst"
    assert TEST_PASSWORD not in str(entry.details)
    assert "Pendente" in app_client.get("/users", headers=HTML).text


def test_new_user_is_sent_to_totp_enrolment_on_first_login(
    app_client: TestClient, admin: str, login: Any
) -> None:
    _post(app_client, "/users", admin, username="carol", role="viewer", password=TEST_PASSWORD)
    app_client.cookies.clear()
    r = login("carol", TEST_PASSWORD)
    assert r.status_code == 303 and r.headers["location"] == "/totp/setup"


@pytest.mark.parametrize(
    ("form", "message"),
    [
        ({"username": "dave", "role": "viewer", "password": "short"}, "pelo menos"),
        (
            {"username": "dave", "role": "viewer", "password": "dave-dave-dave-1!"},
            "nome de usuário",
        ),
        ({"username": "dave", "role": "viewer", "password": "password1234"}, "comum"),
        ({"username": "a", "role": "viewer", "password": TEST_PASSWORD}, "Usuário inválido"),
        ({"username": "bad name", "role": "viewer", "password": TEST_PASSWORD}, "Usuário inválido"),
        ({"username": "dave", "role": "root", "password": TEST_PASSWORD}, "Perfil inválido"),
    ],
)
def test_create_user_validates(
    app_client: TestClient, admin: str, form: dict[str, str], message: str
) -> None:
    before = len(_all(app_client, User))
    r = _post(app_client, "/users", admin, **form)
    assert r.status_code == 422 and message in r.text
    assert len(_all(app_client, User)) == before
    assert _audit(app_client, "user.create") == []


def test_create_duplicate_username_conflicts(app_client: TestClient, admin: str) -> None:
    r = _post(
        app_client, "/users", admin, username="u-admin", role="viewer", password=TEST_PASSWORD
    )
    assert r.status_code == 409 and "Já existe" in r.text
    assert len(_all(app_client, User)) == 1


def test_change_role_persists_and_audits(
    app_client: TestClient, admin: str, make_user: Any
) -> None:
    other = make_user("erin", Role.viewer)
    r = _post(app_client, f"/users/{other.id}/role", admin, role="analyst")
    assert r.status_code == 303
    assert _user(app_client, "erin").role is Role.analyst
    (entry,) = _audit(app_client, "user.role_change")
    assert entry.details["from"] == "viewer" and entry.details["to"] == "analyst"
    assert _post(app_client, f"/users/{other.id}/role", admin, role="superuser").status_code == 422
    assert _user(app_client, "erin").role is Role.analyst


def test_cannot_change_own_role_or_disable_self(app_client: TestClient, admin: str) -> None:
    me = _user(app_client, "u-admin")
    assert _post(app_client, f"/users/{me.id}/role", admin, role="viewer").status_code == 409
    assert _post(app_client, f"/users/{me.id}/disable", admin).status_code == 409
    after = _user(app_client, "u-admin")
    assert after.role is Role.admin and not after.disabled
    assert _audit(app_client, "user.role_change") == [] and _audit(app_client, "user.disable") == []


def test_last_active_admin_guard(db_session: Any, make_user: Any) -> None:
    make_user("only", Role.admin)
    only = db_session.scalars(select(User)).one()
    assert _removes_last_admin(db_session, only) is True
    make_user("second", Role.admin)
    assert _removes_last_admin(db_session, only) is False
    db_session.execute(update(User).where(User.username == "second").values(disabled=True))
    assert _removes_last_admin(db_session, only) is True


def test_disable_blocks_login_and_enable_restores(
    app_client: TestClient, admin: str, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    other = make_user("frank", Role.analyst)
    r = _post(app_client, f"/users/{other.id}/disable", admin)
    assert r.status_code == 303 and _user(app_client, "frank").disabled is True
    (entry,) = _audit(app_client, "user.disable")
    assert entry.target == "frank"
    assert "Desativado" in app_client.get("/users", headers=HTML).text
    assert login("frank", TEST_PASSWORD, other.code(frozen_clock.current)).status_code != 303
    assert _post(app_client, f"/users/{other.id}/enable", admin).status_code == 303
    assert _user(app_client, "frank").disabled is False
    assert len(_audit(app_client, "user.enable")) == 1
    frozen_clock.advance(seconds=31)
    assert login("frank", TEST_PASSWORD, other.code(frozen_clock.current)).status_code == 303


def test_user_unknown_id_404(app_client: TestClient, admin: str) -> None:
    for action in ("disable", "enable"):
        assert _post(app_client, f"/users/{uuid.uuid4()}/{action}", admin).status_code == 404
    assert _post(app_client, f"/users/{uuid.uuid4()}/role", admin, role="viewer").status_code == 404


def test_users_mutations_need_csrf(app_client: TestClient, admin: str, make_user: Any) -> None:
    other = make_user("gina", Role.viewer)
    assert (
        _post(
            app_client, "/users", None, username="x-user", role="viewer", password=TEST_PASSWORD
        ).status_code
        == 403
    )
    assert _post(app_client, f"/users/{other.id}/disable", "bad").status_code == 403
    assert _post(app_client, f"/users/{other.id}/role", None, role="admin").status_code == 403
    assert _user(app_client, "gina").role is Role.viewer and not _user(app_client, "gina").disabled
    assert len(_all(app_client, User)) == 2


@pytest.mark.parametrize("role", [Role.analyst, Role.viewer])
def test_users_pages_forbidden_for_non_admin(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, role: Role
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, role)
    victim = make_user("hank", Role.viewer)
    assert app_client.get("/users", headers=HTML).status_code == 403
    assert (
        _post(
            app_client, "/users", token, username="x-user", role="admin", password=TEST_PASSWORD
        ).status_code
        == 403
    )
    for action in ("disable", "enable"):
        assert _post(app_client, f"/users/{victim.id}/{action}", token).status_code == 403
    assert _post(app_client, f"/users/{victim.id}/role", token, role="admin").status_code == 403
    assert _user(app_client, "hank").role is Role.viewer
    assert "/users" not in app_client.get("/", headers=HTML).text


def test_users_escape_username(app_client: TestClient, admin: str) -> None:
    with _db(app_client) as s:
        s.execute(update(User).where(User.username == "u-admin").values(username=XSS))
        s.commit()
    r = app_client.get("/users", headers=HTML)
    assert XSS not in r.text and ESCAPED in r.text
    bad = _post(app_client, "/users", admin, username=XSS, role="viewer", password=TEST_PASSWORD)
    assert bad.status_code == 422 and XSS not in bad.text


# ----------------------------------------------------------------------------- audit


def _seed_audit(client: TestClient, count: int, **details: Any) -> None:
    with _db(client) as s:
        for i in range(count):
            audit.record(
                s,
                action="test.event",
                actor_user_id=None,
                actor_device_id=None,
                target=f"t{i}",
                details={"i": i, **details},
            )
        s.commit()


def test_audit_page_newest_first_with_escaped_json(app_client: TestClient, admin: str) -> None:
    _seed_audit(app_client, 3, note=XSS)
    r = app_client.get("/audit", headers=HTML)
    assert r.status_code == 200
    assert XSS not in r.text and "&lt;script&gt;" in r.text
    assert r.text.index(">t2<") < r.text.index(">t1<") < r.text.index(">t0<")
    assert "sistema" in r.text and "test.event" in r.text


def test_audit_pagination(app_client: TestClient, admin: str) -> None:
    _seed_audit(app_client, 55)
    total = len(_all(app_client, AuditEntry))
    first = app_client.get("/audit", headers=HTML).text
    assert f"{total} registro(s) · página 1 de 2" in first
    assert first.count("<tr>") == 51
    second = app_client.get("/audit?page=2", headers=HTML).text
    assert second.count("<tr>") == total - 50 + 1
    assert app_client.get("/audit?page=abc", headers=HTML).status_code == 200


def test_audit_shows_user_actor(app_client: TestClient, admin: str) -> None:
    _post(app_client, "/users", admin, username="ivy-2", role="viewer", password=TEST_PASSWORD)
    page = app_client.get("/audit", headers=HTML).text
    assert "user.create" in page and "u-admin" in page


def test_audit_verify_ok(app_client: TestClient, admin: str) -> None:
    _seed_audit(app_client, 3)
    r = _post(app_client, "/audit/verify", admin)
    assert r.status_code == 200 and "íntegra" in r.text


def test_audit_verify_reports_first_bad_seq(app_client: TestClient, admin: str) -> None:
    _seed_audit(app_client, 4)
    with _db(app_client) as s:
        seq = s.scalars(select(AuditEntry.seq).order_by(AuditEntry.seq)).all()[2]
        s.execute(text("UPDATE audit_log SET action = 'tampered' WHERE seq = :s"), {"s": seq})
        s.commit()
    r = _post(app_client, "/audit/verify", admin)
    assert r.status_code == 200 and "inválida" in r.text and f"seq {seq}." in r.text


def test_audit_verify_needs_csrf(app_client: TestClient, admin: str) -> None:
    assert _post(app_client, "/audit/verify", None).status_code == 403
    assert _post(app_client, "/audit/verify", "bad").status_code == 403


@pytest.mark.parametrize("role", [Role.analyst, Role.viewer])
def test_audit_forbidden_for_non_admin(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, role: Role
) -> None:
    token = _login(app_client, make_user, login, frozen_clock, role)
    assert app_client.get("/audit", headers=HTML).status_code == 403
    assert _post(app_client, "/audit/verify", token).status_code == 403
