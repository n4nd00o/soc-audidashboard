import hashlib
import uuid
from datetime import timedelta
from typing import Any

import pytest
from audidash_server.api.deps import client_ip
from audidash_server.models import ApiToken, AuditEntry, Device, EnrollmentToken, Role, User
from audidash_server.settings import Settings
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request


def _rows(client: TestClient, model: Any) -> list[Any]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(model)).all())


def _audit(client: TestClient, action: str) -> list[AuditEntry]:
    return [a for a in _rows(client, AuditEntry) if a.action == action]


def _enroll(client: TestClient, token: str, csr_pem: bytes, name: str = "pc") -> Any:
    return client.post(
        "/enroll", json={"token": token, "device_name": name, "csr_pem": csr_pem.decode()}
    )


# --- enrollment -------------------------------------------------------------------------


def test_enroll_issues_cert_and_records_device(
    app_client: TestClient, issue_enrollment_token: Any, csr: Any, frozen_clock: Any
) -> None:
    token = issue_enrollment_token()
    r = _enroll(app_client, token, csr(), "lab-pc")
    assert r.status_code == 201, r.text
    body = r.json()
    device_id = uuid.UUID(body["device_id"])
    cert = x509.load_pem_x509_certificate(body["cert_pem"].encode())
    ca_cert = x509.load_pem_x509_certificate(body["ca_pem"].encode())
    cert.verify_directly_issued_by(ca_cert)
    (device,) = _rows(app_client, Device)
    der = cert.public_bytes(serialization.Encoding.DER)
    assert device.id == device_id and device.name == "lab-pc"
    assert device.cert_fingerprint == hashlib.sha256(der).hexdigest()
    assert device.cert_not_after == cert.not_valid_after_utc
    (row,) = _rows(app_client, EnrollmentToken)
    assert row.used_at == frozen_clock.current and row.device_id == device_id
    assert row.token_sha256 == hashlib.sha256(token.encode()).hexdigest()
    (entry,) = _audit(app_client, "device.enroll")
    assert entry.actor_device_id == device_id


def test_enroll_token_reuse_is_gone(
    app_client: TestClient, issue_enrollment_token: Any, csr: Any, frozen_clock: Any
) -> None:
    token = issue_enrollment_token()
    assert _enroll(app_client, token, csr()).status_code == 201
    r = _enroll(app_client, token, csr())
    assert r.status_code == 410
    assert len(_rows(app_client, Device)) == 1


def test_enroll_expired_token_is_gone(
    app_client: TestClient, issue_enrollment_token: Any, csr: Any, frozen_clock: Any
) -> None:
    token = issue_enrollment_token()
    frozen_clock.advance(hours=24, seconds=1)
    assert _enroll(app_client, token, csr()).status_code == 410
    assert _rows(app_client, Device) == []


def test_enroll_unknown_token_rejected(app_client: TestClient, csr: Any) -> None:
    r = _enroll(app_client, "not-a-real-token", csr())
    assert r.status_code == 401
    assert r.json() == {"detail": "invalid enrollment token"}


def test_enroll_bad_csr_does_not_consume_token(
    app_client: TestClient, issue_enrollment_token: Any, csr: Any, frozen_clock: Any
) -> None:
    token = issue_enrollment_token()
    assert _enroll(app_client, token, csr(san="x.example")).status_code == 400
    assert _rows(app_client, EnrollmentToken)[0].used_at is None
    assert _enroll(app_client, token, csr()).status_code == 201


# --- proxy trust (mTLS identity) --------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Audidash-Proxy-Secret": "wrong"},
        {"X-Client-Cert-Fingerprint": "{fp}"},
        {"X-Audidash-Proxy-Secret": "wrong", "X-Client-Cert-Fingerprint": "{fp}"},
        {"X-Audidash-Proxy-Secret": "{secret}", "X-Client-Cert-Fingerprint": "0" * 64},
        {"X-Audidash-Proxy-Secret": "{secret}", "X-Client-Cert-Fingerprint": "not-hex"},
    ],
    ids=["none", "wrong-secret", "fp-only", "fp-wrong-secret", "unknown-fp", "bad-fp"],
)
def test_forged_proxy_headers_rejected(
    app_client: TestClient,
    make_api_user: Any,
    settings: Settings,
    headers: dict[str, str],
) -> None:
    api = make_api_user()
    secret = settings.proxy_secret.get_secret_value()
    forged = {k: v.format(fp=api.device.fingerprint, secret=secret) for k, v in headers.items()}
    forged["Authorization"] = f"Bearer {api.token}"
    r = app_client.get("/api/v1/assets", headers=forged)
    assert r.status_code == 401
    assert r.json() == {"detail": "client certificate required"}


def test_fingerprint_normalized_from_proxy_format(make_api_user: Any) -> None:
    api = make_api_user()
    fp = api.device.fingerprint
    colon_upper = ":".join(fp[i : i + 2] for i in range(0, 64, 2)).upper()
    api.device.headers["X-Client-Cert-Fingerprint"] = f" {colon_upper} "
    assert api.get("/api/v1/assets").status_code == 200


def test_revoked_device_rejected(
    app_client: TestClient, make_api_user: Any, frozen_clock: Any
) -> None:
    api = make_api_user()
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        device = s.get(Device, api.device.id)
        device.revoked_at = frozen_clock.current
        s.commit()
    assert api.get("/api/v1/assets").status_code == 401


def test_expired_device_cert_rejected(make_api_user: Any, frozen_clock: Any) -> None:
    api = make_api_user()
    frozen_clock.advance(days=91)
    assert api.get("/api/v1/assets").status_code == 401


def _request(headers: dict[str, str], peer: str = "10.0.0.9") -> Request:
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (peer, 1234),
    }
    return Request(scope)


def test_client_ip_trusts_forwarded_only_with_proxy_secret(
    app_client: TestClient, settings: Settings
) -> None:
    secret = settings.proxy_secret.get_secret_value()
    req = _request({"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
    req.scope["app"] = app_client.app
    assert client_ip(req) == "10.0.0.9"
    req = _request({"X-Forwarded-For": "203.0.113.7, 10.0.0.1", "X-Audidash-Proxy-Secret": secret})
    req.scope["app"] = app_client.app
    assert client_ip(req) == "203.0.113.7"


# --- API login -------------------------------------------------------------------------


def test_api_login_issues_device_bound_token(
    app_client: TestClient,
    make_user: Any,
    enroll_device: Any,
    api_login: Any,
    frozen_clock: Any,
) -> None:
    u = make_user("bob", Role.analyst)
    device = enroll_device()
    r = api_login(device, u, u.code(frozen_clock.current))
    assert r.status_code == 200, r.text
    body = r.json()
    (row,) = _rows(app_client, ApiToken)
    assert row.token_sha256 == hashlib.sha256(body["access_token"].encode()).hexdigest()
    assert row.device_id == device.id and row.user_id == u.id
    assert row.expires_at == frozen_clock.current + timedelta(minutes=15)
    (entry,) = _audit(app_client, "login.success")
    assert entry.actor_user_id == u.id and entry.actor_device_id == device.id


def test_api_login_wrong_password_counts_and_locks(
    app_client: TestClient,
    make_user: Any,
    enroll_device: Any,
    api_login: Any,
    frozen_clock: Any,
) -> None:
    u = make_user("bob")
    device = enroll_device()
    for _ in range(5):
        r = api_login(device, u, u.code(frozen_clock.current), password="Wrong-password-123")  # noqa: S106
        assert r.status_code == 401
        assert r.json() == {"detail": "invalid credentials"}
    locked = _rows(app_client, User)
    assert any(x.username == "bob" and x.locked_until is not None for x in locked)
    frozen_clock.advance(seconds=30)
    assert api_login(device, u, u.code(frozen_clock.current)).status_code == 401
    failures = _audit(app_client, "login.failure")
    assert len(failures) == 6
    assert all(f.actor_device_id == device.id for f in failures)


def test_api_login_totp_replay_rejected(
    make_user: Any, enroll_device: Any, api_login: Any, frozen_clock: Any
) -> None:
    u = make_user("bob")
    device = enroll_device()
    code = u.code(frozen_clock.current)
    assert api_login(device, u, code).status_code == 200
    assert api_login(device, u, code).status_code == 401


def test_api_login_requires_enrolled_totp(
    make_user: Any, enroll_device: Any, api_login: Any, frozen_clock: Any
) -> None:
    u = make_user("bob", with_totp=False)
    device = enroll_device()
    r = api_login(device, u, "000000")
    assert r.status_code == 403
    assert r.json() == {"detail": "complete TOTP enrolment in the dashboard first"}


def test_api_login_requires_device(
    app_client: TestClient, make_user: Any, frozen_clock: Any
) -> None:
    u = make_user("bob")
    r = app_client.post(
        "/api/v1/auth/token",
        json={"username": "bob", "password": u.password, "totp": u.code(frozen_clock.current)},
    )
    assert r.status_code == 401


def test_api_login_validation_error_does_not_echo_password(
    app_client: TestClient, make_api_user: Any
) -> None:
    api = make_api_user()
    r = app_client.post(
        "/api/v1/auth/token",
        json={"username": "bob", "password": "Sup3r-Secret-Value"},
        headers=api.device.headers,
    )
    assert r.status_code == 422
    assert "Sup3r-Secret-Value" not in r.text


# --- bearer tokens ----------------------------------------------------------------------


def test_bearer_from_another_device_rejected(
    app_client: TestClient, make_api_user: Any, enroll_device: Any
) -> None:
    api = make_api_user()
    other = enroll_device("other")
    r = app_client.get(
        "/api/v1/assets", headers={**other.headers, "Authorization": f"Bearer {api.token}"}
    )
    assert r.status_code == 401


def test_bearer_missing_or_expired_rejected(
    app_client: TestClient, make_api_user: Any, frozen_clock: Any
) -> None:
    api = make_api_user()
    assert app_client.get("/api/v1/assets", headers=api.device.headers).status_code == 401
    frozen_clock.advance(minutes=15, seconds=1)
    assert api.get("/api/v1/assets").status_code == 401


def test_api_ignores_session_cookie(
    app_client: TestClient, make_api_user: Any, login: Any, frozen_clock: Any
) -> None:
    api = make_api_user()
    frozen_clock.advance(seconds=30)
    dash = login(api.user.username, api.user.password, api.user.code(frozen_clock.current))
    assert dash.status_code == 303 and app_client.cookies
    r = app_client.get("/api/v1/assets", headers=api.device.headers)
    assert r.status_code == 401


# --- assets -----------------------------------------------------------------------------

ASSET = {"name": "srv1", "address": "srv1.local", "asset_type": "linux", "criticality": "high"}


def test_create_and_list_assets(app_client: TestClient, make_api_user: Any) -> None:
    api = make_api_user("ana", Role.analyst)
    r = api.post("/api/v1/assets", {**ASSET, "tags": ["prod"]})
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["name"] == "srv1" and created["tags"] == ["prod"]
    listed = api.get("/api/v1/assets").json()
    assert listed == [
        {
            "id": created["id"],
            "name": "srv1",
            "address": "srv1.local",
            "asset_type": "linux",
            "criticality": "high",
        }
    ]
    (entry,) = _audit(app_client, "asset.create")
    assert entry.actor_user_id == api.user.id and entry.actor_device_id == api.device.id


def test_create_asset_duplicate_conflict(make_api_user: Any) -> None:
    api = make_api_user()
    assert api.post("/api/v1/assets", ASSET).status_code == 201
    assert api.post("/api/v1/assets", ASSET).status_code == 409


def test_create_asset_viewer_forbidden(make_api_user: Any) -> None:
    api = make_api_user("vic", Role.viewer)
    assert api.post("/api/v1/assets", ASSET).status_code == 403
    assert api.get("/api/v1/assets").status_code == 200
