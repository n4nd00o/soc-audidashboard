from collections.abc import Mapping

import pytest
from audidash_server.app import create_app
from audidash_server.settings import Settings
from fastapi.testclient import TestClient
from pydantic import SecretStr

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def _check(h: Mapping[str, str]) -> None:
    assert h["content-security-policy"] == CSP
    assert h["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["x-frame-options"] == "DENY"
    assert h["cross-origin-opener-policy"] == "same-origin"
    assert h["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert "server" not in h


def test_healthz(app_client: TestClient) -> None:
    r = app_client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_security_headers(app_client: TestClient) -> None:
    _check(app_client.get("/healthz").headers)


def test_security_headers_on_404(app_client: TestClient) -> None:
    r = app_client.get("/nope")
    assert r.status_code == 404
    _check(r.headers)


def test_security_headers_on_static(app_client: TestClient) -> None:
    r = app_client.get("/static/missing.css")
    assert r.status_code == 404
    _check(r.headers)


def test_docs_disabled_in_production(prod_settings: Settings) -> None:
    client = TestClient(create_app(prod_settings), base_url="https://testserver")
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_security_headers_on_unhandled_500(prod_settings: Settings) -> None:
    app = create_app(prod_settings)

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("secret-detail-xyz")

    client = TestClient(app, base_url="https://testserver", raise_server_exceptions=False)
    r = client.get("/boom")
    assert r.status_code == 500
    _check(r.headers)
    assert "secret-detail-xyz" not in r.text


def test_create_app_fails_fast_in_production_without_secrets(settings: Settings) -> None:
    bad = settings.model_copy(update={"dev_mode": False, "proxy_secret": SecretStr("")})
    with pytest.raises(ValueError, match="AUDIDASH_PROXY_SECRET"):
        create_app(bad)


def test_docs_enabled_in_dev(app_client: TestClient) -> None:
    assert app_client.get("/openapi.json").status_code == 200
