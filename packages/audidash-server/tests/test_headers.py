from fastapi.testclient import TestClient

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def _check(headers: "dict[str, str] | object") -> None:
    h = headers
    assert h["content-security-policy"] == CSP  # type: ignore[index]
    assert h["strict-transport-security"] == "max-age=31536000; includeSubDomains"  # type: ignore[index]
    assert h["x-content-type-options"] == "nosniff"  # type: ignore[index]
    assert h["referrer-policy"] == "no-referrer"  # type: ignore[index]
    assert h["x-frame-options"] == "DENY"  # type: ignore[index]
    assert h["cross-origin-opener-policy"] == "same-origin"  # type: ignore[index]
    assert h["permissions-policy"] == "camera=(), microphone=(), geolocation=()"  # type: ignore[index]
    assert "server" not in h  # type: ignore[operator]


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


def test_docs_disabled_in_production(settings: "object") -> None:
    from audidash_server.app import create_app

    s = settings.model_copy(update={"dev_mode": False})  # type: ignore[attr-defined]
    client = TestClient(create_app(s), base_url="https://testserver")
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_docs_enabled_in_dev(app_client: TestClient) -> None:
    assert app_client.get("/openapi.json").status_code == 200
