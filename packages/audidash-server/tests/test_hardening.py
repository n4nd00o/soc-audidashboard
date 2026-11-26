"""Task 12 hardening carry-overs: sessions vs. disabled/demoted users, Host validation."""

import inspect
import re
from typing import Any

import pytest
from audidash_server.ca import CAError
from audidash_server.models import EnrollmentToken, Role, User
from audidash_server.settings import Settings
from audidash_server.web import device_queries as dq
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from starlette.datastructures import URL
from starlette.requests import Request

HTML = {"Accept": "text/html"}


def _login_admin(client: TestClient, make_user: Any, login: Any, clock: Any, name: str) -> str:
    user = make_user(name, Role.admin)
    assert login(user.username, user.password, user.code(clock.current)).status_code == 303
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/", headers=HTML).text)
    assert match
    return match.group(1)


def _update_user(client: TestClient, name: str, **values: Any) -> None:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        user = s.scalars(select(User).where(User.username == name)).one()
        for key, value in values.items():
            setattr(user, key, value)
        s.commit()


def test_logged_in_session_of_disabled_user_is_rejected(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _login_admin(app_client, make_user, login, frozen_clock, "gone")
    assert app_client.get("/users", headers=HTML).status_code == 200
    _update_user(app_client, "gone", disabled=True)
    page = app_client.get("/users", headers=HTML, follow_redirects=False)
    assert page.status_code in (303, 401)
    assert "gone" not in page.text
    assert app_client.get("/users", follow_redirects=False).status_code in (303, 401)


def test_demoted_admin_gets_403_on_users_with_existing_session(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _login_admin(app_client, make_user, login, frozen_clock, "demoted")
    assert app_client.get("/users", headers=HTML).status_code == 200
    _update_user(app_client, "demoted", role=Role.viewer)
    assert app_client.get("/users", headers=HTML).status_code == 403


def test_last_admin_guard_locks_rows_with_for_update(db_session: Any) -> None:
    from audidash_server.web import routes_users

    captured: list[str] = []
    original = db_session.scalars

    def spy(statement: Any, *args: Any, **kwargs: Any) -> Any:
        captured.append(str(statement.compile(dialect=postgresql.dialect())))  # type: ignore[no-untyped-call]
        return original(statement, *args, **kwargs)

    db_session.scalars = spy
    routes_users._active_admins(db_session)
    assert "FOR UPDATE" in captured[0]


# --------------------------------------------------------------------- default_urls


@pytest.mark.parametrize(
    ("base", "dashboard", "api"),
    [
        ("https://audi.example.org/", "https://audi.example.org", "https://audi.example.org:9443"),
        (
            "https://audi.example.org:8443/",
            "https://audi.example.org:8443",
            "https://audi.example.org:9443",
        ),
        ("https://10.1.2.3:8443/", "https://10.1.2.3:8443", "https://10.1.2.3:9443"),
        ("https://[::1]:8443/", "https://[::1]:8443", "https://[::1]:9443"),
        ("https://[fe80::1]/", "https://[fe80::1]", "https://[fe80::1]:9443"),
    ],
)
def test_default_urls_accepts_plain_hosts(base: str, dashboard: str, api: str) -> None:
    assert dq.default_urls(base) == (dashboard, api, True)


@pytest.mark.parametrize(
    "base",
    [
        "https://evil$(id)/",
        "https://evil`id`.example/",
        "https://a;rm -rf x/",
        "https://a'b/",
        'https://a"b/',
        "https://a b/",
        "https://a&b/",
        "https://user@host/",
        "https://host:99999999/",
        "https://host:0/",
        "https://host:65536/",
        "https://[::1/",
        "ftp://host/",
        "https:///",
    ],
)
def test_default_urls_rejects_hostile_hosts(base: str) -> None:
    assert dq.default_urls(base) == (dq.PLACEHOLDER_DASHBOARD, dq.PLACEHOLDER_API, False)
    assert dq.PLACEHOLDER_DASHBOARD == "https://<servidor>:8443"


def test_hostile_host_header_falls_back_to_placeholder_with_warning(
    app_client: TestClient,
    make_user: Any,
    login: Any,
    frozen_clock: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    csrf = _login_admin(app_client, make_user, login, frozen_clock, "root-admin")
    # httpx will not send such a Host header, so model what the ASGI server would hand over.
    hostile = URL("https://$(touch${IFS}x).evil/")
    monkeypatch.setattr(Request, "base_url", property(lambda _self: hostile))
    r = app_client.post(
        "/devices/tokens", data={"name": "laptop-a", "csrf_token": csrf}, follow_redirects=False
    )
    assert r.status_code == 200
    assert "https://&lt;servidor&gt;:8443" in r.text
    assert "AUDIDASH_PUBLIC_DASHBOARD_URL" in r.text
    assert "touch" not in r.text


def test_good_host_has_no_warning(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    csrf = _login_admin(app_client, make_user, login, frozen_clock, "root-admin")
    r = app_client.post(
        "/devices/tokens", data={"name": "laptop-a", "csrf_token": csrf}, follow_redirects=False
    )
    assert r.status_code == 200
    assert "AUDIDASH_PUBLIC_DASHBOARD_URL" not in r.text
    assert "--server https://testserver" in r.text


# ------------------------------------------------------------------ settings URL charset


@pytest.mark.parametrize(
    "value",
    [
        "https://host/$(id)",
        "https://host/`id`",
        "https://host/a;b",
        "https://host/a'b",
        'https://host/a"b',
        "https://host/a b",
        "https://host/a&b",
        "https://host/a|b",
        "https://host/a\\b",
        "https://host/a(b)",
    ],
)
def test_settings_url_rejects_shell_metacharacters(value: str) -> None:
    with pytest.raises(ValueError, match="https"):
        Settings(public_dashboard_url=value)
    with pytest.raises(ValueError, match="https"):
        Settings(public_api_url=value)


@pytest.mark.parametrize(
    "value",
    ["https://audi.example.org", "https://audi.example.org:8443/", "https://[::1]:9443/base-1_2.x"],
)
def test_settings_url_accepts_normal_urls(value: str) -> None:
    assert Settings(public_dashboard_url=value).public_dashboard_url == value.rstrip("/")


# ------------------------------------------- CA fingerprint is loaded before the token commit


def test_device_token_not_created_when_ca_unavailable(
    app_client: TestClient,
    make_user: Any,
    login: Any,
    frozen_clock: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    csrf = _login_admin(app_client, make_user, login, frozen_clock, "root-admin")

    def broken(_request: Any) -> Any:
        raise CAError("cannot decrypt CA key")

    monkeypatch.setattr("audidash_server.web.routes_devices.get_ca", broken)
    with pytest.raises(CAError):
        app_client.post(
            "/devices/tokens", data={"name": "laptop-a", "csrf_token": csrf}, follow_redirects=False
        )
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        assert list(s.scalars(select(EnrollmentToken))) == []


def test_db_routes_are_sync_so_blocking_work_runs_in_the_threadpool(
    app_client: TestClient,
) -> None:
    # An `async def` route runs on the event loop: blocking SQLAlchemy / Argon2 calls in it
    # would stall every other request. Only these coroutine endpoints are allowed: healthz
    # touches nothing, upload_run streams the body and hands ingestion to the threadpool.
    allowed = {"healthz", "upload_run"}
    routes = list(_api_routes(app_client.app.routes))  # type: ignore[attr-defined]
    assert len(routes) > 30  # the included routers were walked
    offenders = sorted(
        f"{route.endpoint.__module__}.{route.endpoint.__name__}"
        for route in routes
        if inspect.iscoroutinefunction(route.endpoint) and route.endpoint.__name__ not in allowed
    )
    assert offenders == []


def _api_routes(routes: Any) -> Any:
    """Every APIRoute, descending into included routers (FastAPI keeps them nested)."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        nested = getattr(route, "original_router", None)
        if nested is not None:
            yield from _api_routes(nested.routes)
