import re
from typing import Any, cast

import pytest
from audidash_server.auth.csrf import csrf_protect
from audidash_server.auth.rbac import require_role
from audidash_server.auth.sessions import current_user
from audidash_server.models import Role, User
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

HTML = {"Accept": "text/html"}


@pytest.fixture
def rbac_client(app_client: TestClient) -> TestClient:
    app = cast(FastAPI, app_client.app)

    @app.post("/_t/admin", dependencies=[Depends(csrf_protect)])
    def admin_only(user: User = require_role(Role.admin)) -> dict[str, str]:  # noqa: B008
        return {"user": user.username}

    @app.post(
        "/_t/write",
        dependencies=[require_role(Role.admin, Role.analyst), Depends(csrf_protect)],
    )
    def write() -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/_t/read")
    def read(user: User = Depends(current_user)) -> dict[str, str]:  # noqa: B008
        return {"role": user.role.value}

    return app_client


def _token(client: TestClient) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/", headers=HTML).text)
    assert match
    return match.group(1)


@pytest.mark.parametrize(
    ("role", "admin_status", "write_status"),
    [
        (Role.admin, 200, 200),
        (Role.analyst, 403, 200),
        (Role.viewer, 403, 403),
    ],
)
def test_role_matrix(
    rbac_client: TestClient,
    make_user: Any,
    login: Any,
    frozen_clock: Any,
    role: Role,
    admin_status: int,
    write_status: int,
) -> None:
    u = make_user(f"u-{role.value}", role)
    assert login(u.username, u.password, u.code(frozen_clock.current)).status_code == 303
    headers = {"HX-CSRF-Token": _token(rbac_client)}
    admin = rbac_client.post("/_t/admin", headers=headers)
    assert admin.status_code == admin_status
    if admin_status == 403:
        assert admin.json() == {"detail": "Forbidden"}
    assert rbac_client.post("/_t/write", headers=headers).status_code == write_status
    assert rbac_client.get("/_t/read").json() == {"role": role.value}


def test_viewer_post_admin_route_forbidden_even_with_csrf(
    rbac_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user("viewer1", Role.viewer)
    login(u.username, u.password, u.code(frozen_clock.current))
    r = rbac_client.post("/_t/admin", data={"csrf_token": _token(rbac_client)})
    assert r.status_code == 403
    assert r.json() == {"detail": "Forbidden"}  # from RBAC, not from CSRF


def test_admin_route_requires_csrf(
    rbac_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user("admin1", Role.admin)
    login(u.username, u.password, u.code(frozen_clock.current))
    assert rbac_client.post("/_t/admin").status_code == 403
    assert rbac_client.post("/_t/admin", headers={"HX-CSRF-Token": "nope"}).status_code == 403


def test_role_routes_require_authentication(rbac_client: TestClient) -> None:
    assert rbac_client.post("/_t/admin").status_code == 401
    assert rbac_client.get("/_t/read").status_code == 401


def test_disabled_user_session_rejected(
    rbac_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user("gone", Role.admin)
    login(u.username, u.password, u.code(frozen_clock.current))
    with rbac_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        user = s.get(User, u.id)
        assert user is not None
        user.disabled = True
        s.commit()
    assert rbac_client.get("/_t/read").status_code == 401
