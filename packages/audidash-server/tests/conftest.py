import re
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pyotp
import pytest
from audidash_server import clock
from audidash_server.app import create_app
from audidash_server.auth.passwords import hash_password
from audidash_server.auth.totp import encrypt_totp_secret, totp_secret_new
from audidash_server.db import init_db, make_engine
from audidash_server.models import Role, User
from audidash_server.settings import Settings
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session as DbSession

TEST_PASSWORD = "Corr3ct-Horse-Battery-Staple"  # noqa: S105 - test fixture value
_CSRF_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return Settings(
        dev_mode=True,
        data_dir=data_dir,
        database_url=f"sqlite:///{(tmp_path / 'audidash.db').as_posix()}",
    )


@pytest.fixture
def app_client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings), base_url="https://testserver")


@pytest.fixture
def prod_settings(settings: Settings) -> Settings:
    good = SecretStr("p" * 32)
    return settings.model_copy(
        update={
            "dev_mode": False,
            "secret_key": good,
            "proxy_secret": good,
            "ca_passphrase": good,
        }
    )


@pytest.fixture
def db_session(settings: Settings) -> Iterator[DbSession]:
    engine = make_engine(settings.database_url)
    init_db(engine)
    with DbSession(engine) as session:
        yield session
    engine.dispose()


class FrozenClock:
    def __init__(self, start: datetime) -> None:
        self.current = start

    def now(self) -> datetime:
        return self.current

    def advance(self, **kwargs: float) -> None:
        self.current += timedelta(**kwargs)


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> FrozenClock:
    # Start mid-step so +/- one 30 s step stays deterministic.
    fc = FrozenClock(datetime(2026, 11, 25, 12, 0, 10, tzinfo=UTC))
    monkeypatch.setattr(clock, "now", fc.now)
    return fc


@dataclass
class AuthUser:
    id: uuid.UUID
    username: str
    password: str
    totp_secret: str | None

    def code(self, at: datetime) -> str:
        assert self.totp_secret is not None
        return pyotp.TOTP(self.totp_secret).at(at)


MakeUser = Callable[..., AuthUser]


@pytest.fixture
def make_user(app_client: TestClient, settings: Settings) -> MakeUser:
    def _make(
        username: str = "alice", role: Role = Role.admin, *, with_totp: bool = True
    ) -> AuthUser:
        secret = totp_secret_new() if with_totp else None
        user = User(
            id=uuid.uuid4(),
            username=username,
            password_hash=hash_password(TEST_PASSWORD),
            totp_secret_enc=(
                encrypt_totp_secret(secret, settings.secret_key.get_secret_value())
                if secret
                else None
            ),
            role=role,
            failed_logins=0,
            created_at=datetime.now(UTC),
        )
        with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
            s.add(user)
            s.commit()
        return AuthUser(user.id, username, TEST_PASSWORD, secret)

    return _make


def csrf_from(html: str) -> str:
    match = _CSRF_FIELD.search(html)
    assert match, "csrf_token hidden field missing"
    return match.group(1)


LoginFn = Callable[..., httpx.Response]


@pytest.fixture
def login(app_client: TestClient) -> LoginFn:
    def _login(username: str, password: str, code: str = "") -> httpx.Response:
        page = app_client.get("/login")
        assert page.status_code == 200
        response: httpx.Response = app_client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "totp": code,
                "csrf_token": csrf_from(page.text),
            },
            follow_redirects=False,
        )
        return response

    return _login
