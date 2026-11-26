import hashlib
import os
import re
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pyotp
import pytest
from audidash_server import clock
from audidash_server.app import create_app
from audidash_server.auth.passwords import hash_password
from audidash_server.auth.totp import encrypt_totp_secret, totp_secret_new
from audidash_server.db import init_db, make_engine, run_migrations
from audidash_server.models import Base, Role, User
from audidash_server.services.enrollment import create_enrollment_token
from audidash_server.settings import Settings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import event, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session as DbSession

TEST_PASSWORD = "Corr3ct-Horse-Battery-Staple"  # noqa: S105 - test fixture value
_CSRF_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')


# When set (CI `server-postgres` job), the suite runs against this PostgreSQL database instead
# of a per-test SQLite file. Isolation: the schema is created ONCE per session through the real
# Alembic migrations, and every test starts by TRUNCATE-ing all tables (RESTART IDENTITY CASCADE).
# The database must be disposable and used by one pytest process at a time.
TEST_DATABASE_URL = os.environ.get("AUDIDASH_TEST_DATABASE_URL", "")


def _carries_nul(value: object) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_carries_nul(k) or _carries_nul(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_carries_nul(v) for v in value)
    return False


def _reject_nul_parameters(
    conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool
) -> None:
    # PostgreSQL text columns cannot hold NUL (psycopg raises DataError); SQLite stores it
    # silently. Fail the same way on every backend so NUL reaching the DB is caught locally.
    if _carries_nul(parameters):
        raise ValueError("PostgreSQL text fields cannot contain NUL (0x00) bytes")


@pytest.fixture(autouse=True)
def _pg_like_nul_guard() -> Iterator[None]:
    event.listen(Engine, "before_cursor_execute", _reject_nul_parameters)
    try:
        yield
    finally:
        event.remove(Engine, "before_cursor_execute", _reject_nul_parameters)


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def ensure_disposable_test_database(url: str) -> None:
    """Refuse (before any DROP) unless the database is clearly a throwaway test database.

    Accepted: a name ending in ``_test`` on any host, or a name containing ``test`` on a
    local host. Anything else aborts the session with a usage error.
    """
    parsed = make_url(url)
    name = parsed.database or ""
    local = (parsed.host or "localhost") in _LOCAL_HOSTS
    if name.endswith("_test") or (local and "test" in name):
        return
    raise pytest.UsageError(
        f"AUDIDASH_TEST_DATABASE_URL points at database {name!r} on {parsed.host!r}: the test "
        "suite DROPS its public schema, so the database name must end with '_test' (or contain "
        "'test' on localhost). Refusing to run."
    )


@pytest.fixture(scope="session")
def _pg_schema() -> str:
    if not TEST_DATABASE_URL:
        return ""
    ensure_disposable_test_database(TEST_DATABASE_URL)
    engine = make_engine(TEST_DATABASE_URL)
    try:
        # Start from a clean slate, then build the schema exactly as production does.
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()
    run_migrations(TEST_DATABASE_URL)
    return TEST_DATABASE_URL


def _truncate_all(url: str) -> None:
    engine = make_engine(url)
    try:
        tables = list(Base.metadata.sorted_tables)
        if not tables:
            return
        names = ", ".join(f'"{t.name}"' for t in tables)
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))  # noqa: S608
    finally:
        engine.dispose()


@pytest.fixture
def settings(tmp_path: Path, _pg_schema: str) -> Settings:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    if _pg_schema:
        _truncate_all(_pg_schema)
        url = _pg_schema
    else:
        url = f"sqlite:///{(tmp_path / 'audidash.db').as_posix()}"
    return Settings(dev_mode=True, data_dir=data_dir, database_url=url)


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


# --- device enrollment / mTLS API helpers -----------------------------------------------


def make_csr(
    key: ec.EllipticCurvePrivateKey | None = None,
    *,
    san: str | None = None,
) -> bytes:
    """PEM CSR for `key` (a fresh P-256 key by default), optionally with a SAN extension."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client-chosen")])
    )
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def pem_fingerprint(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


@dataclass
class EnrolledDevice:
    id: uuid.UUID
    fingerprint: str
    headers: dict[str, str]


IssueToken = Callable[..., str]
EnrollFn = Callable[..., EnrolledDevice]


@pytest.fixture
def issue_enrollment_token(app_client: TestClient, make_user: MakeUser) -> IssueToken:
    admins: list[AuthUser] = []

    def _issue() -> str:
        if not admins:
            admins.append(make_user("enroll-admin", Role.admin))
        with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
            token = create_enrollment_token(s, admins[0].id)
            s.commit()
        return token

    return _issue


@pytest.fixture
def enroll_device(
    app_client: TestClient, settings: Settings, issue_enrollment_token: IssueToken
) -> EnrollFn:
    def _enroll(name: str = "laptop") -> EnrolledDevice:
        r = app_client.post(
            "/enroll",
            json={
                "token": issue_enrollment_token(),
                "device_name": name,
                "csr_pem": make_csr().decode(),
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        fp = pem_fingerprint(body["cert_pem"])
        headers = {
            "X-Audidash-Proxy-Secret": settings.proxy_secret.get_secret_value(),
            "X-Client-Cert-Fingerprint": fp,
        }
        return EnrolledDevice(uuid.UUID(body["device_id"]), fp, headers)

    return _enroll


@dataclass
class ApiUser:
    client: TestClient
    user: AuthUser
    device: EnrolledDevice
    token: str

    @property
    def headers(self) -> dict[str, str]:
        return {**self.device.headers, "Authorization": f"Bearer {self.token}"}

    def get(self, path: str) -> httpx.Response:
        response: httpx.Response = self.client.get(path, headers=self.headers)
        return response

    def post(self, path: str, body: Any) -> httpx.Response:
        response: httpx.Response = self.client.post(path, json=body, headers=self.headers)
        return response


MakeApiUser = Callable[..., ApiUser]


ApiLoginFn = Callable[..., httpx.Response]


@pytest.fixture
def csr() -> Callable[..., bytes]:
    return make_csr


@pytest.fixture
def api_login(app_client: TestClient) -> ApiLoginFn:
    def _login(
        device: EnrolledDevice, user: AuthUser, code: str, password: str | None = None
    ) -> httpx.Response:
        response: httpx.Response = app_client.post(
            "/api/v1/auth/token",
            json={"username": user.username, "password": password or user.password, "totp": code},
            headers=device.headers,
        )
        return response

    return _login


@pytest.fixture
def make_api_user(
    app_client: TestClient,
    make_user: MakeUser,
    enroll_device: EnrollFn,
    api_login: ApiLoginFn,
    frozen_clock: FrozenClock,
) -> MakeApiUser:
    def _make(username: str = "alice", role: Role = Role.admin) -> ApiUser:
        user = make_user(username, role)
        device = enroll_device(f"{username}-laptop")
        r = api_login(device, user, user.code(frozen_clock.current))
        assert r.status_code == 200, r.text
        return ApiUser(app_client, user, device, r.json()["access_token"])

    return _make
