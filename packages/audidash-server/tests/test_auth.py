import getpass
import hashlib
import io
import re
import sys
from datetime import timedelta
from typing import Any

import pyotp
import pytest
from audidash_server import cli
from audidash_server.auth import passwords, routes, service
from audidash_server.auth.lockout import clear_failures_if_unlocked, record_failure
from audidash_server.auth.passwords import (
    WeakPasswordError,
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)
from audidash_server.auth.sessions import SESSION_COOKIE
from audidash_server.auth.totp import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    totp_match_step,
    totp_secret_new,
    totp_verify,
)
from audidash_server.db import init_db, make_engine
from audidash_server.models import Role, Session, User
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

GENERIC_ERROR = "Usuário, senha ou código inválidos."
HTML = {"Accept": "text/html"}
KEY = "k" * 48


def _sessions(client: TestClient) -> list[Session]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(Session)).all())


def _user(client: TestClient, username: str) -> User:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        user: User = s.scalars(select(User).where(User.username == username)).one()
        return user


def _cookie_token(response: Any) -> str:
    header = response.headers["set-cookie"]
    match = re.match(rf"{SESSION_COOKIE}=([^;]+); ", header)
    assert match, header
    return match.group(1)


def _csrf(client: TestClient) -> str:
    page = client.get("/", headers=HTML)
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match
    return match.group(1)


# --- passwords -------------------------------------------------------------------------


def test_hash_is_argon2id_and_verifies() -> None:
    h = hash_password("a-long-unique-passphrase")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "a-long-unique-passphrase")
    assert not verify_password(h, "wrong-passphrase-xx")
    assert not verify_password("not-a-hash", "whatever")
    assert not needs_rehash(h)


@pytest.mark.parametrize(
    ("pw", "username"),
    [
        ("short-pw", "bob"),  # < 12 chars
        ("passwordpassword", "bob"),  # common list
        ("qwertyuiop123", "bob"),  # common list
        ("password123456!", "bob"),  # common base + digits/symbols
        ("aaaaaaaaaaaaaaaa", "bob"),  # all-same-char
        ("xx-mallory-2026-xx", "Mallory"),  # contains username
    ],
)
def test_password_policy_rejects(pw: str, username: str) -> None:
    with pytest.raises(WeakPasswordError):
        validate_password(pw, username)


def test_password_policy_accepts_strong() -> None:
    validate_password("vivid-Orbit-73-lantern", "bob")


def test_common_password_list_is_bundled() -> None:
    assert len(passwords.common_passwords()) >= 200


# --- totp ------------------------------------------------------------------------------


def test_totp_secret_encrypted_at_rest(frozen_clock: Any) -> None:
    secret = totp_secret_new()
    token = encrypt_totp_secret(secret, KEY)
    assert secret not in token
    assert decrypt_totp_secret(token, KEY) == secret
    with pytest.raises(ValueError):
        decrypt_totp_secret(token, "z" * 48)


def test_totp_verify_window(frozen_clock: Any) -> None:
    secret = totp_secret_new()
    now = frozen_clock.current
    totp = pyotp.TOTP(secret)
    assert totp_verify(secret, totp.at(now))
    assert totp_verify(secret, totp.at(now - timedelta(seconds=30)))
    assert totp_verify(secret, totp.at(now + timedelta(seconds=30)))
    assert not totp_verify(secret, totp.at(now - timedelta(seconds=60)))
    assert not totp_verify(secret, totp.at(now + timedelta(seconds=60)))
    assert not totp_verify(secret, totp.at(now - timedelta(seconds=90)))
    assert not totp_verify(secret, "12345")
    assert not totp_verify(secret, "abcdef")


# --- login -----------------------------------------------------------------------------


def test_login_page_has_no_inline_script_or_style(app_client: TestClient) -> None:
    page = app_client.get("/login")
    assert page.status_code == 200
    assert not re.search(r"<script(?![^>]*\bsrc=)", page.text)  # external scripts only
    assert "style=" not in page.text and "<style" not in page.text
    assert 'lang="pt-BR"' in page.text


def test_login_happy_path_sets_exact_cookie(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    r = login(u.username, u.password, u.code(frozen_clock.current))
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    token = _cookie_token(r)
    assert r.headers["set-cookie"] == (
        f"{SESSION_COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/"
    )
    rows = _sessions(app_client)
    assert len(rows) == 1
    assert rows[0].token_sha256 == hashlib.sha256(token.encode()).hexdigest()
    assert token not in (rows[0].csrf_token, str(rows[0].id))
    assert app_client.get("/", headers=HTML).status_code == 200


def test_wrong_totp_is_generic_401_and_counts(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    r = login(u.username, u.password, "000000")
    assert r.status_code == 401
    assert GENERIC_ERROR in r.text
    assert SESSION_COOKIE not in r.headers.get("set-cookie", "")
    assert _user(app_client, u.username).failed_logins == 1
    unknown = login("nobody", u.password, u.code(frozen_clock.current))
    assert unknown.status_code == 401 and GENERIC_ERROR in unknown.text
    wrong_pw = login(u.username, "Wrong-password-123", u.code(frozen_clock.current))
    assert wrong_pw.status_code == 401 and GENERIC_ERROR in wrong_pw.text


def test_unknown_user_still_runs_argon2(
    login: Any, monkeypatch: pytest.MonkeyPatch, frozen_clock: Any
) -> None:
    calls: list[str] = []
    real = passwords.verify_password

    def spy(h: str, pw: str) -> bool:
        calls.append(h)
        return real(h, pw)

    monkeypatch.setattr(passwords, "verify_password", spy)
    assert login("ghost", "Some-password-1234", "123456").status_code == 401
    assert len(calls) == 1 and calls[0].startswith("$argon2id$")


def test_lockout_after_five_failures(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    for i in range(4):
        assert login(u.username, "Wrong-password-123", "000000").status_code == 401
        user = _user(app_client, u.username)
        assert (user.failed_logins, user.locked_until) == (i + 1, None)
    assert login(u.username, "Wrong-password-123", "000000").status_code == 401
    user = _user(app_client, u.username)
    assert user.locked_until == frozen_clock.current + timedelta(minutes=15)
    r = login(u.username, u.password, u.code(frozen_clock.current))
    assert r.status_code == 401 and GENERIC_ERROR in r.text
    frozen_clock.advance(minutes=14, seconds=50)
    assert login(u.username, u.password, u.code(frozen_clock.current)).status_code == 401
    frozen_clock.advance(seconds=11)
    assert login(u.username, u.password, u.code(frozen_clock.current)).status_code == 303
    assert _user(app_client, u.username).failed_logins == 0


def test_success_resets_failure_counter(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    for _ in range(4):
        login(u.username, "Wrong-password-123", "000000")
    assert login(u.username, u.password, u.code(frozen_clock.current)).status_code == 303
    user = _user(app_client, u.username)
    assert user.failed_logins == 0 and user.locked_until is None


def test_totp_code_cannot_be_replayed(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    code = u.code(frozen_clock.current)
    assert login(u.username, u.password, code).status_code == 303
    app_client.cookies.clear()
    assert login(u.username, u.password, code).status_code == 401
    frozen_clock.advance(seconds=30)
    assert login(u.username, u.password, u.code(frozen_clock.current)).status_code == 303


def test_login_rotates_session_token(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    first = _cookie_token(login(u.username, u.password, u.code(frozen_clock.current)))
    frozen_clock.advance(seconds=30)
    second = _cookie_token(login(u.username, u.password, u.code(frozen_clock.current)))
    assert first != second
    hashes = {s.token_sha256 for s in _sessions(app_client)}
    assert hashes == {hashlib.sha256(second.encode()).hexdigest()}


def test_login_requires_login_csrf(
    app_client: TestClient, make_user: Any, frozen_clock: Any
) -> None:
    u = make_user()
    form = {"username": u.username, "password": u.password, "totp": u.code(frozen_clock.current)}
    assert app_client.post("/login", data=form).status_code == 403
    app_client.get("/login")
    forged = app_client.post("/login", data={**form, "csrf_token": "x.y"})
    assert forged.status_code == 403
    assert _user(app_client, u.username).failed_logins == 0


def test_per_ip_rate_limit(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    for i in range(20):
        assert login(f"ghost{i}", "Wrong-password-123", "000000").status_code == 401
    r = login(u.username, u.password, u.code(frozen_clock.current))
    assert r.status_code == 429
    frozen_clock.advance(minutes=15, seconds=1)
    assert login(u.username, u.password, u.code(frozen_clock.current)).status_code == 303


# --- sessions --------------------------------------------------------------------------


def test_unauthenticated_responses(app_client: TestClient) -> None:
    html = app_client.get("/", headers=HTML, follow_redirects=False)
    assert html.status_code == 303 and html.headers["location"] == "/login"
    htmx = app_client.get("/", headers={"HX-Request": "true"}, follow_redirects=False)
    assert htmx.status_code == 401 and htmx.headers["HX-Redirect"] == "/login"
    api = app_client.get("/", headers={"Accept": "application/json"}, follow_redirects=False)
    assert api.status_code == 401 and api.json() == {"detail": "Not authenticated"}


def test_idle_timeout_30_minutes(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    login(u.username, u.password, u.code(frozen_clock.current))
    frozen_clock.advance(minutes=29)
    assert app_client.get("/", headers=HTML).status_code == 200  # refreshes last_seen
    frozen_clock.advance(minutes=29)
    assert app_client.get("/", headers=HTML).status_code == 200
    frozen_clock.advance(minutes=30, seconds=1)
    r = app_client.get("/", headers=HTML, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert _sessions(app_client) == []


def test_absolute_timeout_12_hours(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    login(u.username, u.password, u.code(frozen_clock.current))
    for _ in range(35):  # 35 * 20 min = 11 h 40 min, always active
        frozen_clock.advance(minutes=20)
        assert app_client.get("/", headers=HTML).status_code == 200
    frozen_clock.advance(minutes=20, seconds=1)  # 12 h 00 min 01 s
    r = app_client.get("/", headers=HTML, follow_redirects=False)
    assert r.status_code == 303
    assert _sessions(app_client) == []


def test_logout_requires_csrf_and_deletes_session(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    login(u.username, u.password, u.code(frozen_clock.current))
    assert app_client.post("/logout", follow_redirects=False).status_code == 403
    assert (
        app_client.post("/logout", data={"csrf_token": "wrong"}, follow_redirects=False).status_code
        == 403
    )
    assert len(_sessions(app_client)) == 1
    r = app_client.post("/logout", data={"csrf_token": _csrf(app_client)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert r.headers["set-cookie"].startswith(f"{SESSION_COOKIE}=; Max-Age=0;")
    assert _sessions(app_client) == []


def test_csrf_accepts_htmx_header(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    login(u.username, u.password, u.code(frozen_clock.current))
    token = _csrf(app_client)
    page = app_client.get("/", headers=HTML)
    assert f'hx-headers=\'{{"HX-CSRF-Token": "{token}"}}\'' in page.text
    r = app_client.post("/logout", headers={"HX-Request": "true", "HX-CSRF-Token": token})
    assert r.status_code == 204 and r.headers["HX-Redirect"] == "/login"
    assert _sessions(app_client) == []


# --- first login: TOTP enrolment ------------------------------------------------------


def test_first_login_requires_totp_setup(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any, settings: Any
) -> None:
    u = make_user("newbie", Role.viewer, with_totp=False)
    r = login(u.username, u.password)
    assert r.status_code == 303 and r.headers["location"] == "/totp/setup"
    # A pending session is not a full session.
    assert app_client.get("/", headers=HTML, follow_redirects=False).status_code == 303
    page = app_client.get("/totp/setup")
    assert page.status_code == 200
    assert 'src="data:image/svg+xml;base64,' in page.text
    assert not re.search(r"<script(?![^>]*\bsrc=)", page.text) and "style=" not in page.text
    secret = re.search(r'<code class="totp-secret">([A-Z2-7]+)</code>', page.text)
    assert secret
    setup = re.search(r'name="setup_token" value="([^"]+)"', page.text)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert setup and csrf
    form = {"setup_token": setup.group(1), "csrf_token": csrf.group(1)}
    bad = app_client.post("/totp/setup", data={**form, "code": "000000"})
    assert bad.status_code == 400
    code = pyotp.TOTP(secret.group(1)).at(frozen_clock.current)
    no_csrf = app_client.post(
        "/totp/setup", data={"setup_token": form["setup_token"], "code": code}
    )
    assert no_csrf.status_code == 403
    ok = app_client.post("/totp/setup", data={**form, "code": code}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/"
    assert app_client.get("/", headers=HTML).status_code == 200
    user = _user(app_client, u.username)
    assert user.totp_secret_enc is not None
    key = settings.secret_key.get_secret_value()
    assert decrypt_totp_secret(user.totp_secret_enc, key) == secret.group(1)
    assert len(_sessions(app_client)) == 1  # pending session replaced, not kept


def test_users_with_totp_cannot_reach_setup(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = make_user()
    login(u.username, u.password, u.code(frozen_clock.current))
    r = app_client.get("/totp/setup", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


# --- create-admin CLI ----------------------------------------------------------------


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> str:
    url = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    monkeypatch.setenv("AUDIDASH_DATABASE_URL", url)
    monkeypatch.setenv("AUDIDASH_DEV_MODE", "1")
    monkeypatch.setenv("AUDIDASH_SECRET_KEY", KEY)
    return url


def _prompts(monkeypatch: pytest.MonkeyPatch, *answers: str) -> None:
    it = iter(answers)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(it))


def _users(url: str) -> list[User]:
    engine = make_engine(url)
    init_db(engine)  # the CLI may have exited before touching the database
    try:
        with DbSession(engine) as s:
            return list(s.scalars(select(User)).all())
    finally:
        engine.dispose()


@pytest.mark.parametrize("weak", ["short1!", "password123456", "admin-admin-admin"])
def test_create_admin_rejects_weak_password(
    cli_env: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], weak: str
) -> None:
    _prompts(monkeypatch, weak, weak)
    assert cli.main(["create-admin", "--username", "admin"]) == 1
    assert "senha" in capsys.readouterr().err.lower()
    assert _users(cli_env) == []


def test_create_admin_rejects_mismatch(cli_env: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _prompts(monkeypatch, "vivid-Orbit-73-lantern", "vivid-Orbit-73-lanterm")
    assert cli.main(["create-admin", "--username", "root"]) == 1
    assert _users(cli_env) == []


def test_create_admin_success_and_idempotency(
    cli_env: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _prompts(monkeypatch, "vivid-Orbit-73-lantern", "vivid-Orbit-73-lantern")
    assert cli.main(["create-admin", "--username", "root"]) == 0
    out = capsys.readouterr().out
    uri = re.search(r"otpauth://totp/\S+", out)
    assert uri and "secret=" in uri.group(0)
    users = _users(cli_env)
    assert [(x.username, x.role) for x in users] == [("root", Role.admin)]
    assert users[0].password_hash.startswith("$argon2id$")
    assert users[0].totp_secret_enc is not None
    secret = pyotp.parse_uri(uri.group(0)).secret
    assert decrypt_totp_secret(users[0].totp_secret_enc, KEY) == secret
    _prompts(monkeypatch, "vivid-Orbit-73-lantern", "vivid-Orbit-73-lantern")
    assert cli.main(["create-admin", "--username", "root"]) == 1
    assert "existe" in capsys.readouterr().err
    assert len(_users(cli_env)) == 1


# --- fix round 1: atomic lockout, timing, enrolment edge cases ------------------------


def test_failure_increment_is_sql_side(
    app_client: TestClient, make_user: Any, frozen_clock: Any
) -> None:
    u = make_user()
    factory = app_client.app.state.sessionmaker  # type: ignore[attr-defined]
    with factory() as a, factory() as b:
        stale_a = a.get(User, u.id)
        stale_b = b.get(User, u.id)
        assert stale_a is not None and stale_b is not None
        assert stale_a.failed_logins == stale_b.failed_logins == 0  # both read k = 0
        assert record_failure(a, u.id, frozen_clock.current) is False
        a.commit()
        assert record_failure(b, u.id, frozen_clock.current) is False
        b.commit()
    assert _user(app_client, u.username).failed_logins == 2  # k + 2, no lost update


def test_lock_triggers_at_exactly_five_sql_side(
    app_client: TestClient, make_user: Any, frozen_clock: Any
) -> None:
    u = make_user()
    factory = app_client.app.state.sessionmaker  # type: ignore[attr-defined]
    results = []
    for _ in range(5):
        with factory() as db:
            results.append(record_failure(db, u.id, frozen_clock.current))
            db.commit()
    assert results == [False, False, False, False, True]
    user = _user(app_client, u.username)
    assert user.locked_until == frozen_clock.current + timedelta(minutes=15)
    with factory() as db:  # a stale "not locked" guess cannot complete a login
        assert clear_failures_if_unlocked(db, u.id, frozen_clock.current) is False


def test_every_failure_path_does_the_same_db_write(
    app_client: TestClient,
    make_user: Any,
    login: Any,
    frozen_clock: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Any] = []
    real = record_failure

    def spy(db: Any, user_id: Any, now: Any) -> bool:
        calls.append(user_id)
        return real(db, user_id, now)

    monkeypatch.setattr(service, "record_failure", spy)
    u = make_user()
    make_user("off", Role.viewer)
    with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        off = s.scalars(select(User).where(User.username == "off")).one()
        off.disabled = True
        s.commit()
    login("ghost", "Wrong-password-123", "000000")  # unknown
    login("off", u.password, "000000")  # disabled
    login(u.username, "Wrong-password-123", "000000")  # counted
    assert calls == [None, None, u.id]
    for _ in range(4):
        login(u.username, "Wrong-password-123", "000000")
    calls.clear()
    login(u.username, u.password, u.code(frozen_clock.current))  # locked
    assert calls == [None]


def _pending_client(app_client: TestClient, make_user: Any, login: Any, name: str) -> Any:
    u = make_user(name, Role.viewer, with_totp=False)
    assert login(u.username, u.password).headers["location"] == "/totp/setup"
    return u


def _setup_fields(page: str) -> dict[str, str]:
    fields = {}
    for name in ("setup_token", "csrf_token"):
        m = re.search(rf'name="{name}" value="([^"]+)"', page)
        assert m
        fields[name] = m.group(1)
    secret = re.search(r'<code class="totp-secret">([A-Z2-7]+)</code>', page)
    assert secret
    fields["secret"] = secret.group(1)
    return fields


def test_pending_session_capped_at_10_minutes(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _pending_client(app_client, make_user, login, "slow")
    frozen_clock.advance(minutes=9, seconds=59)
    assert app_client.get("/totp/setup").status_code == 200
    frozen_clock.advance(seconds=2)  # 10 min 01 s after creation, though not idle
    r = app_client.get("/totp/setup", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert _sessions(app_client) == []


def test_setup_token_for_another_user_rejected(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _pending_client(app_client, make_user, login, "victim")
    victim = _setup_fields(app_client.get("/totp/setup").text)
    other = TestClient(app_client.app, base_url="https://testserver")
    o = make_user("mallory", Role.viewer, with_totp=False)
    page = other.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert csrf
    other.post(
        "/login",
        data={"username": o.username, "password": o.password, "csrf_token": csrf.group(1)},
    )
    mine = _setup_fields(other.get("/totp/setup").text)
    code = pyotp.TOTP(victim["secret"]).at(frozen_clock.current)
    form = {"setup_token": victim["setup_token"], "csrf_token": mine["csrf_token"], "code": code}
    r = other.post("/totp/setup", data=form, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/totp/setup"
    assert _user(app_client, "mallory").totp_secret_enc is None
    assert _user(app_client, "victim").totp_secret_enc is None


def test_expired_setup_token_rejected(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    u = _pending_client(app_client, make_user, login, "late")
    old = _setup_fields(app_client.get("/totp/setup").text)  # issued at t0
    frozen_clock.advance(minutes=9)
    login(u.username, u.password)  # fresh pending session, alive until t0 + 19 min
    fresh = _setup_fields(app_client.get("/totp/setup").text)
    frozen_clock.advance(minutes=1, seconds=1)  # old token is now 10 min 01 s old
    code = pyotp.TOTP(old["secret"]).at(frozen_clock.current)
    form = {"setup_token": old["setup_token"], "csrf_token": fresh["csrf_token"], "code": code}
    r = app_client.post("/totp/setup", data=form, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/totp/setup"
    assert _user(app_client, "late").totp_secret_enc is None
    # The fresh token (9 min later) is still accepted at the same instant.
    good = pyotp.TOTP(fresh["secret"]).at(frozen_clock.current)
    form = {"setup_token": fresh["setup_token"], "csrf_token": fresh["csrf_token"], "code": good}
    ok = app_client.post("/totp/setup", data=form, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/"


def test_pending_session_cannot_logout(
    app_client: TestClient, make_user: Any, login: Any, frozen_clock: Any
) -> None:
    _pending_client(app_client, make_user, login, "half")
    fields = _setup_fields(app_client.get("/totp/setup").text)
    r = app_client.post("/logout", data={"csrf_token": fields["csrf_token"]})
    assert r.status_code == 401
    assert len(_sessions(app_client)) == 1


def test_concurrent_enrolment_completion_is_not_a_500(
    app_client: TestClient,
    make_user: Any,
    login: Any,
    frozen_clock: Any,
    monkeypatch: pytest.MonkeyPatch,
    settings: Any,
) -> None:
    u = _pending_client(app_client, make_user, login, "twice")
    fields = _setup_fields(app_client.get("/totp/setup").text)
    real = totp_match_step
    key = settings.secret_key.get_secret_value()

    def racing(secret: str, code: str, at: Any = None) -> int | None:
        step = real(secret, code, at)
        # Simulate the other submit winning between our read and our writes.
        with app_client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
            other = s.get(User, u.id)
            assert other is not None
            other.totp_secret_enc = encrypt_totp_secret(secret, key)
            for row in s.scalars(select(Session)).all():
                s.delete(row)
            s.commit()
        return step

    monkeypatch.setattr(routes, "totp_match_step", racing)
    code = pyotp.TOTP(fields["secret"]).at(frozen_clock.current)
    form = {"setup_token": fields["setup_token"], "csrf_token": fields["csrf_token"], "code": code}
    r = app_client.post("/totp/setup", data=form, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert SESSION_COOKIE not in r.headers.get("set-cookie", "")
    assert _sessions(app_client) == []


# --- create-admin automation flags and interrupted prompts ----------------------------

PASSWORD_OK = "vivid-Orbit-73-lantern"  # noqa: S105 - test fixture value


def test_create_admin_password_stdin_and_secret_file(
    cli_env: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Any,
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD_OK + "\n"))
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": pytest.fail("must not prompt"))
    out_file = tmp_path / "totp.secret"
    argv = ["create-admin", "--username", "ciadmin", "--password-stdin", "--totp-secret-out"]
    assert cli.main([*argv, str(out_file)]) == 0
    shown = capsys.readouterr()
    secret = out_file.read_text().strip()
    assert secret and secret not in shown.out + shown.err
    assert "otpauth://" not in shown.out
    users = _users(cli_env)
    assert [u.username for u in users] == ["ciadmin"]
    assert users[0].totp_secret_enc is not None
    assert decrypt_totp_secret(users[0].totp_secret_enc, KEY) == secret
    if sys.platform != "win32":
        assert out_file.stat().st_mode & 0o777 == 0o600


def test_create_admin_secret_file_never_overwritten(
    cli_env: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    out_file = tmp_path / "totp.secret"
    out_file.write_text("precious")
    _prompts(monkeypatch, PASSWORD_OK, PASSWORD_OK)
    argv = ["create-admin", "--username", "ciadmin", "--totp-secret-out", str(out_file)]
    assert cli.main(argv) == 1
    assert out_file.read_text() == "precious"
    assert _users(cli_env) == []


def test_create_admin_failure_leaves_no_secret_file(
    cli_env: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    out_file = tmp_path / "totp.secret"
    monkeypatch.setattr("sys.stdin", io.StringIO("short1!\n"))
    argv = ["create-admin", "--username", "ciadmin", "--password-stdin", "--totp-secret-out"]
    assert cli.main([*argv, str(out_file)]) == 1
    assert not out_file.exists()


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
def test_create_admin_interrupted_prompt_is_clean(
    cli_env: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    exc: type[BaseException],
) -> None:
    def _boom(prompt: str = "") -> str:
        raise exc

    monkeypatch.setattr(getpass, "getpass", _boom)
    assert cli.main(["create-admin", "--username", "root"]) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "Traceback" not in err
    assert _users(cli_env) == []


def test_create_admin_empty_stdin_is_clean(
    cli_env: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert cli.main(["create-admin", "--username", "root", "--password-stdin"]) == 2
    assert capsys.readouterr().err.count("\n") == 1


def test_set_cookie_accepts_urlsafe_and_signed_values() -> None:
    from audidash_server.auth.sessions import clear_cookie, set_cookie
    from starlette.responses import Response

    response = Response()
    set_cookie(response, SESSION_COOKIE, "abc-DEF_123")
    set_cookie(response, "__Host-audidash_login_csrf", "nonce_-x.0a1b2c")
    clear_cookie(response, SESSION_COOKIE)
    assert response.headers.getlist("set-cookie")[0].startswith(f"{SESSION_COOKIE}=abc-DEF_123;")


@pytest.mark.parametrize("value", ["a\r\nSet-Cookie: x=1", "a;Path=/x", "a b", "a,b", "ok\n"])
def test_set_cookie_rejects_injection_in_value(value: str) -> None:
    from audidash_server.auth.sessions import set_cookie
    from starlette.responses import Response

    with pytest.raises(ValueError):
        set_cookie(Response(), SESSION_COOKIE, value)


@pytest.mark.parametrize("name", ["a=b", "a;b", "a\r\nb", ""])
def test_cookie_name_is_validated(name: str) -> None:
    from audidash_server.auth.sessions import clear_cookie, set_cookie
    from starlette.responses import Response

    with pytest.raises(ValueError):
        set_cookie(Response(), name, "v")
    with pytest.raises(ValueError):
        clear_cookie(Response(), name)


def test_login_page_never_echoes_client_csrf_cookie(app_client: TestClient) -> None:
    from audidash_server.auth.csrf import LOGIN_CSRF_COOKIE

    first = app_client.get("/login")
    assert LOGIN_CSRF_COOKIE in first.headers.get("set-cookie", "")
    # The browser now holds a valid signed cookie: the server reuses it for the form
    # but must not emit a Set-Cookie carrying the client-supplied value back.
    second = app_client.get("/login")
    assert LOGIN_CSRF_COOKIE not in second.headers.get("set-cookie", "")
    token = app_client.cookies.get(LOGIN_CSRF_COOKIE)
    assert token is not None and token in second.text
