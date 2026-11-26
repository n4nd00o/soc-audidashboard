"""Login (password + TOTP), first-login TOTP enrolment, logout and the post-login landing page."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import timedelta
from typing import Annotated, Any

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session as DbSession
from starlette.responses import Response

from audidash_server import clock
from audidash_server.auth import passwords
from audidash_server.auth.csrf import (
    check_login_csrf,
    csrf_protect,
    login_csrf_token,
    set_login_csrf_cookie,
    tokens_equal,
)
from audidash_server.auth.ratelimit import LoginRateLimiter
from audidash_server.auth.sessions import (
    SESSION_COOKIE,
    clear_cookie,
    client_ip,
    create_session,
    current_session,
    current_user,
    delete_session_by_token,
    pending_session,
    set_cookie,
)
from audidash_server.auth.totp import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    provisioning_uri,
    qr_svg_data_uri,
    setup_fernet,
    totp_match_step,
    totp_secret_new,
)
from audidash_server.db import get_session
from audidash_server.models import Session, User
from audidash_server.settings import Settings

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)
SETUP_TOKEN_TTL_SECONDS = 600
GENERIC_LOGIN_ERROR = "Usuário, senha ou código inválidos."
RATE_LIMITED_ERROR = "Muitas tentativas de login. Aguarde alguns minutos e tente novamente."
FORM_EXPIRED_ERROR = "O formulário expirou. Recarregue a página e tente novamente."

Db = Annotated[DbSession, Depends(get_session)]
FormStr = Annotated[str, Form()]


def render(
    request: Request, name: str, context: dict[str, Any], status_code: int = 200
) -> Response:
    response: Response = request.app.state.templates.TemplateResponse(
        request, name, context, status_code=status_code
    )
    return response


def _secret_key(request: Request) -> str:
    settings: Settings = request.app.state.settings
    return settings.secret_key.get_secret_value()


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


# --- login ---------------------------------------------------------------------------


def _login_page(
    request: Request, *, error: str | None = None, username: str = "", status_code: int = 200
) -> Response:
    token = login_csrf_token(request)
    response = render(
        request,
        "login.html",
        {"login_csrf": token, "error": error, "username": username},
        status_code,
    )
    set_login_csrf_cookie(response, token)
    return response


@router.get("/login")
def login_form(request: Request) -> Response:
    return _login_page(request)


def _totp_step(request: Request, user: User, code: str) -> int | None:
    """Matching, not-yet-used TOTP step for an enrolled user, else None."""
    if user.totp_secret_enc is None:
        return None
    try:
        secret = decrypt_totp_secret(user.totp_secret_enc, _secret_key(request))
    except ValueError:
        logger.warning("TOTP secret of user %s cannot be decrypted (secret key changed?)", user.id)
        return None
    step = totp_match_step(secret, code)
    if step is None or (user.totp_last_step is not None and step <= user.totp_last_step):
        return None
    return step


def _claim_totp_step(db: DbSession, user: User, step: int) -> bool:
    """Atomically record `step` as used; False if it (or a later one) was already used."""
    result = db.execute(
        update(User)
        .where(User.id == user.id)
        .where(or_(User.totp_last_step.is_(None), User.totp_last_step < step))
        .values(totp_last_step=step)
        .execution_options(synchronize_session=False)
    )
    claimed: int = getattr(result, "rowcount", 0)
    if claimed == 1:
        user.totp_last_step = step
    return claimed == 1


@router.post("/login")
def login_submit(
    request: Request,
    db: Db,
    username: FormStr = "",
    password: FormStr = "",
    totp: FormStr = "",
    csrf_token: FormStr = "",
) -> Response:
    if not check_login_csrf(request, csrf_token):
        return _login_page(request, error=FORM_EXPIRED_ERROR, status_code=403)
    limiter: LoginRateLimiter = request.app.state.login_limiter
    ip = client_ip(request)
    if not limiter.hit(ip or "unknown"):
        return _login_page(request, error=RATE_LIMITED_ERROR, status_code=429)

    def fail() -> Response:
        return _login_page(
            request, error=GENERIC_LOGIN_ERROR, username=username[:64], status_code=401
        )

    user = None
    if len(username) <= 64:
        user = db.scalars(select(User).where(User.username == username)).first()
    if user is None or user.disabled:
        passwords.verify_password(passwords.dummy_hash(), password)  # equalize timing
        return fail()

    now = clock.now()
    password_ok = passwords.verify_password(user.password_hash, password)
    enrolled = user.totp_secret_enc is not None
    step = _totp_step(request, user, totp) if enrolled else None
    if user.locked_until is not None and user.locked_until > now:
        return fail()
    if not password_ok or (enrolled and step is None):
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = now + LOCKOUT
            user.failed_logins = 0
            logger.warning("account %s locked after %d failures", user.id, MAX_FAILED_LOGINS)
        db.commit()
        return fail()

    user.failed_logins = 0
    user.locked_until = None
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
    if step is not None and not _claim_totp_step(db, user, step):
        db.rollback()  # a concurrent login consumed this code first
        return fail()
    delete_session_by_token(db, request.cookies.get(SESSION_COOKIE))  # rotate
    token, _ = create_session(db, user, ip, pending=not enrolled)
    db.commit()
    response = _see_other("/" if enrolled else "/totp/setup")
    set_cookie(response, SESSION_COOKIE, token)
    return response


# --- first-login TOTP enrolment ------------------------------------------------------


def _setup_page(
    request: Request,
    sess: Session,
    user: User,
    secret: str,
    setup_token: str,
    *,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    uri = provisioning_uri(secret, user.username)
    context = {
        "csrf_token": sess.csrf_token,
        "qr_data_uri": qr_svg_data_uri(uri),
        "secret": secret,
        "setup_token": setup_token,
        "error": error,
    }
    return render(request, "totp_setup.html", context, status_code)


@router.get("/totp/setup")
def totp_setup_form(request: Request, db: Db) -> Response:
    pending = pending_session(request, db)
    if pending is None:
        return _see_other("/login")
    sess, user = pending
    secret = totp_secret_new()
    payload = json.dumps({"u": str(user.id), "s": secret}).encode("utf-8")
    setup_token = setup_fernet(_secret_key(request)).encrypt(payload).decode("ascii")
    return _setup_page(request, sess, user, secret, setup_token)


@router.post("/totp/setup")
def totp_setup_submit(
    request: Request,
    db: Db,
    code: FormStr = "",
    setup_token: FormStr = "",
    csrf_token: FormStr = "",
) -> Response:
    pending = pending_session(request, db)
    if pending is None:
        return _see_other("/login")
    sess, user = pending
    if not tokens_equal(sess.csrf_token, csrf_token):
        return Response("CSRF token missing or invalid", status_code=403)
    limiter: LoginRateLimiter = request.app.state.login_limiter
    if not limiter.hit(client_ip(request) or "unknown"):  # code guesses share the login budget
        return Response(RATE_LIMITED_ERROR, status_code=429)
    try:
        raw = setup_fernet(_secret_key(request)).decrypt(
            setup_token.encode("ascii"), ttl=SETUP_TOKEN_TTL_SECONDS
        )
        data = json.loads(raw)
        if uuid.UUID(data["u"]) != user.id:
            raise ValueError("setup token issued for another user")
        secret = str(data["s"])
    except (InvalidToken, ValueError, KeyError, UnicodeEncodeError):
        return _see_other("/totp/setup")
    step = totp_match_step(secret, code)
    if step is None:
        return _setup_page(
            request,
            sess,
            user,
            secret,
            setup_token,
            error="Código inválido. Confira o horário do dispositivo e tente novamente.",
            status_code=400,
        )
    user.totp_secret_enc = encrypt_totp_secret(secret, _secret_key(request))
    user.totp_last_step = step
    db.delete(sess)
    token, _ = create_session(db, user, client_ip(request))
    db.commit()
    response = _see_other("/")
    set_cookie(response, SESSION_COOKIE, token)
    return response


# --- logout & landing ----------------------------------------------------------------


@router.post("/logout", dependencies=[Depends(csrf_protect)])
def logout(
    request: Request,
    db: Db,
    sess: Annotated[Session, Depends(current_session)],
) -> Response:
    db.delete(sess)
    db.commit()
    response: Response
    if request.headers.get("HX-Request"):
        response = Response(status_code=204, headers={"HX-Redirect": "/login"})
    else:
        response = _see_other("/login")
    clear_cookie(response, SESSION_COOKIE)
    return response


@router.get("/")
def home(request: Request, user: Annotated[User, Depends(current_user)]) -> Response:
    """Placeholder landing page; the dashboard (Task 8) replaces it."""
    return render(
        request, "home.html", {"user": user, "csrf_token": request.state.auth_session.csrf_token}
    )
