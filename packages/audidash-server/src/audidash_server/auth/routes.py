"""Login (password + TOTP), first-login TOTP enrolment and logout."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated, Any

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, update
from sqlalchemy.orm import Session as DbSession
from starlette.responses import Response

from audidash_server import clock
from audidash_server.auth import service
from audidash_server.auth.csrf import (
    check_login_csrf,
    csrf_protect,
    issue_login_csrf,
    set_login_csrf_cookie,
    tokens_equal,
)
from audidash_server.auth.ratelimit import LoginRateLimiter
from audidash_server.auth.sessions import (
    SESSION_COOKIE,
    clear_cookie,
    create_session,
    current_session,
    delete_session_by_token,
    pending_session,
    set_cookie,
)
from audidash_server.auth.totp import (
    encrypt_totp_secret,
    provisioning_uri,
    qr_svg_data_uri,
    setup_fernet,
    totp_match_step,
    totp_secret_new,
)
from audidash_server.db import get_session
from audidash_server.models import Session, User
from audidash_server.proxy import client_ip
from audidash_server.settings import Settings
from audidash_server.textguard import without_nul

logger = logging.getLogger(__name__)
router = APIRouter()

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
    token, fresh_cookie = issue_login_csrf(request)
    response = render(
        request,
        "login.html",
        {"login_csrf": token, "error": error, "username": username},
        status_code,
    )
    if fresh_cookie is not None:
        set_login_csrf_cookie(response, fresh_cookie)
    return response


@router.get("/login")
def login_form(request: Request) -> Response:
    return _login_page(request)


@router.post("/login")
def login_submit(  # nosec B107
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

    result = service.authenticate(
        db,
        username=username,
        password=password,
        totp_code=totp,
        secret_key=_secret_key(request),
    )
    if result.outcome is not service.LoginOutcome.ok or result.user is None:
        return _login_page(
            request, error=GENERIC_LOGIN_ERROR, username=without_nul(username)[:64], status_code=401
        )
    enrolled = result.totp_enrolled
    delete_session_by_token(db, request.cookies.get(SESSION_COOKIE))  # rotate
    token, _ = create_session(db, result.user, ip, pending=not enrolled)
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
    issued_at = int(clock.now().timestamp())
    fernet = setup_fernet(_secret_key(request))
    setup_token = fernet.encrypt_at_time(payload, issued_at).decode("ascii")
    return _setup_page(request, sess, user, secret, setup_token)


@router.post("/totp/setup")
def totp_setup_submit(  # nosec B107
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
        raw = setup_fernet(_secret_key(request)).decrypt_at_time(
            setup_token.encode("ascii"),
            ttl=SETUP_TOKEN_TTL_SECONDS,
            current_time=int(clock.now().timestamp()),
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
    # Guarded writes: a concurrent double-submit finds 0 rows and is redirected, not a 500.
    enrolled = db.execute(
        update(User)
        .where(User.id == user.id, User.totp_secret_enc.is_(None))
        .values(
            totp_secret_enc=encrypt_totp_secret(secret, _secret_key(request)),
            totp_last_step=step,
        )
        .execution_options(synchronize_session=False)
    )
    removed = db.execute(
        delete(Session).where(Session.id == sess.id).execution_options(synchronize_session=False)
    )
    if getattr(enrolled, "rowcount", 0) != 1 or getattr(removed, "rowcount", 0) != 1:
        db.rollback()
        return _see_other("/")
    token, _ = create_session(db, user, client_ip(request))
    db.commit()
    response = _see_other("/")
    set_cookie(response, SESSION_COOKIE, token)
    return response


# --- logout --------------------------------------------------------------------------


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
