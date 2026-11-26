"""CSRF: per-session synchronizer token, plus a signed double-submit cookie for the login form."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from starlette.responses import Response

from audidash_server.auth.sessions import current_session, set_cookie
from audidash_server.models import Session
from audidash_server.settings import Settings

CSRF_FIELD = "csrf_token"
CSRF_HEADER = "HX-CSRF-Token"
LOGIN_CSRF_COOKIE = "__Host-audidash_login_csrf"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def tokens_equal(expected: str, provided: str | None) -> bool:
    """Constant-time comparison; False for a missing value."""
    if not provided:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


async def submitted_token(request: Request) -> str | None:
    """Token from the HTMX header, else from the form field."""
    header = request.headers.get(CSRF_HEADER)
    if header:
        return header
    value = (await request.form()).get(CSRF_FIELD)
    return value if isinstance(value, str) else None


async def csrf_protect(
    request: Request, sess: Annotated[Session, Depends(current_session)]
) -> None:
    """Reject state-changing requests whose token does not match the session's (403)."""
    if request.method in _SAFE_METHODS:
        return
    if not tokens_equal(sess.csrf_token, await submitted_token(request)):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


# --- login form (no session yet): signed double-submit cookie --------------------------


def _login_key(settings: Settings) -> bytes:
    return hmac.new(
        settings.secret_key.get_secret_value().encode("utf-8"),
        b"audidash-login-csrf",
        hashlib.sha256,
    ).digest()


def _sign(settings: Settings, nonce: str) -> str:
    return hmac.new(_login_key(settings), nonce.encode("ascii"), hashlib.sha256).hexdigest()


def _valid_login_token(settings: Settings, token: str | None) -> str | None:
    """Return the token if it is `nonce.hmac(nonce)` under this server's key, else None."""
    if not token or "." not in token:
        return None
    nonce, _, sig = token.partition(".")
    if not nonce.isascii():
        return None
    return token if tokens_equal(_sign(settings, nonce), sig) else None


def login_csrf_token(request: Request) -> str:
    """Valid token from the login-CSRF cookie, or a freshly signed one."""
    settings: Settings = request.app.state.settings
    existing = _valid_login_token(settings, request.cookies.get(LOGIN_CSRF_COOKIE))
    if existing:
        return existing
    nonce = secrets.token_urlsafe(32)
    return f"{nonce}.{_sign(settings, nonce)}"


def set_login_csrf_cookie(response: Response, token: str) -> None:
    set_cookie(response, LOGIN_CSRF_COOKIE, token)


def check_login_csrf(request: Request, form_token: str | None) -> bool:
    """Cookie must carry a valid signature and equal the submitted form field."""
    settings: Settings = request.app.state.settings
    cookie = _valid_login_token(settings, request.cookies.get(LOGIN_CSRF_COOKIE))
    return cookie is not None and tokens_equal(cookie, form_token)
