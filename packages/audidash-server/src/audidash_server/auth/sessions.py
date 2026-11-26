"""Server-side dashboard sessions: opaque cookie token, SHA-256 at rest, idle/absolute timeouts."""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession
from starlette.responses import Response

from audidash_server import clock
from audidash_server.db import get_session
from audidash_server.models import Session, User
from audidash_server.settings import Settings

SESSION_COOKIE = "__Host-audidash_session"
COOKIE_ATTRS = "HttpOnly; Secure; SameSite=Strict; Path=/"
PENDING_MAX_AGE = timedelta(minutes=10)  # time allowed to finish first-login TOTP enrolment


class NotAuthenticated(Exception):
    """No valid full session; rendered as 303 /login (HTML) or 401 (HTMX/JSON)."""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def set_cookie(response: Response, name: str, value: str) -> None:
    """Session-lifetime cookie with the exact attributes required by the spec."""
    response.headers.append("set-cookie", f"{name}={value}; {COOKIE_ATTRS}")


def clear_cookie(response: Response, name: str) -> None:
    response.headers.append("set-cookie", f"{name}=; Max-Age=0; {COOKIE_ATTRS}")


def create_session(
    db: DbSession, user: User, ip: str | None, *, pending: bool = False
) -> tuple[str, Session]:
    """Add a new session row (caller commits) and return (cookie token, row)."""
    token = secrets.token_urlsafe(32)
    now = clock.now()
    row = Session(
        user_id=user.id,
        token_sha256=token_hash(token),
        mfa_pending=pending,
        created_at=now,
        last_seen_at=now,
        csrf_token=secrets.token_urlsafe(32),
        ip=ip,
    )
    db.add(row)
    return token, row


def delete_session_by_token(db: DbSession, token: str | None) -> None:
    """Delete the row for `token` if any (caller commits). Used for rotation and logout."""
    if token:
        db.execute(delete(Session).where(Session.token_sha256 == token_hash(token)))


def load_session(db: DbSession, token: str, settings: Settings) -> Session | None:
    """Return the live session for `token`, deleting it if expired; refreshes last_seen_at.

    Commits (expiry delete or last_seen update) before returning, so this must run before the
    handler does any writes of its own.
    """
    row = db.scalars(select(Session).where(Session.token_sha256 == token_hash(token))).first()
    if row is None:
        return None
    now = clock.now()
    idle = timedelta(minutes=settings.session_idle_minutes)
    absolute = timedelta(hours=settings.session_absolute_hours)
    expired = now - row.last_seen_at > idle or now - row.created_at > absolute
    if row.mfa_pending and now - row.created_at > PENDING_MAX_AGE:
        expired = True
    if expired:
        db.delete(row)
        db.commit()
        return None
    row.last_seen_at = now
    db.commit()
    return row


def client_ip(request: Request) -> str | None:
    """Peer address as seen by the app (the reverse proxy's, unless it forwards the client)."""
    return request.client.host if request.client else None


def _load(request: Request, db: DbSession) -> tuple[Session, User] | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    settings: Settings = request.app.state.settings
    row = load_session(db, token, settings)
    if row is None:
        return None
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    return row, user


def current_session(request: Request, db: Annotated[DbSession, Depends(get_session)]) -> Session:
    """Full (MFA-complete) session for this request, else NotAuthenticated."""
    loaded = _load(request, db)
    if loaded is None or loaded[0].mfa_pending:
        raise NotAuthenticated
    request.state.user = loaded[1]
    return loaded[0]


def current_user(request: Request, _sess: Annotated[Session, Depends(current_session)]) -> User:
    user: User = request.state.user
    return user


def pending_session(request: Request, db: DbSession) -> tuple[Session, User] | None:
    """The first-login (TOTP enrolment) session, if this request carries one."""
    loaded = _load(request, db)
    if loaded is None or not loaded[0].mfa_pending or loaded[1].totp_secret_enc is not None:
        return None
    return loaded


async def not_authenticated_handler(request: Request, exc: Exception) -> Response:
    response: Response
    if request.headers.get("HX-Request"):
        response = Response(status_code=401, headers={"HX-Redirect": "/login"})
    elif "text/html" in request.headers.get("accept", ""):
        response = RedirectResponse("/login", status_code=303)
    else:
        response = JSONResponse({"detail": "Not authenticated"}, status_code=401)
    # The cookie is deliberately left alone: it may belong to a pending (TOTP enrolment)
    # session that must survive a stray request to a protected page.
    return response
