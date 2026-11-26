"""API dependencies: CA access, device identity via the proxy (mTLS) and bearer tokens.

The API never looks at the dashboard session cookie.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from audidash_server import clock
from audidash_server.ca import CA, load_or_create_ca
from audidash_server.db import get_session
from audidash_server.models import ApiToken, Device, Role, User
from audidash_server.proxy import (
    CLIENT_CERT_HEADER,
    client_ip,
    normalize_fingerprint,
    proxy_secret_valid,
)
from audidash_server.settings import Settings

__all__ = [
    "ApiPrincipal",
    "ClientDevice",
    "Db",
    "Principal",
    "api_principal",
    "client_device",
    "client_ip",
    "get_ca",
    "Writer",
    "require_api_role",
]

Db = Annotated[DbSession, Depends(get_session)]
_ca_lock = threading.Lock()


def get_ca(request: Request) -> CA:
    """The app's CA, loaded (or created) from `data_dir` on first use."""
    state = request.app.state
    with _ca_lock:
        ca: CA | None = getattr(state, "ca", None)
        if ca is None:
            settings: Settings = state.settings
            ca = load_or_create_ca(settings.data_dir, settings.ca_passphrase)
            state.ca = ca
    return ca


def _unauthorized(detail: str, *, bearer: bool = False) -> HTTPException:
    headers = {"WWW-Authenticate": "Bearer"} if bearer else None
    return HTTPException(status_code=401, detail=detail, headers=headers)


def client_device(request: Request, db: Db) -> Device:
    """Enrolled, non-revoked, unexpired device whose certificate the proxy verified."""
    if not proxy_secret_valid(request):
        raise _unauthorized("client certificate required")
    fingerprint = normalize_fingerprint(request.headers.get(CLIENT_CERT_HEADER))
    if fingerprint is None:
        raise _unauthorized("client certificate required")
    device = db.scalars(select(Device).where(Device.cert_fingerprint == fingerprint)).first()
    now = clock.now()
    if (
        device is None
        or device.revoked_at is not None
        or device.cert_not_after is None
        or device.cert_not_after <= now
    ):
        raise _unauthorized("client certificate required")
    return device


ClientDevice = Annotated[Device, Depends(client_device)]


@dataclass(frozen=True)
class ApiPrincipal:
    user: User
    device: Device


def api_principal(request: Request, db: Db, device: ClientDevice) -> ApiPrincipal:
    """User behind a valid bearer token issued to this very device."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _unauthorized("bearer token required", bearer=True)
    digest = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
    row = db.scalars(select(ApiToken).where(ApiToken.token_sha256 == digest)).first()
    if row is None or row.device_id != device.id or row.expires_at <= clock.now():
        raise _unauthorized("invalid or expired token", bearer=True)
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        raise _unauthorized("invalid or expired token", bearer=True)
    return ApiPrincipal(user=user, device=device)


Principal = Annotated[ApiPrincipal, Depends(api_principal)]


def require_api_role(*roles: Role) -> Any:
    """Dependency marker: the bearer's user must hold one of `roles`, else 403."""
    if not roles:
        raise ValueError("require_api_role needs at least one role")
    allowed = frozenset(roles)

    def _check(principal: Principal) -> ApiPrincipal:
        if principal.user.role not in allowed:
            raise HTTPException(status_code=403, detail="Forbidden")
        return principal

    return Depends(_check)


# Bearer principal allowed to change data (assets, runs).
Writer = Annotated[ApiPrincipal, require_api_role(Role.admin, Role.analyst)]
