"""Devices page queries and the copy-ready enrolment command."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import aliased

from audidash_server import clock
from audidash_server.models import Device, EnrollmentToken, User

API_PORT = 9443
TOKEN_LIST_LIMIT = 100
DEVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,127}")  # same alphabet the CLI sanitizes to


@dataclass(frozen=True)
class DeviceRow:
    id: uuid.UUID
    name: str
    owner: str | None
    created_at: datetime
    cert_not_after: datetime | None
    revoked_at: datetime | None
    state: str  # active | revoked | expired


@dataclass(frozen=True)
class TokenRow:
    id: uuid.UUID
    created_by: str | None
    expires_at: datetime
    used_at: datetime | None
    device_name: str | None
    status: str  # unused | used | expired


def list_devices(db: DbSession) -> list[DeviceRow]:
    now = clock.now()
    rows = db.execute(
        select(Device, User.username)
        .outerjoin(User, User.id == Device.owner_user_id)
        .order_by(Device.created_at.desc(), Device.id)
    ).all()
    result: list[DeviceRow] = []
    for device, owner in rows:
        if device.revoked_at is not None:
            state = "revoked"
        elif device.cert_not_after is None or device.cert_not_after <= now:
            state = "expired"
        else:
            state = "active"
        result.append(
            DeviceRow(
                id=device.id,
                name=device.name,
                owner=owner,
                created_at=device.created_at,
                cert_not_after=device.cert_not_after,
                revoked_at=device.revoked_at,
                state=state,
            )
        )
    return result


def list_tokens(db: DbSession) -> list[TokenRow]:
    """Newest first; never exposes the token (only its hash is stored)."""
    now = clock.now()
    creator = aliased(User)
    rows = db.execute(
        select(EnrollmentToken, creator.username, Device.name)
        .outerjoin(creator, creator.id == EnrollmentToken.created_by)
        .outerjoin(Device, Device.id == EnrollmentToken.device_id)
        .order_by(EnrollmentToken.expires_at.desc(), EnrollmentToken.id)
        .limit(TOKEN_LIST_LIMIT)
    ).all()
    result: list[TokenRow] = []
    for token, username, device_name in rows:
        if token.used_at is not None:
            status = "used"
        elif token.expires_at <= now:
            status = "expired"
        else:
            status = "unused"
        result.append(
            TokenRow(
                id=token.id,
                created_by=username,
                expires_at=token.expires_at,
                used_at=token.used_at,
                device_name=device_name,
                status=status,
            )
        )
    return result


def default_urls(base_url: str) -> tuple[str, str]:
    """(dashboard URL, API URL) derived from the request: same origin, API on port 9443."""
    parts = urlsplit(base_url)
    host = parts.hostname or "localhost"
    if ":" in host:
        host = f"[{host}]"  # IPv6 literal
    return f"{parts.scheme}://{parts.netloc}", f"{parts.scheme}://{host}:{API_PORT}"


def enroll_command(
    *, dashboard_url: str, api_url: str, token: str, name: str, ca_fingerprint: str
) -> str:
    """`audidash enroll ...` using --token=VALUE (a token may start with '-')."""
    quoted = f'"{name}"' if " " in name else name  # DEVICE_NAME allows no other shell syntax
    return (
        f"audidash enroll --server {dashboard_url} --api {api_url} --token={token} "
        f"--name {quoted} --ca-fingerprint {ca_fingerprint}"
    )
