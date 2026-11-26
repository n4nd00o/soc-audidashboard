"""POST /api/v1/auth/token: CLI login over mTLS, yielding a short-lived device-bound token.

Uses the same credential check as the dashboard (`auth.service.authenticate`) plus the shared
per-IP login rate limiter; TOTP is mandatory here (no first-login enrolment over the API).
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete

from audidash_server import clock
from audidash_server.api.deps import ClientDevice, Db
from audidash_server.auth import service
from audidash_server.auth.ratelimit import LoginRateLimiter
from audidash_server.models import ApiToken
from audidash_server.proxy import client_ip
from audidash_server.services.enrollment import token_sha256
from audidash_server.settings import Settings

router = APIRouter(prefix="/api/v1/auth")

API_TOKEN_TTL = timedelta(minutes=15)


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(max_length=256)
    password: str = Field(max_length=1024)
    totp: str = Field(max_length=16)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_at: datetime


@router.post("/token")
def issue_token(
    body: TokenRequest, request: Request, db: Db, device: ClientDevice
) -> TokenResponse:
    limiter: LoginRateLimiter = request.app.state.login_limiter
    if not limiter.hit(client_ip(request) or "unknown"):
        raise HTTPException(status_code=429, detail="too many login attempts")
    settings: Settings = request.app.state.settings
    result = service.authenticate(
        db,
        username=body.username,
        password=body.password,
        totp_code=body.totp,
        secret_key=settings.secret_key.get_secret_value(),
        actor_device_id=device.id,
        require_totp=True,
    )
    if result.outcome is service.LoginOutcome.totp_not_enrolled:
        raise HTTPException(
            status_code=403, detail="complete TOTP enrolment in the dashboard first"
        )
    if result.outcome is not service.LoginOutcome.ok or result.user is None:
        raise HTTPException(
            status_code=401, detail="invalid credentials", headers={"WWW-Authenticate": "Bearer"}
        )
    now = clock.now()
    db.execute(delete(ApiToken).where(ApiToken.expires_at <= now))  # housekeeping
    token = secrets.token_urlsafe(32)
    expires_at = now + API_TOKEN_TTL
    db.add(
        ApiToken(
            token_sha256=token_sha256(token),
            user_id=result.user.id,
            device_id=device.id,
            expires_at=expires_at,
        )
    )
    db.commit()
    return TokenResponse(access_token=token, expires_at=expires_at)
