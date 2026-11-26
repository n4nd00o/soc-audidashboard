"""GET /api/v1/verified: the allowlist of manifest hashes an admin has verified (mTLS + bearer)."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import select

from audidash_server.api.deps import Db, Principal
from audidash_server.models import VerifiedPlugin

router = APIRouter(prefix="/api/v1/verified")


class VerifiedOut(BaseModel):
    manifest_sha256: list[str]


@router.get("")
def list_verified(db: Db, _principal: Principal) -> VerifiedOut:
    query = select(VerifiedPlugin.manifest_sha256).order_by(VerifiedPlugin.manifest_sha256)
    return VerifiedOut(manifest_sha256=list(db.scalars(query)))
