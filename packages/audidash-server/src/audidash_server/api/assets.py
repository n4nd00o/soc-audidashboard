"""GET/POST /api/v1/assets (mTLS + bearer)."""

from __future__ import annotations

from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from audidash_server import audit, clock
from audidash_server.api.deps import Db, Principal, Writer
from audidash_server.models import Asset
from audidash_server.services.assets import AssetCreate

router = APIRouter(prefix="/api/v1/assets")


class AssetOut(BaseModel):
    id: str
    name: str
    address: str | None
    asset_type: TargetType
    criticality: Criticality


class AssetCreated(AssetOut):
    tags: list[str]


def _out(asset: Asset) -> AssetOut:
    return AssetOut(
        id=str(asset.id),
        name=asset.name,
        address=asset.address,
        asset_type=asset.asset_type,
        criticality=asset.criticality,
    )


@router.get("")
def list_assets(db: Db, _principal: Principal) -> list[AssetOut]:
    return [_out(a) for a in db.scalars(select(Asset).order_by(Asset.name))]


@router.post("", status_code=201)
def create_asset(
    body: AssetCreate,
    db: Db,
    principal: Writer,
) -> AssetCreated:
    if db.scalars(select(Asset.id).where(Asset.name == body.name)).first() is not None:
        raise HTTPException(status_code=409, detail="asset name already exists")
    asset = Asset(
        name=body.name,
        address=body.address,
        asset_type=body.asset_type,
        criticality=body.criticality,
        tags=list(body.tags),
        created_at=clock.now(),
    )
    db.add(asset)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()  # lost a race with a concurrent create of the same name
        raise HTTPException(status_code=409, detail="asset name already exists") from None
    audit.record(
        db,
        action="asset.create",
        actor_user_id=principal.user.id,
        actor_device_id=principal.device.id,
        target=asset.name,
        details={
            "asset_id": str(asset.id),
            "asset_type": str(asset.asset_type),
            "criticality": str(asset.criticality),
        },
    )
    db.commit()
    return AssetCreated(**_out(asset).model_dump(), tags=asset.tags)
