"""Asset field validation shared by the mTLS API and the dashboard so the rules cannot drift."""

from __future__ import annotations

from typing import Annotated

from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality
from pydantic import BaseModel, ConfigDict, Field

NO_CONTROL = r"^[^\x00-\x1f\x7f-\x9f]+$"


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128, pattern=NO_CONTROL)
    address: str | None = Field(default=None, min_length=1, max_length=255, pattern=NO_CONTROL)
    asset_type: TargetType
    criticality: Criticality
    tags: list[Annotated[str, Field(min_length=1, max_length=64, pattern=NO_CONTROL)]] = Field(
        default=[], max_length=32
    )
