"""Finding schema shared by plugins, runner, storage and dashboard."""

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Category(StrEnum):
    misconfiguration = "misconfiguration"
    vulnerability = "vulnerability"
    suspicious = "suspicious"
    compliance = "compliance"


class FindingStatus(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    auto_resolved = "auto_resolved"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_-]{1,63}$")
    title: str = Field(min_length=1, max_length=200)
    severity: Severity
    category: Category
    target: str = Field(min_length=1, max_length=255)
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = []
    item_key: str | None = None


class PluginOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[Finding]
    warnings: list[str] = []


def fingerprint(plugin_id: str, finding_id: str, asset_id: str, item_key: str | None = None) -> str:
    """Stable identity of a finding across runs (sha256 hex)."""
    raw = "\x1f".join([plugin_id, finding_id, asset_id, item_key or ""])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
