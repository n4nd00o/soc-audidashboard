"""Threat scoring: 0-100 score per asset and globally."""

import math
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from audidash_core.findings import Category, FindingStatus, Severity


class Criticality(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"


class Band(StrEnum):
    low = "low"
    moderate = "moderate"
    high = "high"
    critical = "critical"


@dataclass(frozen=True)
class ScoredFinding:
    severity: Severity
    category: Category
    status: FindingStatus


_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.info: 0.0,
    Severity.low: 1.0,
    Severity.medium: 3.0,
    Severity.high: 7.0,
    Severity.critical: 10.0,
}
_CRITICALITY_WEIGHT: dict[Criticality, float] = {
    Criticality.low: 0.5,
    Criticality.medium: 1.0,
    Criticality.high: 1.5,
}
_SUSPICIOUS_MULTIPLIER = 1.5
_COUNTED_STATUSES = frozenset({FindingStatus.open, FindingStatus.acknowledged})


def finding_weight(f: ScoredFinding) -> float:
    """Weight of one finding; zero unless its status is open or acknowledged."""
    if f.status not in _COUNTED_STATUSES:
        return 0.0
    weight = _SEVERITY_WEIGHT[f.severity]
    if f.category is Category.suspicious:
        weight *= _SUSPICIOUS_MULTIPLIER
    return weight


def asset_score(
    findings: Iterable[ScoredFinding], criticality: Criticality, k: float = 20.0
) -> float:
    """Saturating score in [0, 100]: 100 * (1 - exp(-sum/k)), rounded to 2 decimals."""
    if k <= 0:
        raise ValueError("k must be positive")
    total = sum(finding_weight(f) for f in findings) * _CRITICALITY_WEIGHT[criticality]
    return round(100.0 * (1.0 - math.exp(-total / k)), 2)


def global_score(assets: Iterable[tuple[float, Criticality]]) -> float:
    """Criticality-weighted mean of asset scores; 0.0 when there is no weight."""
    weighted = 0.0
    total_weight = 0.0
    for score, criticality in assets:
        w = _CRITICALITY_WEIGHT[criticality]
        weighted += score * w
        total_weight += w
    if total_weight == 0:
        return 0.0
    return round(weighted / total_weight, 2)


def band(score: float) -> Band:
    if score < 25:
        return Band.low
    if score < 50:
        return Band.moderate
    if score < 75:
        return Band.high
    return Band.critical
