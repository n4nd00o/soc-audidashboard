import pytest
from audidash_core.findings import Category, FindingStatus, Severity
from audidash_core.scoring import (
    Band,
    Criticality,
    ScoredFinding,
    asset_score,
    band,
    finding_weight,
    global_score,
)


def sf(
    severity: Severity,
    category: Category = Category.misconfiguration,
    status: FindingStatus = FindingStatus.open,
) -> ScoredFinding:
    return ScoredFinding(severity=severity, category=category, status=status)


def test_empty_asset_is_zero() -> None:
    assert asset_score([], Criticality.medium) == 0.0


def test_single_critical_medium_asset() -> None:
    score = asset_score([sf(Severity.critical)], Criticality.medium)
    assert score == 39.35
    assert band(39.35) is Band.moderate


def test_suspicious_multiplier() -> None:
    f = sf(Severity.high, Category.suspicious)
    assert finding_weight(f) == 10.5
    assert asset_score([f], Criticality.high) == 54.5


def test_acknowledged_counts() -> None:
    f = sf(Severity.critical, status=FindingStatus.acknowledged)
    assert asset_score([f], Criticality.medium) == 39.35


@pytest.mark.parametrize(
    "status",
    [
        FindingStatus.resolved,
        FindingStatus.false_positive,
        FindingStatus.accepted_risk,
        FindingStatus.auto_resolved,
    ],
)
def test_resolved_not_counted(status: FindingStatus) -> None:
    assert asset_score([sf(Severity.critical, status=status)], Criticality.high) == 0.0


def test_saturates_below_100() -> None:
    many = [sf(Severity.critical)] * 50
    high = asset_score(many, Criticality.high)
    assert 99.9 <= high <= 100.0
    low = asset_score([sf(Severity.critical)] * 3, Criticality.low)
    assert 0.0 < low < 100.0


def test_invalid_k_raises() -> None:
    with pytest.raises(ValueError):
        asset_score([], Criticality.low, k=0)
    with pytest.raises(ValueError):
        asset_score([], Criticality.low, k=-1.0)


def test_global_weighted() -> None:
    assert global_score([(80.0, Criticality.high), (20.0, Criticality.low)]) == 65.0


def test_global_empty_is_zero() -> None:
    assert global_score([]) == 0.0


def test_band_edges() -> None:
    assert band(24.99) is Band.low
    assert band(25) is Band.moderate
    assert band(50) is Band.high
    assert band(75) is Band.critical
