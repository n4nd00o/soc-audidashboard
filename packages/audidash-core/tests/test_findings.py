import pytest
from audidash_core.findings import Finding, Severity, fingerprint
from pydantic import ValidationError

SPEC_FINDING = {
    "id": "SSH-001",
    "title": "Login root via SSH habilitado",
    "severity": "high",
    "category": "misconfiguration",
    "target": "srv01",
    "evidence": "PermitRootLogin yes",
    "recommendation": "Definir PermitRootLogin no",
    "references": ["CIS 5.2.10", "ISO27002:2022 8.5"],
}


def test_parses_valid_finding() -> None:
    finding = Finding.model_validate(SPEC_FINDING)
    assert finding.severity is Severity.high
    assert finding.references == ["CIS 5.2.10", "ISO27002:2022 8.5"]


def test_rejects_unknown_severity() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({**SPEC_FINDING, "severity": "urgent"})


def test_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({**SPEC_FINDING, "trust": "official"})


@pytest.mark.parametrize(
    "extra",
    [
        {"item_key": "k" * 256},
        {"references": ["r" * 201]},
        {"references": ["r"] * 51},
    ],
)
def test_rejects_oversized_item_key_and_references(extra: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate({**SPEC_FINDING, **extra})


def test_accepts_item_key_and_references_at_limits() -> None:
    finding = Finding.model_validate(
        {**SPEC_FINDING, "item_key": "k" * 255, "references": ["r" * 200] * 50}
    )
    assert finding.item_key is not None and len(finding.item_key) == 255


def test_fingerprint_stable_and_distinct() -> None:
    a = fingerprint("ssh", "SSH-001", "asset1")
    assert a == fingerprint("ssh", "SSH-001", "asset1")
    assert len(a) == 64
    alice = fingerprint("ssh", "SSH-001", "asset1", "alice")
    bob = fingerprint("ssh", "SSH-001", "asset1", "bob")
    assert alice != bob
