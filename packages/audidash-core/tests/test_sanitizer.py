import time

import pytest
from audidash_core.findings import Category, Finding, Severity
from audidash_core.sanitizer import MAX_EVIDENCE_CHARS, redact, sanitize_finding

SUFFIX = "…[truncated]"


@pytest.mark.parametrize(
    ("text", "token"),
    [
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
            "[REDACTED:private_key]",
        ),
        ("AKIAIOSFODNN7EXAMPLE", "[REDACTED:aws_access_key]"),
        (
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "[REDACTED:aws_secret]",
        ),
        ("Server=x;Password=Hunter2!;", "[REDACTED:password]"),
        ("password: hunter2", "[REDACTED:password]"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part-1", "[REDACTED:jwt]"),
        ("AccountKey=abc123+/==;", "[REDACTED:azure_key]"),
        ("Authorization: Bearer abc.def", "[REDACTED:bearer]"),
        ("123.456.789-09", "[REDACTED:cpf]"),
        ("12345678909", "[REDACTED:cpf]"),
        ("joao@empresa.com.br", "[REDACTED:email]"),
        ("(11) 98765-4321", "[REDACTED:phone]"),
        ("+55 11 987654321", "[REDACTED:phone]"),
    ],
)
def test_redacts(text: str, token: str) -> None:
    out = redact(text)
    assert token in out
    assert "abc\n" not in out
    for secret in ("Hunter2", "hunter2", "wJalr", "joao@", "98765", "987654321", "sig_part"):
        assert secret not in out


@pytest.mark.parametrize(
    "text",
    [
        "10.0.0.5:22",
        "OpenSSH_9.6p1 Ubuntu-3ubuntu13",
        "OpenSSH_8.9p1",
        "2026-11-25 10:00:01",
        "-rw-r--r-- 1 root root 4096",
        "id 123456789012345",
    ],
)
def test_does_not_redact_ordinary_evidence(text: str) -> None:
    assert redact(text) == text


def test_does_not_redact_ip_or_port() -> None:
    assert redact("10.0.0.5:22") == "10.0.0.5:22"


def _finding(**kw: str) -> Finding:
    base = {
        "id": "SSH-001",
        "title": "t",
        "severity": Severity.high,
        "category": Category.misconfiguration,
        "target": "joao@empresa.com.br",
    }
    return Finding.model_validate({**base, **kw})


def test_sanitizes_all_text_fields() -> None:
    f = sanitize_finding(
        _finding(title="leak AKIAIOSFODNN7EXAMPLE", recommendation="rotate password: hunter2")
    )
    assert "[REDACTED:aws_access_key]" in f.title
    assert "[REDACTED:password]" in f.recommendation
    assert f.target == "joao@empresa.com.br"


def test_title_stays_within_limit() -> None:
    f = sanitize_finding(_finding(title="a@b.co " * 28))
    assert len(f.title) == 200


def test_truncates_evidence() -> None:
    f = sanitize_finding(_finding(evidence="x" * 5000))
    assert len(f.evidence) <= MAX_EVIDENCE_CHARS + len(SUFFIX)
    assert f.evidence.endswith(SUFFIX)


def test_unterminated_private_key_is_redacted_to_end() -> None:
    out = redact("before" + chr(10) + "-----BEGIN RSA PRIVATE KEY-----" + chr(10) + "SECRETBODY")
    assert out == "before" + chr(10) + "[REDACTED:private_key]"


@pytest.mark.parametrize("unit", ["a", "1.", "a-", "a.", "eyJ", "a@b."])
def test_redact_is_fast_on_huge_input(unit: str) -> None:
    text = unit * (1_000_000 // len(unit))
    start = time.perf_counter()
    redact(text)
    sanitize_finding(_finding(evidence=text, recommendation=text, title=text[:200]))
    assert time.perf_counter() - start < 1.0


def test_secret_straddling_cap_does_not_leak() -> None:
    evidence = "x " * 2000 + "AKIAIOSFODNN7EXAMPLE" + " y" * 5000
    out = sanitize_finding(_finding(evidence=evidence)).evidence
    assert "AKIA" not in out
    cut = "x " * 1999 + "password=" + "hunter2" * 2000
    assert "hunter2" not in sanitize_finding(_finding(evidence=cut)).evidence


GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "postgres://admin:S3cretPass@db:5432/app",
            "postgres://admin:[REDACTED:password]@db:5432/app",
        ),
        ("redis://:hunter2pw@cache:6379/0", "redis://:[REDACTED:password]@cache:6379/0"),
        (f"token={GH_TOKEN}", "token=[REDACTED:token]"),
        ("api_key=sk_live_51Habcdefghijkl", "api_key=[REDACTED:token]"),
        (
            "https://x.example/cb?access_token=xyz&state=1",
            "https://x.example/cb?access_token=[REDACTED:token]&state=1",
        ),
        ("?token=abc&state=keep;", "?token=[REDACTED:token]&state=keep;"),
        ('password = "correct horse battery"', "password = [REDACTED:password]"),
        ("Password=p@ss word;Server=x", "Password=[REDACTED:password];Server=x"),
        ("client_secret: 'a b c' next", "client_secret: [REDACTED:token] next"),
        ("refresh-token=abc123;", "refresh-token=[REDACTED:token];"),
        ("X-Api-Key: k3y-value", "X-Api-Key: [REDACTED:token]"),
        ('{"secret": "s3cr3t"}', '{"secret": [REDACTED:token]}'),
        ("db_password=hunter2", "db_password=[REDACTED:password]"),
        (f"leaked {GH_TOKEN} here", "leaked [REDACTED:token] here"),
        ("gho_abcdefghij1234567890", "[REDACTED:token]"),
        ("ghs_abcdefghij1234567890", "[REDACTED:token]"),
        ("github_pat_11ABCDEFG0123456789_abcdefXYZ", "[REDACTED:token]"),
        ("slack xoxb-1234567890-abcdefghij", "slack [REDACTED:token]"),
        ("xoxp-1234567890-abcdefghij", "[REDACTED:token]"),
        ("sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc", "[REDACTED:token]"),
        ("rk_" + "live_4eC39HqLyjWDarjtT1zdp7dc", "[REDACTED:token]"),
    ],
)
def test_redacts_spec_secret_shapes(text: str, expected: str) -> None:
    assert redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "https://github.com/org/repo",
        "http://example.com:8080/path@v2",
        "the token expired yesterday",
        "secret scanning is enabled",
        "Server=x;Password=[REDACTED:password];",
        "AccountKey=[REDACTED:azure_key];",
    ],
)
def test_new_rules_have_no_false_positives(text: str) -> None:
    assert redact(text) == text


@pytest.mark.parametrize("unit", ["://", "a:", "token=", "password=", "ghp_", "x@", "=;"])
def test_new_rules_are_fast_on_huge_input(unit: str) -> None:
    text = unit * (1_000_000 // len(unit))
    start = time.perf_counter()
    redact(text)
    assert time.perf_counter() - start < 1.0


def test_password_rule_fast_on_whitespace() -> None:
    start = time.perf_counter()
    redact("password=" + " " * 1_000_000)
    assert time.perf_counter() - start < 1.0
