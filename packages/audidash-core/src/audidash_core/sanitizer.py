"""Client-side redaction of secrets and personal data (LGPD) from findings."""

import re

from audidash_core.findings import Finding

MAX_EVIDENCE_CHARS = 2000
_TRUNCATED_SUFFIX = "…[truncated]"
_MAX_TITLE_CHARS = 200

# (pattern, replacement) applied in order; private keys first so their body
# is not partially matched by later patterns.
_RULES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED:private_key]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_access_key]"),
    (
        re.compile(r"aws_secret_access_key\s*[=:]\s*\S+", re.IGNORECASE),
        "[REDACTED:aws_secret]",
    ),
    (
        re.compile(r"\b(password|passwd|pwd)(\s*[=:]\s*)[^;\s]+", re.IGNORECASE),
        r"\1\2[REDACTED:password]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "[REDACTED:jwt]",
    ),
    (
        re.compile(r"\b(AccountKey|SharedAccessKey)=[^;\s]+", re.IGNORECASE),
        r"\1=[REDACTED:azure_key]",
    ),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE), "[REDACTED:bearer]"),
    # CPF: punctuated, or a standalone 11-digit token (not inside longer digit runs).
    (re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)"), "[REDACTED:cpf]"),
    (re.compile(r"\b\d{11}\b"), "[REDACTED:cpf]"),
    (
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
        "[REDACTED:email]",
    ),
    # Brazilian phones: "(11) 98765-4321" or "+55 11 987654321".
    (re.compile(r"\(\d{2}\)\s?9?\d{4}-?\d{4}(?!\d)"), "[REDACTED:phone]"),
    (re.compile(r"\+55\s?\d{2}\s?9?\d{4}-?\d{4}(?!\d)"), "[REDACTED:phone]"),
]


def redact(text: str) -> str:
    """Replace secrets and personal data in ``text`` with ``[REDACTED:<kind>]``."""
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def sanitize_finding(f: Finding) -> Finding:
    """Return a copy of ``f`` with text fields redacted; ``target`` is left intact."""
    evidence = redact(f.evidence)
    if len(evidence) > MAX_EVIDENCE_CHARS:
        evidence = evidence[:MAX_EVIDENCE_CHARS] + _TRUNCATED_SUFFIX
    return f.model_copy(
        update={
            "title": redact(f.title)[:_MAX_TITLE_CHARS],
            "evidence": evidence,
            "recommendation": redact(f.recommendation),
        }
    )
