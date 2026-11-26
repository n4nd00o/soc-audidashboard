"""Client-side redaction of secrets and personal data (LGPD) from findings."""

import re

from audidash_core.findings import Finding

MAX_EVIDENCE_CHARS = 2000
_TRUNCATED_SUFFIX = "…[truncated]"
_MAX_TITLE_CHARS = 200
_EMPTY_TITLE = "(untitled)"
_INPUT_MARGIN = 2
# Between a secret's key and its value: optional closing quote (JSON), then = or :.
# Values already redacted are left alone so earlier, more specific tokens survive.
_SEPARATOR = r"""(["']?\s*[=:]\s*)(?!\[REDACTED:)"""
# A quoted secret value is redacted whole; each rule appends its unquoted alternatives.
_QUOTED = r"""(?:"[^"\r\n]{0,1024}"|'[^'\r\n]{0,1024}'"""

# (pattern, replacement) applied in order; private keys first so their body
# is not partially matched by later patterns.
_RULES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            # Unterminated blocks (e.g. truncated output) are redacted to the end.
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
        "[REDACTED:private_key]",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_access_key]"),
    (
        re.compile(r"aws_secret_access_key\s*[=:]\s*\S+", re.IGNORECASE),
        "[REDACTED:aws_secret]",
    ),
    # URI userinfo: scheme://user:password@host (user may be empty: redis://:pw@host).
    (
        re.compile(r"(?<=[A-Za-z0-9])(://[^:/@\s]{0,256}):[^@\s/]{1,1024}@"),
        r"\1:[REDACTED:password]@",
    ),
    # Well-known token formats (GitHub, Slack, Stripe).
    (
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{8,255}|github_pat_[A-Za-z0-9_]{8,255}"
            r"|xox[baprs]-[A-Za-z0-9-]{8,255}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,255})"
        ),
        "[REDACTED:token]",
    ),
    # Passwords: quoted values whole, ";"-terminated (connection strings) up to ";".
    (
        re.compile(
            r"(?<![A-Za-z0-9])(password|passwd|pwd)"
            + _SEPARATOR
            + _QUOTED
            + r"""|[^;\s"'][^;\r\n"']{0,255}(?=;)|[^;\s]+)""",
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED:password]",
    ),
    # Generic key=value / key: value secrets (query strings, env files, JSON).
    (
        re.compile(
            r"(?<![A-Za-z0-9])(access[_-]?token|refresh[_-]?token|client[_-]?secret"
            r"|api[_-]?key|token|secret)" + _SEPARATOR + _QUOTED + r"""|[^&;\s"']+)""",
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED:token]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{1,2000}\.[A-Za-z0-9_-]{1,2000}\.[A-Za-z0-9_-]{1,2000}"),
        "[REDACTED:jwt]",
    ),
    (
        re.compile(r"\b(AccountKey|SharedAccessKey)=[^;\s]+", re.IGNORECASE),
        r"\1=[REDACTED:azure_key]",
    ),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE), "[REDACTED:bearer]"),
    # CPF: punctuated, or a standalone 11-digit token (not inside longer digit runs).
    (re.compile(r"(?<![0-9])[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}(?![0-9])"), "[REDACTED:cpf]"),
    (re.compile(r"\b[0-9]{11}\b"), "[REDACTED:cpf]"),
    (
        re.compile(
            r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}"
        ),
        "[REDACTED:email]",
    ),
    # Brazilian phones: "(11) 98765-4321" or "+55 11 987654321".
    (re.compile(r"\([0-9]{2}\)\s?9?[0-9]{4}-?[0-9]{4}(?![0-9])"), "[REDACTED:phone]"),
    (re.compile(r"\+55\s?[0-9]{2}\s?9?[0-9]{4}-?[0-9]{4}(?![0-9])"), "[REDACTED:phone]"),
]


def strip_nul(text: str) -> str:
    """Drop NUL (0x00): servers storing findings in PostgreSQL text columns reject it."""
    return text.replace("\x00", "")


def redact(text: str) -> str:
    """Replace secrets and personal data in ``text`` with ``[REDACTED:<kind>]``.

    NUL characters are stripped first, so every redacted string is also NUL-free.
    """
    text = strip_nul(text)
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def _bounded(text: str, limit: int) -> str:
    """Cap ``text`` before redaction so regex work stays bounded.

    When cut, the trailing partial token is dropped so a secret straddling the
    cut cannot leak a prefix. Unterminated private-key blocks are handled by
    the redaction rule itself (redacted to end of string).
    """
    cap = limit * _INPUT_MARGIN
    if len(text) <= cap:
        return text
    text = text[:cap]
    cut = max(text.rfind(c) for c in (" ", chr(9), chr(10), chr(13)))
    return text[:cut] if cut > 0 else text


def redact_capped(text: str, limit: int) -> str:
    """Redact ``text`` with bounded work, truncating the result to ``limit`` chars."""
    redacted = redact(_bounded(text, limit))
    if len(redacted) > limit or len(text) > limit * _INPUT_MARGIN:
        redacted = redacted[:limit] + _TRUNCATED_SUFFIX
    return redacted


def sanitize_finding(f: Finding) -> Finding:
    """Return a copy of ``f`` with text fields redacted and NUL-free; ``target`` is left intact."""
    title = redact(_bounded(f.title, _MAX_TITLE_CHARS))[:_MAX_TITLE_CHARS]
    return f.model_copy(
        update={
            "title": title or _EMPTY_TITLE,  # a NUL-only title must stay a valid Finding
            "evidence": redact_capped(f.evidence, MAX_EVIDENCE_CHARS),
            "recommendation": redact_capped(f.recommendation, MAX_EVIDENCE_CHARS),
            "references": [strip_nul(r) for r in f.references],
            "item_key": None if f.item_key is None else strip_nul(f.item_key),
        }
    )
