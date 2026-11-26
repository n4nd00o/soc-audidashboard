"""NUL (0x00) guards for untrusted text: PostgreSQL text columns cannot store it (psycopg raises).

Every boundary that can carry user- or device-supplied text into a query rejects or drops NUL
before the database is reached, so the failure is a normal 4xx (or an ignored filter), never
a 500.
"""

from __future__ import annotations

from collections.abc import Mapping

NUL = "\x00"


def nul_path(value: object, path: str = "") -> str | None:
    """Dotted path of the first string (value or mapping key) containing NUL, else None."""
    if isinstance(value, str):
        return path if NUL in value else None
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and NUL in key:
                return child
            found = nul_path(item, child)
            if found is not None:
                return found
        return None
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found = nul_path(item, f"{path}.{index}" if path else str(index))
            if found is not None:
                return found
    return None


def filter_text(raw: str | None, limit: int = 128) -> str:
    """Query-string filter value: dropped entirely (no filter) when it contains NUL."""
    if not raw or NUL in raw:
        return ""
    return raw[:limit]


def without_nul(text: str) -> str:
    """Copy safe to echo back into a re-rendered form."""
    return text.replace(NUL, "")
