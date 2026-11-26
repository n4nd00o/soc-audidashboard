"""Single source of "now" so tests can freeze time by monkeypatching `clock.now`.

Callers must use `clock.now()` via the module (not `from ... import now`) for patching to work.
"""

from __future__ import annotations

from datetime import UTC, datetime


def now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)
