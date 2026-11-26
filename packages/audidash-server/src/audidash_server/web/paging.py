"""Shared pagination helpers for the admin pages (50 rows per page)."""

from __future__ import annotations

PAGE_SIZE = 50
_MAX_PAGE = 100_000


def parse_page(raw: str | None) -> int:
    try:
        return min(max(1, int(raw or "1")), _MAX_PAGE)
    except ValueError:
        return 1


def page_count(total: int) -> int:
    return max(1, -(-total // PAGE_SIZE))
