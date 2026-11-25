"""Stdlib-only helpers for SOC AudiDashboard plugins.

This package must never import ``audidash_core`` or any third-party module: plugins run in an
isolated interpreter where only the standard library and this package are importable. The
runner remains the real validator of the output; this module only gives authors fast feedback.
"""

import json
import sys
from collections.abc import Callable
from typing import Any

__all__ = ["Reporter", "read_input", "run"]

_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_CATEGORIES = frozenset({"misconfiguration", "vulnerability", "suspicious", "compliance"})


def read_input() -> dict[str, Any]:
    """Read the run payload (``target``, ``target_type``, ``parameters``, ``credentials``)."""
    data = json.loads(sys.stdin.read())
    if not isinstance(data, dict):
        raise ValueError("input payload must be a JSON object")
    return data


class Reporter:
    """Collects findings and warnings and prints them as the plugin output JSON."""

    def __init__(self, target: str = "") -> None:
        self.target = target
        self._findings: list[dict[str, Any]] = []
        self._warnings: list[str] = []

    def add(
        self,
        id: str,  # noqa: A002 - mirrors the output schema field name
        title: str,
        severity: str,
        category: str,
        evidence: str = "",
        recommendation: str = "",
        references: list[str] | None = None,
        item_key: str | None = None,
    ) -> None:
        if severity not in _SEVERITIES:
            raise ValueError(
                f"unknown severity {severity!r}; expected one of {sorted(_SEVERITIES)}"
            )
        if category not in _CATEGORIES:
            raise ValueError(
                f"unknown category {category!r}; expected one of {sorted(_CATEGORIES)}"
            )
        self._findings.append(
            {
                "id": id,
                "title": title,
                "severity": severity,
                "category": category,
                "target": self.target,
                "evidence": evidence,
                "recommendation": recommendation,
                "references": list(references or []),
                "item_key": item_key,
            }
        )

    def warn(self, msg: str) -> None:
        self._warnings.append(msg)

    def emit(self) -> None:
        sys.stdout.write(json.dumps({"findings": self._findings, "warnings": self._warnings}))
        sys.stdout.flush()


def run(main: Callable[[dict[str, Any], Reporter], None]) -> None:
    """Read input, call ``main(input, reporter)`` and emit the result.

    An uncaught exception prints ``Type: message`` (never a traceback) to stderr and exits 1.
    """
    try:
        data = read_input()
        reporter = Reporter(str(data.get("target", "")))
        main(data, reporter)
        reporter.emit()
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
