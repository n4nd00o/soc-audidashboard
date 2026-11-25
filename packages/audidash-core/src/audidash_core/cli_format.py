"""Terminal formatting helpers for the ``audidash`` CLI."""

import re

from audidash_core.catalog import CatalogEntry
from audidash_core.findings import Finding, Severity

_SEVERITY_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")
_LINE_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")


def _escape(match: re.Match[str]) -> str:
    char = match.group()
    return f"\\x{ord(char):02x}" if ord(char) < 0x100 else f"\\u{ord(char):04x}"


def clean(text: str) -> str:
    """Escape control characters in multi-line text (newlines and tabs are kept)."""
    return _CONTROL_CHARS.sub(_escape, text)


def clean_line(text: str) -> str:
    """Escape control characters including newlines/tabs, for single-line fields."""
    return _LINE_CHARS.sub(_escape, text)


def table(headers: list[str], rows: list[list[str]]) -> str:
    """Plain fixed-width table (no third-party deps)."""
    cells = [[clean_line(c) for c in row] for row in rows]
    widths = [max([len(h), *(len(r[i]) for r in cells)]) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    lines.extend(
        "  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in cells
    )
    return "\n".join(lines)


def source_text(entry: CatalogEntry) -> str:
    """Full source of every file listed in the manifest (and only those)."""
    parts: list[str] = []
    for relative in sorted(entry.manifest.files):
        data = (entry.path / relative).read_bytes()
        parts.append(f"===== {clean_line(relative)} =====")
        text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
        parts.append(clean(text))
    return "\n".join(parts)


def summary(entry: CatalogEntry) -> str:
    """Manifest summary including permissions and parameters."""
    m = entry.manifest
    lines = [
        f"id:          {m.id}",
        f"name:        {clean_line(m.name)}",
        f"version:     {m.version}",
        f"trust:       {entry.trust.value}",
        f"author:      {clean_line(m.author)}",
        f"license:     {clean_line(m.license)}",
        f"runtime:     {m.runtime.value}",
        f"execution:   {m.execution.value}",
        f"connection:  {m.connection.value}",
        f"targets:     {', '.join(t.value for t in m.targets)}",
        f"description: {clean_line(m.description)}",
        "permissions:",
        *(f"  - {clean_line(p)}" for p in m.permissions),
    ]
    if m.parameters:
        lines.append("parameters:")
        lines.extend(
            f"  {clean_line(name)} ({spec.type}): {clean_line(spec.description)}"
            for name, spec in m.parameters.items()
        )
    return "\n".join(lines)


def findings_table(findings: list[Finding]) -> str:
    """Findings sorted by severity (critical first) then id."""
    ordered = sorted(findings, key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.id))
    rows = [[f.severity.value, f.id, f.category.value, f.title] for f in ordered]
    return table(["SEVERITY", "ID", "CATEGORY", "TITLE"], rows)
