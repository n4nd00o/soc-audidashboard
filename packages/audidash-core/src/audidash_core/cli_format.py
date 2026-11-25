"""Terminal formatting helpers for the ``audidash`` CLI."""

import re

from audidash_core.catalog import CatalogEntry
from audidash_core.findings import Finding, Severity

_SEVERITY_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(text: str) -> str:
    """Make untrusted text safe for a terminal: show control characters, never emit them."""
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def table(headers: list[str], rows: list[list[str]]) -> str:
    """Plain fixed-width table (no third-party deps)."""
    cells = [[clean(c) for c in row] for row in rows]
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
        parts.append(f"===== {clean(relative)} =====")
        text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
        parts.append(clean(text))
    return "\n".join(parts)


def summary(entry: CatalogEntry) -> str:
    """Manifest summary including permissions and parameters."""
    m = entry.manifest
    lines = [
        f"id:          {m.id}",
        f"name:        {clean(m.name)}",
        f"version:     {m.version}",
        f"trust:       {entry.trust.value}",
        f"author:      {clean(m.author)}",
        f"license:     {clean(m.license)}",
        f"runtime:     {m.runtime.value}",
        f"execution:   {m.execution.value}",
        f"connection:  {m.connection.value}",
        f"targets:     {', '.join(t.value for t in m.targets)}",
        f"description: {clean(m.description)}",
        "permissions:",
        *(f"  - {clean(p)}" for p in m.permissions),
    ]
    if m.parameters:
        lines.append("parameters:")
        lines.extend(
            f"  {name} ({spec.type}): {clean(spec.description)}"
            for name, spec in m.parameters.items()
        )
    return "\n".join(lines)


def findings_table(findings: list[Finding]) -> str:
    """Findings sorted by severity (critical first) then id."""
    ordered = sorted(findings, key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.id))
    rows = [[f.severity.value, f.id, f.category.value, f.title] for f in ordered]
    return table(["SEVERITY", "ID", "CATEGORY", "TITLE"], rows)
