"""Application-name alias table — the primary EDR-inventory-matching output.

One row per (tool, unique alias). Aliases are collected from:
- Tool.Name
- Details.PEMetadata[].Product
- Details.PEMetadata[].Description
- Details.PEMetadata[].OriginalFileName (with `.exe` stripped)

Rationale: EDR application inventories (SentinelOne, CrowdStrike, Intune, etc.)
list installed software by display name — usually the PE Product or
OriginalFileName value. Exposing each distinct alias as its own row makes the
CSV trivially `VLOOKUP`-able from a spreadsheet: you match on
`application_name_lower` against a `=LOWER(your_edr_name)` column.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .models import Tool


@dataclass(frozen=True)
class ApplicationAlias:
    tool_slug: str
    tool_name: str
    application_name: str       # original casing/spelling
    application_name_lower: str  # pre-lowercased for VLOOKUP against =LOWER(edr_name)
    alias_source: str            # which field the alias came from
    category: str
    free: str
    website: str
    supported_os: str            # pipe-separated


def _strip_exe(s: str) -> str:
    s = s.strip()
    if s.lower().endswith(".exe"):
        s = s[:-4]
    return s.strip()


def _iter_tool_aliases(tool: Tool) -> list[tuple[str, str]]:
    """Return [(alias, source), ...] without dedup — caller dedupes."""
    out: list[tuple[str, str]] = []
    if tool.Name:
        out.append((tool.Name.strip(), "Name"))
    for pe in tool.Details.PEMetadata:
        if pe.Product:
            out.append((pe.Product.strip(), "PEMetadata.Product"))
        if pe.Description:
            out.append((pe.Description.strip(), "PEMetadata.Description"))
        if pe.OriginalFileName:
            stripped = _strip_exe(pe.OriginalFileName)
            if stripped:
                out.append((stripped, "PEMetadata.OriginalFileName"))
    return out


def collect(tools: list[Tool]) -> list[ApplicationAlias]:
    rows: list[ApplicationAlias] = []
    for t in tools:
        seen_lower: set[str] = set()
        for alias, source in _iter_tool_aliases(t):
            if not alias:
                continue
            key = alias.lower()
            if key in seen_lower:
                continue
            seen_lower.add(key)
            free = t.Details.Free
            free_str = "" if free is None else ("true" if free is True else "false" if free is False else str(free))
            rows.append(ApplicationAlias(
                tool_slug=t.slug,
                tool_name=t.Name,
                application_name=alias,
                application_name_lower=key,
                alias_source=source,
                category=t.Category,
                free=free_str,
                website=t.Details.Website or "",
                supported_os=" | ".join(t.Details.SupportedOS),
            ))
    # Stable sort by lower alias then slug so successive runs produce
    # byte-identical CSVs (matters for git diffing in the daily action).
    rows.sort(key=lambda r: (r.application_name_lower, r.tool_slug, r.alias_source))
    return rows


def write_csv(rows: list[ApplicationAlias], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "application_name", "application_name_lower", "tool_slug", "tool_name",
            "alias_source", "category", "free", "website", "supported_os",
        ])
        for r in rows:
            w.writerow([
                r.application_name, r.application_name_lower, r.tool_slug, r.tool_name,
                r.alias_source, r.category, r.free, r.website, r.supported_os,
            ])
