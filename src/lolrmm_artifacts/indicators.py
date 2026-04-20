"""Flat, deduplicated indicator lists per type.

These are the copy-pasteable outputs: one indicator per line, sorted,
deduped (case-insensitive for strings, case-sensitive for paths/regex).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from .models import Tool
from .normalize import expand_windows_path

INDICATOR_TYPES = [
    "filename",             # bare executable names from Details.PEMetadata + InstallationPaths
    "pe-original-name",     # Details.PEMetadata[].OriginalFileName
    "pe-description",       # Details.PEMetadata[].Description
    "pe-product",           # Details.PEMetadata[].Product
    "installation-path",    # Details.InstallationPaths
    "disk-path",            # Artifacts.Disk[].File (raw)
    "disk-path-expanded",   # Artifacts.Disk[].File with %ENV% expanded
    "registry",             # Artifacts.Registry[].Path
    "domain",               # Artifacts.Network[].Domains
    "port",                 # Artifacts.Network[].Ports
    "event-id",             # Artifacts.EventLog[].EventID
    "service-name",         # Artifacts.EventLog[].ServiceName
    "named-pipe",           # Artifacts.Other where Type == NamedPipe
    "user-agent",           # Artifacts.Other where Type == User-Agent
    "vulnerability",        # Details.Vulnerabilities
]

_EXE_BASENAME = re.compile(r"[^\\/]+\.exe$", re.IGNORECASE)


def _iter_filenames(tool: Tool) -> Iterable[str]:
    """Bare `something.exe` basenames from PE metadata AND installation paths."""
    for pe in tool.Details.PEMetadata:
        if pe.Filename:
            yield pe.Filename.strip().split("\\")[-1].split("/")[-1]
    for p in tool.Details.InstallationPaths:
        m = _EXE_BASENAME.search(p.strip())
        if m:
            yield m.group(0)


def _iter_other(tools: list[Tool], type_filter: str) -> Iterable[str]:
    for t in tools:
        for o in t.Artifacts.Other:
            if (o.Type or "").strip().lower() == type_filter.lower() and o.Value:
                yield o.Value.strip()


def collect(tools: list[Tool], kind: str) -> list[str]:
    """Return the deduplicated, sorted indicator list for `kind`."""
    if kind not in INDICATOR_TYPES:
        raise ValueError(f"Unknown indicator type: {kind}. Valid: {', '.join(INDICATOR_TYPES)}")

    items: list[str] = []
    for t in tools:
        if kind == "filename":
            items.extend(_iter_filenames(t))
        elif kind == "pe-original-name":
            items.extend(pe.OriginalFileName for pe in t.Details.PEMetadata if pe.OriginalFileName)
        elif kind == "pe-description":
            items.extend(pe.Description for pe in t.Details.PEMetadata if pe.Description)
        elif kind == "pe-product":
            items.extend(pe.Product for pe in t.Details.PEMetadata if pe.Product)
        elif kind == "installation-path":
            items.extend(t.Details.InstallationPaths)
        elif kind == "disk-path":
            items.extend(d.File.strip() for d in t.Artifacts.Disk if d.File)
        elif kind == "disk-path-expanded":
            items.extend(expand_windows_path(d.File.strip()) for d in t.Artifacts.Disk if d.File)
        elif kind == "registry":
            items.extend(r.Path for r in t.Artifacts.Registry if r.Path)
        elif kind == "domain":
            for n in t.Artifacts.Network:
                items.extend(d for d in n.Domains if d)
        elif kind == "port":
            for n in t.Artifacts.Network:
                items.extend(str(p) for p in n.Ports if p is not None and str(p) != "")
        elif kind == "event-id":
            items.extend(str(e.EventID) for e in t.Artifacts.EventLog if e.EventID is not None)
        elif kind == "service-name":
            items.extend(e.ServiceName for e in t.Artifacts.EventLog if e.ServiceName)
        elif kind == "vulnerability":
            items.extend(t.Details.Vulnerabilities)

    if kind == "named-pipe":
        items.extend(_iter_other(tools, "NamedPipe"))
    elif kind == "user-agent":
        items.extend(_iter_other(tools, "User-Agent"))

    # case-insensitive dedupe for name-like fields, case-sensitive for paths/regex
    case_insensitive = kind in {"filename", "pe-original-name", "pe-product", "domain", "service-name", "user-agent"}
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        key = it.lower() if case_insensitive else it
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    out.sort(key=str.lower)
    return out


def write_flat(items: list[str], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")


def sigma_urls(tools: list[Tool]) -> list[str]:
    urls: set[str] = set()
    for t in tools:
        for d in t.Detections:
            if d.url:
                urls.add(d.url.strip())
    return sorted(urls)
