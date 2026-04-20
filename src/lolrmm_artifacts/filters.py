"""Simple in-memory filters for the `list` command."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Tool
from .normalize import canonical_os


def apply(
    tools: Iterable[Tool],
    *,
    category: str | None = None,
    os_: str | None = None,
    capability: str | None = None,
    free: bool | None = None,
    name_contains: str | None = None,
) -> list[Tool]:
    out: list[Tool] = []
    want_os = canonical_os(os_) if os_ else None
    cap_lc = capability.lower() if capability else None
    name_lc = name_contains.lower() if name_contains else None

    for t in tools:
        if category and t.Category.lower() != category.lower():
            continue
        if want_os:
            tool_os = {canonical_os(o) for o in t.Details.SupportedOS}
            if want_os not in tool_os:
                continue
        if cap_lc and not any(cap_lc in c.lower() for c in t.Details.Capabilities):
            continue
        if free is not None:
            tool_free = t.Details.Free
            if isinstance(tool_free, str):
                tool_free_bool = tool_free.strip().lower() == "true"
            elif isinstance(tool_free, bool):
                tool_free_bool = tool_free
            else:
                tool_free_bool = False
            if tool_free_bool != free:
                continue
        if name_lc and name_lc not in t.Name.lower():
            continue
        out.append(t)
    return out
