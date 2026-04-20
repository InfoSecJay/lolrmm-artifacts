"""Summary counts across the parsed tool corpus."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .models import Tool
from .normalize import canonical_os


@dataclass
class Stats:
    tool_count: int = 0
    by_category: Counter = field(default_factory=Counter)
    by_os: Counter = field(default_factory=Counter)
    by_capability: Counter = field(default_factory=Counter)
    artifact_counts: dict[str, int] = field(default_factory=dict)
    detection_count: int = 0
    tools_without_artifacts: list[str] = field(default_factory=list)
    tools_without_detections: list[str] = field(default_factory=list)


def compute(tools: list[Tool]) -> Stats:
    s = Stats(tool_count=len(tools))
    disk = evt = reg = net = other = 0
    for t in tools:
        s.by_category[t.Category] += 1
        for os_ in t.Details.SupportedOS:
            s.by_os[canonical_os(os_) or os_] += 1
        for c in t.Details.Capabilities:
            s.by_capability[c] += 1

        d_c = len(t.Artifacts.Disk)
        e_c = len(t.Artifacts.EventLog)
        r_c = len(t.Artifacts.Registry)
        n_c = sum(max(len(n.Domains), 1) * max(len(n.Ports), 1) for n in t.Artifacts.Network)
        o_c = len(t.Artifacts.Other)

        disk += d_c; evt += e_c; reg += r_c; net += n_c; other += o_c
        s.detection_count += len(t.Detections)

        if d_c + e_c + r_c + n_c + o_c == 0:
            s.tools_without_artifacts.append(t.slug)
        if not t.Detections:
            s.tools_without_detections.append(t.slug)

    s.artifact_counts = {
        "disk": disk,
        "eventlog": evt,
        "registry": reg,
        "network_pairs": net,
        "other": other,
        "total": disk + evt + reg + net + other,
    }
    return s
