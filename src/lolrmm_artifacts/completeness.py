"""Completeness check — did we actually get everything from LOLRMM?

Two categories of failure:
  HARD — fetch/parse went wrong. The daily refresh must fail on these so
         stale data doesn't get committed.
  SOFT — a tool's YAML is sparse upstream (missing artifacts, missing PE
         metadata, etc.). Not our bug; surfaced as coverage data so the
         user can decide where to file issues against LOLRMM upstream.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .fetch import list_remote_yaml_files
from .models import Tool


@dataclass
class ToolCoverage:
    slug: str
    name: str
    category: str
    has_pe_metadata: bool
    has_installation_paths: bool
    has_capabilities: bool
    has_supported_os: bool
    has_disk: bool
    has_eventlog: bool
    has_registry: bool
    has_network: bool
    has_other: bool
    has_detections: bool

    @property
    def empty_sections(self) -> list[str]:
        fields = [
            ("pe_metadata", self.has_pe_metadata),
            ("installation_paths", self.has_installation_paths),
            ("capabilities", self.has_capabilities),
            ("supported_os", self.has_supported_os),
            ("disk", self.has_disk),
            ("eventlog", self.has_eventlog),
            ("registry", self.has_registry),
            ("network", self.has_network),
            ("other", self.has_other),
            ("detections", self.has_detections),
        ]
        return [name for name, present in fields if not present]


@dataclass
class CompletenessReport:
    expected_files: list[str] = field(default_factory=list)
    fetched_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    extra_files: list[str] = field(default_factory=list)  # in fetch but not in listing; unlikely
    parse_errors: list[tuple[str, str]] = field(default_factory=list)
    tool_coverage: list[ToolCoverage] = field(default_factory=list)
    section_counts: dict[str, int] = field(default_factory=dict)

    @property
    def hard_ok(self) -> bool:
        return not self.missing_files and not self.parse_errors

    def to_dict(self) -> dict:
        return {
            "expected_count": len(self.expected_files),
            "fetched_count": len(self.fetched_files),
            "missing_files": self.missing_files,
            "extra_files": self.extra_files,
            "parse_errors": self.parse_errors,
            "section_counts": self.section_counts,
            "tools_with_no_artifacts": [tc.slug for tc in self.tool_coverage
                                         if not any([tc.has_disk, tc.has_eventlog, tc.has_registry,
                                                     tc.has_network, tc.has_other])],
            "tools_with_no_detections": [tc.slug for tc in self.tool_coverage if not tc.has_detections],
            "hard_ok": self.hard_ok,
        }


def _coverage(t: Tool) -> ToolCoverage:
    return ToolCoverage(
        slug=t.slug,
        name=t.Name,
        category=t.Category,
        has_pe_metadata=bool(t.Details.PEMetadata),
        has_installation_paths=bool(t.Details.InstallationPaths),
        has_capabilities=bool(t.Details.Capabilities),
        has_supported_os=bool(t.Details.SupportedOS),
        has_disk=bool(t.Artifacts.Disk),
        has_eventlog=bool(t.Artifacts.EventLog),
        has_registry=bool(t.Artifacts.Registry),
        has_network=bool(t.Artifacts.Network),
        has_other=bool(t.Artifacts.Other),
        has_detections=bool(t.Detections),
    )


def compute(
    tools: list[Tool],
    fetched_filenames: list[str],
    parse_errors: list[tuple[str, str]],
    *,
    expected_filenames: list[str] | None = None,
) -> CompletenessReport:
    """Build a report. If expected_filenames is None, the upstream listing is
    re-queried — pass it in from the sync pipeline to avoid the extra API call.
    """
    if expected_filenames is None:
        expected_filenames = list_remote_yaml_files()
    expected = set(expected_filenames)
    fetched = set(fetched_filenames)

    cov = [_coverage(t) for t in tools]
    counts = Counter()
    for tc in cov:
        for field_name in ("pe_metadata", "installation_paths", "capabilities", "supported_os",
                           "disk", "eventlog", "registry", "network", "other", "detections"):
            if getattr(tc, f"has_{field_name}"):
                counts[field_name] += 1

    return CompletenessReport(
        expected_files=sorted(expected_filenames),
        fetched_files=sorted(fetched_filenames),
        missing_files=sorted(expected - fetched),
        extra_files=sorted(fetched - expected),
        parse_errors=parse_errors,
        tool_coverage=cov,
        section_counts=dict(counts),
    )


def write_markdown(report: CompletenessReport, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# LOLRMM export completeness report")
    lines.append("")
    lines.append(f"- Expected files (upstream listing): **{len(report.expected_files)}**")
    lines.append(f"- Fetched + parsed tools: **{len(report.fetched_files)}**")
    lines.append(f"- Missing: **{len(report.missing_files)}**")
    lines.append(f"- Parse errors: **{len(report.parse_errors)}**")
    lines.append(f"- Status: {'PASS' if report.hard_ok else 'FAIL'}")
    lines.append("")

    if report.missing_files:
        lines.append("## Missing files")
        lines.append("")
        for name in report.missing_files:
            lines.append(f"- `{name}`")
        lines.append("")

    if report.parse_errors:
        lines.append("## Parse errors")
        lines.append("")
        for name, msg in report.parse_errors:
            lines.append(f"- `{name}` — {msg}")
        lines.append("")

    lines.append("## Section coverage (number of tools populating each section)")
    lines.append("")
    lines.append(f"Of {len(report.tool_coverage)} tools total:")
    lines.append("")
    lines.append("| Section | Tools populating | % |")
    lines.append("| --- | ---: | ---: |")
    total = max(len(report.tool_coverage), 1)
    for field_name in ("pe_metadata", "installation_paths", "capabilities", "supported_os",
                       "disk", "eventlog", "registry", "network", "other", "detections"):
        n = report.section_counts.get(field_name, 0)
        pct = n * 100 / total
        lines.append(f"| {field_name} | {n} | {pct:.0f}% |")
    lines.append("")

    empty_tools = [tc for tc in report.tool_coverage
                   if not any([tc.has_disk, tc.has_eventlog, tc.has_registry,
                               tc.has_network, tc.has_other])]
    lines.append(f"## Tools with no artifacts at all ({len(empty_tools)})")
    lines.append("")
    for tc in empty_tools:
        lines.append(f"- `{tc.slug}` ({tc.category})")
    lines.append("")

    no_det = [tc for tc in report.tool_coverage if not tc.has_detections]
    lines.append(f"## Tools with no detections ({len(no_det)})")
    lines.append("")
    for tc in no_det:
        lines.append(f"- `{tc.slug}` ({tc.category})")
    lines.append("")

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(report: CompletenessReport, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "slug", "name", "category",
            "has_pe_metadata", "has_installation_paths", "has_capabilities", "has_supported_os",
            "has_disk", "has_eventlog", "has_registry", "has_network", "has_other",
            "has_detections", "empty_sections",
        ])
        for tc in sorted(report.tool_coverage, key=lambda t: t.slug):
            w.writerow([
                tc.slug, tc.name, tc.category,
                tc.has_pe_metadata, tc.has_installation_paths, tc.has_capabilities, tc.has_supported_os,
                tc.has_disk, tc.has_eventlog, tc.has_registry, tc.has_network, tc.has_other,
                tc.has_detections, " | ".join(tc.empty_sections),
            ])


def write_json(report: CompletenessReport, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
