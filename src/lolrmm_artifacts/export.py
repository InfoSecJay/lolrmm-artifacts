"""Full-dataset exporters (JSON and CSV)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import Tool
from .normalize import canonical_os, expand_windows_path


def export_json(tools: list[Tool], out: Path) -> None:
    """Single JSON array, full nested schema."""
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = [t.model_dump(mode="json", exclude_none=False) for t in tools]
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def export_csv(tools: list[Tool], out_dir: Path) -> dict[str, Path]:
    """Multiple CSVs in out_dir — nesting doesn't fit a single sheet cleanly."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    # tools.csv — one row per tool, list-valued fields joined with ` | `.
    tools_path = out_dir / "tools.csv"
    with tools_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "slug", "name", "category", "description", "author",
            "created", "last_modified", "website", "privileges", "free",
            "verification", "supported_os", "capabilities",
            "installation_paths", "pe_original_names", "pe_filenames",
            "vulnerabilities", "references", "source_file",
        ])
        for t in tools:
            w.writerow([
                t.slug, t.Name, t.Category, t.Description, t.Author or "",
                t.Created or "", t.LastModified or "", t.Details.Website or "",
                t.Details.Privileges or "",
                str(t.Details.Free) if t.Details.Free is not None else "",
                str(t.Details.Verification) if t.Details.Verification is not None else "",
                " | ".join(t.Details.SupportedOS),
                " | ".join(t.Details.Capabilities),
                " | ".join(t.Details.InstallationPaths),
                " | ".join(pe.OriginalFileName for pe in t.Details.PEMetadata if pe.OriginalFileName),
                " | ".join(pe.Filename for pe in t.Details.PEMetadata if pe.Filename),
                " | ".join(t.Details.Vulnerabilities),
                " | ".join(t.References),
                t.source_file or "",
            ])
    paths["tools"] = tools_path

    # artifacts_disk.csv
    p = out_dir / "artifacts_disk.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "name", "file", "file_expanded", "os_raw", "os_canonical", "type", "description"])
        for t in tools:
            for d in t.Artifacts.Disk:
                path = d.File.strip()
                w.writerow([t.slug, t.Name, path, expand_windows_path(path),
                            d.OS or "", canonical_os(d.OS) or "", d.Type or "", d.Description or ""])
    paths["artifacts_disk"] = p

    # artifacts_eventlog.csv
    p = out_dir / "artifacts_eventlog.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "name", "event_id", "provider_name", "log_file",
                    "service_name", "image_path", "command_line", "description"])
        for t in tools:
            for e in t.Artifacts.EventLog:
                w.writerow([t.slug, t.Name, e.EventID or "", e.ProviderName or "",
                            e.LogFile or "", e.ServiceName or "", e.ImagePath or "",
                            e.CommandLine or "", e.Description or ""])
    paths["artifacts_eventlog"] = p

    # artifacts_registry.csv
    p = out_dir / "artifacts_registry.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "name", "path", "description"])
        for t in tools:
            for r in t.Artifacts.Registry:
                w.writerow([t.slug, t.Name, r.Path, r.Description or ""])
    paths["artifacts_registry"] = p

    # artifacts_network.csv — one row per (domain, port) pair
    p = out_dir / "artifacts_network.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "name", "domain", "port", "description"])
        for t in tools:
            for n in t.Artifacts.Network:
                domains = n.Domains or [""]
                ports = n.Ports or [""]
                for dom in domains:
                    for port in ports:
                        w.writerow([t.slug, t.Name, dom, port, n.Description or ""])
    paths["artifacts_network"] = p

    # artifacts_other.csv
    p = out_dir / "artifacts_other.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "name", "type", "value"])
        for t in tools:
            for o in t.Artifacts.Other:
                w.writerow([t.slug, t.Name, o.Type or "", o.Value or ""])
    paths["artifacts_other"] = p

    # detections.csv
    p = out_dir / "detections.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["slug", "name", "url", "description"])
        for t in tools:
            for d in t.Detections:
                w.writerow([t.slug, t.Name, d.url or "", d.Description or ""])
    paths["detections"] = p

    return paths
