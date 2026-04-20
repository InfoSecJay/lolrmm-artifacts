"""SQLite store for parsed LOLRMM tools.

A deliberately simple schema: one row per tool (json blob + denormalized
common fields for filtering) plus narrow tables per artifact type so that
indicators queries and stats don't have to re-scan the YAML.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Tool
from .normalize import canonical_os, expand_windows_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS tools (
    slug TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT,
    description TEXT,
    author TEXT,
    created TEXT,
    last_modified TEXT,
    website TEXT,
    privileges TEXT,
    free TEXT,
    verification TEXT,
    source_file TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_capabilities (
    slug TEXT, capability TEXT,
    PRIMARY KEY (slug, capability),
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tool_os (
    slug TEXT, os TEXT,
    PRIMARY KEY (slug, os),
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tool_installation_paths (
    slug TEXT, path TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tool_pe (
    slug TEXT, filename TEXT, original_file_name TEXT, description TEXT, product TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tool_vulnerabilities (
    slug TEXT, url TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tool_references (
    slug TEXT, url TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS art_disk (
    slug TEXT, file TEXT, file_expanded TEXT, description TEXT,
    os_raw TEXT, os_canonical TEXT, type TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS art_eventlog (
    slug TEXT, event_id TEXT, provider_name TEXT, log_file TEXT,
    service_name TEXT, image_path TEXT, command_line TEXT, description TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS art_registry (
    slug TEXT, path TEXT, description TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS art_network (
    slug TEXT, description TEXT, domain TEXT, port TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS art_other (
    slug TEXT, type TEXT, value TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detections (
    slug TEXT, url TEXT, description TEXT,
    FOREIGN KEY (slug) REFERENCES tools(slug) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tools_category ON tools(category);
CREATE INDEX IF NOT EXISTS idx_disk_os ON art_disk(os_canonical);
CREATE INDEX IF NOT EXISTS idx_cap ON tool_capabilities(capability);
CREATE INDEX IF NOT EXISTS idx_net_domain ON art_network(domain);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _bool_or_str(v: bool | str | None) -> str | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    s = v.strip()
    return s or None


def upsert_tool(conn: sqlite3.Connection, tool: Tool) -> None:
    slug = tool.slug
    payload = tool.model_dump(mode="json", exclude_none=False)

    # delete any prior child rows; simplest correct behaviour for re-sync.
    for tbl in (
        "tool_capabilities", "tool_os", "tool_installation_paths", "tool_pe",
        "tool_vulnerabilities", "tool_references",
        "art_disk", "art_eventlog", "art_registry", "art_network", "art_other",
        "detections",
    ):
        conn.execute(f"DELETE FROM {tbl} WHERE slug = ?", (slug,))

    conn.execute(
        """
        INSERT INTO tools (slug, name, category, description, author, created, last_modified,
                           website, privileges, free, verification, source_file, payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            name=excluded.name, category=excluded.category, description=excluded.description,
            author=excluded.author, created=excluded.created, last_modified=excluded.last_modified,
            website=excluded.website, privileges=excluded.privileges,
            free=excluded.free, verification=excluded.verification,
            source_file=excluded.source_file, payload_json=excluded.payload_json
        """,
        (
            slug, tool.Name, tool.Category, tool.Description, tool.Author,
            tool.Created, tool.LastModified,
            tool.Details.Website, tool.Details.Privileges,
            _bool_or_str(tool.Details.Free), _bool_or_str(tool.Details.Verification),
            tool.source_file, json.dumps(payload, ensure_ascii=False),
        ),
    )

    for cap in tool.Details.Capabilities:
        conn.execute("INSERT OR IGNORE INTO tool_capabilities VALUES (?, ?)", (slug, cap))
    for os_ in tool.Details.SupportedOS:
        conn.execute("INSERT OR IGNORE INTO tool_os VALUES (?, ?)", (slug, canonical_os(os_) or os_))
    for p in tool.Details.InstallationPaths:
        conn.execute("INSERT INTO tool_installation_paths VALUES (?, ?)", (slug, p))
    for pe in tool.Details.PEMetadata:
        conn.execute(
            "INSERT INTO tool_pe VALUES (?, ?, ?, ?, ?)",
            (slug, pe.Filename, pe.OriginalFileName, pe.Description, pe.Product),
        )
    for v in tool.Details.Vulnerabilities:
        conn.execute("INSERT INTO tool_vulnerabilities VALUES (?, ?)", (slug, v))
    for r in tool.References:
        conn.execute("INSERT INTO tool_references VALUES (?, ?)", (slug, r))

    for d in tool.Artifacts.Disk:
        conn.execute(
            "INSERT INTO art_disk VALUES (?, ?, ?, ?, ?, ?, ?)",
            (slug, d.File.strip(), expand_windows_path(d.File.strip()),
             d.Description, d.OS, canonical_os(d.OS), d.Type),
        )
    for e in tool.Artifacts.EventLog:
        conn.execute(
            "INSERT INTO art_eventlog VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (slug, str(e.EventID) if e.EventID is not None else None,
             e.ProviderName, e.LogFile, e.ServiceName, e.ImagePath,
             e.CommandLine, e.Description),
        )
    for r in tool.Artifacts.Registry:
        conn.execute("INSERT INTO art_registry VALUES (?, ?, ?)", (slug, r.Path, r.Description))
    for n in tool.Artifacts.Network:
        domains = n.Domains or [None]
        ports = n.Ports or [None]
        # emit one row per (domain, port) so indicator extraction is trivial;
        # if either side is empty the other still gets recorded.
        if not n.Domains and not n.Ports:
            conn.execute("INSERT INTO art_network VALUES (?, ?, ?, ?)", (slug, n.Description, None, None))
            continue
        for dom in domains:
            for port in ports:
                conn.execute(
                    "INSERT INTO art_network VALUES (?, ?, ?, ?)",
                    (slug, n.Description, dom, str(port) if port is not None else None),
                )
    for o in tool.Artifacts.Other:
        conn.execute("INSERT INTO art_other VALUES (?, ?, ?)", (slug, o.Type, o.Value))

    for det in tool.Detections:
        conn.execute(
            "INSERT INTO detections VALUES (?, ?, ?)",
            (slug, det.url, det.Description),
        )


def sync(conn: sqlite3.Connection, tools: list[Tool]) -> None:
    with conn:
        for t in tools:
            upsert_tool(conn, t)


def load_all(conn: sqlite3.Connection) -> list[Tool]:
    rows = conn.execute("SELECT payload_json, source_file FROM tools ORDER BY slug").fetchall()
    out: list[Tool] = []
    for row in rows:
        tool = Tool.model_validate(json.loads(row["payload_json"]))
        tool.source_file = row["source_file"]
        out.append(tool)
    return out
