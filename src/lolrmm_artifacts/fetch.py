"""Fetch LOLRMM YAML files.

Default source is GitHub raw — it reads the /yaml directory listing from the
Contents API, then downloads each file. A local --source directory is also
supported for offline/CI use.
"""

from __future__ import annotations

import base64
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

import httpx

GITHUB_OWNER = "magicsword-io"
GITHUB_REPO = "LOLRMM"
GITHUB_BRANCH = "main"
YAML_DIR = "yaml"

CONTENTS_API = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{YAML_DIR}?ref={GITHUB_BRANCH}"
RAW_BASE = f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/{GITHUB_BRANCH}/{YAML_DIR}"


@dataclass
class FetchedFile:
    name: str
    content: str


def _client(timeout: float = 30.0) -> httpx.Client:
    headers = {"User-Agent": "lolrmm-artifacts/0.1"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(timeout=timeout, headers=headers, follow_redirects=True)


def list_remote_yaml_files() -> list[str]:
    """Return every *.yaml / *.yml filename in the LOLRMM yaml/ directory."""
    with _client() as c:
        r = c.get(CONTENTS_API)
        r.raise_for_status()
        entries = r.json()
    return sorted(
        e["name"] for e in entries
        if e.get("type") == "file" and e["name"].lower().endswith((".yaml", ".yml"))
    )


def _fetch_via_contents_api(client: httpx.Client, name: str) -> str:
    # The Contents API returns base64 content from git — used when raw.githubusercontent
    # returns a stale 404 (CDN propagation lag, observed intermittently on LOLRMM).
    api = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{YAML_DIR}/{name}?ref={GITHUB_BRANCH}"
    r = client.get(api)
    r.raise_for_status()
    blob = r.json()
    encoding = blob.get("encoding", "base64")
    if encoding == "base64":
        return base64.b64decode(blob["content"]).decode("utf-8")
    return blob.get("content", "")


def fetch_remote(workers: int = 8) -> list[FetchedFile]:
    """Download every YAML from GitHub raw in parallel, with a Contents API fallback."""
    names = list_remote_yaml_files()
    out: list[FetchedFile] = []
    with _client() as c:
        def _get(name: str) -> FetchedFile:
            r = c.get(f"{RAW_BASE}/{name}")
            if r.status_code == 404:
                return FetchedFile(name=name, content=_fetch_via_contents_api(c, name))
            r.raise_for_status()
            return FetchedFile(name=name, content=r.text)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_get, n) for n in names]
            for f in as_completed(futures):
                out.append(f.result())
    out.sort(key=lambda f: f.name)
    return out


def read_local(source: Path) -> list[FetchedFile]:
    """Read every *.yaml / *.yml from a local directory."""
    files: list[FetchedFile] = []
    for p in sorted(source.iterdir()):
        if p.is_file() and p.suffix.lower() in {".yaml", ".yml"}:
            files.append(FetchedFile(name=p.name, content=p.read_text(encoding="utf-8")))
    return files
