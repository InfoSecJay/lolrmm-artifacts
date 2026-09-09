# lolrmm-artifacts

A Python CLI that parses the [LOLRMM](https://github.com/magicsword-io/LOLRMM) YAML corpus and exports RMM tool artifacts in formats useful for detection engineering — **especially matching your EDR application inventory against the known-RMM list**.

Fresh exports are regenerated daily by a GitHub Action and committed to [data/](data/), so you can read them straight from the repo.

## Primary use case: match EDR app inventory against known RMM tools

Your EDR (SentinelOne, CrowdStrike, Intune, etc.) exports installed applications by display name — "AnyDesk", "TeamViewer", "LogMeIn Pro", etc. **[data/applications.csv](data/applications.csv)** is built for `VLOOKUP` against that list.

It's a long-format table — **one row per (tool, alias)** — with these columns:

| Column | Example |
| --- | --- |
| `application_name` | `AnyDesk` |
| `application_name_lower` | `anydesk` ← match your lowercased EDR name here |
| `tool_slug` | `anydesk` |
| `tool_name` | `AnyDesk` |
| `alias_source` | `Name` / `PEMetadata.Product` / `PEMetadata.Description` / `PEMetadata.OriginalFileName` |
| `category` | `RMM` or `RAT` |
| `free`, `website`, `supported_os` | additional context |

Aliases per tool are collected from every spelling LOLRMM tracks, deduplicated (case-insensitive). So `TeamViewer.exe` in your EDR matches the `TeamViewer` tool via the `pe-original-name`-sourced alias, and a `Product=AnyDesk` export also matches the `anydesk` tool via the `pe-product`-sourced alias.

### Spreadsheet workflow

1. Pull [data/applications.csv](data/applications.csv) from this repo (always fresh, refreshed daily).
2. In your EDR inventory spreadsheet, add a column: `=LOWER(A2)` where A is the app name.
3. `VLOOKUP(that_column, applications.csv!B:I, <col>, FALSE)` — column B (`application_name_lower`) is your lookup key.

Any match = an RMM/RAT is installed and you can pull up the full LOLRMM record from the other columns.

## What gets exported

Everything lives under [data/](data/) and is overwritten by the daily refresh:

| File | What it is |
| --- | --- |
| [applications.csv](data/applications.csv) | The EDR-matching alias table (above). |
| [lolrmm.json](data/lolrmm.json) | Full dataset, nested. |
| [csv/tools.csv](data/csv/tools.csv), [csv/artifacts_*.csv](data/csv/), [csv/detections.csv](data/csv/detections.csv) | One CSV per artifact section. |
| [indicators/*.txt](data/indicators/) | Flat, deduped, sorted indicator lists per type — one per line, ready for a SIEM/EDR watchlist. |
| [sigma_urls.txt](data/sigma_urls.txt) | Every Sigma rule URL referenced by any tool, deduped. |
| [powerquery/*.yml](data/powerquery/) | Two SentinelOne PowerQuery hunting rules (process + URL) with the indicator lists baked in. See below. |
| [stats.json](data/stats.json) | Corpus counts by category / OS / capability / artifact. |
| [completeness_report.md](data/completeness_report.md), `.csv`, `.json` | Did we fetch everything upstream has? Which tools have sparse data? |

### Available indicator types

`filename`, `pe-original-name`, `pe-description`, `pe-product`, `installation-path`, `disk-path`, `disk-path-expanded`, `registry`, `domain`, `port`, `event-id`, `service-name`, `named-pipe`, `user-agent`, `vulnerability`.

`disk-path-expanded` rewrites Windows env vars (`%APPDATA%`, `%PROGRAMDATA%`, `%LOCALAPPDATA%`, `%PROGRAMFILES%`, `%TEMP%`, ...) into wildcarded canonical forms like `C:\Users\*\AppData\Roaming\...` so SIEM queries don't need to replicate the expansion.

## SentinelOne PowerQuery rules

[data/powerquery/](data/powerquery/) holds two ready-to-paste hunting queries, one file each, in a concise Sigma-shaped YAML (title, id, description, ATT&CK tags, logsource, `query`, falsepositives, level):

| File | Matches | Indicator source |
| --- | --- | --- |
| [lolrmm_process.yml](data/powerquery/lolrmm_process.yml) | `src.process.displayName contains (...)` on `Process Creation` events | every alias in `applications.csv` (`application_name_lower`) |
| [lolrmm_url.yml](data/powerquery/lolrmm_url.yml) | `url.address contains (...)` on `url` events | every Network domain in `indicators/domain.txt` |

Both aggregate with `| group` (count, estimated hosts/users, sites) so they are hunting/baseline queries, not per-event alerts. The lists are rebuilt from the corpus on every `lolrmm refresh`, so the daily action keeps them current with LOLRMM. The `modified` date only changes when the query text changes.

Process aliases longer than 100 characters, or containing quotes/backslashes, are dropped: upstream occasionally puts a whole paragraph in a PE description field, and that can never match a display name. Aliases of four characters or fewer are listed under `generated.short_aliases` because `contains` over-matches on them.

URL entries are normalised so PowerQuery `contains` can actually match them: `*.example.com` becomes the suffix `.example.com`; regex and mid-string wildcards (`relay-[a-f0-9]{8}.net.anydesk.com:443`, `agents*-cloud.acronis.com`) are reduced to their literal tail; schemes and ports are stripped; anything that is not a hostname is dropped. The `generated:` block in each file records the indicator count plus every entry that was rewritten or dropped, so the diff is auditable.

## Completeness check

Every run also produces a [completeness_report.md](data/completeness_report.md) answering:

- Did we fetch every `yaml/*.yaml` that's currently on upstream LOLRMM's `main`?
- Did any YAML fail to parse?
- How many tools populate each section (Disk, EventLog, Registry, Network, Other, Detections, PEMetadata, InstallationPaths, Capabilities, SupportedOS)?
- Which tools have no artifacts at all? Which have no detections?

The daily workflow runs with `--strict` and **fails hard** if any upstream file is missing or parsing blew up — so you'll see a failed Actions run instead of silently stale data.

## Daily refresh (GitHub Action)

[.github/workflows/refresh.yml](.github/workflows/refresh.yml) runs every day at 06:17 UTC (and on manual `workflow_dispatch`):

1. Checks out the repo, sets up Python 3.12, installs the package.
2. Runs `pytest -q`.
3. Runs `lolrmm refresh --out data/ --strict`.
4. If anything under `data/` changed, commits the diff as `chore(data): daily LOLRMM refresh (<date>)`.
5. Also uploads `data/` as a 30-day artifact for auditability.

## CLI reference

```bash
# One-shot for CI: fetch + export everything + completeness check.
lolrmm refresh --out data/

# Individual commands:
lolrmm sync                                           # fetch + build SQLite
lolrmm export --format json --out data/lolrmm.json
lolrmm export --format csv  --out data/csv
lolrmm applications --out data/applications.csv       # EDR alias table
lolrmm powerquery --out data/powerquery               # SentinelOne hunting rules
lolrmm indicators --type filename --out ind/filenames.txt
lolrmm sigma-urls --out data/sigma_urls.txt
lolrmm completeness --out data/
lolrmm stats
lolrmm list --os Windows --capability "Remote Control"
lolrmm show anydesk
```

### Data source

Default is GitHub raw over HTTPS. Set `GITHUB_TOKEN` in the environment (or via the workflow's built-in token) to lift anonymous rate limits. Pass `--source /path/to/cloned/yaml` to `sync`/`refresh` for offline/air-gapped use.

There's a fallback: GitHub's raw CDN occasionally 404s files that the Contents API confirms exist (observed on `aeroadmin.yaml`); `fetch.py` falls back to the Contents API's base64 blob when that happens.

## Install (local dev)

```bash
python -m venv .venv
.venv/Scripts/activate       # Windows (bash/MSYS)
# or:  source .venv/bin/activate   (Linux/macOS)
pip install -e ".[dev]"
pytest -q
```

Needs Python 3.11+.
