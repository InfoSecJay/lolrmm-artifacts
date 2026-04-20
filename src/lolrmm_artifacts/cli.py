"""Typer CLI for lolrmm-artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import applications as apps_mod
from . import completeness as completeness_mod
from . import export as export_mod
from . import fetch as fetch_mod
from . import filters as filters_mod
from . import indicators as indicators_mod
from . import metrics as metrics_mod
from . import parse as parse_mod
from . import store as store_mod

DEFAULT_DB = Path("data/lolrmm.db")

app = typer.Typer(no_args_is_help=True, add_completion=False, help="LOLRMM artifact exporter.")
console = Console()


def _load_tools_or_exit(db: Path):
    if not db.exists():
        console.print(f"[red]No database at {db}. Run `lolrmm sync` first.[/red]")
        raise typer.Exit(code=1)
    conn = store_mod.connect(db)
    try:
        return store_mod.load_all(conn)
    finally:
        conn.close()


@app.command()
def sync(
    source: Annotated[
        Path | None,
        typer.Option("--source", "-s", help="Local directory of YAML files. Defaults to GitHub raw."),
    ] = None,
    db: Annotated[Path, typer.Option("--db", help="SQLite DB path.")] = DEFAULT_DB,
    workers: Annotated[int, typer.Option(help="Parallel HTTP workers for remote fetch.")] = 8,
) -> None:
    """Download/read LOLRMM YAML files and populate the local SQLite store."""
    if source:
        console.print(f"Reading YAML from [cyan]{source}[/cyan]")
        files = fetch_mod.read_local(source)
    else:
        console.print("Fetching YAML from [cyan]GitHub (magicsword-io/LOLRMM@main)[/cyan]")
        files = fetch_mod.fetch_remote(workers=workers)
    console.print(f"Got [bold]{len(files)}[/bold] files. Parsing...")
    result = parse_mod.parse_many(files)
    console.print(f"Parsed [bold green]{len(result.tools)}[/bold green] tools, "
                  f"[bold red]{len(result.errors)}[/bold red] errors.")
    for name, msg in result.errors:
        console.print(f"  [yellow]{name}[/yellow] -> {msg}")
    conn = store_mod.connect(db)
    try:
        store_mod.sync(conn, result.tools)
    finally:
        conn.close()
    console.print(f"Stored at [cyan]{db}[/cyan].")


@app.command()
def export(
    format: Annotated[str, typer.Option("--format", "-f", help="json or csv")] = "json",
    out: Annotated[Path, typer.Option("--out", "-o", help="Output file (json) or directory (csv).")] = Path("out"),
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
) -> None:
    """Export the full dataset as JSON or a set of CSVs."""
    tools = _load_tools_or_exit(db)
    fmt = format.lower()
    if fmt == "json":
        target = out if out.suffix else out / "lolrmm.json"
        export_mod.export_json(tools, target)
        console.print(f"Wrote [cyan]{target}[/cyan] ({len(tools)} tools)")
    elif fmt == "csv":
        paths = export_mod.export_csv(tools, out)
        for label, path in paths.items():
            console.print(f"  {label:>20}: [cyan]{path}[/cyan]")
    else:
        console.print(f"[red]Unknown format: {format}. Use json or csv.[/red]")
        raise typer.Exit(code=1)


@app.command()
def indicators(
    type: Annotated[str, typer.Option("--type", "-t", help=f"One of: {', '.join(indicators_mod.INDICATOR_TYPES)}")] = ...,  # noqa: B008
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Output file. Omit to print to stdout.")] = None,
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
) -> None:
    """Emit a deduped, sorted flat list of a single indicator type."""
    tools = _load_tools_or_exit(db)
    items = indicators_mod.collect(tools, type)
    if out:
        indicators_mod.write_flat(items, out)
        console.print(f"Wrote [bold]{len(items)}[/bold] {type} indicators -> [cyan]{out}[/cyan]")
    else:
        for it in items:
            print(it)


@app.command("list")
def list_cmd(
    category: Annotated[str | None, typer.Option(help="RMM or RAT")] = None,
    os_: Annotated[str | None, typer.Option("--os", help="Windows/Linux/MacOS/...")] = None,
    capability: Annotated[str | None, typer.Option(help="Substring match on capability")] = None,
    free: Annotated[bool | None, typer.Option("--free/--paid", help="Filter free tools")] = None,
    name: Annotated[str | None, typer.Option("--name", help="Substring match on tool name")] = None,
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
) -> None:
    """List tools, filtered."""
    tools = _load_tools_or_exit(db)
    matched = filters_mod.apply(tools, category=category, os_=os_, capability=capability, free=free, name_contains=name)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Slug"); table.add_column("Name"); table.add_column("Category")
    table.add_column("OS"); table.add_column("Capabilities")
    for t in matched:
        table.add_row(
            t.slug, t.Name, t.Category,
            ", ".join(t.Details.SupportedOS),
            ", ".join(t.Details.Capabilities[:4]) + ("..." if len(t.Details.Capabilities) > 4 else ""),
        )
    console.print(table)
    console.print(f"[bold]{len(matched)}[/bold] of {len(tools)} tools matched.")


@app.command()
def show(
    slug_or_name: Annotated[str, typer.Argument(help="Tool slug or substring of name")],
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
) -> None:
    """Pretty-print one tool's full record."""
    tools = _load_tools_or_exit(db)
    key = slug_or_name.lower()
    match = next((t for t in tools if t.slug == key), None)
    if not match:
        match = next((t for t in tools if key in t.Name.lower()), None)
    if not match:
        console.print(f"[red]No tool matching '{slug_or_name}'.[/red]")
        raise typer.Exit(code=1)
    console.print_json(json.dumps(match.model_dump(mode="json"), ensure_ascii=False))


@app.command()
def stats(
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
    top: Annotated[int, typer.Option(help="Top-N capabilities/OS to show")] = 15,
) -> None:
    """Summary counts across the corpus."""
    tools = _load_tools_or_exit(db)
    s = metrics_mod.compute(tools)
    console.print(f"[bold]Tools:[/bold] {s.tool_count}")
    console.print(f"[bold]By category:[/bold] " + ", ".join(f"{k}={v}" for k, v in s.by_category.most_common()))
    console.print(f"[bold]Detection refs:[/bold] {s.detection_count}")
    console.print("[bold]Artifact counts:[/bold]")
    for k, v in s.artifact_counts.items():
        console.print(f"  {k:>15}: {v}")
    console.print(f"\n[bold]Top {top} OS:[/bold]")
    for os_, n in s.by_os.most_common(top):
        console.print(f"  {os_:<15} {n}")
    console.print(f"\n[bold]Top {top} capabilities:[/bold]")
    for cap, n in s.by_capability.most_common(top):
        console.print(f"  {cap:<30} {n}")
    console.print(f"\n[bold]Tools without artifacts:[/bold] {len(s.tools_without_artifacts)}")
    console.print(f"[bold]Tools without detections:[/bold] {len(s.tools_without_detections)}")


@app.command("sigma-urls")
def sigma_urls_cmd(
    out: Annotated[Path | None, typer.Option("--out", "-o")] = None,
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
) -> None:
    """Deduplicated list of every Sigma rule URL referenced across all tools."""
    tools = _load_tools_or_exit(db)
    urls = indicators_mod.sigma_urls(tools)
    if out:
        indicators_mod.write_flat(urls, out)
        console.print(f"Wrote [bold]{len(urls)}[/bold] Sigma URLs -> [cyan]{out}[/cyan]")
    else:
        for u in urls:
            print(u)


@app.command()
def applications(
    out: Annotated[Path, typer.Option("--out", "-o", help="Output CSV path.")] = Path("data/applications.csv"),
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
) -> None:
    """Write applications.csv — one row per (tool, alias) for EDR VLOOKUP.

    Match your EDR inventory's application-name column against the
    `application_name_lower` column for case-insensitive lookups.
    """
    tools = _load_tools_or_exit(db)
    rows = apps_mod.collect(tools)
    apps_mod.write_csv(rows, out)
    console.print(
        f"Wrote [bold]{len(rows)}[/bold] application aliases ({len(tools)} tools) -> [cyan]{out}[/cyan]"
    )


@app.command()
def completeness(
    out_dir: Annotated[Path, typer.Option("--out", "-o", help="Directory for report files.")] = Path("data"),
    db: Annotated[Path, typer.Option("--db")] = DEFAULT_DB,
    strict: Annotated[bool, typer.Option("--strict/--no-strict", help="Exit non-zero on missing files or parse errors.")] = True,
) -> None:
    """Report on fetch completeness and per-tool artifact coverage.

    Writes completeness_report.md, completeness_report.csv, and
    completeness_report.json to --out. Exits non-zero in --strict mode if
    any expected files are missing or any parse errors occurred.
    """
    tools = _load_tools_or_exit(db)
    # Upstream listing — one fresh API call per completeness run.
    expected = fetch_mod.list_remote_yaml_files()
    fetched = [t.source_file for t in tools if t.source_file]
    report = completeness_mod.compute(
        tools=tools, fetched_filenames=fetched, parse_errors=[],
        expected_filenames=expected,
    )
    completeness_mod.write_markdown(report, out_dir / "completeness_report.md")
    completeness_mod.write_csv(report, out_dir / "completeness_report.csv")
    completeness_mod.write_json(report, out_dir / "completeness_report.json")
    console.print(
        f"Coverage: {len(report.fetched_files)}/{len(report.expected_files)} files, "
        f"{len(report.missing_files)} missing, {len(report.parse_errors)} parse errors. "
        f"Status: [bold]{'PASS' if report.hard_ok else 'FAIL'}[/bold]"
    )
    console.print(f"Reports -> [cyan]{out_dir}[/cyan]")
    if strict and not report.hard_ok:
        raise typer.Exit(code=2)


@app.command()
def refresh(
    out_dir: Annotated[Path, typer.Option("--out", "-o", help="Output directory — everything written here.")] = Path("data"),
    source: Annotated[
        Path | None,
        typer.Option("--source", "-s", help="Local YAML dir (testing). Defaults to GitHub raw."),
    ] = None,
    workers: Annotated[int, typer.Option()] = 8,
    strict: Annotated[bool, typer.Option("--strict/--no-strict", help="Fail the run on missing files or parse errors.")] = True,
) -> None:
    """One-shot: fetch, parse, export, and completeness-check. Use from CI.

    Writes the full export set under --out (default: data/):
      - lolrmm.json
      - csv/*.csv
      - indicators/*.txt
      - applications.csv
      - sigma_urls.txt
      - completeness_report.{md,csv,json}
      - stats.json
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Fetch + parse.
    if source:
        console.print(f"Reading YAML from [cyan]{source}[/cyan]")
        files = fetch_mod.read_local(source)
        expected_listing = [f.name for f in files]
    else:
        console.print("Fetching YAML from [cyan]GitHub (magicsword-io/LOLRMM@main)[/cyan]")
        expected_listing = fetch_mod.list_remote_yaml_files()
        files = fetch_mod.fetch_remote(workers=workers)
    parsed = parse_mod.parse_many(files)
    console.print(
        f"Parsed [bold green]{len(parsed.tools)}[/bold green] / {len(files)} files, "
        f"[bold red]{len(parsed.errors)}[/bold red] errors"
    )
    for name, msg in parsed.errors:
        console.print(f"  [yellow]{name}[/yellow] -> {msg}")

    # 2. Write DB (used by subsequent read-only consumers if invoked separately).
    db_path = out_dir / "lolrmm.db"
    conn = store_mod.connect(db_path)
    try:
        store_mod.sync(conn, parsed.tools)
    finally:
        conn.close()

    tools = parsed.tools

    # 3. Full-dataset exports.
    export_mod.export_json(tools, out_dir / "lolrmm.json")
    export_mod.export_csv(tools, out_dir / "csv")
    console.print(f"Wrote JSON + CSV bundle -> [cyan]{out_dir}[/cyan]")

    # 4. Flat indicator lists.
    ind_dir = out_dir / "indicators"
    for kind in indicators_mod.INDICATOR_TYPES:
        items = indicators_mod.collect(tools, kind)
        indicators_mod.write_flat(items, ind_dir / f"{kind}.txt")
    console.print(f"Wrote {len(indicators_mod.INDICATOR_TYPES)} indicator lists -> [cyan]{ind_dir}[/cyan]")

    # 5. Sigma URL index.
    urls = indicators_mod.sigma_urls(tools)
    indicators_mod.write_flat(urls, out_dir / "sigma_urls.txt")

    # 6. The EDR-match table — the primary VLOOKUP target.
    apps_rows = apps_mod.collect(tools)
    apps_mod.write_csv(apps_rows, out_dir / "applications.csv")
    console.print(f"Wrote [bold]{len(apps_rows)}[/bold] application aliases -> [cyan]applications.csv[/cyan]")

    # 7. Stats snapshot.
    stats_obj = metrics_mod.compute(tools)
    stats_payload = {
        "tool_count": stats_obj.tool_count,
        "by_category": dict(stats_obj.by_category),
        "by_os": dict(stats_obj.by_os),
        "by_capability": dict(stats_obj.by_capability),
        "artifact_counts": stats_obj.artifact_counts,
        "detection_count": stats_obj.detection_count,
        "tools_without_artifacts_count": len(stats_obj.tools_without_artifacts),
        "tools_without_detections_count": len(stats_obj.tools_without_detections),
    }
    (out_dir / "stats.json").write_text(
        json.dumps(stats_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # 8. Completeness — written last so it reflects everything above.
    report = completeness_mod.compute(
        tools=tools,
        fetched_filenames=[f.name for f in files],
        parse_errors=parsed.errors,
        expected_filenames=expected_listing,
    )
    completeness_mod.write_markdown(report, out_dir / "completeness_report.md")
    completeness_mod.write_csv(report, out_dir / "completeness_report.csv")
    completeness_mod.write_json(report, out_dir / "completeness_report.json")

    status = "PASS" if report.hard_ok else "FAIL"
    console.print(
        f"Completeness: [bold]{status}[/bold] - "
        f"{len(report.fetched_files)}/{len(report.expected_files)} files, "
        f"{len(report.missing_files)} missing, {len(report.parse_errors)} parse errors"
    )
    if strict and not report.hard_ok:
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
