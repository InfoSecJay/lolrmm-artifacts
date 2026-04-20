from lolrmm_artifacts import applications


def test_anydesk_has_canonical_alias(fixture_tools):
    rows = applications.collect(fixture_tools)
    anydesk_rows = [r for r in rows if r.tool_slug == "anydesk"]
    assert anydesk_rows, "AnyDesk produced no rows"
    lowers = {r.application_name_lower for r in anydesk_rows}
    assert "anydesk" in lowers


def test_exe_stripped_from_originalfilename(fixture_tools):
    rows = applications.collect(fixture_tools)
    # AnyDesk's OriginalFileName is "AnyDesk.exe" — we want "AnyDesk" as an alias,
    # not "AnyDesk.exe".
    names = {r.application_name for r in rows if r.tool_slug == "anydesk"}
    assert "AnyDesk" in names
    assert "AnyDesk.exe" not in names


def test_dedup_per_tool(fixture_tools):
    rows = applications.collect(fixture_tools)
    # No (tool_slug, application_name_lower) duplicates within a single tool.
    per_tool: dict[str, set[str]] = {}
    for r in rows:
        pts = per_tool.setdefault(r.tool_slug, set())
        assert r.application_name_lower not in pts, f"dup in {r.tool_slug}: {r.application_name_lower}"
        pts.add(r.application_name_lower)


def test_tools_with_empty_pemetadata_still_have_name(fixture_tools):
    # ConnectWise Control has PEMetadata with empty strings — only the Tool.Name
    # alias should survive.
    rows = applications.collect(fixture_tools)
    cw = [r for r in rows if r.tool_slug == "connectwise_control"]
    assert cw, "ConnectWise Control produced no rows"
    assert any(r.alias_source == "Name" for r in cw)


def test_csv_roundtrip(tmp_path, fixture_tools):
    rows = applications.collect(fixture_tools)
    out = tmp_path / "applications.csv"
    applications.write_csv(rows, out)
    text = out.read_text(encoding="utf-8")
    assert "application_name,application_name_lower" in text.splitlines()[0]
    assert "anydesk" in text.lower()
    assert "teamviewer" in text.lower()


def test_output_is_deterministic(fixture_tools):
    # Byte-equal across runs — matters for clean git diffs on the daily refresh.
    rows1 = applications.collect(fixture_tools)
    rows2 = applications.collect(fixture_tools)
    assert rows1 == rows2
