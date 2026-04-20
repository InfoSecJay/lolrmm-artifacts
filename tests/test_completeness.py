from lolrmm_artifacts import completeness


def test_all_sections_reported(fixture_tools):
    fetched = [t.source_file for t in fixture_tools]
    report = completeness.compute(
        tools=fixture_tools,
        fetched_filenames=fetched,
        parse_errors=[],
        expected_filenames=fetched,
    )
    assert report.hard_ok
    assert len(report.tool_coverage) == len(fixture_tools)
    assert report.section_counts["disk"] >= 1  # at least anydesk has disk entries


def test_missing_files_mark_failure(fixture_tools):
    fetched = [t.source_file for t in fixture_tools][:-1]  # drop one
    expected = [t.source_file for t in fixture_tools]
    report = completeness.compute(
        tools=fixture_tools,
        fetched_filenames=fetched,
        parse_errors=[],
        expected_filenames=expected,
    )
    assert not report.hard_ok
    assert report.missing_files


def test_parse_errors_mark_failure(fixture_tools):
    fetched = [t.source_file for t in fixture_tools]
    report = completeness.compute(
        tools=fixture_tools,
        fetched_filenames=fetched,
        parse_errors=[("broken.yaml", "boom")],
        expected_filenames=fetched,
    )
    assert not report.hard_ok


def test_writers(tmp_path, fixture_tools):
    fetched = [t.source_file for t in fixture_tools]
    report = completeness.compute(
        tools=fixture_tools,
        fetched_filenames=fetched,
        parse_errors=[],
        expected_filenames=fetched,
    )
    md = tmp_path / "r.md"
    csv_ = tmp_path / "r.csv"
    json_ = tmp_path / "r.json"
    completeness.write_markdown(report, md)
    completeness.write_csv(report, csv_)
    completeness.write_json(report, json_)
    assert "# LOLRMM export completeness report" in md.read_text(encoding="utf-8")
    assert "slug,name,category" in csv_.read_text(encoding="utf-8").splitlines()[0]
    assert '"hard_ok": true' in json_.read_text(encoding="utf-8")


def test_coverage_flags_reflect_fixtures(fixture_tools):
    fetched = [t.source_file for t in fixture_tools]
    report = completeness.compute(
        tools=fixture_tools, fetched_filenames=fetched, parse_errors=[], expected_filenames=fetched,
    )
    by_slug = {tc.slug: tc for tc in report.tool_coverage}
    # ConnectWise Control has empty Disk/EventLog/Registry sections in its YAML.
    cw = by_slug["connectwise_control"]
    assert not cw.has_disk
    assert not cw.has_eventlog
    assert not cw.has_registry
    assert cw.has_network  # but it does have a Network section

    # AnyDesk has everything including Other.
    ad = by_slug["anydesk"]
    assert ad.has_disk and ad.has_eventlog and ad.has_registry and ad.has_network
    assert ad.has_other
    assert ad.has_detections
