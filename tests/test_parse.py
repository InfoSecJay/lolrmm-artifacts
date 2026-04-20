"""Parsing and schema-tolerance tests across real LOLRMM fixtures."""

from __future__ import annotations

from lolrmm_artifacts.models import Tool


def test_all_fixtures_parse(fixture_tools):
    assert len(fixture_tools) == 6  # anydesk, atera, connectwise_control, kaseya, splashtop, teamviewer
    assert all(isinstance(t, Tool) for t in fixture_tools)


def test_source_file_is_populated(fixture_tools):
    assert all(t.source_file for t in fixture_tools)


def test_slug_from_filename(fixture_tools):
    slugs = {t.slug for t in fixture_tools}
    assert "anydesk" in slugs
    assert "connectwise_control" in slugs


def test_pemetadata_dict_and_list_both_parse(fixture_tools):
    # kaseya uses a list where only some entries have OriginalFileName
    kaseya = next(t for t in fixture_tools if t.slug == "kaseya")
    filenames = [pe.Filename for pe in kaseya.Details.PEMetadata if pe.Filename]
    assert "agentmon.exe" in filenames


def test_free_verification_mixed_types(fixture_tools):
    # anydesk has Free: true (bool), connectwise_control has Free: '' (empty str -> None)
    anydesk = next(t for t in fixture_tools if t.slug == "anydesk")
    assert anydesk.Details.Free in (True, "true")
    cw = next(t for t in fixture_tools if t.slug == "connectwise_control")
    assert cw.Details.Free in (None, "", False)


def test_detections_use_sigma_field(fixture_tools):
    anydesk = next(t for t in fixture_tools if t.slug == "anydesk")
    assert anydesk.Detections
    assert all(d.url and d.url.startswith("http") for d in anydesk.Detections)


def test_other_artifacts_parsed(fixture_tools):
    anydesk = next(t for t in fixture_tools if t.slug == "anydesk")
    types = {o.Type for o in anydesk.Artifacts.Other}
    assert "User-Agent" in types
    assert "NamedPipe" in types


def test_empty_artifact_sections_are_lists(fixture_tools):
    # connectwise_control has Disk: [] etc.
    cw = next(t for t in fixture_tools if t.slug == "connectwise_control")
    assert cw.Artifacts.Disk == []
    assert cw.Artifacts.Registry == []
    assert cw.Artifacts.Network  # has at least one entry
