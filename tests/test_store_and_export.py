from lolrmm_artifacts import export, store


def test_sqlite_roundtrip(tmp_path, fixture_tools):
    db = tmp_path / "lolrmm.db"
    conn = store.connect(db)
    store.sync(conn, fixture_tools)

    # re-sync should be idempotent (no row explosion in child tables)
    store.sync(conn, fixture_tools)

    loaded = store.load_all(conn)
    assert len(loaded) == len(fixture_tools)
    loaded_slugs = {t.slug for t in loaded}
    assert loaded_slugs == {t.slug for t in fixture_tools}

    disk_rows = conn.execute("SELECT COUNT(*) AS c FROM art_disk").fetchone()["c"]
    expected_disk = sum(len(t.Artifacts.Disk) for t in fixture_tools)
    assert disk_rows == expected_disk
    conn.close()


def test_sync_prunes_tools_removed_upstream(tmp_path, fixture_tools):
    # A local DB outlives upstream renames; sync must mirror the parsed set so
    # dead slugs cannot leak into DB-backed exports (seen: microsoft_rdp -> microsoft_tsc).
    conn = store.connect(tmp_path / "lolrmm.db")
    store.sync(conn, fixture_tools)
    keep = fixture_tools[:-1]
    gone = fixture_tools[-1].slug
    store.sync(conn, keep)
    assert {t.slug for t in store.load_all(conn)} == {t.slug for t in keep}
    orphans = conn.execute("SELECT COUNT(*) AS c FROM art_network WHERE slug = ?", (gone,)).fetchone()["c"]
    assert orphans == 0

    # An empty parse result must not wipe the store.
    store.sync(conn, [])
    assert len(store.load_all(conn)) == len(keep)
    conn.close()


def test_json_export(tmp_path, fixture_tools):
    out = tmp_path / "out.json"
    export.export_json(fixture_tools, out)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert '"AnyDesk"' in text


def test_csv_export(tmp_path, fixture_tools):
    paths = export.export_csv(fixture_tools, tmp_path)
    for key in ("tools", "artifacts_disk", "artifacts_registry", "artifacts_network", "detections"):
        assert paths[key].exists()
    tools_csv = paths["tools"].read_text(encoding="utf-8")
    assert "anydesk" in tools_csv
    assert "TeamViewer" in tools_csv
