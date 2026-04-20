from lolrmm_artifacts import indicators


def test_filename_dedup_case_insensitive(fixture_tools):
    names = indicators.collect(fixture_tools, "filename")
    lowered = [n.lower() for n in names]
    assert len(lowered) == len(set(lowered))
    assert any(n.lower() == "teamviewer.exe" for n in names)


def test_domain_extraction(fixture_tools):
    domains = indicators.collect(fixture_tools, "domain")
    assert "boot.net.anydesk.com" in domains
    assert "live.screenconnect.com" in domains


def test_disk_path_expansion_emits_wildcarded(fixture_tools):
    paths = indicators.collect(fixture_tools, "disk-path-expanded")
    assert any(p.startswith(r"C:\Users\*\AppData\Roaming\AnyDesk") for p in paths)


def test_registry_paths(fixture_tools):
    regs = indicators.collect(fixture_tools, "registry")
    assert r"HKLM\SOFTWARE\TeamViewer\*" in regs


def test_sigma_urls_dedup(fixture_tools):
    urls = indicators.sigma_urls(fixture_tools)
    assert urls == sorted(urls)
    assert len(urls) == len(set(urls))
    assert any("sigma" in u.lower() for u in urls)


def test_named_pipe_from_other(fixture_tools):
    pipes = indicators.collect(fixture_tools, "named-pipe")
    assert "adprinterpipe" in pipes


def test_user_agent_from_other(fixture_tools):
    uas = indicators.collect(fixture_tools, "user-agent")
    assert any("AnyDesk" in u for u in uas)
