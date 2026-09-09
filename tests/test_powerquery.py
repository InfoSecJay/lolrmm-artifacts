from pathlib import Path

import pytest
import yaml

from lolrmm_artifacts import powerquery


# --- url_substring: the substring-matcher FP-trap fixture ---------------------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("*.anydesk.com", ".anydesk.com"),
        ("*.GoToMyPC.com", ".gotomypc.com"),                       # host lowercased
        ("*ammyy.com", "ammyy.com"),                               # star without dot
        ("*.-dms.zoho.com.cn", ".-dms.zoho.com.cn"),               # odd but literal
        ("agents*-cloud.acronis.com", "-cloud.acronis.com"),       # mid-string glob
        ("plus*.site24x7.com", ".site24x7.com"),
        ("pdqinstallers.*.r2.cloudflarestorage.com", ".r2.cloudflarestorage.com"),
        ("relay-[a-f0-9]{8}.net.anydesk.com:443", ".net.anydesk.com"),  # regex + port
        ("https://github.com/dchapyshev/aspia", "github.com/dchapyshev/aspia"),
        ("github.com/Mikej81/WebRDP", "github.com/Mikej81/WebRDP"),  # path case kept
        ("zoho.com/assist/", "zoho.com/assist/"),
        ("136.243.104.235", "136.243.104.235"),
        ("upload_data.qq.com", "upload_data.qq.com"),  # underscore hosts exist in the wild
        ("  boot.net.anydesk.com  ", "boot.net.anydesk.com"),
        ("user_managed", None),      # not a hostname
        ("*", None),
        ("*.com", None),             # bare TLD would match everything
        ("evil corp.com", None),     # whitespace
        ("it's.example.com", None),  # would break the string literal
        ("", None),
    ],
)
def test_url_substring(raw, expected):
    assert powerquery.url_substring(raw) == expected


# --- collectors ------------------------------------------------------------------

def test_process_values_are_lowercase_deduped_sorted(fixture_tools):
    values, meta = powerquery.process_values(fixture_tools)
    assert values == sorted(set(values))
    assert all(v == v.lower() for v in values)
    assert "anydesk" in values
    assert "teamviewer" in values
    assert meta["source"].startswith("applications.csv")


def test_url_values_have_no_pattern_tokens(fixture_tools):
    values, meta = powerquery.url_values(fixture_tools)
    assert ".anydesk.com" in values
    assert "boot.net.anydesk.com" in values
    assert ".net.anydesk.com" in values          # from the relay-[a-f0-9]{8} regex entry
    assert "managedsupport.kaseya.net" in values  # from *managedsupport.kaseya.net
    assert not any(ch in v for v in values for ch in "*[]{}()?")
    assert any(r.startswith("relay-[a-f0-9]{8}") for r in meta["rewritten"])
    assert meta["dropped"] == []


# --- query text ------------------------------------------------------------------

def test_process_query_matches_user_template(fixture_tools):
    query, generated = powerquery.build(powerquery.PROCESS_RULE, fixture_tools)
    assert query.startswith("event.type='Process Creation'\n| filter src.process.displayName contains (\n")
    assert "    'anydesk',\n" in query
    assert "  by src.process.displayName, src.process.publisher, src.process.name\n" in query
    assert "est_hosts = estimate_distinct(endpoint.name)" in query
    assert generated["indicators"] == query.count("\n    '") + query.count('\n    "')
    assert generated["tools"] == len(fixture_tools)


def test_url_query_matches_user_template(fixture_tools):
    query, _ = powerquery.build(powerquery.URL_RULE, fixture_tools)
    assert query.startswith("event.category='url'\n| filter url.address contains (\n")
    assert "| let domain = net_url_domain(url.address)\n" in query
    assert "    urls = array_agg(url.address)\n" in query
    assert query.endswith("  by domain, src.process.displayName, src.process.publisher\n")


def test_quote_switches_to_double_quotes_on_apostrophe():
    assert powerquery._quote("anydesk") == "'anydesk'"
    assert powerquery._quote("i'm intouch") == '"i\'m intouch"'


# --- file output -----------------------------------------------------------------

def test_write_rules_produces_parseable_sigma_shaped_yaml(tmp_path: Path, fixture_tools):
    paths = powerquery.write_rules(fixture_tools, tmp_path, today="2026-09-09")
    assert set(paths) == {"process", "url"}
    for spec in powerquery.RULES:
        doc = yaml.safe_load(paths[spec.key].read_text(encoding="utf-8"))
        assert doc["id"] == spec.id
        assert doc["title"] == spec.title
        assert doc["logsource"] == {"product": "sentinelone", "service": "powerquery", "category": spec.category}
        assert doc["query"].startswith(spec.head.split("\n")[0])
        assert doc["tags"][0] == "attack.command_and_control"
        assert doc["falsepositives"]
        assert doc["level"] == "low"
        assert str(doc["modified"]) == "2026-09-09"


def test_modified_only_bumps_when_query_changes(tmp_path: Path, fixture_tools):
    powerquery.write_rules(fixture_tools, tmp_path, today="2026-09-09")
    first = {p.name: p.read_text(encoding="utf-8") for p in tmp_path.iterdir()}

    # Same data, later day: byte-identical (no noisy daily commits).
    powerquery.write_rules(fixture_tools, tmp_path, today="2026-09-10")
    second = {p.name: p.read_text(encoding="utf-8") for p in tmp_path.iterdir()}
    assert first == second

    # Fewer tools => different list => modified bumps.
    powerquery.write_rules(fixture_tools[:-1], tmp_path, today="2026-09-11")
    doc = yaml.safe_load((tmp_path / "lolrmm_process.yml").read_text(encoding="utf-8"))
    assert str(doc["modified"]) == "2026-09-11"


def test_output_is_deterministic(fixture_tools):
    a = powerquery.build(powerquery.URL_RULE, fixture_tools)
    b = powerquery.build(powerquery.URL_RULE, fixture_tools)
    assert a == b
