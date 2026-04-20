from __future__ import annotations

from pathlib import Path

import pytest

from lolrmm_artifacts.fetch import read_local
from lolrmm_artifacts.parse import parse_many


FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_tools():
    files = read_local(FIXTURE_DIR)
    result = parse_many(files)
    assert not result.errors, f"Fixture parse errors: {result.errors}"
    return result.tools
