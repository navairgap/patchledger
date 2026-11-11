"""Shared test fixtures and helpers."""

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PLACEHOLDER = "PLACEHOLDER-REPLACED-AT-RUNTIME"


def fixture_path(name: str) -> Path:
    return FIXTURES_DIR / name


def load_fixture_json(name: str):
    return json.loads(fixture_path(name).read_text(encoding="utf-8"))


def write_json(tmp_path: Path, name: str, data) -> Path:
    """Write data as JSON into tmp_path and return the file path."""
    out = tmp_path / name
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out


@pytest.fixture()
def gitleaks_report(tmp_path: Path) -> Path:
    """Gitleaks report with runtime-built fake secrets (no real-looking literals in repo)."""
    data = load_fixture_json("gitleaks_basic.json")
    fake = "AKIA" + "IOSFODNN7EXAMPLE"[:7] + "7" + "Q" * 8  # 20-char AWS-shaped fake
    for item in data:
        item["Secret"] = fake
        item["Match"] = f"key = \"{fake}\""
    return write_json(tmp_path, "gitleaks_report.json", data)
