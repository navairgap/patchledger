"""Tests for parser error handling: malformed, oversized, and hostile inputs."""


import pytest

from conftest import load_fixture_json, write_json
from patchledger.config import PatchLedgerConfig
from patchledger.errors import ReportImportError
from patchledger.parsers import parse_report_file


def test_invalid_json(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not valid", encoding="utf-8")
    with pytest.raises(ReportImportError, match="not valid JSON"):
        parse_report_file(p, PatchLedgerConfig())


def test_empty_file(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    with pytest.raises(ReportImportError, match="empty"):
        parse_report_file(p, PatchLedgerConfig())


def test_missing_file(tmp_path):
    with pytest.raises(ReportImportError, match="not found"):
        parse_report_file(tmp_path / "nope.json", PatchLedgerConfig())


def test_directory_as_report(tmp_path):
    with pytest.raises(ReportImportError, match="not a file"):
        parse_report_file(tmp_path, PatchLedgerConfig())


def test_nan_constants_rejected(tmp_path):
    p = tmp_path / "nan.json"
    p.write_text('{"results": [], "score": NaN}', encoding="utf-8")
    with pytest.raises(ReportImportError, match="non-standard numeric"):
        parse_report_file(p, PatchLedgerConfig())


def test_unknown_format(tmp_path):
    p = tmp_path / "unknown.json"
    p.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(ReportImportError, match="Unrecognized report format"):
        parse_report_file(p, PatchLedgerConfig())


def test_oversized_file(tmp_path):
    p = tmp_path / "big.json"
    p.write_bytes(b"[" + b" " * (2 * 1024 * 1024) + b"]")
    config = PatchLedgerConfig()
    config.import_config.max_report_size_mb = 1
    with pytest.raises(ReportImportError, match="exceeding"):
        parse_report_file(p, config)


def test_deeply_nested_json(tmp_path):
    p = tmp_path / "deep.json"
    depth = 200_000
    p.write_text("[" * depth + "]" * depth, encoding="utf-8")
    with pytest.raises(ReportImportError):
        parse_report_file(p, PatchLedgerConfig())


def test_sarif_wrong_version(tmp_path):
    data = load_fixture_json("sarif_basic.sarif")
    data["version"] = "9.9"
    p = write_json(tmp_path, "sarif_bad_version.json", data)
    with pytest.raises(ReportImportError, match="SARIF version"):
        parse_report_file(p, PatchLedgerConfig())


def test_semgrep_results_wrong_type(tmp_path):
    p = write_json(
        tmp_path, "semgrep_bad_results.json", {"errors": [], "version": "1.0", "results": "no"}
    )
    with pytest.raises(ReportImportError, match="results"):
        parse_report_file(p, PatchLedgerConfig())


def test_gitleaks_not_a_list(tmp_path):
    p = write_json(tmp_path, "gitleaks_obj.json", {"RuleID": "x", "Secret": "y"})
    with pytest.raises(ReportImportError, match="Unrecognized report format"):
        parse_report_file(p, PatchLedgerConfig())


def test_partial_malformed_entries_are_skipped_with_warnings(tmp_path):
    data = load_fixture_json("semgrep_basic.json")
    data["results"].append({"check_id": "", "path": "x", "extra": {}})
    data["results"].append("not-an-object")
    p = write_json(tmp_path, "semgrep_partial.json", data)
    result = parse_report_file(p, PatchLedgerConfig())
    assert len(result.findings) == 2
    assert len(result.warnings) == 2
