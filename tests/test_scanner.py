"""Tests for the scanner runner: fake scanners plus availability semantics."""

from pathlib import Path

from patchledger.config import PatchLedgerConfig
from patchledger.models import ToolRunStatus
from patchledger.scanner import (
    collect_git_metadata,
    discover_tool,
    get_tool_version,
    run_all_scanners,
    run_scanner,
)


def _make_executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


FAKE_SEMGREP = """#!/usr/bin/env python3
import json
print(json.dumps({
    "results": [{
        "check_id": "test.rule",
        "path": "app.py",
        "start": {"line": 3, "col": 1},
        "end": {"line": 3, "col": 10},
        "extra": {"message": "Fake finding (test scanner)", "severity": "ERROR", "lines": "bad()"}
    }],
    "errors": [], "version": "test-0"
}))
"""

FAKE_FAILING = """#!/usr/bin/env python3
import sys
sys.stderr.write("simulated scanner crash\\n")
sys.exit(5)
"""


def test_discover_tool_ignores_local_files(tmp_path):
    """Regression (security review F2): discovery must never honor
    repo-local executable files — only PATH and the interpreter's directory."""
    script = _make_executable(tmp_path / "fakescan", "#!/bin/sh\necho ok\n")
    assert discover_tool("fakescan") is None  # exists on disk, not on PATH
    assert script.exists()


def test_discover_tool_missing(tmp_path):
    assert discover_tool("definitely-not-installed-tool-xyz") is None


def test_run_scanner_fake_success(tmp_path):
    fake = _make_executable(tmp_path / "fakesemgrep", FAKE_SEMGREP)
    target = tmp_path / "repo"
    target.mkdir()
    outcome = run_scanner("semgrep", str(fake), target, timeout=60, scan_root=str(target))
    assert outcome.status == ToolRunStatus.RAN
    assert len(outcome.findings) == 1
    assert outcome.findings[0].rule_id == "test.rule"


def test_run_scanner_failure_recorded_honestly(tmp_path):
    fake = _make_executable(tmp_path / "fakefail", FAKE_FAILING)
    target = tmp_path / "repo"
    target.mkdir()
    outcome = run_scanner("semgrep", str(fake), target, timeout=60)
    assert outcome.status == ToolRunStatus.FAILED
    assert outcome.exit_code == 5
    assert "simulated scanner crash" in (outcome.note or "")


def test_run_scanner_unknown_tool_is_skipped(tmp_path):
    outcome = run_scanner("nope", "/bin/true", tmp_path, timeout=10)
    assert outcome.status == ToolRunStatus.SKIPPED


def test_run_all_scanners_records_unavailable(tmp_path):
    config = PatchLedgerConfig()
    config.scanning.enabled = ["definitely-not-installed-tool-xyz"]
    target = tmp_path / "repo"
    target.mkdir()
    outcomes = run_all_scanners(config, target)
    assert outcomes[0].status == ToolRunStatus.UNAVAILABLE
    assert outcomes[0].note


def test_get_tool_version_best_effort(tmp_path):
    script = _make_executable(
        tmp_path / "fakev", "#!/bin/sh\necho fake-1.2.3\n"
    )
    assert get_tool_version(str(script), ["--version"]) == "fake-1.2.3"
    assert get_tool_version(str(tmp_path / "missing"), ["--version"]) is None


def test_collect_git_metadata_non_git(tmp_path):
    commit, branch = collect_git_metadata(tmp_path)
    assert commit is None
    assert branch is None
