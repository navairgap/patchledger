"""Tests for the pipeline: scan/import -> normalize -> store."""

import json

import pytest

from patchledger.config import PatchLedgerConfig
from patchledger.errors import ProjectError
from patchledger.models import ScanSource, ToolRunStatus
from patchledger.parsers.common import RawFinding
from patchledger.pipeline import import_reports, resolve_target, scan_repository
from patchledger.scanner import ScannerOutcome
from patchledger.storage import PatchLedgerDB


def _fake_outcome(tool="semgrep", rule="rule-1", path="app.py", line=3):
    return ScannerOutcome(
        tool=tool,
        status=ToolRunStatus.RAN,
        version="test",
        findings=[
            RawFinding(
                scanner=tool, rule_id=rule, message=f"issue {rule}",
                file_path=path, start_line=line, severity_hint="ERROR",
                evidence=f"evidence-{rule}",
            )
        ],
    )


def test_resolve_target_validation(tmp_path):
    assert resolve_target(tmp_path) == tmp_path.resolve()
    with pytest.raises(ProjectError):
        resolve_target(tmp_path / "missing")
    with pytest.raises(ProjectError):
        resolve_target(tmp_path / "file.txt") if (tmp_path / "file.txt").write_text("x") else None


def test_scan_repository_stores_normalized_scan(tmp_path, monkeypatch):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("print('hi')\n")

    def fake_run(config, target, enabled=None):
        return [_fake_outcome(), _fake_outcome(tool="bandit", rule="B101")]

    monkeypatch.setattr("patchledger.pipeline.run_all_scanners", fake_run)

    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        result = scan_repository(db, target, PatchLedgerConfig())
        assert result.scan.source == ScanSource.SCAN
        assert len(result.findings) == 2
        tools = {t.tool: t.status for t in result.scan.tools}
        assert tools == {"semgrep": ToolRunStatus.RAN, "bandit": ToolRunStatus.RAN}

        stored = db.get_findings(result.scan.id)
        assert len(stored) == 2
        assert stored[0].occurrences[0].file_path == "app.py"


def test_scan_repository_target_required(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        with pytest.raises(ProjectError):
            scan_repository(db, tmp_path / "does-not-exist", PatchLedgerConfig())


def test_import_reports_merges_and_relativizes(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    report = tmp_path / "semgrep.json"
    report.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "r1",
                        "path": str(target / "app.py"),  # absolute path in report
                        "start": {"line": 4},
                        "end": {"line": 4},
                        "extra": {"message": "issue r1", "severity": "ERROR", "lines": "bad()"},
                    }
                ],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )

    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        result = import_reports(db, [report], PatchLedgerConfig(), target)
        assert result.scan.source == ScanSource.IMPORT
        assert result.scan.tools[0].status == ToolRunStatus.IMPORTED
        assert result.findings[0].file_path == "app.py"  # relativized to scan root
