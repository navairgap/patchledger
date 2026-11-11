"""Tests for SQLite storage: persistence, restart survival, transactions, history."""

import pytest

from patchledger.config import PatchLedgerConfig
from patchledger.errors import StorageError
from patchledger.models import (
    Finding,
    FindingStatus,
    Scan,
    ScanSource,
    ScanToolRun,
    Severity,
    ToolRunStatus,
)
from patchledger.normalizer import normalize_findings
from patchledger.parsers.common import RawFinding
from patchledger.storage import PatchLedgerDB


def _finding(fp_suffix: str, scanner: str = "semgrep", path: str = "app.py") -> Finding:
    return normalize_findings(
        [
            RawFinding(
                scanner=scanner,
                rule_id=f"rule-{fp_suffix}",
                message=f"message {fp_suffix}",
                file_path=path,
                start_line=1,
                severity_hint="ERROR",
            )
        ],
        PatchLedgerConfig(),
    ).findings[0]


def _scan(project_id: str, target: str = "/repo", tools: list[ScanToolRun] | None = None) -> Scan:
    return Scan(
        project_id=project_id,
        target_path=target,
        source=ScanSource.SCAN,
        tools=tools or [ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN)],
    )


def test_project_ensure_is_idempotent(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        p1 = db.ensure_project("demo", "/repo")
        p2 = db.ensure_project("demo-renamed", "/repo")
        assert p1.id == p2.id  # same root path -> same project
        assert p2.name == "demo"  # existing record wins


def test_scan_insert_and_read_back(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        project = db.ensure_project("demo", "/repo")
        scan = _scan(project.id)
        findings = [_finding("a"), _finding("b", path="other.py")]
        db.insert_scan(scan, findings)

        loaded = db.get_findings(scan.id)
        assert len(loaded) == 2
        assert {f.fingerprint for f in loaded} == {f.fingerprint for f in findings}
        assert loaded[0].occurrences  # occurrences round-trip
        assert loaded[0].severity == Severity.HIGH


def test_history_survives_reopen(tmp_path):
    path = tmp_path / "db.sqlite"
    with PatchLedgerDB(path) as db:
        project = db.ensure_project("demo", "/repo")
        db.insert_scan(_scan(project.id), [_finding("x")])
        scan_id = db.list_scans(project.id)[0].id

    with PatchLedgerDB(path) as db:  # simulate restart
        project = db.ensure_project("demo", "/repo")
        scans = db.list_scans(project.id)
        assert [s.id for s in scans] == [scan_id]
        assert db.get_findings(scan_id)


def test_duplicate_fingerprint_in_one_scan_rejected(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        project = db.ensure_project("demo", "/repo")
        f = _finding("dup")
        with pytest.raises(StorageError, match="constraints"):
            db.insert_scan(_scan(project.id), [f, f])


def test_status_history_round_trip(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        project = db.ensure_project("demo", "/repo")
        scan_a = _scan(project.id)
        scan_b = _scan(project.id)
        db.insert_scan(scan_a, [])
        db.insert_scan(scan_b, [])
        db.record_status(
            project.id, "fp1", scan_a.id, FindingStatus.RESOLVED, "verified by semgrep coverage"
        )
        db.record_status(project.id, "fp1", scan_b.id, FindingStatus.REINTRODUCED, "came back")
        history = db.status_history(project.id)
        assert [h["status"] for h in history] == ["resolved", "reintroduced"]
        latest = db.latest_statuses(project.id)
        assert latest["fp1"]["status"] == "reintroduced"


def test_fingerprint_history_spans_scans(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        project = db.ensure_project("demo", "/repo")
        f = _finding("persist")
        s1 = _scan(project.id)
        s2 = _scan(project.id)
        db.insert_scan(s1, [f])
        db.insert_scan(s2, [f])
        hist = db.fingerprint_history(project.id, f.fingerprint)
        assert len(hist) == 2


def test_schema_version_recorded(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db:
        row = db._conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        assert row["value"] == "1"
        assert db.health_check()
