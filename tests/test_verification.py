"""Tests for scan comparison and evidence-based patch verification.

These encode the product's core promise: a finding is only called fixed when
the evidence supports it. Every false-resolution trap gets a test.
"""

import pytest

from patchledger.comparison import compare_scans
from patchledger.config import PatchLedgerConfig
from patchledger.models import (
    FindingStatus,
    Scan,
    ScanSource,
    ScanToolRun,
    ToolRunStatus,
)
from patchledger.normalizer import normalize_findings
from patchledger.parsers.common import RawFinding
from patchledger.storage import PatchLedgerDB
from patchledger.verification import (
    INCONCLUSIVE,
    VERIFIED_FIXED,
    resolution_verdict,
    update_ledger_after_scan,
    verify_scans,
)

CONFIG = PatchLedgerConfig()


def _finding(rule="rule-1", path="app.py", evidence="ev-1", severity="ERROR",
             scanner="semgrep") -> object:
    return normalize_findings(
        [RawFinding(scanner=scanner, rule_id=rule, message=f"msg {rule}",
                    file_path=path, start_line=1, severity_hint=severity, evidence=evidence)],
        CONFIG,
    ).findings[0]


def _insert(db, project_id, created_at, target="/repo", tools=None, findings=None,
            source=ScanSource.SCAN):
    scan = Scan(
        project_id=project_id,
        target_path=target,
        source=source,
        created_at=created_at,
        tools=tools if tools is not None else [
            ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN, version="1.0")
        ],
    )
    db.insert_scan(scan, findings or [])
    return scan


@pytest.fixture()
def db(tmp_path):
    with PatchLedgerDB(tmp_path / "db.sqlite") as db_handle:
        yield db_handle


def test_resolution_verified_when_scanner_reran(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding()
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00", findings=[])
    verdict = resolution_verdict(db, project.id, f.fingerprint, s2, CONFIG)
    assert verdict.state == VERIFIED_FIXED


def test_resolution_inconclusive_when_scanner_missing(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding()
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00",
                 tools=[ScanToolRun(tool="bandit", status=ToolRunStatus.RAN)])
    verdict = resolution_verdict(db, project.id, f.fingerprint, s2, CONFIG)
    assert verdict.state == INCONCLUSIVE
    assert any("semgrep did not run" in r for r in verdict.reasons)


def test_resolution_inconclusive_when_scanner_failed(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding()
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00",
                 tools=[ScanToolRun(tool="semgrep", status=ToolRunStatus.FAILED, note="boom")])
    verdict = resolution_verdict(db, project.id, f.fingerprint, s2, CONFIG)
    assert verdict.state == INCONCLUSIVE
    assert any("did not run successfully" in r for r in verdict.reasons)


def test_resolution_inconclusive_when_current_scan_imported(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding()
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00",
                 tools=[ScanToolRun(tool="semgrep", status=ToolRunStatus.IMPORTED)],
                 source=ScanSource.IMPORT)
    verdict = resolution_verdict(db, project.id, f.fingerprint, s2, CONFIG)
    assert verdict.state == INCONCLUSIVE
    assert any("imported" in r for r in verdict.reasons)


def test_resolution_inconclusive_across_different_targets(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding()
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f], target="/repo")
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00", findings=[], target="/other")
    verdict = resolution_verdict(db, project.id, f.fingerprint, s2, CONFIG)
    assert verdict.state == INCONCLUSIVE


def test_version_change_is_caveat_not_blocker(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding()
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00",
                 tools=[ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN, version="2.0")])
    verdict = resolution_verdict(db, project.id, f.fingerprint, s2, CONFIG)
    assert verdict.state == VERIFIED_FIXED
    assert any("version changed" in c for c in verdict.caveats)


def test_verify_scans_reports_counts(db):
    project = db.ensure_project("demo", "/repo")
    f1 = _finding(rule="gone", evidence="ev-gone")
    f2 = _finding(rule="stays", evidence="ev-stays")
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f1, f2])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00", findings=[f2])
    s1 = db.list_scans(project.id)[0]
    report = verify_scans(db, s1, s2, CONFIG)
    counts = report.counts()
    assert counts["new"] == 0
    assert counts["persistent"] == 1
    assert counts["resolved_candidates"] == 1
    assert counts["verified_fixed"] == 1
    assert counts["inconclusive"] == 0


def test_reintroduction_detected(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding(rule="regression", evidence="ev-r")
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f])
    _insert(db, project.id, "2026-11-02T00:00:00+00:00", findings=[])  # resolved here
    s3 = _insert(db, project.id, "2026-11-03T00:00:00+00:00", findings=[f])
    s2 = db.list_scans(project.id)[1]
    diff = compare_scans(db, s2, s3)
    assert [fl.title for fl in diff.reintroduced]  # came back vs baseline s2


def test_compare_flags_changed_severity_and_evidence(db):
    project = db.ensure_project("demo", "/repo")
    old = _finding(rule="r", evidence="same code", severity="WARNING")
    new = _finding(rule="r", evidence="same code", severity="ERROR")
    moved_old = _finding(rule="moved", evidence="same snippet", severity="ERROR")
    # same identity, different reported line -> changed evidence
    moved_new = normalize_findings(
        [RawFinding(scanner="semgrep", rule_id="moved", message="msg moved",
                    file_path="app.py", start_line=99, severity_hint="ERROR",
                    evidence="same snippet")],
        CONFIG,
    ).findings[0]
    s1 = _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[old, moved_old])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00", findings=[new, moved_new])
    diff = compare_scans(db, s1, s2)
    assert len(diff.persistent) == 2
    assert len(diff.changed_severity) == 1
    assert len(diff.changed_evidence) == 1


def test_content_change_produces_new_identity_not_changed_evidence(db):
    """Editing the flagged code = old finding resolves + new finding appears."""
    project = db.ensure_project("demo", "/repo")
    old = _finding(rule="r", evidence="old code")
    new = _finding(rule="r", evidence="new code")
    s1 = _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[old])
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00", findings=[new])
    diff = compare_scans(db, s1, s2)
    assert len(diff.persistent) == 0
    assert len(diff.resolved_candidates) == 1
    assert len(diff.new) == 1


def test_compare_incompatible_targets_note(db):
    project = db.ensure_project("demo", "/repo")
    s1 = _insert(db, project.id, "2026-11-01T00:00:00+00:00", target="/repo")
    s2 = _insert(db, project.id, "2026-11-02T00:00:00+00:00", target="/elsewhere")
    diff = compare_scans(db, s1, s2)
    assert diff.compatible is False
    assert diff.notes


def test_ledger_statuses_across_lifecycle(db):
    project = db.ensure_project("demo", "/repo")
    fixed = _finding(rule="will-fix", evidence="ev-will-fix")
    persistent = _finding(rule="persists", evidence="ev-persists")
    # a finding that only bandit ever reported -> verifiable only while bandit runs
    bandit_only = _finding(rule="bandit-only", evidence="ev-bandit", scanner="bandit")

    # scan 1 (semgrep+bandit ran): fixed, persistent, bandit_only all present
    _insert(db, project.id, "2026-11-01T00:00:00+00:00",
            tools=[ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN, version="1.0"),
                   ScanToolRun(tool="bandit", status=ToolRunStatus.RAN, version="1.0")],
            findings=[fixed, persistent, bandit_only])
    # scan 2 (only bandit): fixed absent -> resolution candidate, semgrep missing
    _insert(db, project.id, "2026-11-02T00:00:00+00:00",
            tools=[ScanToolRun(tool="bandit", status=ToolRunStatus.RAN, version="1.0")],
            findings=[persistent, bandit_only])

    ledger = {e.fingerprint: e for e in update_ledger_after_scan(db, project.id, CONFIG)}
    assert ledger[fixed.fingerprint].status == FindingStatus.INCONCLUSIVE  # semgrep missing
    assert ledger[persistent.fingerprint].status == FindingStatus.OPEN
    assert ledger[bandit_only.fingerprint].status == FindingStatus.OPEN  # present in latest

    # scan 3 (only semgrep): fixed absent again -> now verifiable;
    # bandit_only absent -> bandit missing -> inconclusive
    _insert(db, project.id, "2026-11-03T00:00:00+00:00",
            tools=[ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN, version="1.0")],
            findings=[persistent])
    ledger = {e.fingerprint: e for e in update_ledger_after_scan(db, project.id, CONFIG)}
    assert ledger[fixed.fingerprint].status == FindingStatus.RESOLVED
    assert ledger[fixed.fingerprint].verdict is not None
    assert ledger[fixed.fingerprint].verdict.is_verified
    assert ledger[bandit_only.fingerprint].status == FindingStatus.INCONCLUSIVE

    history = db.status_history(project.id)
    statuses = [h["status"] for h in history]
    assert "inconclusive" in statuses and "resolved" in statuses


def test_reintroduction_via_ledger(db):
    project = db.ensure_project("demo", "/repo")
    f = _finding(rule="relapse", evidence="ev-relapse")
    _insert(db, project.id, "2026-11-01T00:00:00+00:00", findings=[f])
    _insert(db, project.id, "2026-11-02T00:00:00+00:00", findings=[])  # resolved
    update_ledger_after_scan(db, project.id, CONFIG)  # pipeline runs this after every scan
    _insert(db, project.id, "2026-11-03T00:00:00+00:00", findings=[f])  # back again
    ledger = {e.fingerprint: e for e in update_ledger_after_scan(db, project.id, CONFIG)}
    assert ledger[f.fingerprint].status == FindingStatus.REINTRODUCED
