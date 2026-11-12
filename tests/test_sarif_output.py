"""Tests for SARIF output."""

import json

from patchledger.config import PatchLedgerConfig
from patchledger.models import Scan, ScanSource, ScanToolRun, ToolRunStatus
from patchledger.normalizer import normalize_findings
from patchledger.parsers.common import RawFinding
from patchledger.reporting import ReportData, build_coverage
from patchledger.sarif_output import render_sarif


def _report() -> ReportData:
    findings = normalize_findings(
        [
            RawFinding(
                scanner="semgrep", rule_id="r1", message="issue one",
                file_path="app.py", start_line=10, severity_hint="ERROR",
                evidence="code()",
            ),
            RawFinding(
                scanner="pip-audit", rule_id="PYSEC-1", message="dep vuln",
                severity_hint="high", evidence="flask==0.12.4",
            ),
        ],
        PatchLedgerConfig(),
    ).findings
    scan = Scan(
        project_id="p", target_path="/repo", source=ScanSource.SCAN,
        tools=[
            ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN, version="1.0"),
            ScanToolRun(tool="gitleaks", status=ToolRunStatus.UNAVAILABLE, note="missing"),
        ],
    )
    return ReportData(
        project_name="demo", project_root="/repo", scan=scan,
        findings=findings, generated_at="2026-01-01T00:00:00+00:00",
        coverage=build_coverage(scan),
    )


def test_sarif_is_valid_2_1_0():
    doc = json.loads(render_sarif(_report()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "PatchLedger"
    assert len(run["results"]) == 2
    assert {r["ruleId"] for r in run["results"]} == {"r1", "PYSEC-1"}


def test_sarif_fingerprints_and_levels():
    doc = json.loads(render_sarif(_report()))
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert results["r1"]["level"] == "error"
    assert results["PYSEC-1"]["level"] == "error"
    fp = results["r1"]["partialFingerprints"]["patchledgerFingerprint/v1"]
    assert fp.startswith("fp2:")
    assert results["r1"]["properties"]["rawSeverity"] == "ERROR"


def test_sarif_locations_and_coverage_honesty():
    doc = json.loads(render_sarif(_report()))
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    # file finding has a location; dependency finding has none
    assert results["r1"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert results["PYSEC-1"]["locations"] == []
    run = doc["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False  # gitleaks unavailable
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert any("gitleaks" in n["message"]["text"] for n in notifications)
    assert run["properties"]["coverageComplete"] is False
