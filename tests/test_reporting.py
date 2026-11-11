"""Tests for report generation: JSON, Markdown, HTML, and XSS resistance."""

import json

from patchledger.config import PatchLedgerConfig
from patchledger.html_report import render_html
from patchledger.models import Finding, Scan, ScanSource, ScanToolRun, Severity, ToolRunStatus
from patchledger.normalizer import normalize_findings
from patchledger.parsers.common import RawFinding
from patchledger.reporting import (
    ReportData,
    build_coverage,
    render_json,
    render_markdown,
    sort_findings,
)

HOSTILE = '<script>alert("xss")</script>" onload="alert(1)'


def _finding(severity="high", rule="r1", title="Finding title",
             evidence="evidence()", path="src/app.py", line=3) -> Finding:
    return normalize_findings(
        [RawFinding(scanner="semgrep", rule_id=rule, message=title, file_path=path,
                    start_line=line, severity_hint=severity.upper(), evidence=evidence)],
        PatchLedgerConfig(),
    ).findings[0]


def _report(findings, tools=None, synthetic=False) -> ReportData:
    scan = Scan(
        project_id="p1",
        target_path="/repo",
        source=ScanSource.SCAN,
        tools=tools if tools is not None else [
            ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN)
        ],
    )
    return ReportData(
        project_name="demo",
        project_root="/repo",
        scan=scan,
        findings=findings,
        generated_at="2026-11-11T00:00:00+00:00",
        coverage=build_coverage(scan),
        is_synthetic_example=synthetic,
    )


def test_json_report_structure():
    report = _report([_finding()])
    doc = json.loads(render_json(report))
    assert doc["project"]["name"] == "demo"
    assert doc["coverage"]["complete"] is True
    assert doc["overall_status"] == "FAIL"
    assert doc["summary"]["finding_count"] == 1
    assert doc["findings"][0]["severity"] == "high"
    assert doc["findings"][0]["occurrences"][0]["file_path"] == "src/app.py"


def test_json_report_records_incomplete_coverage():
    tools = [
        ScanToolRun(tool="semgrep", status=ToolRunStatus.RAN),
        ScanToolRun(tool="gitleaks", status=ToolRunStatus.UNAVAILABLE, note="missing"),
    ]
    doc = json.loads(render_json(_report([], tools=tools)))
    assert doc["coverage"]["complete"] is False
    assert doc["coverage"]["unavailable"] == ["gitleaks"]
    assert "incomplete" in doc["overall_status"].lower()


def test_markdown_report_sections():
    report = _report([_finding()], synthetic=True)
    md = render_markdown(report)
    assert "# PatchLedger Security Report" in md
    assert "SYNTHETIC EXAMPLE DATA" in md
    assert "## Scanner coverage" in md
    assert "## Summary" in md
    assert "### 1. [HIGH] Finding title" in md
    assert "Remediation guidance" in md


def test_markdown_escapes_pipe_in_notes():
    tools = [ScanToolRun(tool="t", status=ToolRunStatus.FAILED, note="a|b|c")]
    md = render_markdown(_report([], tools=tools))
    assert "a\\|b\\|c" in md


def test_html_is_self_contained_and_dark():
    report = _report([_finding()])
    html_out = render_html(report)
    assert html_out.startswith("<!DOCTYPE html>")
    assert "Content-Security-Policy" in html_out
    assert "--bg: #0d1117" in html_out
    assert "<script" not in html_out


def test_html_escapes_hostile_finding_text():
    report = _report(
        [_finding(title=HOSTILE, evidence=HOSTILE, rule=HOSTILE, path=HOSTILE)]
    )
    html_out = render_html(report)
    assert "<script>alert" not in html_out
    assert 'onload="alert' not in html_out
    assert "&lt;script&gt;" in html_out


def test_json_report_takes_verbatim_hostile_text():
    """JSON is a data format: content stays verbatim, consumers must escape."""
    doc = json.loads(render_json(_report([_finding(title=HOSTILE)])))
    assert doc["findings"][0]["title"] == HOSTILE


def test_sort_findings_order():
    findings = [
        _finding(severity="low", rule="r-low"),
        _finding(severity="critical", rule="r-crit"),
        _finding(severity="high", rule="r-high"),
    ]
    ordered = sort_findings(findings)
    assert [f.severity for f in ordered] == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]


def test_overall_status_levels():
    assert _report([]).overall_status().startswith("PASS")
    assert _report([_finding(severity="medium")]).overall_status().startswith("WARN")
    assert _report([_finding(severity="critical")]).overall_status().startswith("FAIL")
