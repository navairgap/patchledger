"""Tests for the core data models."""

import pytest

from patchledger.models import (
    Finding,
    Occurrence,
    Scan,
    ScanSource,
    ScanToolRun,
    Severity,
    ToolRunStatus,
)


def test_finding_location_str():
    f = Finding(
        fingerprint="fp1:abc", scanner="semgrep", rule_id="r", severity=Severity.HIGH,
        title="t", file_path="src/app.py", start_line=42,
    )
    assert f.location_str == "src/app.py:42"
    f2 = Finding(fingerprint="fp1:abc", scanner="s", rule_id="r", severity=Severity.LOW, title="t")
    assert f2.location_str == "-"


def test_finding_rejects_unknown_fields():
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        Finding(
            fingerprint="x", scanner="s", rule_id="r",
            severity=Severity.LOW, title="t", bogus=1,
        )


def test_scan_tool_map():
    scan = Scan(
        project_id="p",
        target_path="/repo",
        source=ScanSource.SCAN,
        tools=[ScanToolRun(tool="bandit", status=ToolRunStatus.FAILED)],
    )
    tm = scan.tool_map()
    assert tm["bandit"].status == ToolRunStatus.FAILED


def test_occurrence_defaults():
    occ = Occurrence(scanner="bandit", rule_id="B602")
    assert occ.evidence == ""
    assert occ.metadata == {}
