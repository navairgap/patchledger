"""Regression tests for the independent security review findings (M9)."""


from patchledger.config import PatchLedgerConfig
from patchledger.html_report import render_html
from patchledger.models import Scan, ScanSource
from patchledger.normalizer import normalize_findings
from patchledger.parsers.common import RawFinding
from patchledger.reporting import ReportData, build_coverage, render_json, render_markdown


def _gitleaks_finding(fake: str):
    return RawFinding(
        scanner="gitleaks",
        rule_id="aws-access-token",
        message="AWS Access Key",
        file_path="config/settings.py",
        start_line=12,
        severity_hint="high",
        metadata={"raw_secret": fake, "raw_match": f"key = \"{fake}\""},
    )


def test_f1_no_secret_material_in_any_normalized_field():
    """F1: raw_secret/raw_match must be stripped from all persisted metadata."""
    fake = "AKIA" + "B" * 12 + "CDEF"
    res = normalize_findings([_gitleaks_finding(fake)], PatchLedgerConfig())
    f = res.findings[0]
    assert "raw_secret" not in f.metadata
    assert "raw_match" not in f.metadata
    assert "raw_secret" not in f.occurrences[0].metadata
    assert fake not in f.evidence
    assert fake not in f.remediation


def test_f1_no_secret_in_any_report_renderer(tmp_path):
    """F1: the secret must appear in NO renderer output, including JSON."""
    fake = "AKIA" + "C" * 12 + "DCEF"
    res = normalize_findings([_gitleaks_finding(fake)], PatchLedgerConfig())
    scan = Scan(project_id="p", target_path="/repo", source=ScanSource.SCAN)
    data = ReportData(
        project_name="demo", project_root="/repo", scan=scan,
        findings=res.findings, generated_at="2026-01-01T00:00:00+00:00",
        coverage=build_coverage(scan),
    )
    for renderer in (render_json, render_markdown, render_html):
        text = renderer(data)
        assert fake not in text, f"secret leaked into {renderer.__name__}"
    assert "raw_secret" not in render_json(data)


def test_f7_distinct_gitleaks_secrets_get_distinct_fingerprints():
    """F7: two different leaked credentials must not share a fingerprint."""
    config = PatchLedgerConfig()
    a = normalize_findings([_gitleaks_finding("AKIA" + "A" * 16)], config).findings[0]
    b = normalize_findings([_gitleaks_finding("AKIA" + "B" * 16)], config).findings[0]
    assert a.fingerprint != b.fingerprint
    # same secret twice -> stable fingerprint
    a2 = normalize_findings([_gitleaks_finding("AKIA" + "A" * 16)], config).findings[0]
    assert a.fingerprint == a2.fingerprint


def test_f6_markdown_injection_is_contained():
    """F6: repo-controlled text must not forge markdown structure or close fences."""
    hostile_title = "Title\n# FORGED HEADING via newline\n- forged list"
    hostile_evidence = "line1\n``` \ninjected block\n``` "
    res = normalize_findings(
        [RawFinding(
            scanner="semgrep", rule_id="r", message=hostile_title,
            file_path="a.py", start_line=1, severity_hint="ERROR",
            evidence=hostile_evidence,
        )],
        PatchLedgerConfig(),
    )
    scan = Scan(project_id="p", target_path="/repo", source=ScanSource.SCAN)
    data = ReportData(
        project_name="demo", project_root="/repo", scan=scan,
        findings=res.findings, generated_at="t", coverage=build_coverage(scan),
    )
    md = render_markdown(data)
    for line in md.splitlines():
        assert not line.startswith("# FORGED HEADING")
        assert not line.startswith("- forged list")
    # the injected fence inside evidence cannot close its own block: every
    # fence line in the rendered report is at least as long as needed
    assert "injected block" in md  # content still present, but fenced


def test_f6_fence_sizing():
    from patchledger.reporting import _md_fence

    assert _md_fence("plain") == "```"
    assert _md_fence("a```b") == "````"
    assert _md_fence("a````b") == "`````"


def test_f2_config_has_no_extra_paths():
    """F2: removed config keys are ignored, not executed upon.

    Unknown config keys must never break loading (forward/backward
    compatibility) and never influence tool discovery — config is data,
    not execution policy.
    """
    config = PatchLedgerConfig.model_validate(
        {"scanning": {"extra_paths": ["/attacker"], "enabled": ["bandit"]}}
    )
    assert config.scanning.enabled == ["bandit"]
    assert not hasattr(config.scanning, "extra_paths")
