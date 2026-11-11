"""Tests for report parsers (happy paths)."""


from conftest import fixture_path, load_fixture_json
from patchledger.config import PatchLedgerConfig
from patchledger.parsers import parse_report_file


def test_parse_semgrep_fixture(tmp_path):
    result = parse_report_file(fixture_path("semgrep_basic.json"), PatchLedgerConfig())
    assert result.scanner == "semgrep"
    assert len(result.findings) == 2
    f = result.findings[0]
    assert f.rule_id == "python.lang.security.audit.subprocess-shell-true"
    assert f.file_path == "app/shell.py"
    assert f.start_line == 10
    assert f.severity_hint == "ERROR"
    assert f.evidence.strip() == "subprocess.run(cmd, shell=True)"


def test_parse_bandit_fixture(tmp_path):
    result = parse_report_file(fixture_path("bandit_basic.json"), PatchLedgerConfig())
    assert result.scanner == "bandit"
    assert len(result.findings) == 2
    f = result.findings[0]
    assert f.rule_id == "B602"
    assert f.start_line == 10
    assert f.end_line == 12
    assert f.severity_hint == "HIGH"
    assert f.confidence_hint == "HIGH"
    assert "shell=True" in f.evidence
    assert not f.evidence.lstrip().startswith(">")


def test_parse_gitleaks_fixture(gitleaks_report):
    result = parse_report_file(gitleaks_report, PatchLedgerConfig())
    assert result.scanner == "gitleaks"
    assert len(result.findings)  # 2 entries
    f = result.findings[0]
    assert f.rule_id == "aws-access-token"
    assert f.file_path == "config/settings.py"
    assert f.metadata["raw_secret"]  # carried for normalizer redaction
    assert f.evidence == ""  # parser leaves evidence empty


def test_parse_pip_audit_fixture(tmp_path):
    result = parse_report_file(fixture_path("pip_audit_basic.json"), PatchLedgerConfig())
    assert result.scanner == "pip-audit"
    # 2 vulnerable packages, 1 vuln each (jinja2 has none)
    assert len(result.findings) == 2
    f = result.findings[0]
    assert f.rule_id == "PYSEC-2026-0001"
    assert f.evidence == "flask==2.3.2"
    assert f.fix and "2.3.3" in f.fix


def test_parse_pip_audit_wrapped_object(tmp_path):
    """pip-audit 2.x emits {"dependencies": [...], "fixes": [...]} (verified live)."""
    from conftest import write_json

    raw = load_fixture_json("pip_audit_basic.json")
    p = write_json(tmp_path, "pip_audit_wrapped.json", {"dependencies": raw, "fixes": []})
    result = parse_report_file(p, PatchLedgerConfig())
    assert result.scanner == "pip-audit"
    assert len(result.findings) == 2


def test_pip_audit_duplicate_advisories_merge():
    """pip-audit reports the same advisory from multiple sources; dedup merges."""
    from patchledger.deduplication import merge_duplicates
    from patchledger.normalizer import normalize_findings

    result = parse_report_file(fixture_path("pip_audit_basic.json"), PatchLedgerConfig())
    raws = result.findings + list(result.findings)  # simulate duplicate advisory entries
    config = PatchLedgerConfig()
    findings = normalize_findings(raws, config).findings
    merged, count = merge_duplicates(findings)
    assert len(merged) == 2
    assert count == 2
    assert all(len(f.occurrences) == 2 for f in merged)


def test_parse_sarif_fixture(tmp_path):
    # scan_root matches the originalUriBaseIds target so absolute URIs relativize
    result = parse_report_file(
        fixture_path("sarif_basic.sarif"), PatchLedgerConfig(), scan_root="/home/dev/project"
    )
    assert result.scanner == "Semgrep"
    assert len(result.findings) == 3
    first, second, trivy = result.findings
    assert first.file_path == "app/db.py"
    assert first.start_line == 30
    assert first.evidence.strip().startswith("query")
    assert first.severity_hint == "error"
    assert first.fix and "parameterized" in first.fix
    # second: no explicit level -> rule default error; URI-escaped path decoded
    assert second.file_path == "app/paths.py"
    assert second.severity_hint == "error"
    # third: second run scanned by Trivy
    assert trivy.scanner == "Trivy"
