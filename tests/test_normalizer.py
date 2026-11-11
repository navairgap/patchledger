"""Tests for finding normalization: severity, confidence, redaction, suppression."""

from patchledger.config import PatchLedgerConfig
from patchledger.models import Confidence, Severity
from patchledger.normalizer import (
    map_confidence,
    map_severity,
    normalize_findings,
    redact_text,
)
from patchledger.parsers.common import RawFinding


def _raw(**kwargs) -> RawFinding:
    defaults = dict(
        scanner="semgrep",
        rule_id="some-rule",
        message="Message text",
        file_path="src/app.py",
        start_line=1,
        severity_hint="ERROR",
    )
    defaults.update(kwargs)
    return RawFinding(**defaults)


def test_severity_mapping_table():
    assert map_severity("ERROR") == Severity.HIGH
    assert map_severity("error") == Severity.HIGH
    assert map_severity("WARNING") == Severity.MEDIUM
    assert map_severity("critical") == Severity.CRITICAL
    assert map_severity("note") == Severity.INFO
    assert map_severity("MODERATE") == Severity.MEDIUM
    assert map_severity(None) == Severity.UNKNOWN
    assert map_severity("banana") == Severity.UNKNOWN


def test_confidence_mapping():
    assert map_confidence("HIGH") == Confidence.HIGH
    assert map_confidence("Medium") == Confidence.MEDIUM
    assert map_confidence(None) == Confidence.UNKNOWN


def test_basic_normalization_preserves_metadata():
    config = PatchLedgerConfig()
    res = normalize_findings([_raw(metadata={"custom": "x"})], config)
    f = res.findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.UNKNOWN
    assert f.metadata == {"custom": "x"}
    assert f.occurrences[0].metadata == {"custom": "x"}
    assert f.category in {"sast", "injection", "other"}
    assert f.remediation  # guidance attached


def test_gitleaks_evidence_is_redacted():
    config = PatchLedgerConfig()
    fake = "AKIA" + "B" * 12 + "CDEF"
    raw = RawFinding(
        scanner="gitleaks",
        rule_id="aws-access-token",
        message="AWS Access Key",
        file_path="config/settings.py",
        start_line=12,
        severity_hint="high",
        metadata={"raw_secret": fake, "raw_match": f"key = \"{fake}\""},
    )
    res = normalize_findings([raw], config)
    f = res.findings[0]
    assert f.severity == Severity.HIGH
    assert f.category == "secret"
    assert fake not in f.evidence
    assert fake not in f.occurrences[0].evidence
    assert "secret redacted" in f.evidence


def test_redact_text_masks_quoted_literals():
    fake = "x-live-" + "a" * 30
    text = f'API_KEY = "{fake}"'
    out = redact_text(text)
    assert fake not in out
    assert "[redacted]" in out


def test_redact_text_masks_private_key_blocks():
    key = "-----BEGIN RSA PRIVATE KEY-----\n" + "AAAA" * 40 + "\n-----END RSA PRIVATE KEY-----"
    out = redact_text(key)
    assert "AAAA" * 40 not in out
    assert "[redacted private key block]" in out


def test_redaction_can_be_disabled():
    config = PatchLedgerConfig()
    config.redact_secrets = False
    fake = "x-live-" + "b" * 30
    raw = _raw(
        rule_id="hardcoded-password-string",
        message="hardcoded secret",
        evidence=f'PASSWORD = "{fake}"',
    )
    res = normalize_findings([raw], config)
    assert fake in res.findings[0].evidence


def test_disabled_rules_suppression_is_counted():
    config = PatchLedgerConfig()
    config.import_config.disabled_rules = ["some-rule"]
    res = normalize_findings([_raw(), _raw()], config)
    assert res.findings == []
    assert res.suppressed == {"some-rule": 2}


def test_semgrep_sarif_cross_format_fingerprint_stability():
    """Same semgrep finding via JSON and SARIF must produce the same fingerprint."""
    from patchledger.parsers.sarif import parse_sarif
    from patchledger.parsers.semgrep import parse_semgrep

    config = PatchLedgerConfig()
    json_result = parse_semgrep(
        {
            "results": [
                {
                    "check_id": "r1",
                    "path": "app.py",
                    "start": {"line": 3},
                    "end": {"line": 3},
                    "extra": {"message": "Same message", "severity": "ERROR", "lines": "code()"},
                }
            ]
        }
    )
    sarif_result = parse_sarif(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "r1",
                            "level": "error",
                            "message": {"text": "Same message"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )
    f_json = normalize_findings(json_result.findings, config).findings[0]
    f_sarif = normalize_findings(sarif_result.findings, config).findings[0]
    assert f_json.fingerprint == f_sarif.fingerprint
