"""Tests for within-scan deduplication."""

from patchledger.config import PatchLedgerConfig
from patchledger.deduplication import merge_duplicates
from patchledger.models import Severity
from patchledger.normalizer import normalize_findings
from patchledger.parsers.common import RawFinding


def _raw(rule_id="r1", path="app.py", message="m", line=1, scanner="semgrep"):
    return RawFinding(
        scanner=scanner, rule_id=rule_id, message=message,
        file_path=path, start_line=line, severity_hint="ERROR",
    )


def test_identical_findings_merge_preserving_occurrences():
    config = PatchLedgerConfig()
    findings = normalize_findings([_raw(line=5), _raw(line=9)], config).findings
    assert len(findings) == 2  # before merge: two Finding objects, same fingerprint
    merged, count = merge_duplicates(findings)
    assert count == 1  # one duplicate folded away
    assert len(merged) == 1
    assert len(merged[0].occurrences) == 2
    assert merged[0].occurrences[0].start_line == 5
    assert merged[0].occurrences[1].start_line == 9


def test_generic_message_findings_stay_distinct():
    """Two bandit B101 asserts with different snippets must not merge."""
    config = PatchLedgerConfig()
    a = normalize_findings(
        [_raw(rule_id="B101", message="Use of assert detected.", scanner="bandit", line=3)],
        config,
    ).findings[0]
    b = normalize_findings(
        [_raw(rule_id="B101", message="Use of assert detected.", scanner="bandit", line=8)],
        config,
    ).findings[0]
    # evidence differs (bandit code snippets) -> different fingerprints
    a.evidence, b.evidence = "assert x", "assert y"
    from patchledger.fingerprints import compute_fingerprint

    a.fingerprint = compute_fingerprint(
        scanner="bandit", rule_id="B101", file_path="app.py",
        message="Use of assert detected.", evidence="assert x",
    )
    b.fingerprint = compute_fingerprint(
        scanner="bandit", rule_id="B101", file_path="app.py",
        message="Use of assert detected.", evidence="assert y",
    )
    merged, count = merge_duplicates([a, b])
    assert count == 0
    assert len(merged) == 2


def test_most_severe_occurrence_becomes_primary():
    config = PatchLedgerConfig()
    low = normalize_findings(
        [RawFinding(scanner="semgrep", rule_id="r1", message="m", file_path="app.py",
                    start_line=1, severity_hint="NOTE")], config
    ).findings[0]
    high = normalize_findings(
        [RawFinding(scanner="semgrep", rule_id="r1", message="m", file_path="app.py",
                    start_line=1, severity_hint="ERROR")], config
    ).findings[0]
    merged, _ = merge_duplicates([low, high])
    assert len(merged) == 1
    assert merged[0].severity == Severity.HIGH
