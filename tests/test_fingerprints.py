"""Tests for deterministic fingerprint generation."""

from patchledger.fingerprints import (
    compute_fingerprint,
    normalize_path_for_fingerprint,
    normalize_scanner_name,
    normalize_text_for_fingerprint,
)


def test_scanner_name_normalization():
    assert normalize_scanner_name("Semgrep") == "semgrep"
    assert normalize_scanner_name("pip_audit") == "pip-audit"
    assert normalize_scanner_name("  Trivy ") == "trivy"
    assert normalize_scanner_name("Custom Tool") == "custom-tool"


def test_path_normalization():
    assert normalize_path_for_fingerprint("a//b\\c.py") == "a/b/c.py"
    assert normalize_path_for_fingerprint(None) == ""
    assert normalize_path_for_fingerprint("/x/y/") == "x/y"


def test_text_normalization():
    assert normalize_text_for_fingerprint("  a\n  b\t c ") == "a b c"
    assert normalize_text_for_fingerprint(None) == ""


def test_fingerprint_is_stable_across_cosmetic_changes():
    a = compute_fingerprint(
        scanner="Semgrep", rule_id="r1", file_path="a//b.py", message="msg", evidence=""
    )
    b = compute_fingerprint(
        scanner="semgrep", rule_id="r1", file_path="a/b.py", message="  msg  ", evidence="other"
    )
    assert a == b


def test_fingerprint_changes_with_substance():
    variants = [
        dict(scanner="semgrep", rule_id="r2", file_path="a.py", message="m", evidence=""),
        dict(scanner="semgrep", rule_id="r1", file_path="b.py", message="m", evidence=""),
        dict(scanner="semgrep", rule_id="r1", file_path="a.py", message="m2", evidence=""),
        dict(scanner="bandit", rule_id="r1", file_path="a.py", message="m", evidence=""),
    ]
    fps = {compute_fingerprint(**v) for v in variants}
    assert len(fps) == len(variants)


def test_fingerprint_falls_back_to_evidence_when_message_empty():
    a = compute_fingerprint(scanner="s", rule_id="r", file_path="f", message="", evidence="EV")
    b = compute_fingerprint(scanner="s", rule_id="r", file_path="f", message="EV", evidence="")
    assert a == b


def test_fingerprint_has_version_prefix():
    fp = compute_fingerprint(scanner="s", rule_id="r", file_path=None, message="m", evidence="")
    assert fp.startswith("fp1:")
