"""Tests for deterministic risk scoring."""

from patchledger.config import PatchLedgerConfig
from patchledger.models import Confidence, Finding
from patchledger.normalizer import normalize_findings
from patchledger.parsers.common import RawFinding
from patchledger.scoring import apply_scores, score_finding


def _finding(severity="HIGH", confidence=None, evidence="code()", category=None) -> Finding:
    raw = RawFinding(
        scanner="semgrep", rule_id="r1", message="m", file_path="a.py",
        start_line=1, severity_hint=severity, evidence=evidence,
    )
    finding = normalize_findings([raw], PatchLedgerConfig()).findings[0]
    if confidence:
        finding.confidence = Confidence(confidence)
    if category:
        finding.category = category
    return finding


def test_score_is_deterministic_and_explainable():
    config = PatchLedgerConfig()
    f = _finding()
    score1, factors1 = score_finding(f, config)
    score2, factors2 = score_finding(f, config)
    assert score1 == score2
    assert factors1 == factors2
    assert factors1[0].startswith("base severity high = 70")
    assert any("evidence present" in x for x in factors1)


def test_severity_drives_base_score():
    config = PatchLedgerConfig()
    scores = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        scores[sev] = score_finding(_finding(severity=sev.upper()), config)[0]
    assert scores["critical"] > scores["high"] > scores["medium"] > scores["low"] > scores["info"]


def test_confidence_and_category_adjustments_apply():
    config = PatchLedgerConfig()
    base_score, _ = score_finding(_finding(confidence="unknown"), config)
    boosted, factors = score_finding(
        _finding(confidence="high", category="secret"), config
    )
    assert boosted > base_score
    assert any("confidence high" in x for x in factors)
    assert any("category secret" in x for x in factors)


def test_missing_evidence_reduces_score():
    config = PatchLedgerConfig()
    with_ev, _ = score_finding(_finding(evidence="code()"), config)
    without_ev, factors = score_finding(_finding(evidence=""), config)
    assert without_ev < with_ev
    assert any("no evidence snippet" in x for x in factors)


def test_score_is_clamped():
    config = PatchLedgerConfig()
    config.scoring.severity_base["critical"] = 200
    score, factors = score_finding(_finding(severity="CRITICAL"), config)
    assert score == 100
    assert factors[-1].startswith("clamped")


def test_config_overrides_change_scores():
    config = PatchLedgerConfig()
    config.scoring.severity_base["high"] = 10
    score, _ = score_finding(_finding(severity="HIGH"), config)
    assert score == 15  # base 10 + evidence present 5 + confidence unknown 0


def test_apply_scores_updates_findings():
    findings = [_finding(), _finding(severity="LOW")]
    apply_scores(findings, PatchLedgerConfig())
    assert findings[0].score > findings[1].score
    assert findings[0].score_factors
