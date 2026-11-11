"""Deterministic, explainable risk scoring.

The score is a prioritization aid, not a judgment: it starts from the
normalized severity (which comes from the scanner via explicit mapping
tables) and applies documented, configurable adjustments. Every adjustment
is recorded on the finding, so every score can be explained line by line.

PatchLedger never invents CVSS scores and never escalates severity on its
own — the score can only reflect evidence that scanners actually reported.
"""

from __future__ import annotations

from patchledger.config import PatchLedgerConfig
from patchledger.models import Finding


def score_finding(finding: Finding, config: PatchLedgerConfig) -> tuple[int, list[str]]:
    """Compute the risk score and the list of factors that produced it.

    Returns (score 0-100, factors). Pure function — deterministic for any
    finding + config pair.
    """
    rules = config.scoring
    score = rules.severity_base.get(finding.severity.value, 30)
    factors = [f"base severity {finding.severity.value} = {score}"]

    conf_adj = rules.confidence_adjustment.get(finding.confidence.value, 0)
    if conf_adj:
        score += conf_adj
        factors.append(f"scanner confidence {finding.confidence.value}: {conf_adj:+d}")

    if finding.evidence.strip():
        score += rules.evidence_present_adjustment
        factors.append(f"evidence present: {rules.evidence_present_adjustment:+d}")
    else:
        score += rules.evidence_missing_adjustment
        factors.append(f"no evidence snippet: {rules.evidence_missing_adjustment:+d}")

    category_adj = rules.category_adjustment.get(finding.category, 0)
    if category_adj:
        score += category_adj
        factors.append(f"category {finding.category}: {category_adj:+d}")

    score = max(0, min(100, score))
    factors.append(f"clamped to 0-100 → {score}")
    return score, factors


def apply_scores(findings: list[Finding], config: PatchLedgerConfig) -> list[Finding]:
    """Score findings in place (returns the same list for chaining)."""
    for finding in findings:
        finding.score, finding.score_factors = score_finding(finding, config)
    return findings
