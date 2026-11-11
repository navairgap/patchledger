"""AI review prompt generation — works offline, no API key required.

Produces a Markdown prompt (and a JSON variant) that a developer can paste
into ANY external AI assistant or human reviewer. The prompt carries the
evidence, asks focused questions, and explicitly forbids inventing facts.
The generator itself never calls a model.
"""

from __future__ import annotations

import json

from patchledger import __version__
from patchledger.models import Finding, FindingStatus, Scan
from patchledger.verification import LedgerEntry

_REVIEWABLE = (FindingStatus.OPEN, FindingStatus.INCONCLUSIVE, FindingStatus.REINTRODUCED)

PROMPT_CONSTRAINTS = """Rules for the reviewer:
- Do NOT invent evidence. Only reason from the code, the evidence snippets and
  the metadata below. If the provided context is insufficient, say exactly
  what is missing and how to obtain it.
- Do NOT claim a vulnerability is fixed or exploitable without citing the
  specific code that proves it.
- Propose minimal, safe fixes: smallest change that removes the issue without
  changing unrelated behavior. Note any behavior change explicitly.
- Do not propose disabling the scanner rule or suppressing the finding unless
  you can prove it is a false positive — and then say what proof is missing.
- If a finding is marked inconclusive, first assess whether the code is
  actually fixed; do not assume either way.
"""


def _finding_block(index: int, finding: Finding, status: FindingStatus) -> list[str]:
    lines = [
        f"### Finding {index}: {finding.title}",
        f"- Status in ledger: **{status.value}**"
        + ("" if status != FindingStatus.INCONCLUSIVE else
           " (absent from the latest scan, but resolution could not be verified — "
           "treat as possibly still present)"),
        f"- Scanner: {finding.scanner} — rule `{finding.rule_id}`",
        f"- Severity: {finding.severity.value}"
        + (f" (scanner reported: {finding.raw_severity})" if finding.raw_severity else ""),
        f"- Confidence: {finding.confidence.value}",
        f"- Location: `{finding.location_str}`",
        f"- Fingerprint: `{finding.fingerprint}`",
    ]
    if finding.description and finding.description != finding.title:
        lines.append(f"- Detail: {finding.description}")
    if finding.evidence:
        lines.append("- Evidence (scanner-reported, secrets redacted):")
        lines.append("```")
        lines.extend(finding.evidence.rstrip().splitlines()[:20])
        lines.append("```")
    if finding.remediation:
        lines.append("- Local remediation guidance (advice, verify against the code):")
        for line in finding.remediation.splitlines():
            lines.append(f"  > {line}")
    if len(finding.occurrences) > 1:
        lines.append(f"- {len(finding.occurrences)} occurrences share this fingerprint.")
    lines.append("- Questions for the reviewer:")
    lines.append("  1. Is this finding real in the current code, or a false positive?")
    lines.append("  2. If real: what is the minimal safe fix? Show exact code.")
    lines.append("  3. If fixed: what in the code proves it?")
    lines.append("  4. What tests would prevent reintroduction?")
    return lines


def select_reviewable(ledger: list[LedgerEntry]) -> list[LedgerEntry]:
    """Findings worth review: open, reintroduced and inconclusive ones."""
    return [e for e in ledger if e.status in _REVIEWABLE]


def build_review_prompt(
    ledger: list[LedgerEntry],
    project_name: str,
    scan: Scan,
    max_findings: int = 25,
) -> str:
    """Build the full Markdown review prompt."""
    entries = select_reviewable(ledger)
    entries.sort(key=lambda e: -e.finding.score)
    truncated = entries[max_findings:]
    entries = entries[:max_findings]

    lines: list[str] = []
    lines.append("# Security review request")
    lines.append("")
    lines.append("You are reviewing security findings for the project below. The findings were")
    lines.append("produced by static scanners and normalized by PatchLedger. Evidence is")
    lines.append("scanner-reported; secrets have been redacted. Nothing here has been sent")
    lines.append("anywhere — you are reviewing a local export.")
    lines.append("")
    lines.append(f"- Project: {project_name}")
    lines.append(f"- Scan: {scan.id} ({scan.created_at}, source: {scan.source.value})")
    if scan.git_commit:
        lines.append(f"- Git: `{scan.git_commit[:12]}`"
                     + (f" ({scan.git_branch})" if scan.git_branch else ""))
    lines.append(f"- Findings selected for review: {len(entries)}"
                 + (f" (of {len(entries) + len(truncated)}; export truncated)"
                    if truncated else ""))
    lines.append("")
    lines.append(PROMPT_CONSTRAINTS)
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for i, entry in enumerate(entries, 1):
        lines.extend(_finding_block(i, entry.finding, entry.status))
        lines.append("")
    if truncated:
        lines.append(f"_({len(truncated)} further findings omitted by the export limit.)_")
        lines.append("")
    lines.append("## Response format")
    lines.append("")
    lines.append("For each finding, answer: verdict (real / false positive / already fixed /")
    lines.append("uncertain), the exact code change if a fix is needed, and the reasoning.")
    lines.append("")
    lines.append(f"_Generated by patchledger {__version__} — a deterministic, offline export._")
    lines.append("")
    return "\n".join(lines)


def build_review_prompt_json(ledger: list[LedgerEntry], project_name: str, scan: Scan) -> str:
    """JSON variant of the prompt payload (machine-consumable)."""
    entries = select_reviewable(ledger)
    doc = {
        "generator": f"patchledger {__version__}",
        "project": project_name,
        "scan": {"id": scan.id, "created_at": scan.created_at, "source": scan.source.value},
        "constraints": PROMPT_CONSTRAINTS,
        "findings": [
            {
                "fingerprint": e.finding.fingerprint,
                "status": e.status.value,
                "title": e.finding.title,
                "scanner": e.finding.scanner,
                "rule_id": e.finding.rule_id,
                "severity": e.finding.severity.value,
                "confidence": e.finding.confidence.value,
                "location": e.finding.location_str,
                "description": e.finding.description,
                "evidence": e.finding.evidence,
                "remediation_guidance": e.finding.remediation,
                "score": e.finding.score,
                "score_factors": e.finding.score_factors,
                "questions": [
                    "Is this finding real in the current code, or a false positive?",
                    "If real: what is the minimal safe fix?",
                    "If fixed: what in the code proves it?",
                    "What tests would prevent reintroduction?",
                ],
            }
            for e in entries
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
