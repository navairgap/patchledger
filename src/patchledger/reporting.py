"""Report generation: JSON, Markdown and self-contained HTML.

All reporters render the same :class:`ReportData`. Untrusted content (finding
text, paths, evidence) is escaped in the HTML reporter and quoted safely in
Markdown; the HTML report contains **no JavaScript at all**, which removes the
script-injection sink entirely. Reports state scanner coverage honestly: a
scan with unavailable or failed tools is labelled as incomplete.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from patchledger import __version__
from patchledger.errors import PatchLedgerError
from patchledger.models import Finding, Scan, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


class ReportError(PatchLedgerError):
    """Report generation failure."""


@dataclass
class CoverageSummary:
    """Honest summary of what actually ran."""

    total_tools: int = 0
    ran: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    imported: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """A scan counts as complete only when every participating tool ran."""
        return not (self.failed or self.unavailable or self.skipped)

    @property
    def has_coverage(self) -> bool:
        return self.total_tools > 0


@dataclass
class ComparisonSummary:
    """Diff against a previous scan (filled by comparison/verification)."""

    baseline_scan_id: str
    baseline_created_at: str
    new: int = 0
    persistent: int = 0
    resolved_candidates: int = 0
    reintroduced: int = 0
    changed_severity: int = 0
    changed_evidence: int = 0
    verified_fixed: int = 0
    inconclusive: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class ReportData:
    """Everything a report renders."""

    project_name: str
    project_root: str
    scan: Scan
    findings: list[Finding]
    generated_at: str
    coverage: CoverageSummary
    comparison: ComparisonSummary | None = None
    is_synthetic_example: bool = False
    notes: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def overall_status(self) -> str:
        """PASS/WARN/FAIL from severity plus an incomplete-coverage caveat."""
        counts = self.severity_counts()
        if counts.get("critical", 0) or counts.get("high", 0):
            status = "FAIL"
        elif counts.get("medium", 0) or counts.get("low", 0):
            status = "WARN"
        else:
            status = "PASS"
        if not self.coverage.complete:
            status += " (incomplete coverage)"
        return status


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic report order: severity, then score desc, then location."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda f: (rank.get(f.severity, 99), -f.score, f.file_path or "", f.start_line or 0),
    )


def build_coverage(scan: Scan) -> CoverageSummary:
    coverage = CoverageSummary(total_tools=len(scan.tools))
    for tool in scan.tools:
        bucket = {
            "ran": coverage.ran,
            "failed": coverage.failed,
            "unavailable": coverage.unavailable,
            "skipped": coverage.skipped,
            "imported": coverage.imported,
        }.get(tool.status.value)
        if bucket is not None:
            bucket.append(tool.tool)
    return coverage


# ------------------------------------------------------------------- JSON
def render_json(data: ReportData) -> str:
    """Structured machine-readable report."""
    doc = {
        "schema_version": 1,
        "generator": f"patchledger {__version__}",
        "generated_at": data.generated_at,
        "synthetic_example": data.is_synthetic_example,
        "project": {"name": data.project_name, "root": data.project_root},
        "scan": {
            "id": data.scan.id,
            "created_at": data.scan.created_at,
            "target_path": data.scan.target_path,
            "source": data.scan.source.value,
            "label": data.scan.label,
            "git_commit": data.scan.git_commit,
            "git_branch": data.scan.git_branch,
            "notes": data.scan.notes,
            "tools": [
                {
                    "tool": t.tool,
                    "status": t.status.value,
                    "version": t.version,
                    "exit_code": t.exit_code,
                    "note": t.note,
                }
                for t in data.scan.tools
            ],
        },
        "coverage": {
            "complete": data.coverage.complete,
            "ran": data.coverage.ran,
            "failed": data.coverage.failed,
            "unavailable": data.coverage.unavailable,
            "skipped": data.coverage.skipped,
            "imported": data.coverage.imported,
        },
        "overall_status": data.overall_status(),
        "summary": {
            "finding_count": len(data.findings),
            "by_severity": data.severity_counts(),
        },
        "comparison": _comparison_dict(data.comparison),
        "findings": [_finding_dict(f) for f in data.findings],
        "notes": data.notes,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _comparison_dict(comparison: ComparisonSummary | None) -> dict | None:
    if comparison is None:
        return None
    return {
        "baseline_scan_id": comparison.baseline_scan_id,
        "baseline_created_at": comparison.baseline_created_at,
        "new": comparison.new,
        "persistent": comparison.persistent,
        "resolved_candidates": comparison.resolved_candidates,
        "reintroduced": comparison.reintroduced,
        "changed_severity": comparison.changed_severity,
        "changed_evidence": comparison.changed_evidence,
        "verified_fixed": comparison.verified_fixed,
        "inconclusive": comparison.inconclusive,
        "notes": comparison.notes,
    }


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "scanner": f.scanner,
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "raw_severity": f.raw_severity,
        "confidence": f.confidence.value,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "file_path": f.file_path,
        "start_line": f.start_line,
        "end_line": f.end_line,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "score": f.score,
        "score_factors": f.score_factors,
        "status": f.status.value,
        "metadata": f.metadata,
        "occurrences": [
            {
                "scanner": o.scanner,
                "rule_id": o.rule_id,
                "file_path": o.file_path,
                "start_line": o.start_line,
                "end_line": o.end_line,
                "evidence": o.evidence,
                "message": o.message,
                "metadata": o.metadata,
            }
            for o in f.occurrences
        ],
    }


# --------------------------------------------------------------- Markdown
_MD_LEADING = ("#", "-", ">", "+", "|", "*")


def _md_escape(text: str) -> str:
    """Escape Markdown metacharacters in repo-controlled inline text.

    Repo content flows into titles, descriptions, and guidance; without this
    a crafted finding could forge headings, list items, or block quotes in
    the rendered report (security review F6). Newlines are collapsed (they
    would let content start a fresh line, the actual injection vector),
    backslashes and backticks are escaped, and a leading structure character
    is escaped for the cases where the text does start a line.
    """
    escaped = (
        text.replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )
    if escaped.startswith(_MD_LEADING):
        escaped = "\\" + escaped
    return escaped


def _md_fence(evidence: str) -> str:
    """A code fence longer than any backtick run inside the evidence
    (CommonMark fence rule) so evidence cannot close its own block."""
    longest = 0
    run = 0
    for char in evidence:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def render_markdown(data: ReportData) -> str:
    """Human-readable Markdown report (escaping keeps structure intact)."""
    lines: list[str] = []
    push = lines.append
    counts = data.severity_counts()

    push("# PatchLedger Security Report")
    push("")
    if data.is_synthetic_example:
        push("> **SYNTHETIC EXAMPLE DATA** — generated for illustration only. "
             "Not the result of a real scan.")
        push("")
    push(f"- **Project:** {data.project_name}")
    push(f"- **Root:** `{data.project_root}`")
    push(f"- **Scan:** `{data.scan.id}` ({data.scan.source.value}, {data.scan.created_at})")
    if data.scan.git_commit:
        push(f"- **Git:** `{data.scan.git_commit[:12]}`"
             + (f" on `{data.scan.git_branch}`" if data.scan.git_branch else ""))
    push(f"- **Generated:** {data.generated_at}")
    push(f"- **Overall status:** **{data.overall_status()}**")
    push("")

    push("## Scanner coverage")
    push("")
    if not data.coverage.has_coverage:
        push("_No scanner information recorded for this scan (imported reports only)._")
    else:
        push("| Tool | Status | Version | Note |")
        push("|------|--------|---------|------|")
        for t in data.scan.tools:
            note = (t.note or "").replace("|", "\\|")
            push(f"| {t.tool} | {t.status.value} | {t.version or '-'} | {note} |")
    if not data.coverage.complete:
        push("")
        push("> ⚠️ **Incomplete coverage** — some tools did not run. Findings "
             "below are not a complete picture, and resolution claims are "
             "treated as unverified.")
    push("")

    push("## Summary")
    push("")
    push("| Severity | Count |")
    push("|----------|-------|")
    for severity in SEVERITY_ORDER:
        push(f"| {severity.value} | {counts.get(severity.value, 0)} |")
    push(f"| **Total** | **{len(data.findings)}** |")
    push("")

    if data.comparison is not None:
        c = data.comparison
        push(f"## Comparison with scan `{c.baseline_scan_id}` ({c.baseline_created_at})")
        push("")
        push(f"- New: **{c.new}**")
        push(f"- Persistent: **{c.persistent}**")
        push(f"- Resolved candidates: **{c.resolved_candidates}** "
             f"(verified fixed: **{c.verified_fixed}**, inconclusive: **{c.inconclusive}**)")
        push(f"- Reintroduced: **{c.reintroduced}**")
        if c.changed_severity or c.changed_evidence:
            push(f"- Changed severity: **{c.changed_severity}**; "
                 f"changed evidence: **{c.changed_evidence}**")
        for note in c.notes:
            push(f"- Note: {note}")
        push("")

    push("## Findings")
    push("")
    if not data.findings:
        push("_No findings recorded._")
    for i, f in enumerate(data.findings, 1):
        push(f"### {i}. [{f.severity.value.upper()}] {_md_escape(f.title)}")
        push("")
        push(f"- **Scanner:** {_md_escape(f.scanner)} — rule `{f.rule_id}`")
        push(f"- **Location:** `{f.location_str}`")
        push(f"- **Category:** {_md_escape(f.category)} — confidence: {f.confidence.value}"
             + (f" (scanner said: {_md_escape(f.raw_severity)})" if f.raw_severity else ""))
        push(f"- **Fingerprint:** `{f.fingerprint}`")
        if f.description and f.description != f.title:
            push(f"- **Detail:** {_md_escape(f.description)}")
        if f.evidence:
            fence = _md_fence(f.evidence)
            push("- **Evidence** (scanner-reported, secrets redacted):")
            push("")
            push(fence)
            for ev_line in f.evidence.rstrip().splitlines()[:20]:
                push(ev_line)
            push(fence)
        if f.score_factors:
            push(f"- **Risk score:** {f.score} — "
                 f"{_md_escape('; '.join(f.score_factors))}")
        if f.remediation:
            push("- **Remediation guidance** (advice, not evidence):")
            push("")
            for rem_line in f.remediation.splitlines():
                push(f"  > {_md_escape(rem_line)}")
        if len(f.occurrences) > 1:
            push(f"- **Occurrences:** {len(f.occurrences)} sightings merged "
                 "(identical fingerprint)")
        push("")

    push("---")
    push(f"_Generated by patchledger {__version__}. Evidence is scanner-reported; "
         "remediation text is guidance from the local knowledge base._")
    push("")
    return "\n".join(lines)


def write_report(data: ReportData, fmt: str, output: Path) -> Path:
    """Render a report to a file. fmt: json | markdown | md | html | sarif."""
    from patchledger.html_report import render_html
    from patchledger.sarif_output import render_sarif

    renderers = {
        "json": render_json,
        "markdown": render_markdown,
        "md": render_markdown,
        "html": render_html,
        "sarif": render_sarif,
    }
    renderer = renderers.get(fmt)
    if renderer is None:
        raise ReportError(
            f"Unknown report format '{fmt}'. Supported: json, markdown, html, sarif"
        )
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(renderer(data), encoding="utf-8")
    return output
