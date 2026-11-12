"""End-to-end pipeline orchestration: scan/import -> normalize -> store.

This module is the bridge between raw scanner execution and the database.
Both entry points produce the same artifact: one immutable scan with
normalized, deduplicated findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from patchledger.config import PatchLedgerConfig
from patchledger.deduplication import merge_duplicates
from patchledger.errors import ProjectError, ReportImportError
from patchledger.models import Finding, Scan, ScanSource, ScanToolRun, ToolRunStatus
from patchledger.normalizer import NormalizeResult, normalize_findings
from patchledger.parsers import parse_report_file
from patchledger.parsers.common import RawFinding
from patchledger.scanner import ScannerOutcome, collect_git_metadata, run_all_scanners
from patchledger.scoring import apply_scores
from patchledger.storage import PatchLedgerDB
from patchledger.verification import LedgerEntry, update_ledger_after_scan


def resolve_target(target: Path) -> Path:
    """Resolve and validate a scan target directory."""
    resolved = Path(target).resolve()
    if not resolved.exists():
        raise ProjectError(f"Target path does not exist: {resolved}")
    if not resolved.is_dir():
        raise ProjectError(f"Target path is not a directory: {resolved}")
    return resolved


@dataclass
class ScanRunResult:
    """Everything one scan/import produced, for CLI reporting."""

    scan: Scan
    findings: list[Finding]
    suppressed: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    merged_count: int = 0
    outcomes: list[ScannerOutcome] = field(default_factory=list)
    ledger: list[LedgerEntry] = field(default_factory=list)


def _normalize_and_merge(
    raw_findings: list[RawFinding], config: PatchLedgerConfig, scan_root: str
) -> tuple[list[Finding], NormalizeResult, int]:
    normalized = normalize_findings(raw_findings, config, scan_root)
    merged, merged_count = merge_duplicates(normalized.findings)
    apply_scores(merged, config)
    return merged, normalized, merged_count


def _dedupe_tools(tools: list[ScanToolRun]) -> list[ScanToolRun]:
    """One row per tool per scan (a tool appears once even if outcomes repeat)."""
    seen: dict[str, ScanToolRun] = {}
    for tool in tools:
        if tool.tool not in seen:
            seen[tool.tool] = tool
    return list(seen.values())


def _finalize(
    db: PatchLedgerDB, project_id: str, config: PatchLedgerConfig
) -> list[LedgerEntry]:
    """Refresh the finding ledger and persist status transitions."""
    return update_ledger_after_scan(db, project_id, config)


def scan_repository(
    db: PatchLedgerDB,
    target: Path,
    config: PatchLedgerConfig,
    enabled: list[str] | None = None,
    label: str | None = None,
) -> ScanRunResult:
    """Run available scanners against the target and store one scan."""
    target = resolve_target(target)

    outcomes = run_all_scanners(config, target, enabled)
    raw_findings = [raw for outcome in outcomes for raw in outcome.findings]
    findings, normalized, merged_count = _normalize_and_merge(raw_findings, config, str(target))

    commit, branch = collect_git_metadata(target)
    project = db.ensure_project(target.name, str(target))

    scan = Scan(
        project_id=project.id,
        target_path=str(target),
        source=ScanSource.SCAN,
        label=label,
        git_commit=commit,
        git_branch=branch,
        tools=_dedupe_tools(
            [
                ScanToolRun(
                    tool=o.tool,
                    status=o.status,
                    version=o.version,
                    exit_code=o.exit_code,
                    note=o.note,
                )
                for o in outcomes
            ]
        ),
        notes=json.dumps({"suppressed": normalized.suppressed}) if normalized.suppressed else None,
    )
    db.insert_scan(scan, findings)
    ledger = _finalize(db, project.id, config)
    return ScanRunResult(
        scan=scan,
        findings=findings,
        suppressed=normalized.suppressed,
        warnings=normalized.warnings,
        merged_count=merged_count,
        outcomes=outcomes,
        ledger=ledger,
    )


def import_reports(
    db: PatchLedgerDB,
    report_paths: list[Path],
    config: PatchLedgerConfig,
    target: Path,
    label: str | None = None,
) -> ScanRunResult:
    """Import existing scanner reports as one scan bound to the target repo."""
    target = resolve_target(target)
    if not report_paths:
        raise ReportImportError("No report files provided")

    all_warnings: list[str] = []
    raw_findings: list[RawFinding] = []
    scanners_seen: list[str] = []

    for path in report_paths:
        result = parse_report_file(Path(path), config, scan_root=str(target))
        raw_findings.extend(result.findings)
        all_warnings.extend(f"{Path(path).name}: {w}" for w in result.warnings)
        if result.scanner and result.scanner not in scanners_seen:
            scanners_seen.append(result.scanner)

    findings, normalized, merged_count = _normalize_and_merge(raw_findings, config, str(target))
    project = db.ensure_project(target.name, str(target))

    scan = Scan(
        project_id=project.id,
        target_path=str(target),
        source=ScanSource.IMPORT,
        label=label,
        # Imported reports cannot assert local scanner coverage: recorded as
        # IMPORTED status so patch verification treats resolutions honestly.
        tools=_dedupe_tools(
            [
                ScanToolRun(
                    tool=name,
                    status=ToolRunStatus.IMPORTED,
                    note="imported report; scanner coverage not guaranteed",
                )
                for name in scanners_seen
            ]
        ),
        notes=json.dumps({"suppressed": normalized.suppressed}) if normalized.suppressed else None,
    )
    db.insert_scan(scan, findings)
    ledger = _finalize(db, project.id, config)
    return ScanRunResult(
        scan=scan,
        findings=findings,
        suppressed=normalized.suppressed,
        warnings=all_warnings,
        merged_count=merged_count,
        ledger=ledger,
    )
