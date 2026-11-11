"""Evidence-based patch verification and the project finding ledger.

The core promise: a finding is only ``resolved`` when the evidence supports
it. A finding that disappears from a scan is a *resolution candidate*; it
becomes ``fixed_verified`` only when every scanner that ever reported it ran
successfully against the same target in the current scan. Otherwise the state
is ``inconclusive`` — explicitly NOT treated as fixed.

States:

* ``open``         — present in the latest scan.
* ``reintroduced`` — was resolved and has come back.
* ``resolved``     — absent from the latest scan and verified with coverage.
* ``inconclusive`` — absent from the latest scan but unverifiable (missing
                     or failed scanner, imported report, different target).
                     The finding is still effectively open.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from patchledger.comparison import ScanDiff, compare_scans
from patchledger.config import PatchLedgerConfig
from patchledger.models import Finding, FindingStatus, Scan, ToolRunStatus
from patchledger.storage import PatchLedgerDB

VERIFIED_FIXED = "fixed_verified"
INCONCLUSIVE = "inconclusive"


@dataclass
class Verdict:
    """The verification decision for one resolution candidate."""

    fingerprint: str
    state: str  # VERIFIED_FIXED | INCONCLUSIVE
    reasons: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    @property
    def is_verified(self) -> bool:
        return self.state == VERIFIED_FIXED


@dataclass
class VerificationReport:
    """Full verification of a baseline scan against a newer scan."""

    baseline: Scan
    current: Scan
    diff: ScanDiff
    verdicts: dict[str, Verdict] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        verified = sum(1 for v in self.verdicts.values() if v.is_verified)
        return {
            **self.diff.summary(),
            "verified_fixed": verified,
            "inconclusive": len(self.verdicts) - verified,
        }


@dataclass
class LedgerEntry:
    """Current status of one fingerprint across the project's scans."""

    fingerprint: str
    status: FindingStatus
    finding: Finding  # most recent sighting
    first_seen: str
    last_seen: str
    seen_in_scans: int
    verdict: Verdict | None = None


def resolution_verdict(
    db: PatchLedgerDB,
    project_id: str,
    fingerprint: str,
    current_scan: Scan,
    config: PatchLedgerConfig,
) -> Verdict:
    """Decide whether an absent finding can honestly be called fixed.

    Strictness rules (each failure makes the verdict inconclusive):

    1. The fingerprint must have a baseline observation.
    2. The current scan must target the same path as the last observation.
    3. Every scanner that ever reported the fingerprint must appear in the
       current scan with status ``ran`` (a real local run, not an import).
    4. A scanner version change between baseline and current is recorded as
       a caveat (rule sets may differ) but does not block verification.
    """
    history = db.fingerprint_history(project_id, fingerprint)
    if not history:
        return Verdict(fingerprint, INCONCLUSIVE, ["no baseline observation found"])

    last = history[-1]
    reasons: list[str] = []
    caveats: list[str] = []

    if current_scan.target_path != last["target_path"]:
        reasons.append(
            f"last seen at target {last['target_path']!r}, current scan targeted "
            f"{current_scan.target_path!r}"
        )

    scanners = {h["scanner"] for h in history}
    tool_map = current_scan.tool_map()
    for scanner in sorted(scanners):
        run = tool_map.get(scanner)
        if run is None:
            reasons.append(f"scanner {scanner} did not run in the current scan")
        elif run.status == ToolRunStatus.IMPORTED:
            reasons.append(
                f"scanner {scanner} results were imported from a report; "
                "coverage cannot be guaranteed"
            )
        elif run.status in (ToolRunStatus.FAILED, ToolRunStatus.UNAVAILABLE, ToolRunStatus.SKIPPED):
            reasons.append(f"scanner {scanner} did not run successfully ({run.status.value})")

    if config.verification.treat_version_change_as_caveat and not reasons:
        current_versions = {
            scanner: tool_map[scanner].version for scanner in scanners if scanner in tool_map
        }
        for scanner in sorted(scanners):
            baseline_versions = {
                h["tool_version"] for h in history if h["scanner"] == scanner and h["tool_version"]
            }
            current_version = current_versions.get(scanner)
            if current_version and baseline_versions and current_version not in baseline_versions:
                caveats.append(
                    f"scanner {scanner} version changed "
                    f"({', '.join(sorted(baseline_versions))} -> {current_version}); "
                    "rule sets may differ"
                )

    if reasons:
        return Verdict(fingerprint, INCONCLUSIVE, reasons, caveats)
    return Verdict(
        fingerprint, VERIFIED_FIXED, ["all reporting scanners ran successfully"], caveats
    )


def verify_scans(
    db: PatchLedgerDB,
    baseline: Scan,
    current: Scan,
    config: PatchLedgerConfig,
) -> VerificationReport:
    """Verify every resolution candidate between two scans."""
    diff = compare_scans(db, baseline, current)
    report = VerificationReport(baseline=baseline, current=current, diff=diff)
    for candidate in diff.resolved_candidates:
        report.verdicts[candidate.fingerprint] = resolution_verdict(
            db, baseline.project_id, candidate.fingerprint, current, config
        )
    return report


def compute_project_ledger(
    db: PatchLedgerDB,
    project_id: str,
    config: PatchLedgerConfig,
) -> list[LedgerEntry]:
    """Derive the current per-fingerprint status across all scans.

    This is the "ledger" view: for every fingerprint ever observed, its
    current state, first/last seen, and (for absent findings) the resolution
    verdict against the latest scan.
    """
    scans = db.list_scans(project_id)
    if not scans:
        return []
    latest = scans[-1]
    latest_index = db.get_fingerprint_index(latest.id)
    recorded = db.latest_statuses(project_id)

    observations: dict[str, list[dict]] = {}
    for row in db.project_findings(project_id):
        observations.setdefault(row["fingerprint"], []).append(row)

    entries: list[LedgerEntry] = []
    for fingerprint, rows in observations.items():
        first_seen = rows[0]["scan_created_at"]
        last_seen = rows[-1]["scan_created_at"]
        last_row = rows[-1]

        if fingerprint in latest_index:
            finding = latest_index[fingerprint]
            previous = recorded.get(fingerprint, {}).get("status")
            status = FindingStatus.REINTRODUCED if previous == "resolved" else FindingStatus.OPEN
            verdict = None
        else:
            scan_findings = db.get_findings(last_row["scan_id"])
            last_finding = next(
                (f for f in scan_findings if f.fingerprint == fingerprint), None
            )
            if last_finding is None:  # defensive: row exists but load failed
                continue
            finding = last_finding
            verdict = resolution_verdict(db, project_id, fingerprint, latest, config)
            status = FindingStatus.RESOLVED if verdict.is_verified else FindingStatus.INCONCLUSIVE

        entries.append(
            LedgerEntry(
                fingerprint=fingerprint,
                status=status,
                finding=finding,
                first_seen=first_seen,
                last_seen=last_seen,
                seen_in_scans=len(rows),
                verdict=verdict,
            )
        )

    entries.sort(key=lambda e: (-e.finding.score, e.finding.file_path or "", e.finding.rule_id))
    return entries


def update_ledger_after_scan(
    db: PatchLedgerDB,
    project_id: str,
    config: PatchLedgerConfig,
) -> list[LedgerEntry]:
    """Recompute the ledger and persist status transitions to status_history.

    Only transitions into non-open states (resolved, inconclusive,
    reintroduced) are recorded; a finding's first detection is already
    captured by its findings rows.
    """
    ledger = compute_project_ledger(db, project_id, config)
    scans = db.list_scans(project_id)
    latest = scans[-1] if scans else None
    recorded = db.latest_statuses(project_id)

    for entry in ledger:
        previous = recorded.get(entry.fingerprint, {}).get("status")
        if entry.status == FindingStatus.OPEN:
            continue
        if entry.status.value == previous:
            continue
        reason = "; ".join(entry.verdict.reasons + entry.verdict.caveats) if entry.verdict else ""
        verification = None
        if entry.verdict is not None:
            verification = {"state": entry.verdict.state, "reasons": entry.verdict.reasons,
                            "caveats": entry.verdict.caveats}
        db.record_status(
            project_id,
            entry.fingerprint,
            latest.id if latest else "",
            entry.status,
            reason=reason or "reappeared in latest scan",
            verification=verification,
        )
    return ledger


__all__ = [
    "INCONCLUSIVE",
    "VERIFIED_FIXED",
    "LedgerEntry",
    "ScanDiff",
    "Verdict",
    "VerificationReport",
    "compare_scans",
    "compute_project_ledger",
    "resolution_verdict",
    "update_ledger_after_scan",
    "verify_scans",
]
