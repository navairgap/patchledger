"""Scan comparison: what changed between two scans.

Two scans are comparable when they observed the same target path. The diff
uses stable fingerprints, so persistent findings survive line-number shifts
while genuinely changed code produces new identities. Reintroduction is
detected by consulting earlier scans, not just the two being compared.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from patchledger.models import Finding, Scan
from patchledger.storage import PatchLedgerDB


@dataclass
class FindingPair:
    """The same fingerprint observed in both scans (A = older, B = newer)."""

    fingerprint: str
    old: Finding
    new: Finding


@dataclass
class ScanDiff:
    """Result of comparing two scans."""

    scan_a: Scan
    scan_b: Scan
    new: list[Finding] = field(default_factory=list)
    persistent: list[FindingPair] = field(default_factory=list)
    resolved_candidates: list[Finding] = field(default_factory=list)
    reintroduced: list[Finding] = field(default_factory=list)
    changed_severity: list[FindingPair] = field(default_factory=list)
    changed_evidence: list[FindingPair] = field(default_factory=list)
    compatible: bool = True
    notes: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.resolved_candidates or self.reintroduced)

    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "persistent": len(self.persistent),
            "resolved_candidates": len(self.resolved_candidates),
            "reintroduced": len(self.reintroduced),
            "changed_severity": len(self.changed_severity),
            "changed_evidence": len(self.changed_evidence),
        }


def _earlier_fingerprints(db: PatchLedgerDB, project_id: str, before_scan: Scan) -> set[str]:
    """Fingerprints seen in any scan of the project strictly before `before_scan`.

    Scans are sequence-ordered, so everything listed before `before_scan` is
    earlier — clock granularity does not matter.
    """
    seen: set[str] = set()
    for scan in db.list_scans(project_id):
        if scan.id == before_scan.id:
            break
        seen |= set(db.get_fingerprint_index(scan.id).keys())
    return seen


def compare_scans(db: PatchLedgerDB, scan_a: Scan, scan_b: Scan) -> ScanDiff:
    """Compare two scans of the same project (A older, B newer)."""
    diff = ScanDiff(scan_a=scan_a, scan_b=scan_b)

    if scan_a.target_path != scan_b.target_path:
        diff.compatible = False
        diff.notes.append(
            f"Scans observed different target paths "
            f"({scan_a.target_path} vs {scan_b.target_path}); resolution claims "
            "cannot be verified across different targets."
        )

    index_a = db.get_fingerprint_index(scan_a.id)
    index_b = db.get_fingerprint_index(scan_b.id)

    fps_a = set(index_a.keys())
    fps_b = set(index_b.keys())

    diff.new = [index_b[fp] for fp in sorted(fps_b - fps_a)]
    diff.resolved_candidates = [index_a[fp] for fp in sorted(fps_a - fps_b)]

    earlier = _earlier_fingerprints(db, scan_a.project_id, scan_a)
    diff.reintroduced = [
        index_b[fp] for fp in sorted((fps_b - fps_a) & earlier)
    ]

    for fp in sorted(fps_a & fps_b):
        pair = FindingPair(fingerprint=fp, old=index_a[fp], new=index_b[fp])
        diff.persistent.append(pair)
        if pair.old.severity != pair.new.severity:
            diff.changed_severity.append(pair)
        # "Changed evidence" = same identity, different reported location.
        # Content changes are identity changes by design (the fingerprint
        # includes the snippet), so they surface as resolved+new pairs.
        location_moved = (
            pair.old.start_line != pair.new.start_line
            or pair.old.end_line != pair.new.end_line
        )
        if location_moved or (pair.old.evidence or "") != (pair.new.evidence or ""):
            diff.changed_evidence.append(pair)

    return diff
