"""Within-scan deduplication.

Findings that share a fingerprint are the same issue observed more than once
(e.g. the same tool run exported twice). They merge into one finding whose
``occurrences`` list preserves every sighting with scanner-specific evidence —
deduplication never discards evidence, and cross-scanner findings are never
merged (their fingerprints differ by design).
"""

from __future__ import annotations

from patchledger.models import Finding, Severity

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}


def _primary_sort_key(finding: Finding) -> tuple:
    return (
        _SEVERITY_RANK.get(finding.severity, 5),
        finding.file_path or "",
        finding.start_line or 0,
    )


def merge_duplicates(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Merge findings sharing a fingerprint (within one scan).

    Returns the deduplicated list and the number of duplicates folded away
    (each duplicate's evidence survives as an occurrence). The primary finding
    is the most severe sighting (ties broken by location, deterministically).
    """
    by_fingerprint: dict[str, list[Finding]] = {}
    for finding in findings:
        by_fingerprint.setdefault(finding.fingerprint, []).append(finding)

    merged: list[Finding] = []
    merged_count = 0
    for group in by_fingerprint.values():
        group.sort(key=_primary_sort_key)
        primary = group[0]
        if len(group) > 1:
            merged_count += len(group) - 1
            primary = primary.model_copy(deep=True)
            primary.occurrences = [occ for f in group for occ in f.occurrences]
        merged.append(primary)

    merged.sort(key=_primary_sort_key)
    return merged, merged_count
