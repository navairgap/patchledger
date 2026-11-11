"""Semgrep JSON parser (output of ``semgrep --json``)."""

from __future__ import annotations

from typing import Any

from patchledger.parsers.common import ParseResult, RawFinding, normalize_file_path, to_int


def parse_semgrep(data: Any, scan_root: str | None = None) -> ParseResult:
    """Parse semgrep JSON output into raw findings."""
    if not isinstance(data, dict):
        raise ValueError("Semgrep report must be a JSON object")

    results = data.get("results")
    if results is None:
        raise ValueError("Semgrep report has no 'results' field")
    if not isinstance(results, list):
        raise ValueError("Semgrep 'results' field is not a list")

    findings: list[RawFinding] = []
    warnings: list[str] = []

    errors = data.get("errors")
    if isinstance(errors, list) and errors:
        warnings.append(f"semgrep reported {len(errors)} error(s) during its run")

    for idx, result in enumerate(results):
        if not isinstance(result, dict):
            warnings.append(f"results[{idx}] is not an object; skipped")
            continue

        check_id = str(result.get("check_id") or "").strip()
        if not check_id:
            warnings.append(f"results[{idx}] has no check_id; skipped")
            continue

        start_raw = result.get("start")
        start = start_raw if isinstance(start_raw, dict) else {}
        end_raw = result.get("end")
        end = end_raw if isinstance(end_raw, dict) else {}
        extra_raw = result.get("extra")
        extra = extra_raw if isinstance(extra_raw, dict) else {}

        metadata = extra.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}

        references: list[str] = []
        raw_refs = metadata.get("references")
        if isinstance(raw_refs, list):
            references = [str(r) for r in raw_refs if isinstance(r, str)]
        elif isinstance(raw_refs, str):
            references = [raw_refs]
        semgrep_refs = extra.get("references")
        if isinstance(semgrep_refs, list):
            references += [str(r) for r in semgrep_refs if isinstance(r, str)]

        lines = extra.get("lines")
        evidence = lines if isinstance(lines, str) else ""

        fix = extra.get("fix")
        fix_text = fix if isinstance(fix, str) else None

        path = result.get("path")
        normalized_path = normalize_file_path(str(path) if path else None, scan_root)

        findings.append(
            RawFinding(
                scanner="semgrep",
                rule_id=check_id,
                message=str(extra.get("message") or ""),
                description=str(metadata.get("short_description") or ""),
                file_path=normalized_path,
                start_line=to_int(start.get("line")),
                end_line=to_int(end.get("line")),
                evidence=evidence,
                severity_hint=str(extra.get("severity") or "") or None,
                confidence_hint=str(metadata.get("confidence") or "") or None,
                fix=fix_text,
                references=references,
                metadata=metadata,
            )
        )

    return ParseResult(scanner="semgrep", findings=findings, warnings=warnings)
