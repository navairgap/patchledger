"""Bandit JSON parser (output of ``bandit -f json``)."""

from __future__ import annotations

import re
from typing import Any

from patchledger.parsers.common import ParseResult, RawFinding, normalize_file_path, to_int

# Bandit prefixes the flagged line inside `code` with a wrapped marker like
# "   > "; strip it so evidence is the code as written.
_MARKER = re.compile(r"^\s*>\s?")


def _clean_code(code: str) -> str:
    return "\n".join(_MARKER.sub("", line) for line in code.splitlines())


def parse_bandit(data: Any, scan_root: str | None = None) -> ParseResult:
    """Parse bandit JSON output into raw findings."""
    if not isinstance(data, dict):
        raise ValueError("Bandit report must be a JSON object")

    results = data.get("results")
    if results is None:
        raise ValueError("Bandit report has no 'results' field")
    if not isinstance(results, list):
        raise ValueError("Bandit 'results' field is not a list")

    findings: list[RawFinding] = []
    warnings: list[str] = []

    errors = data.get("errors")
    if isinstance(errors, list) and errors:
        warnings.append(f"bandit reported {len(errors)} error(s) during its run")

    for idx, result in enumerate(results):
        if not isinstance(result, dict):
            warnings.append(f"results[{idx}] is not an object; skipped")
            continue

        test_id = str(result.get("test_id") or "").strip()
        test_name = str(result.get("test_name") or "").strip()
        if not test_id and not test_name:
            warnings.append(f"results[{idx}] has neither test_id nor test_name; skipped")
            continue
        rule_id = test_id or test_name

        filename = result.get("filename")
        path = normalize_file_path(str(filename) if filename else None, scan_root)

        line_range = result.get("line_range")
        end_line = to_int(line_range[-1]) if isinstance(line_range, list) and line_range else None

        code = result.get("code")
        evidence = _clean_code(code) if isinstance(code, str) else ""

        cwe = result.get("issue_cwe")
        metadata: dict[str, Any] = {}
        if isinstance(cwe, dict) and cwe.get("id"):
            metadata["cwe"] = cwe["id"]
        if test_name:
            metadata["test_name"] = test_name
        more_info = result.get("more_info")
        if isinstance(more_info, str) and more_info:
            metadata["more_info"] = more_info

        references: list[str] = []
        if isinstance(more_info, str) and more_info:
            references.append(more_info)

        findings.append(
            RawFinding(
                scanner="bandit",
                rule_id=rule_id,
                message=str(result.get("issue_text") or ""),
                description=test_name,
                file_path=path,
                start_line=to_int(result.get("line_number")),
                end_line=end_line,
                evidence=evidence,
                severity_hint=str(result.get("issue_severity") or "") or None,
                confidence_hint=str(result.get("issue_confidence") or "") or None,
                references=references,
                metadata=metadata,
            )
        )

    return ParseResult(scanner="bandit", findings=findings, warnings=warnings)
