"""Gitleaks JSON parser (output of ``gitleaks detect --report-format json``).

Gitleaks reports contain raw secret material in ``Match``/``Secret`` fields.
This parser carries those values through the pipeline so the normalizer can
apply redaction before anything is stored or rendered — the parser itself
does not decide redaction policy.
"""

from __future__ import annotations

from typing import Any

from patchledger.parsers.common import ParseResult, RawFinding, normalize_file_path, to_int


def parse_gitleaks(data: Any, scan_root: str | None = None) -> ParseResult:
    """Parse gitleaks JSON output (a top-level array) into raw findings."""
    if isinstance(data, dict):
        # Some wrappers emit {"findings": [...]}
        data = data.get("findings")
    if not isinstance(data, list):
        raise ValueError("Gitleaks report must be a JSON array of findings")

    findings: list[RawFinding] = []
    warnings: list[str] = []

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            warnings.append(f"findings[{idx}] is not an object; skipped")
            continue

        rule_id = str(item.get("RuleID") or "").strip()
        if not rule_id:
            warnings.append(f"findings[{idx}] has no RuleID; skipped")
            continue

        path = normalize_file_path(str(item.get("File") or "") or None, scan_root)

        match = item.get("Match")
        secret = item.get("Secret")
        metadata: dict[str, Any] = {}
        # Carry raw secret material in metadata for normalizer redaction.
        if isinstance(match, str) and match:
            metadata["raw_match"] = match
        if isinstance(secret, str) and secret:
            metadata["raw_secret"] = secret
        commit = item.get("Commit")
        if isinstance(commit, str) and commit:
            metadata["commit"] = commit
        date = item.get("Date")
        if isinstance(date, str) and date:
            metadata["commit_date"] = date
        email = item.get("Email")
        if isinstance(email, str) and email:
            metadata["commit_email"] = email
        tags = item.get("Tags")
        if isinstance(tags, list):
            metadata["tags"] = [str(t) for t in tags]

        start_line = to_int(item.get("StartLine"))
        end_line = to_int(item.get("EndLine"))

        findings.append(
            RawFinding(
                scanner="gitleaks",
                rule_id=rule_id,
                message=str(item.get("Description") or ""),
                description=str(item.get("Description") or ""),
                file_path=path,
                start_line=start_line,
                end_line=end_line,
                # Evidence is intentionally empty here; the normalizer builds
                # redacted evidence from raw_match/raw_secret.
                evidence="",
                # Leaked credentials: conservatively high until a human confirms
                # validity. The normalizer's explicit mapping table decides.
                severity_hint="high",
                confidence_hint="high",
                metadata=metadata,
            )
        )

    return ParseResult(scanner="gitleaks", findings=findings, warnings=warnings)
