"""SARIF 2.1.0 parser.

SARIF is the interchange format of many security tools (semgrep, trivy,
CodeQL, ...) so a single parser gives broad compatibility. Validation is
defensive: malformed entries are skipped with a warning instead of failing
the whole import when the rest of the report is usable.
"""

from __future__ import annotations

from typing import Any

from patchledger.parsers.common import ParseResult, RawFinding, sarif_uri_to_path

_LEVEL_TO_SEVERITY = {
    "error": "error",
    "warning": "warning",
    "note": "note",
    "none": "none",
}


def _rule_lookup(run: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Map ruleIndex -> rule definition for a run."""
    driver = run.get("tool", {}).get("driver", {}) or {}
    rules = driver.get("rules") or []
    return {idx: rule for idx, rule in enumerate(rules) if isinstance(rule, dict)}


def _rule_level(rule: dict[str, Any]) -> str | None:
    """Default severity level from a rule definition, if declared."""
    default = rule.get("defaultConfiguration") or {}
    level = default.get("level")
    if isinstance(level, str) and level.lower() in _LEVEL_TO_SEVERITY:
        return level.lower()
    return None


def _rule_text(rule: dict[str, Any], *keys: str) -> str:
    """Extract text from rule description structures (multiFormatDetails)."""
    for key in keys:
        block = rule.get(key)
        if isinstance(block, dict):
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                return text
    return ""


def parse_sarif(data: Any, scan_root: str | None = None) -> ParseResult:
    """Parse a SARIF 2.1.0 document into raw findings.

    ``scan_root`` relativizes absolute artifact URIs against the scanned tree.
    """
    if not isinstance(data, dict):
        raise ValueError("SARIF report must be a JSON object")
    version = data.get("version")
    if version != "2.1.0":
        raise ValueError(
            f"Unsupported SARIF version {version!r}: this parser implements SARIF 2.1.0"
        )
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF report contains no runs")

    findings: list[RawFinding] = []
    warnings: list[str] = []
    scanners: set[str] = set()

    for run_idx, run in enumerate(runs):
        if not isinstance(run, dict):
            warnings.append(f"run[{run_idx}] is not an object; skipped")
            continue

        tool = run.get("tool") or {}
        driver = tool.get("driver") if isinstance(tool, dict) else None
        driver = driver if isinstance(driver, dict) else {}
        scanner_name = str(driver.get("name") or "sarif").strip() or "sarif"
        scanners.add(scanner_name)
        rules = _rule_lookup(run)

        original_uri_bases = run.get("originalUriBaseIds") or {}
        if not isinstance(original_uri_bases, dict):
            original_uri_bases = {}

        def resolve_uri_base(uri_base_id: str, uri: str, _bases: dict = original_uri_bases) -> str:
            base_entry = _bases.get(uri_base_id)
            if isinstance(base_entry, dict):
                base_uri = base_entry.get("uri") or ""
                if base_uri and not uri.startswith(("file:", "/")):
                    return base_uri.rstrip("/") + "/" + uri
            return uri

        results = run.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            warnings.append(f"run[{run_idx}].results is not a list; skipped")
            continue

        for res_idx, result in enumerate(results):
            if not isinstance(result, dict):
                warnings.append(f"run[{run_idx}].results[{res_idx}] is not an object; skipped")
                continue

            rule_id = str(result.get("ruleId") or "").strip()
            if not rule_id:
                rule_id = "unknown-rule"
                warnings.append(
                    f"run[{run_idx}].results[{res_idx}] has no ruleId; recorded as 'unknown-rule'"
                )

            message = ""
            message_obj = result.get("message")
            if isinstance(message_obj, dict):
                text = message_obj.get("text")
                if isinstance(text, str):
                    message = text

            # Severity: result level > rule default > unspecified
            level = result.get("level")
            if not (isinstance(level, str) and level.lower() in _LEVEL_TO_SEVERITY):
                level = None
            rule_def: dict[str, Any] | None = None
            rule_index = result.get("ruleIndex")
            if isinstance(rule_index, int) and rule_index in rules:
                rule_def = rules[rule_index]
            elif rule_id:
                for candidate in rules.values():
                    if candidate.get("id") == rule_id:
                        rule_def = candidate
                        break
            if level is None and rule_def is not None:
                level = _rule_level(rule_def)
            severity_hint = level.lower() if isinstance(level, str) else None

            # Location + snippet evidence
            file_path: str | None = None
            start_line: int | None = None
            end_line: int | None = None
            evidence = ""
            locations = result.get("locations")
            if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                phys = locations[0].get("physicalLocation")
                if isinstance(phys, dict):
                    artifact = phys.get("artifactLocation")
                    if isinstance(artifact, dict):
                        uri = str(artifact.get("uri") or "")
                        uri_base_id = artifact.get("uriBaseId")
                        if isinstance(uri_base_id, str) and uri_base_id:
                            uri = resolve_uri_base(uri_base_id, uri)
                        file_path = sarif_uri_to_path(uri, scan_root)
                    region = phys.get("region")
                    if isinstance(region, dict):
                        from patchledger.parsers.common import to_int

                        start_line = to_int(region.get("startLine"))
                        end_line = to_int(region.get("endLine"))
                        snippet = region.get("snippet")
                        if isinstance(snippet, dict) and isinstance(snippet.get("text"), str):
                            evidence = snippet["text"]

            # Rule help as remediation reference
            references: list[str] = []
            fix_text = ""
            if rule_def is not None:
                help_block = rule_def.get("help") or {}
                if isinstance(help_block, dict):
                    for key in ("text", "markdown"):
                        val = help_block.get(key)
                        if isinstance(val, str) and val.strip():
                            fix_text = val
                            break
                info_uri = driver.get("informationUri")
                if isinstance(info_uri, str) and info_uri:
                    references.append(info_uri)

            properties = result.get("properties")
            metadata = properties if isinstance(properties, dict) else {}

            findings.append(
                RawFinding(
                    scanner=scanner_name,
                    rule_id=rule_id,
                    message=message,
                    description=_rule_text(rule_def, "fullDescription", "shortDescription")
                    if rule_def
                    else "",
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    evidence=evidence,
                    severity_hint=severity_hint,
                    fix=fix_text or None,
                    references=references,
                    metadata=metadata,
                )
            )

    primary = sorted(scanners)[0] if scanners else "sarif"
    return ParseResult(scanner=primary, findings=findings, warnings=warnings)
