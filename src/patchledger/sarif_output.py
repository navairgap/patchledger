"""SARIF 2.1.0 output: export findings for GitHub code scanning & SARIF consumers.

The output side mirrors the input side: findings normalized by PatchLedger can
be emitted as SARIF so platforms with SARIF ingestion (GitHub code scanning,
IDE plugins) can consume them. Coverage honesty travels with the export:
tool runs that did not execute are represented as tool notifications.
"""

from __future__ import annotations

import json

from patchledger import __version__
from patchledger.models import Severity
from patchledger.reporting import ReportData

# Normalized severity -> SARIF level (coarse by design; raw severity is
# preserved in properties so consumers never lose scanner fidelity).
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
    Severity.UNKNOWN: "note",
}


def render_sarif(data: ReportData) -> str:
    """Render a report as a SARIF 2.1.0 document (single driver run)."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in data.findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title[:1000]},
                "helpUri": _first_uri(finding.remediation) or "",
            }
        locations: list[dict] = []
        if finding.file_path:
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {"startLine": max(finding.start_line or 1, 1)},
                    }
                }
            )
        result = {
            "ruleId": finding.rule_id,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.description or finding.title},
            "locations": locations,
            "partialFingerprints": {"patchledgerFingerprint/v1": finding.fingerprint},
            "properties": {
                "patchledgerSeverity": finding.severity.value,
                "rawSeverity": finding.raw_severity or "",
                "confidence": finding.confidence.value,
                "category": finding.category,
                "score": finding.score,
                "status": finding.status.value,
            },
        }
        results.append(result)

    tool_notifications = [
        {
            "level": "note",
            "message": {"text": (
                f"Scanner '{tool.tool}' status: {tool.status.value}"
                + (f" — {tool.note}" if tool.note else "")
            )},
        }
        for tool in data.scan.tools
        if tool.status.value != "ran"
    ]

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PatchLedger",
                        "version": __version__,
                        "informationUri": "https://github.com/navairgap/patchledger",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": data.coverage.complete,
                        "toolExecutionNotifications": tool_notifications,
                        "endTimeUtc": data.generated_at,
                    }
                ],
                "properties": {
                    "overallStatus": data.overall_status(),
                    "coverageComplete": data.coverage.complete,
                    "syntheticExample": data.is_synthetic_example,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _first_uri(remediation: str) -> str | None:
    for token in remediation.replace(";", " ").split():
        if token.startswith(("http://", "https://")):
            return token.rstrip(".")
    return None
