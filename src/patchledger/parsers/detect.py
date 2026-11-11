"""Report format auto-detection from content (extension is only a hint)."""

from __future__ import annotations

from typing import Any

SUPPORTED_FORMATS = ("sarif", "semgrep", "gitleaks", "bandit", "pip-audit")


def detect_format(data: Any) -> str:
    """Identify the scanner-report format of a parsed JSON document.

    Raises ValueError with an explanation when the content matches no
    supported format.
    """
    if isinstance(data, dict):
        # SARIF: "runs" is the distinctive key; the parser validates the version
        # precisely so wrong versions get an actionable error.
        runs = data.get("runs")
        if isinstance(runs, list):
            return "sarif"

        results = data.get("results")
        if "results" in data:
            if "generated_at" in data or "metrics" in data:
                return "bandit"
            if isinstance(results, list) and results and isinstance(results[0], dict):
                first = results[0]
                if "check_id" in first:
                    return "semgrep"
                if "test_id" in first or "issue_severity" in first:
                    return "bandit"
            if "errors" in data or "version" in data:
                return "semgrep"
            return "bandit"

    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            if "RuleID" in first:
                return "gitleaks"
            if "name" in first and "vulns" in first:
                return "pip-audit"
        # Empty arrays are ambiguous by content
        raise ValueError(
            "Report is an empty JSON array — cannot determine the scanner format. "
            "Supported: sarif, semgrep, gitleaks, bandit, pip-audit."
        )

    raise ValueError(
        "Unrecognized report format. Supported: " + ", ".join(SUPPORTED_FORMATS) + "."
    )
