"""Regenerate the synthetic example reports in examples/.

The examples are produced by PatchLedger's real reporters from a synthetic
scan — clearly labeled SYNTHETIC EXAMPLE DATA, never presented as a real scan.

Usage: python scripts/generate_examples.py
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from patchledger.config import PatchLedgerConfig  # noqa: E402
from patchledger.models import Finding, Scan, ScanSource, ScanToolRun  # noqa: E402
from patchledger.normalizer import normalize_findings  # noqa: E402
from patchledger.parsers.common import RawFinding  # noqa: E402
from patchledger.reporting import (  # noqa: E402
    ComparisonSummary,
    ReportData,
    build_coverage,
    sort_findings,
    write_report,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

# Credential-like values are assembled at runtime: this generator produces
# synthetic data and must not contain real-looking secret literals.
FAKE_KEY = "AKIA" + "EX" * 9 + "AMP"


def _raw(scanner, rule, message, path=None, line=None, severity="ERROR",
         evidence="", fix=None) -> RawFinding:
    return RawFinding(
        scanner=scanner, rule_id=rule, message=message, file_path=path,
        start_line=line, severity_hint=severity, evidence=evidence, fix=fix,
    )


def build_synthetic_findings() -> list[Finding]:
    config = PatchLedgerConfig()
    raws = [
        _raw("gitleaks", "aws-access-token", "AWS Access Key",
             path="config/settings.py", line=12, severity="high",
             evidence=f'aws_key = "{FAKE_KEY}"'),
        _raw("semgrep", "python.lang.security.audit.subprocess-shell-true",
             "Detected subprocess with shell=True. Prefer a command list.",
             path="app/jobs.py", line=87, severity="ERROR",
             evidence="subprocess.run(user_cmd, shell=True)",
             fix="subprocess.run(shlex.split(user_cmd), shell=False)"),
        _raw("semgrep", "python.lang.security.audit.hardcoded-password-string",
             "Detected hardcoded password secret in variable.",
             path="app/jobs.py", line=41, severity="WARNING",
             evidence='DB_PASS = "placeholder-redacted"'),
        _raw("bandit", "B608", "Possible SQL injection vector through string use.",
             path="app/db.py", line=133, severity="HIGH",
             evidence='cursor.execute("SELECT * FROM users WHERE name=\'" + name + "\'")'),
        _raw("pip-audit", "PYSEC-2023-62",
             "Vulnerable dependency: flask==0.12.4 (PYSEC-2023-62) — fixed in 2.2.5, 2.3.2",
             severity="high", evidence="flask==0.12.4",
             fix="Upgrade flask to 2.3.2 or later"),
        _raw("bandit", "B101", "Use of assert detected. The enclosed code will be "
             "removed when compiling to optimised byte code.",
             path="app/validate.py", line=22, severity="LOW", evidence="assert token is not None"),
    ]
    findings = normalize_findings(raws, config).findings
    return sort_findings(findings)


def main() -> None:
    scan = Scan(
        project_id="synthetic-project",
        target_path="/home/dev/example-project",
        source=ScanSource.SCAN,
        created_at="2026-11-11T12:00:00+00:00",
        git_commit="0f1e2d3c4b5a69788796a5b4c3d2e1f001122334",
        git_branch="main",
        tools=[
            ScanToolRun(tool="semgrep", status="ran", version="1.185.0"),
            ScanToolRun(tool="bandit", status="ran", version="1.9.4"),
            ScanToolRun(tool="pip-audit", status="ran", version="2.10.1"),
            ScanToolRun(tool="gitleaks", status="unavailable",
                        note="not installed on this machine"),
            ScanToolRun(tool="trivy", status="skipped",
                        note="disabled in project configuration"),
        ],
    )
    data = ReportData(
        project_name="example-project (synthetic)",
        project_root="/home/dev/example-project",
        scan=scan,
        findings=build_synthetic_findings(),
        generated_at="2026-11-11T12:05:00+00:00",
        coverage=build_coverage(scan),
        comparison=ComparisonSummary(
            baseline_scan_id="3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c",
            baseline_created_at="2026-11-04T09:00:00+00:00",
            new=1, persistent=4, resolved_candidates=2,
            verified_fixed=1, inconclusive=1, reintroduced=0,
            changed_severity=0, changed_evidence=1,
            notes=["Resolution of one finding was inconclusive: gitleaks "
                   "did not run in the current scan."],
        ),
        is_synthetic_example=True,
        notes=["This is a SYNTHETIC example produced by scripts/generate_examples.py "
               "to illustrate report structure. It is not a real scan."],
    )

    EXAMPLES.mkdir(exist_ok=True)
    for fmt, name in (("json", "sample-report.json"),
                      ("markdown", "sample-report.md"),
                      ("html", "sample-report.html")):
        out = write_report(data, fmt, EXAMPLES / name)
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
