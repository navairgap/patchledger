"""Security scanner orchestration.

Principles:

* Scanners run as argv lists through ``subprocess.run`` — never a shell,
  never auto-downloaded, never with user-supplied strings interpolated into
  a command line beyond the target path itself.
* Every tool's participation is recorded honestly: ran / failed / unavailable
  / skipped. A scan is never reported as complete when tools did not run.
* Exit codes do not mean failure for these tools (bandit exits 1 when it
  finds issues, gitleaks exits 1 on leaks, pip-audit exits 1 on
  vulnerabilities): success is determined by a parseable report.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from patchledger.config import PatchLedgerConfig
from patchledger.errors import ScannerError
from patchledger.models import ToolRunStatus
from patchledger.parsers.common import ParseResult, RawFinding

_STDERR_EXCERPT = 500


@dataclass
class ToolSpec:
    """How to invoke one scanner."""

    name: str
    version_args: list[str]

    def report_args(self, target: Path, report_path: Path | None) -> list[str]:
        raise NotImplementedError


def _semgrep_args(target: Path, report_path: Path | None) -> list[str]:
    # Arguments only — run_scanner prepends the discovered binary path.
    return ["scan", "--json", "--quiet", str(target)]


def _bandit_args(target: Path, report_path: Path | None) -> list[str]:
    return ["-r", str(target), "-f", "json", "-q"]


def _gitleaks_args(target: Path, report_path: Path | None) -> list[str]:
    args = [
        "detect",
        "--source", str(target),
        "--report-format", "json",
        "--report-path", str(report_path),
        "--redact",  # gitleaks-side redaction; normalizer redacts again
        "--exit-code", "0",  # findings are not command failures
    ]
    if not (target / ".git").exists():
        args.append("--no-git")
    return args


def _pip_audit_args(target: Path, report_path: Path | None) -> list[str] | None:
    requirements = _find_requirements(target)
    if not requirements:
        return None
    return ["-r", str(requirements), "--format", "json", "--progress-spinner", "off"]


def _trivy_args(target: Path, report_path: Path | None) -> list[str]:
    return [
        "fs",
        "--format", "sarif",
        "--output", str(report_path),
        "--quiet",
        str(target),
    ]


def _find_requirements(target: Path) -> Path | None:
    """Pick the requirements file pip-audit should audit, if any."""
    preferred = target / "requirements.txt"
    if preferred.is_file():
        return preferred
    candidates = sorted(target.glob("requirements*.txt"))
    return candidates[0] if candidates else None


@dataclass
class ScannerOutcome:
    """One tool's participation in a scan, with parsed findings."""

    tool: str
    status: ToolRunStatus
    version: str | None = None
    exit_code: int | None = None
    note: str | None = None
    duration_ms: int | None = None
    findings: list[RawFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parse_result: ParseResult | None = None


def discover_tool(name: str, extra_paths: list[str] | None = None) -> str | None:
    """Locate a scanner binary.

    Lookup order: config ``extra_paths``, then PATH, then the directory of the
    running interpreter (a venv-installed scanner sits next to patchledger).
    """
    for directory in extra_paths or []:
        candidate = Path(directory) / name
        if candidate.is_file() and (candidate.stat().st_mode & 0o111):
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    venv_candidate = Path(sys.executable).parent / name
    if venv_candidate.is_file() and (venv_candidate.stat().st_mode & 0o111):
        return str(venv_candidate)
    return None


def get_tool_version(tool_path: str, spec_version_args: list[str]) -> str | None:
    """Best-effort version lookup; None when it cannot be determined."""
    try:
        proc = subprocess.run(
            [tool_path, *spec_version_args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    output = (proc.stdout or proc.stderr or "").strip()
    first_line = output.splitlines()[0].strip() if output else ""
    return first_line or None


def _parse_scanner_output(tool: str, report_text: str, scan_root: str | None) -> ParseResult:
    """Parse a scanner report by dispatching through the parser registry."""
    import json

    from patchledger.parsers import _PARSERS
    from patchledger.parsers.detect import detect_format

    data = json.loads(report_text)
    fmt = detect_format(data)
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise ScannerError(f"No parser for detected format {fmt!r} from {tool}")
    return parser(data, scan_root)


def run_scanner(
    tool: str,
    tool_path: str,
    target: Path,
    timeout: int,
    scan_root: str | None = None,
) -> ScannerOutcome:
    """Run one scanner against the target and parse its report."""
    outcome = ScannerOutcome(tool=tool, status=ToolRunStatus.FAILED)

    uses_report_file = tool in {"gitleaks", "trivy"}
    with tempfile.TemporaryDirectory(prefix="patchledger-") as tmp:
        report_path = Path(tmp) / "report.json"
        if tool == "semgrep":
            argv = _semgrep_args(target, report_path)
        elif tool == "bandit":
            argv = _bandit_args(target, report_path)
        elif tool == "gitleaks":
            argv = _gitleaks_args(target, report_path)
        elif tool == "pip-audit":
            argv = _pip_audit_args(target, report_path) or []
        elif tool == "trivy":
            argv = _trivy_args(target, report_path)
        else:
            outcome.status = ToolRunStatus.SKIPPED
            outcome.note = f"Unknown scanner {tool!r}"
            return outcome

        # argv[0] is the DISCOVERED binary path, never a bare name: this keeps
        # execution pinned to the tool we located (no PATH re-resolution).
        argv = [tool_path, *argv]

        if not argv:
            outcome.status = ToolRunStatus.SKIPPED
            outcome.note = "no requirements*.txt found; nothing for pip-audit to audit"
            return outcome

        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                cwd=str(target),
            )
        except subprocess.TimeoutExpired:
            outcome.duration_ms = int((time.monotonic() - started) * 1000)
            outcome.status = ToolRunStatus.FAILED
            outcome.note = f"timed out after {timeout}s"
            return outcome
        except OSError as exc:
            outcome.duration_ms = int((time.monotonic() - started) * 1000)
            outcome.status = ToolRunStatus.FAILED
            outcome.note = f"failed to start {tool}: {exc}"
            return outcome

        outcome.duration_ms = int((time.monotonic() - started) * 1000)
        outcome.exit_code = proc.returncode

        report_text = ""
        if uses_report_file:
            if report_path.exists():
                report_text = report_path.read_text(encoding="utf-8", errors="replace")
        else:
            report_text = proc.stdout or ""

        if not report_text.strip():
            stderr_excerpt = (proc.stderr or "")[-_STDERR_EXCERPT:].strip()
            outcome.status = ToolRunStatus.FAILED
            outcome.note = (
                f"exit code {proc.returncode}, no parseable report"
                + (f"; stderr: {stderr_excerpt}" if stderr_excerpt else "")
            )
            return outcome

        try:
            parsed = _parse_scanner_output(tool, report_text, scan_root)
        except Exception as exc:
            outcome.status = ToolRunStatus.FAILED
            outcome.note = f"report could not be parsed: {exc.__class__.__name__}: {exc}"
            return outcome

        outcome.status = ToolRunStatus.RAN
        outcome.findings = parsed.findings
        outcome.warnings = parsed.warnings
        outcome.parse_result = parsed
        return outcome


def run_all_scanners(
    config: PatchLedgerConfig,
    target: Path,
    enabled: list[str] | None = None,
) -> list[ScannerOutcome]:
    """Run every enabled scanner, honestly recording unavailable/failed tools."""
    enabled = enabled if enabled is not None else config.scanning.enabled
    outcomes: list[ScannerOutcome] = []
    target_str = str(target)

    for tool in enabled:
        tool_path = discover_tool(tool, config.scanning.extra_paths)
        if tool_path is None:
            outcomes.append(
                ScannerOutcome(
                    tool=tool,
                    status=ToolRunStatus.UNAVAILABLE,
                    note="not found on PATH or in the patchledger environment",
                )
            )
            continue

        version = get_tool_version(tool_path, _VERSION_ARGS.get(tool, ["--version"]))
        outcome = run_scanner(tool, tool_path, target, config.scanning.timeout_seconds, target_str)
        outcome.version = version
        outcomes.append(outcome)

    return outcomes


_VERSION_ARGS = {
    "semgrep": ["--version"],
    "bandit": ["--version"],
    "gitleaks": ["version"],
    "pip-audit": ["--version"],
    "trivy": ["--version"],
}


def collect_git_metadata(target: Path) -> tuple[str | None, str | None]:
    """Return (commit, branch) for the target if it is a git repository."""
    commit = branch = None
    try:
        proc = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if proc.returncode == 0:
            commit = proc.stdout.strip() or None
        proc = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if proc.returncode == 0:
            name = proc.stdout.strip()
            branch = name if name and name != "HEAD" else None
    except (OSError, subprocess.TimeoutExpired):
        pass
    return commit, branch
