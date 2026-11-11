"""Environment self-check (`patchledger doctor`).

Reports installation health honestly: what is available, what is missing, and
what that means for scan coverage. Missing scanners are expected and
acceptable — they are reported, never hidden.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from patchledger.config import PatchLedgerConfig
from patchledger.scanner import _VERSION_ARGS, discover_tool, get_tool_version
from patchledger.storage import PatchLedgerDB

KNOWN_SCANNERS = ["semgrep", "gitleaks", "bandit", "pip-audit", "trivy"]


@dataclass
class Check:
    """One doctor check result."""

    name: str
    ok: bool | None  # True ok, False problem, None warning/informational
    detail: str


def run_doctor(
    config: PatchLedgerConfig,
    config_dir: Path | None = None,
    db_path: Path | None = None,
    scanners: list[str] | None = None,
) -> list[Check]:
    """Collect environment checks. Does not modify anything."""
    checks: list[Check] = []

    # Python (the interpreter running PatchLedger; 3.10+ is guaranteed by packaging)
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(Check("python", True, f"Python {version}"))

    # Scanners
    enabled = scanners if scanners is not None else config.scanning.enabled
    for tool in enabled:
        path = discover_tool(tool, config.scanning.extra_paths)
        if path is None:
            checks.append(
                Check(
                    f"scanner:{tool}",
                    None,
                    "not installed — scans will report it as unavailable "
                    "(install it to widen coverage)",
                )
            )
            continue
        tool_version = get_tool_version(path, _VERSION_ARGS.get(tool, ["--version"]))
        detail = f"found at {path}" + (f" ({tool_version})" if tool_version else "")
        checks.append(Check(f"scanner:{tool}", True, detail))

    # Configuration
    if config_dir is not None:
        config_path = config_dir / "config.json"
        if config_path.exists():
            try:
                PatchLedgerConfig.load(config_dir)
                checks.append(Check("config", True, f"valid: {config_path}"))
            except Exception as exc:  # precise error already has context
                checks.append(Check("config", False, f"invalid: {exc}"))
        else:
            checks.append(
                Check("config", None, f"no config file at {config_path} (defaults in use)")
            )

    # Database
    if db_path is not None:
        try:
            with PatchLedgerDB(db_path) as db:
                healthy = db.health_check()
                checks.append(
                    Check(
                        "database",
                        healthy,
                        f"{db_path}" + (" — healthy" if healthy else " — health check failed"),
                    )
                )
        except Exception as exc:
            checks.append(Check("database", False, f"cannot open {db_path}: {exc}"))

    return checks
