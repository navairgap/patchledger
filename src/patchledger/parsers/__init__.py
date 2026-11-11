"""Scanner report parsers: unified entry point.

``parse_report_file`` loads a report safely, detects its format from content,
and dispatches to the matching parser. Format detection is content-based so
users do not need to remember the right flags.
"""

from __future__ import annotations

from pathlib import Path

from patchledger.config import PatchLedgerConfig
from patchledger.errors import ReportImportError
from patchledger.parsers.bandit import parse_bandit
from patchledger.parsers.common import ParseResult, load_json_report
from patchledger.parsers.detect import detect_format
from patchledger.parsers.gitleaks import parse_gitleaks
from patchledger.parsers.pip_audit import parse_pip_audit
from patchledger.parsers.sarif import parse_sarif
from patchledger.parsers.semgrep import parse_semgrep

_PARSERS = {
    "sarif": parse_sarif,
    "semgrep": parse_semgrep,
    "gitleaks": parse_gitleaks,
    "bandit": parse_bandit,
    "pip-audit": parse_pip_audit,
}


def parse_report_file(
    path: Path, config: PatchLedgerConfig, scan_root: str | None = None
) -> ParseResult:
    """Parse one scanner report file.

    Raises :class:`ReportImportError` when the file cannot be read, is
    malformed, or matches no supported format.
    """
    data = load_json_report(path, config.import_config.max_report_size_mb)
    try:
        fmt = detect_format(data)
    except ValueError as exc:
        raise ReportImportError(f"Cannot import {path.name}: {exc}") from exc

    parser = _PARSERS[fmt]
    try:
        return parser(data, scan_root)
    except ValueError as exc:
        raise ReportImportError(f"Invalid {fmt} report {path.name}: {exc}") from exc
    except (AttributeError, KeyError, TypeError) as exc:
        # Defensive: unexpected report shapes must not crash the import.
        raise ReportImportError(
            f"Unexpected structure in {fmt} report {path.name}: {exc.__class__.__name__}: {exc}"
        ) from exc
