"""Shared parser infrastructure: safe JSON loading and the raw finding model."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from patchledger.errors import ReportImportError

# Hard cap on report file size. Protects against oversized inputs regardless
# of configuration (a genuine scanner report is never this large).
ABSOLUTE_MAX_REPORT_BYTES = 512 * 1024 * 1024


@dataclass
class RawFinding:
    """Scanner finding exactly as extracted from a report.

    Parsers extract; the normalizer interprets and decides. Fields the scanner
    did not provide stay None/empty — PatchLedger never invents metadata.
    """

    scanner: str
    rule_id: str
    message: str = ""
    description: str = ""
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    evidence: str = ""
    severity_hint: str | None = None  # scanner-provided severity, verbatim
    confidence_hint: str | None = None
    fix: str | None = None  # scanner-suggested fix, verbatim
    references: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)  # preserved verbatim


@dataclass
class ParseResult:
    """Outcome of parsing one report file."""

    scanner: str  # primary scanner identity for the file
    findings: list[RawFinding]
    warnings: list[str] = field(default_factory=list)


def reject_constant(value: str) -> None:
    """Refuse NaN/Infinity JSON constants (non-standard, ambiguous data)."""
    raise ReportImportError(f"JSON contains non-standard numeric constant: {value!r}")


MAX_FINDINGS = 50_000


def loads_strict(text: str, source: str = "report") -> object:
    """Parse JSON text with the same strictness as ``load_json_report``.

    Used for scanner stdout on the live-scan path, which previously used a
    plain ``json.loads`` and would have accepted NaN/Infinity constants.
    """
    try:
        return json.loads(text, parse_constant=reject_constant)
    except ReportImportError:
        raise
    except json.JSONDecodeError as exc:
        raise ReportImportError(
            f"{source} output is not valid JSON: {exc.msg} (line {exc.lineno}, "
            f"column {exc.colno})"
        ) from exc
    except RecursionError as exc:
        raise ReportImportError(f"{source} output is nested too deeply to parse safely.") from exc


def load_json_report(path: Path, max_mb: int) -> object:
    """Load a JSON report safely: size cap, strict parsing, clear errors.

    Raises :class:`ReportImportError` with an actionable message on any
    malformed or oversized input.
    """
    if not path.exists():
        raise ReportImportError(f"Report file not found: {path}")
    if not path.is_file():
        raise ReportImportError(f"Report path is not a file: {path}")

    size = path.stat().st_size
    max_bytes = min(max_mb, 512) * 1024 * 1024
    if size > max_bytes:
        raise ReportImportError(
            f"Report file {path.name} is {size / 1024 / 1024:.1f} MB, exceeding the "
            f"{max_mb} MB limit. Export a filtered report or raise "
            f"`import_config.max_report_size_mb` in your config."
        )
    if size == 0:
        raise ReportImportError(f"Report file is empty: {path}")

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportImportError(f"Cannot read report file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ReportImportError(
            f"Report file {path} is not valid UTF-8 text: {exc}"
        ) from exc

    try:
        return json.loads(text, parse_constant=reject_constant)
    except ReportImportError:
        raise
    except json.JSONDecodeError as exc:
        raise ReportImportError(
            f"Report file {path} is not valid JSON: {exc.msg} (line {exc.lineno}, "
            f"column {exc.colno})"
        ) from exc
    except RecursionError as exc:
        raise ReportImportError(
            f"Report file {path} is nested too deeply to parse safely."
        ) from exc


def normalize_file_path(path: str | None, scan_root: str | None = None) -> str | None:
    """Normalize a scanner-reported path to a POSIX-style string.

    Absolute paths under ``scan_root`` are relativized so a report generated
    elsewhere matches a local scan. Paths that cannot be relativized are kept
    (normalized) — fingerprints then differ from a local scan of the same code,
    which is the honest outcome for a report we cannot map onto this tree.
    """
    if not path:
        return None
    cleaned = path.strip().replace("\\", "/")
    if scan_root and cleaned.startswith("/"):
        root = scan_root.rstrip("/")
        if cleaned.startswith(root + "/"):
            cleaned = cleaned[len(root) + 1 :]
    while "//" in cleaned:
        cleaned = cleaned.replace("//", "/")
    cleaned = cleaned.strip("/")
    return cleaned or None


def sarif_uri_to_path(uri: str, scan_root: str | None = None) -> str | None:
    """Convert a SARIF artifactLocation URI to a normalized path."""
    if not uri:
        return None
    decoded = unquote(uri)
    decoded = decoded.replace("\\", "/")
    # Strip file:// scheme if present
    if decoded.startswith("file://"):
        decoded = decoded[7:]
    return normalize_file_path(decoded, scan_root)


def to_int(value: object) -> int | None:
    """Best-effort int conversion; None when not a usable number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None
