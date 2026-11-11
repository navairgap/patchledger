"""PatchLedger command line interface.

Exit codes (documented in docs/usage.md):

* ``0`` — success (findings may exist but are below the threshold)
* ``1`` — error (bad input, missing database, failed command)
* ``2`` — findings at or above the ``--fail-on`` severity threshold (CI gate)
* ``3`` — scan incomplete and ``--strict`` requested (missing/failed scanners)
"""

from __future__ import annotations

import functools
import json
from collections.abc import Iterable
from pathlib import Path

import click
import typer
from rich.console import Console
from rich.table import Table

from patchledger import __version__
from patchledger.comparison import compare_scans
from patchledger.config import PatchLedgerConfig, validate_fail_on
from patchledger.errors import PatchLedgerError
from patchledger.models import FindingStatus, Project, Scan, Severity, utc_now_iso
from patchledger.reporting import (
    ComparisonSummary,
    ReportData,
    build_coverage,
    sort_findings,
    write_report,
)
from patchledger.storage import PatchLedgerDB
from patchledger.verification import (
    LedgerEntry,
    compute_project_ledger,
    update_ledger_after_scan,
    verify_scans,
)

app = typer.Typer(
    help="Evidence-first security finding and remediation verification.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()
err_console = Console(stderr=True)

DB_DIRNAME = ".patchledger"
DB_FILENAME = "patchledger.db"

_EXIT_OK = 0
_EXIT_ERROR = 1
_EXIT_THRESHOLD = 2
_EXIT_STRICT = 3


class _State:
    """Per-invocation global options."""

    db_path: Path = Path(DB_DIRNAME) / DB_FILENAME
    db_explicit: bool = False
    debug: bool = False


_state = _State()


@app.callback()
def _root(
    db: Path = typer.Option(
        None, "--db", help=f"Path to the PatchLedger database (default {DB_DIRNAME}/{DB_FILENAME})."
    ),
    debug: bool = typer.Option(False, "--debug", help="Show full tracebacks on errors."),
) -> None:
    """Find it. Understand it. Fix it. Prove it."""
    if db is not None:
        _state.db_path = db
        _state.db_explicit = True
    else:
        _state.db_path = Path(DB_DIRNAME) / DB_FILENAME
        _state.db_explicit = False
    _state.debug = debug


def _run(func):
    """Wrap a command body: friendly errors, optional tracebacks."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PatchLedgerError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(_EXIT_ERROR) from None
        except (typer.Exit, click.exceptions.Exit, click.exceptions.Abort):
            raise  # intentional exit codes must pass through untouched
        except Exception as exc:  # unexpected: be honest, keep it inspectable
            if _state.debug:
                raise
            err_console.print(
                f"[red]Unexpected error:[/red] {exc.__class__.__name__}: {exc}\n"
                "Run with --debug for a full traceback."
            )
            raise typer.Exit(_EXIT_ERROR) from None

    return wrapper


def _require_db() -> tuple[PatchLedgerDB, PatchLedgerConfig]:
    db_file = _state.db_path
    if not db_file.exists():
        raise PatchLedgerError(
            f"No PatchLedger database at {db_file}. Run `patchledger init` first."
        )
    db = PatchLedgerDB(db_file)
    config = PatchLedgerConfig.load(db_file.parent)
    return db, config


def _severity_at_or_above(severity: Severity, threshold: str) -> bool:
    order = ["info", "low", "medium", "high", "critical"]
    try:
        return order.index(severity.value) >= order.index(threshold)
    except ValueError:
        return False


def _print_tool_table(scan: Scan) -> None:
    table = Table(title="Scanner coverage", show_lines=False)
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Note", overflow="fold")
    for tool in scan.tools:
        table.add_row(tool.tool, tool.status.value, tool.version or "-", tool.note or "")
    console.print(table)


def _print_ledger(entries: list[LedgerEntry]) -> None:
    table = Table(title=f"Findings ({len(entries)})")
    table.add_column("Status")
    table.add_column("Sev")
    table.add_column("Score", justify="right")
    table.add_column("Scanner")
    table.add_column("Rule")
    table.add_column("Location")
    table.add_column("Title", overflow="fold")
    for entry in entries:
        table.add_row(
            entry.status.value,
            entry.finding.severity.value,
            str(entry.finding.score),
            entry.finding.scanner,
            entry.finding.rule_id,
            entry.finding.location_str,
            entry.finding.title,
        )
    console.print(table)


def _ledger_changes(entries: list[LedgerEntry]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.status.value] = counts.get(entry.status.value, 0) + 1
    return counts


def _filter_ledger(
    entries: Iterable[LedgerEntry], severity: str | None, status: str | None, scanner: str | None
) -> list[LedgerEntry]:
    result = []
    for entry in entries:
        if severity and not _severity_at_or_above(entry.finding.severity, severity):
            continue
        if status and entry.status.value != status:
            continue
        if scanner and entry.finding.scanner != scanner:
            continue
        result.append(entry)
    return result


# --------------------------------------------------------------------- init
@app.command()
@_run
def init(
    path: Path = typer.Argument(Path("."), help="Repository root to initialize."),
) -> None:
    """Initialize a PatchLedger project (creates .patchledger/ + config)."""
    root = Path(path).resolve()
    if not root.is_dir():
        raise PatchLedgerError(f"Not a directory: {root}")
    # Default DB location is inside the target repo; an explicit --db wins.
    db_file = _state.db_path if _state.db_explicit else root / DB_DIRNAME / DB_FILENAME
    ledger_dir = db_file.parent
    config = PatchLedgerConfig.load(ledger_dir)
    config_path = config.save(ledger_dir)
    with PatchLedgerDB(db_file) as _:
        pass
    console.print(f"[green]Initialized PatchLedger project for[/green] {root}")
    console.print(f"Config: {config_path}")
    console.print(f"Database: {db_file}")
    if not _state.db_explicit:
        console.print(
            f"\nNext steps:\n"
            f"  1. Add '{DB_DIRNAME}/' to your .gitignore (it contains local scan data).\n"
            f"  2. Run: patchledger scan {root}\n"
            "  3. Run: patchledger findings"
        )
    else:
        console.print(
            "\nNext steps:\n"
            f"  1. Run: patchledger --db {db_file} scan {root}\n"
            f"  2. Run: patchledger --db {db_file} findings"
        )


# --------------------------------------------------------------------- scan
@app.command()
@_run
def scan(
    target: Path = typer.Argument(Path("."), help="Repository directory to scan."),
    fail_on: str = typer.Option(None, "--fail-on", help="Severity threshold for exit code 2."),
    strict: bool = typer.Option(False, "--strict", help="Exit 3 when the scan is incomplete."),
    scanner: list[str] = typer.Option(
        None, "--scanner", help="Run only these scanners (repeatable). Overrides config."
    ),
) -> int:
    """Run available scanners, normalize findings, store one scan."""
    from patchledger.pipeline import scan_repository

    if fail_on:
        validate_fail_on(fail_on)
    target = Path(target).resolve()
    db, config = _require_db()

    with console.status("Scanning…"):
        result = scan_repository(db, target, config, enabled=scanner)

    _print_tool_table(result.scan)
    console.print(
        f"Scan [cyan]{result.scan.id}[/cyan] stored: {len(result.findings)} findings"
        + (f", {result.merged_count} duplicates merged" if result.merged_count else "")
        + (f", suppressed: {result.suppressed}" if result.suppressed else "")
    )

    counts = _ledger_changes(result.ledger)
    interesting = {
        k: v for k, v in counts.items()
        if k in ("reintroduced", "resolved", "inconclusive")
    }
    if interesting:
        console.print(f"Ledger: {interesting}")
    for warning in result.warnings:
        err_console.print(f"[yellow]Warning:[/yellow] {warning}")

    threshold = fail_on or config.fail_on
    open_or_reintroduced = [
        e for e in result.ledger if e.status in (FindingStatus.OPEN, FindingStatus.REINTRODUCED)
    ]
    hits = [
        e for e in open_or_reintroduced
        if _severity_at_or_above(e.finding.severity, threshold)
    ]
    if hits:
        console.print(
            f"[red]{len(hits)} finding(s) at or above '{threshold}' — failing "
            "(exit 2).[/red] See: patchledger findings"
        )
        code = _EXIT_THRESHOLD
    elif strict and not build_coverage(result.scan).complete:
        console.print("[yellow]Scan incomplete (--strict): exit 3.[/yellow]")
        code = _EXIT_STRICT
    else:
        console.print("[green]Done.[/green]")
        code = _EXIT_OK
    raise typer.Exit(code)


# ------------------------------------------------------------------- import
@app.command(name="import")
@_run
def import_reports_cmd(
    reports: list[Path] = typer.Argument(..., help="Report files to import."),
    target: Path = typer.Option(
        Path("."), "--target", help="Repository root the reports belong to."
    ),
    label: str = typer.Option(None, "--label", help="Label for the imported scan."),
) -> None:
    """Import existing scanner reports (SARIF/semgrep/gitleaks/bandit/pip-audit)."""
    from patchledger.pipeline import import_reports

    db, config = _require_db()
    result = import_reports(db, [Path(r) for r in reports], config, Path(target).resolve(), label)
    console.print(
        f"Imported scan [cyan]{result.scan.id}[/cyan]: {len(result.findings)} findings"
        + (f", {result.merged_count} duplicates merged" if result.merged_count else "")
        + (f", suppressed: {result.suppressed}" if result.suppressed else "")
    )
    tools = {t.tool: t.status.value for t in result.scan.tools}
    console.print(f"Scanners recorded: {tools}")
    console.print(
        "[yellow]Note:[/yellow] imported scans cannot assert scanner coverage; "
        "resolution verification against them is inconclusive by design."
    )
    for warning in result.warnings:
        err_console.print(f"[yellow]Warning:[/yellow] {warning}")


# ----------------------------------------------------------------- findings
@app.command()
@_run
def findings(
    severity: str = typer.Option(None, "--severity", help="Only at/above this severity."),
    status: str = typer.Option(None, "--status", help="open|resolved|reintroduced|inconclusive."),
    scanner: str = typer.Option(None, "--scanner", help="Only this scanner."),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Show the current finding ledger for the project."""
    db, config = _require_db()
    project = _current_project(db)
    entries = compute_project_ledger(db, project.id, config)
    entries = _filter_ledger(entries, severity, status, scanner)

    if json_output:
        payload = [
            {
                "fingerprint": e.fingerprint,
                "status": e.status.value,
                "severity": e.finding.severity.value,
                "score": e.finding.score,
                "scanner": e.finding.scanner,
                "rule_id": e.finding.rule_id,
                "title": e.finding.title,
                "location": e.finding.location_str,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
                "seen_in_scans": e.seen_in_scans,
                "verdict": {
                    "state": e.verdict.state,
                    "reasons": e.verdict.reasons,
                    "caveats": e.verdict.caveats,
                } if e.verdict else None,
            }
            for e in entries
        ]
        console.print_json(json.dumps(payload))
        return

    if severity or status or scanner:
        _print_ledger(entries)
        return
    _print_ledger(entries)
    resolved = [e for e in entries if e.status == FindingStatus.RESOLVED]
    if resolved:
        console.print(f"[green]{len(resolved)} finding(s) verified fixed.[/green]")
    inconclusive = [e for e in entries if e.status == FindingStatus.INCONCLUSIVE]
    if inconclusive:
        console.print(
            f"[yellow]{len(inconclusive)} finding(s) inconclusive — not confirmed fixed.[/yellow]"
        )


def _current_project(db: PatchLedgerDB) -> Project:
    projects = db.list_projects()
    if not projects:
        raise PatchLedgerError("No projects in this database. Run `patchledger scan` first.")
    if len(projects) > 1:
        raise PatchLedgerError(
            "Multiple projects in this database; this beta build uses the first. "
            "Use separate databases (--db) per repository."
        )
    return projects[0]


# ------------------------------------------------------------------- report
@app.command()
@_run
def report(
    fmt: str = typer.Option("html", "--format", help="html | markdown | json"),
    output: Path = typer.Option(None, "--output", help="Output file (default auto-named)."),
    scan_id: str = typer.Option(None, "--scan", help="Scan id (default: latest)."),
) -> None:
    """Generate a security report for a scan (comparison included when available)."""
    db, config = _require_db()
    project = _current_project(db)
    scans = db.list_scans(project.id)
    if not scans:
        raise PatchLedgerError("No scans recorded yet. Run `patchledger scan` first.")
    if scan_id:
        scan = next((s for s in scans if s.id == scan_id), None)
        if scan is None:
            raise PatchLedgerError(f"Scan {scan_id} not found.")
    else:
        scan = scans[-1]

    comparison: ComparisonSummary | None = None
    if len(scans) >= 2 and scan.id == scans[-1].id:
        previous = scans[-2]
        diff = compare_scans(db, previous, scan)
        verdict_report = verify_scans(db, previous, scan, config)
        counts = verdict_report.counts()
        comparison = ComparisonSummary(
            baseline_scan_id=previous.id,
            baseline_created_at=previous.created_at,
            new=counts["new"],
            persistent=counts["persistent"],
            resolved_candidates=counts["resolved_candidates"],
            reintroduced=counts["reintroduced"],
            changed_severity=counts["changed_severity"],
            changed_evidence=counts["changed_evidence"],
            verified_fixed=counts["verified_fixed"],
            inconclusive=counts["inconclusive"],
            notes=diff.notes,
        )

    findings = sort_findings(db.get_findings(scan.id))
    data = ReportData(
        project_name=project.name,
        project_root=project.root_path,
        scan=scan,
        findings=findings,
        generated_at=utc_now_iso(),
        coverage=build_coverage(scan),
        comparison=comparison,
    )
    ext = {"html": ".html", "markdown": ".md", "md": ".md", "json": ".json"}[fmt]
    out_path = output if output else Path(f"patchledger-report-{scan.id[:8]}{ext}")
    written = write_report(data, fmt, out_path)
    console.print(f"[green]Report written:[/green] {written}")


# ------------------------------------------------------------------ history
@app.command()
@_run
def history() -> None:
    """List all recorded scans with coverage status."""
    db, _ = _require_db()
    project = _current_project(db)
    scans = db.list_scans(project.id)
    if not scans:
        console.print("No scans recorded yet.")
        return
    table = Table(title=f"Scan history ({len(scans)})")
    table.add_column("Scan")
    table.add_column("Created")
    table.add_column("Source")
    table.add_column("Tools")
    table.add_column("Findings", justify="right")
    for scan in scans:
        tool_summary = ", ".join(f"{t.tool}:{t.status.value}" for t in scan.tools) or "-"
        count = len(db.get_fingerprint_index(scan.id))
        table.add_row(scan.id[:8], scan.created_at, scan.source.value, tool_summary, str(count))
    console.print(table)


# ------------------------------------------------------------------ compare
@app.command()
@_run
def compare(
    scan_a: str = typer.Argument(..., help="Baseline scan id (older)."),
    scan_b: str = typer.Argument(..., help="Newer scan id."),
) -> None:
    """Compare two scans and show the diff."""
    from patchledger.comparison import compare_scans

    db, _ = _require_db()
    project = _current_project(db)
    scans = {s.id: s for s in db.list_scans(project.id)}
    a = scans.get(scan_a) or next((s for s in scans.values() if s.id.startswith(scan_a)), None)
    b = scans.get(scan_b) or next((s for s in scans.values() if s.id.startswith(scan_b)), None)
    if a is None or b is None:
        raise PatchLedgerError(f"Scan not found: {scan_a if a is None else scan_b}")
    diff = compare_scans(db, a, b)
    for note in diff.notes:
        err_console.print(f"[yellow]{note}[/yellow]")
    counts = diff.summary()
    table = Table(title=f"Compare {a.id[:8]} -> {b.id[:8]}")
    table.add_column("Change")
    table.add_column("Count", justify="right")
    for key, value in counts.items():
        table.add_row(key.replace("_", " "), str(value))
    console.print(table)


# ------------------------------------------------------------------- verify
@app.command()
@_run
def verify(
    baseline: str = typer.Option(None, "--baseline", help="Baseline scan id (default: previous)."),
) -> None:
    """Verify whether findings disappeared with real scanner coverage evidence."""
    db, config = _require_db()
    project = _current_project(db)
    scans = db.list_scans(project.id)
    if len(scans) < 2:
        raise PatchLedgerError("Need at least two scans to verify. Run `patchledger scan` again.")
    current = scans[-1]
    if baseline:
        base = next((s for s in scans[:-1] if s.id.startswith(baseline)), None)
        if base is None:
            raise PatchLedgerError(f"Baseline scan {baseline} not found among earlier scans.")
    else:
        base = scans[-2]

    report = verify_scans(db, base, current, config)
    console.print(f"Verifying [cyan]{base.id[:8]}[/cyan] -> [cyan]{current.id[:8]}[/cyan]")
    for fingerprint, verdict in report.verdicts.items():
        if verdict.is_verified:
            console.print(f"  [green]FIXED VERIFIED[/green] {fingerprint}")
        else:
            console.print(f"  [yellow]INCONCLUSIVE[/yellow] {fingerprint}")
            for reason in verdict.reasons:
                console.print(f"      - {reason}")
        for caveat in verdict.caveats:
            console.print(f"      [dim]! {caveat}[/dim]")
    counts = report.counts()
    console.print(
        f"Summary: new={counts['new']} persistent={counts['persistent']} "
        f"resolved_candidates={counts['resolved_candidates']} "
        f"verified_fixed={counts['verified_fixed']} inconclusive={counts['inconclusive']} "
        f"reintroduced={counts['reintroduced']}"
    )
    update_ledger_after_scan(db, project.id, config)


# ---------------------------------------------------------------- export-ai
@app.command(name="export-ai")
@_run
def export_ai(
    output: Path = typer.Option(None, "--output", help="Output file (default: print to stdout)."),
    json_format: bool = typer.Option(False, "--json", help="Emit the JSON prompt variant."),
    max_findings: int = typer.Option(25, "--max-findings", help="Cap on findings included."),
) -> None:
    """Generate a review prompt for an external AI or human reviewer (offline)."""
    from patchledger.prompt_generator import build_review_prompt, build_review_prompt_json

    db, config = _require_db()
    project = _current_project(db)
    scans = db.list_scans(project.id)
    if not scans:
        raise PatchLedgerError("No scans recorded yet. Run `patchledger scan` first.")
    ledger = compute_project_ledger(db, project.id, config)
    if json_format:
        content = build_review_prompt_json(ledger, project.name, scans[-1])
    else:
        content = build_review_prompt(ledger, project.name, scans[-1], max_findings)
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Review prompt written:[/green] {output}")
    else:
        console.print(content)


# ------------------------------------------------------------------- doctor
@app.command()
@_run
def doctor() -> None:
    """Check installation health: python, scanners, config, database."""
    from patchledger.doctor import run_doctor

    config_dir = _state.db_path.parent
    config = PatchLedgerConfig.load(config_dir) if config_dir.exists() else PatchLedgerConfig()
    checks = run_doctor(config, config_dir, _state.db_path if _state.db_path.exists() else None)
    table = Table(title="PatchLedger doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")
    for check in checks:
        if check.ok is True:
            status = "[green]ok[/green]"
        elif check.ok is False:
            status = "[red]problem[/red]"
        else:
            status = "[yellow]notice[/yellow]"
        table.add_row(check.name, status, check.detail)
    console.print(table)


@app.command()
@_run
def version() -> None:
    """Show the PatchLedger version."""
    console.print(f"patchledger {__version__}")


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
