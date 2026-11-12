"""Tests for every CLI command via CliRunner."""

import json

from typer.testing import CliRunner

from patchledger.cli import app
from patchledger.models import ToolRunStatus
from patchledger.parsers.common import RawFinding
from patchledger.scanner import ScannerOutcome

runner = CliRunner()


def _fake_outcome(tool="semgrep", rule="rule-1", severity="ERROR", evidence="ev-1"):
    return ScannerOutcome(
        tool=tool,
        status=ToolRunStatus.RAN,
        version="test-1",
        findings=[
            RawFinding(
                scanner=tool, rule_id=rule, message=f"msg {rule}",
                file_path="app.py", start_line=3, severity_hint=severity,
                evidence=evidence,
            )
        ],
    )


def _db_args(tmp_path):
    db_path = tmp_path / "data" / "db.sqlite"
    return ["--db", str(db_path)], db_path


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "patchledger " in result.output


def test_help_lists_all_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("init", "scan", "import", "findings", "report", "history",
                "compare", "verify", "export-ai", "doctor"):
        assert cmd in result.output


def test_init_creates_project(tmp_path):
    args, db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    result = runner.invoke(app, [*args, "init", str(repo)])
    assert result.exit_code == 0, result.output
    assert db_path.exists()
    assert (db_path.parent / "config.json").exists()  # config next to explicit --db

    # Default (no --db): everything lands in <repo>/.patchledger/
    default_repo = tmp_path / "repo2"
    default_repo.mkdir()
    result = runner.invoke(app, ["init", str(default_repo)])
    assert result.exit_code == 0, result.output
    assert (default_repo / ".patchledger" / "patchledger.db").exists()
    assert ".patchledger/" in result.output  # gitignore guidance shown


def test_scan_command_with_fake_scanner(tmp_path, monkeypatch):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    runner.invoke(app, [*args, "init", str(repo)])

    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [_fake_outcome()],
    )
    # default fail_on=high and the finding is HIGH severity -> exit 2 by design
    result = runner.invoke(app, [*args, "scan", str(repo)])
    assert result.exit_code == 2, result.output
    assert "Scanner coverage" in result.output
    assert "1 findings" in result.output

    # with the threshold lowered below the finding's severity, exit 0
    result = runner.invoke(app, [*args, "scan", str(repo), "--fail-on", "critical"])
    assert result.exit_code == 0, result.output


def test_scan_exit_code_2_on_threshold(tmp_path, monkeypatch):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])

    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [_fake_outcome(severity="ERROR")],
    )
    result = runner.invoke(app, [*args, "scan", str(repo), "--fail-on", "high"])
    assert result.exit_code == 2, result.output

    # low-severity findings pass the same threshold
    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [_fake_outcome(severity="NOTE", rule="low-rule")],
    )
    result = runner.invoke(app, [*args, "scan", str(repo), "--fail-on", "high"])
    assert result.exit_code == 0, result.output


def test_scan_without_init_fails_friendly(tmp_path):
    args, _ = _db_args(tmp_path)
    result = runner.invoke(app, [*args, "scan", str(tmp_path)])
    assert result.exit_code == 1
    combined = result.output + (result.stderr or "")
    assert "patchledger init" in combined
    assert "Traceback" not in combined


def test_findings_json_and_filters(tmp_path, monkeypatch):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [
            _fake_outcome(severity="ERROR", rule="high-rule"),
            _fake_outcome(severity="NOTE", rule="low-rule"),
        ],
    )
    runner.invoke(app, [*args, "scan", str(repo)])

    result = runner.invoke(app, [*args, "findings", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload) == 2
    assert {f["severity"] for f in payload} == {"high", "info"}  # NOTE maps to info

    result = runner.invoke(app, [*args, "findings", "--severity", "high"])
    assert result.exit_code == 0
    assert "high-rule" in result.output
    assert "low-rule" not in result.output


def test_history_and_compare(tmp_path, monkeypatch):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [_fake_outcome()],
    )
    runner.invoke(app, [*args, "scan", str(repo)])

    result = runner.invoke(app, [*args, "history"])
    assert result.exit_code == 0
    assert "Scan history (1)" in result.output

    # second scan with an extra finding
    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [
            _fake_outcome(), _fake_outcome(rule="new-rule", evidence="ev-new")
        ],
    )
    runner.invoke(app, [*args, "scan", str(repo)])

    result = runner.invoke(app, [*args, "history"])
    assert "Scan history (2)" in result.output

    result = runner.invoke(app, [*args, "compare", "--help"])
    assert result.exit_code == 0


def test_report_generation_all_formats(tmp_path, monkeypatch):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [_fake_outcome()],
    )
    runner.invoke(app, [*args, "scan", str(repo)])

    for fmt, ext in (("html", ".html"), ("markdown", ".md"), ("json", ".json")):
        out = tmp_path / f"report{ext}"
        result = runner.invoke(
            app, [*args, "report", "--format", fmt, "--output", str(out)]
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert content.strip()


def test_export_ai_writes_prompt(tmp_path, monkeypatch):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [_fake_outcome()],
    )
    runner.invoke(app, [*args, "scan", str(repo)])

    out = tmp_path / "prompt.md"
    result = runner.invoke(app, [*args, "export-ai", "--output", str(out)])
    assert result.exit_code == 0, result.output
    content = out.read_text(encoding="utf-8")
    assert "# Security review request" in content
    assert "Do NOT invent evidence" in content
    assert "rule-1" in content


def test_verify_requires_two_scans(tmp_path, monkeypatch):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [_fake_outcome()],
    )
    runner.invoke(app, [*args, "scan", str(repo)])
    result = runner.invoke(app, [*args, "verify"])
    assert result.exit_code == 1
    combined = result.output + (result.stderr or "")
    assert "at least two scans" in combined

    # fix the finding: second scan has no findings, semgrep still runs
    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [
            ScannerOutcome(tool="semgrep", status=ToolRunStatus.RAN, version="test-1",
                           findings=[])
        ],
    )
    runner.invoke(app, [*args, "scan", str(repo)])
    result = runner.invoke(app, [*args, "verify"])
    assert result.exit_code == 0, result.output
    assert "FIXED VERIFIED" in result.output


def test_doctor_runs(tmp_path):
    args, _db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    result = runner.invoke(app, [*args, "doctor"])
    assert result.exit_code == 0, result.output
    assert "python" in result.output
    assert "database" in result.output


def test_scan_label_and_findings_rule_filter(tmp_path, monkeypatch):
    args, db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [
            _fake_outcome(rule="unique-rule-x"),
            _fake_outcome(rule="other-rule"),
        ],
    )
    result = runner.invoke(app, [*args, "scan", str(repo), "--label", "nightly"])
    assert result.exit_code in (0, 2), result.output

    result = runner.invoke(app, [*args, "findings", "--rule", "unique-rule-x", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "unique-rule-x"


def test_export_ai_min_severity(tmp_path, monkeypatch):
    args, db_path = _db_args(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    runner.invoke(app, [*args, "init", str(repo)])
    import patchledger.pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "run_all_scanners",
        lambda config, target, enabled=None: [
            _fake_outcome(rule="high-one", severity="ERROR"),
            _fake_outcome(rule="low-one", severity="NOTE"),
        ],
    )
    runner.invoke(app, [*args, "scan", str(repo), "--fail-on", "critical"])

    out = tmp_path / "prompt.md"
    result = runner.invoke(
        app, [*args, "export-ai", "--output", str(out), "--min-severity", "high"]
    )
    assert result.exit_code == 0, result.output
    content = out.read_text(encoding="utf-8")
    assert "high-one" in content
    assert "low-one" not in content
