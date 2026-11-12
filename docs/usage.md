# Usage handbook

Every PatchLedger command, every flag, and the exit codes CI relies on.

```
patchledger [--db PATH] [--debug] COMMAND
```

| Option    | Meaning                                                        |
|-----------|----------------------------------------------------------------|
| `--db`    | Path to the SQLite database (default `.patchledger/patchledger.db`) |
| `--debug` | Show full tracebacks instead of friendly error messages        |

## Commands

### `patchledger init [PATH]`

Initialize a project: creates `.patchledger/` (config + database) under PATH
(default `.`). An explicit `--db` puts the database anywhere you like.

### `patchledger scan [PATH]`

Run every enabled scanner that is installed, normalize + dedup + score the
results, and store one immutable scan.

```bash
patchledger scan .                       # default threshold from config (high)
patchledger scan . --fail-on medium      # CI gate: exit 2 on medium+ findings
patchledger scan . --strict              # exit 3 when the scan is incomplete
patchledger scan . --scanner bandit --scanner pip-audit   # override tool list
patchledger scan . --label "nightly-42"  # label the stored scan
```

After scanning, PatchLedger prints the honest tool-coverage table, the stored
finding count, and any ledger transitions (resolved / reintroduced /
inconclusive). A finding only becomes *resolved* when every scanner that ever
reported it ran successfully in the newer scan on the same target — otherwise
it is recorded as *inconclusive* (effectively still open).

### `patchledger import FILE...`

Import existing scanner reports as one scan bound to `--target` (default `.`).

```bash
patchledger import semgrep.json bandit.sarif --target .
patchledger import results.sarif --label "ci-run-123"
```

Supported formats (auto-detected from content): SARIF 2.1.0, semgrep JSON,
gitleaks JSON, bandit JSON, pip-audit JSON.

**Honesty note:** imported scans record their tools with status `imported` —
they cannot assert local scanner coverage, so resolution verification against
them is inconclusive by design.

### `patchledger findings`

Show the current per-finding ledger (open / resolved / reintroduced /
inconclusive), sorted by severity and risk score.

```bash
patchledger findings
patchledger findings --severity high          # at or above high
patchledger findings --status inconclusive    # not confirmed fixed
patchledger findings --scanner semgrep
patchledger findings --rule B602              # rule-id substring filter
patchledger findings --json                   # machine-readable
```

### `patchledger history`

List every recorded scan: id, timestamp, source (scan/import), tool statuses,
finding count.

### `patchledger compare SCAN_A SCAN_B`

Diff two scans (ids can be prefixes): new, persistent, resolved candidates,
reintroduced, changed severity, changed location. Targets that differ are
flagged as incompatible.

### `patchledger verify [--baseline ID]`

Explicitly verify resolution candidates between the previous scan and the
latest (or a chosen baseline). Prints per-fingerprint verdicts with reasons
and caveats, and persists status transitions to the audit trail.

### `patchledger report`

Generate a report for a scan (the latest by default, including a comparison
section when a previous scan exists).

```bash
patchledger report --format html --output report.html
patchledger report --format markdown
patchledger report --format json --scan 63c0fe0d
patchledger report --format sarif       # GitHub code scanning ingest
```

The HTML report is a single self-contained file: dark theme, no JavaScript,
Content-Security-Policy included, all dynamic content escaped. The SARIF
export carries normalized severity plus raw severity in properties,
patchledger fingerprints as partialFingerprints, and coverage honesty as
tool notifications.

### `patchledger export-ai`

Build a reviewer-ready prompt (Markdown by default, `--json` for structured
output) from open, reintroduced, and inconclusive findings — with explicit
constraints against inventing evidence. Works fully offline; bring your own
reviewer (human or AI).

```bash
patchledger export-ai --output review-prompt.md --max-findings 25
patchledger export-ai --min-severity high   # prioritize the review scope
```

### `patchledger doctor`

Installation health: Python version, scanner availability with versions,
config validity, database health. Missing scanners are informational, not
errors.

### `patchledger version`

Show the version.

## Exit codes

| Code | Meaning                                                                 |
|------|-------------------------------------------------------------------------|
| 0    | Success — findings may exist but are below the threshold                |
| 1    | Error — bad input, missing database, failed command                     |
| 2    | Findings at or above the `--fail-on` severity threshold (CI gate)        |
| 3    | Scan incomplete (missing/failed scanners) and `--strict` was passed      |

## Configuration

`.patchledger/config.json` (created by `init`, all keys optional):

```json
{
  "scanning":   { "enabled": ["semgrep", "gitleaks", "bandit", "pip-audit"],
                  "timeout_seconds": 600 },
  "scoring":    { "severity_base": { "critical": 90, "high": 70 },
                  "category_adjustment": { "secret": 10 } },
  "verification": { "require_coverage_asserted": true },
  "import_config": { "max_report_size_mb": 50, "disabled_rules": [] },
  "redact_secrets": true,
  "fail_on": "high"
}
```

Rule suppression requires an explicit `disabled_rules` entry — PatchLedger
never hides findings silently, and every suppression is counted and reported
on import/scan.
