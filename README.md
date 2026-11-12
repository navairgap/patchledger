# PatchLedger

**Find it. Understand it. Fix it. Prove it.**

[![CI](https://github.com/navairgap/patchledger/actions/workflows/ci.yml/badge.svg)](https://github.com/navairgap/patchledger/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-3fb968.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-539bf5.svg)](pyproject.toml)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)

An evidence-first, open-source security finding and remediation verification
platform for developers.

PatchLedger runs established security scanners on your repositories (or
imports their reports), merges everything into one deduplicated, scored,
explainable ledger — and then does the part most tools skip: it **verifies
whether a vulnerability was actually fixed** before calling it resolved,
using real scanner-coverage evidence. No AI API, no cloud, no telemetry.

---

## The problem

A typical project runs one tool for secrets, another for vulnerable
dependencies, a third for insecure code. The results land in five formats
with five severity scales. Developers manually reconcile them, and when a
finding stops appearing in scans, everyone *assumes* it was fixed — even if
the scanner never ran, crashed, or didn't cover that code. False "resolved"
states are how regressions reach production.

## What PatchLedger does

1. **Scan** your repo with installed tools: semgrep, gitleaks, bandit,
   pip-audit, trivy — honestly recording which tools ran, failed, or were
   missing. Or **import** existing reports (SARIF 2.1.0, semgrep JSON,
   gitleaks JSON, bandit JSON, pip-audit JSON — auto-detected).
2. **Normalize** every finding into one model with explicit severity tables,
   secret redaction, categories, and offline remediation guidance. Scanner
   metadata is preserved verbatim, never invented.
3. **Fingerprint & dedup** with deterministic, versioned fingerprints that
   survive line shifts; merged sightings keep all occurrences as evidence.
4. **Score** deterministically (0–100) with every adjustment explained.
5. **Store** each scan as an immutable observation in a local SQLite ledger
   with an audit trail of status transitions.
6. **Compare & verify**: diff any two scans; a vanished finding becomes
   *resolved* only when every scanner that ever reported it ran successfully
   on the same target — otherwise it is honestly **inconclusive**.
7. **Report** as JSON, Markdown, or a self-contained dark HTML file (no
   JavaScript, CSP-protected, fully escaped).

## Quick start

```bash
pipx install patchledger          # or: pip install patchledger
cd your-project
patchledger init                  # creates .patchledger/ (config + ledger db)
patchledger scan .                # runs installed scanners
patchledger findings              # the live ledger
# ...fix some code...
patchledger scan .                # re-scan
patchledger verify                # proof, or an honest "inconclusive"
patchledger report --format html  # self-contained report
```

A real session against a deliberately-vulnerable fixture repository:

```
$ patchledger scan ./demo_repo
┏━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━┓
┃ Tool    ┃ Status ┃ Version   ┃ Note ┃
┡━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━┩
│ semgrep │ ran    │ 1.185.0   │      │
│ gitleaks│ unavailable │ — │ not found on PATH or in the patchledger environment │
│ bandit  │ ran    │ 1.9.4     │      │
│ pip-audit│ ran   │ 2.10.1    │      │
└─────────┴────────┴───────────┴──────┘
Scan 63c0fe0d… stored: 11 findings

$ patchledger verify
  FIXED VERIFIED fp2:9d21…  — all reporting scanners ran successfully
  INCONCLUSIVE  fp2:77ab…  — scanner gitleaks did not run in the current scan
```

The `unavailable` row is the point: PatchLedger tells you exactly what
coverage you have instead of pretending.

## Supported scanners

| Scanner   | What it adds                       | Import format(s)         |
|-----------|------------------------------------|--------------------------|
| semgrep   | broad SAST rules                   | JSON, SARIF              |
| bandit    | Python-specific issues             | JSON, SARIF              |
| pip-audit | dependency vulnerabilities         | JSON, SARIF              |
| gitleaks  | secrets in tree/history            | JSON, SARIF              |
| trivy     | filesystem vulns                   | SARIF                    |
| any tool  | anything emitting SARIF 2.1.0      | SARIF                    |

Missing a tool? Everything degrades gracefully — scans record the gap and
verification refuses false resolution claims on top of it.

## Architecture

```
Repository (your code, local)
      |
      v
Scanner runner ──► semgrep / gitleaks / bandit / pip-audit / trivy
      |             (as installed; missing tools recorded honestly)
      v
Parsers ──── SARIF 2.1.0 · semgrep JSON · gitleaks JSON · bandit JSON · pip-audit JSON
      |
      v
Normalizer ─► severity maps · redaction · categories · remediation KB
      |
      v
Fingerprints (fp2) ──► Dedup ──► Risk scoring (explainable)
      |
      v
SQLite ledger ── scans (immutable) · findings · occurrences · status audit trail
      |
      +──────────────┬──────────────────┐
      v              v                  v
Scan comparison  Patch verification  Reports (JSON / MD / HTML)
      └──────────────┴──────────────────┘
                     v
               CLI (Typer + Rich) · GitHub Actions
```

**Tech stack:** Python 3.10+, Typer, Pydantic, SQLite, Rich, pytest. Minimal
runtime dependencies; no server; nothing else to run.

## Example reports

Fully generated examples (clearly labelled synthetic data) live in
[`examples/`](examples/): `sample-report.json`, `sample-report.md`,
`sample-report.html`. The HTML is a single self-contained dark-theme file
with no JavaScript — regenerate them with `python scripts/generate_examples.py`.

## GitHub Actions

Add a security gate to any repository with the copy-paste workflow in
[`docs/example-workflow.md`](docs/example-workflow.md): push/PR triggers,
severity thresholds (`--fail-on high`), strict incomplete-scan mode
(`--strict`), and report artifacts. PatchLedger's own CI runs the test matrix
(3.10–3.14), ruff, mypy, and a wheel smoke test — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Security model

PatchLedger is a security product and is held to that standard: argv-list
subprocess execution only, no auto-downloaded tools, parameterized SQL,
size-capped strict JSON parsing, escaped CSP'd HTML reports, secret redaction
on ingest, and no network access after installation (except pip-audit's
advisory DB). The full threat model, guarantees, and honest limits are in
[`docs/security-model.md`](docs/security-model.md).

## Documentation

- [Installation](docs/installation.md) — per-scanner setup
- [Usage handbook](docs/usage.md) — every command, flag, and exit code
- [Architecture](docs/architecture.md) — data model, fingerprints, verification semantics
- [Security model](docs/security-model.md) — threat model and limits
- [FAQ](docs/faq.md) — the no-AI design, fingerprint behavior, sharing reports
- [Example CI workflow](docs/example-workflow.md) — GitHub Actions recipe

## Contributing

Bug reports, new parser adapters, remediation-knowledge entries, and docs are
all first-class contributions. See
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: report privately per
[SECURITY.md](SECURITY.md).

## Roadmap

- **Now (v0.1):** core pipeline, 5 parsers + generic SARIF, verification,
  reports, CLI, GitHub Actions recipe.
- **Next:** PyPI release, cross-CI-run baselines, SARIF output for GitHub
  code scanning, more remediation knowledge.
- **Later:** optional BYOK AI provider (disabled by default, never required),
  native gitleaks/trivy JSON parsers.
- **Non-goals:** hosted SaaS, telemetry, mandatory AI, automatic code
  modification.

## License

[MIT](LICENSE) — © 2026 navairgap and PatchLedger contributors.
