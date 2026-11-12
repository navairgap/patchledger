<div align="center">

# PatchLedger

**Find it. Understand it. Fix it. Prove it.**

[![Live website](https://img.shields.io/badge/website-navairgap.github.io%2Fpatchledger-46c26e?labelColor=0b0e14)](https://navairgap.github.io/patchledger/)
[![CI](https://github.com/navairgap/patchledger/actions/workflows/ci.yml/badge.svg)](https://github.com/navairgap/patchledger/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-46c26e?labelColor=0b0e14)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-539bf5?labelColor=0b0e14)](pyproject.toml)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230?labelColor=0b0e14)](https://github.com/astral-sh/ruff)

**An evidence-first security finding and remediation verification platform
for developers.**

[Get started](#quick-start) · [Live website](https://navairgap.github.io/patchledger/) · [Documentation](#documentation) · [Report an issue](https://github.com/navairgap/patchledger/issues)

</div>

---

## Why

Security work is fragmented: one scanner finds secrets, another flags
vulnerable dependencies, a third catches insecure code — each with its own
format, severity scale, and dashboard. Teams reconcile them by hand, and when
a finding stops appearing, everyone *assumes* it was fixed. Most pipelines
never check whether the scanner actually ran.

**PatchLedger closes that gap.** It unifies scanner output into one
persistent, deduplicated ledger — and verifies that a vulnerability was
actually fixed, with scanner-coverage evidence, before marking it resolved.
No AI API, no cloud service, no telemetry: your code never leaves your
machine.

## How it works

```
Scan/import ──► Normalize ──► Fingerprint (fp2) ──► Dedup ──► Score ──► SQLite ledger
                                                                    │
        Report (JSON · MD · HTML · SARIF) ◄── Verify ◄── Compare ◄──┘
```

1. **Scan** with installed tools — semgrep, gitleaks, bandit, pip-audit,
   trivy — or **import** existing reports (SARIF 2.1.0, semgrep, gitleaks,
   bandit, pip-audit JSON, auto-detected). Missing tools are recorded
   honestly, never hidden.
2. **Normalize** every result into one model: explicit severity mapping,
   secret redaction, categories, offline remediation guidance.
3. **Fingerprint** deterministically — findings survive line shifts and
   formatter runs; changed code gets a new identity.
4. **Verify** on the next scan: a vanished finding becomes *resolved* only
   when every scanner that ever reported it ran successfully on the same
   target. Otherwise it stays **inconclusive** — explicitly not fixed.

## Quick start

```bash
pipx install patchledger          # or: pip install patchledger

cd your-project
patchledger init                  # creates .patchledger/ (config + ledger db)
patchledger scan .                # runs installed scanners
patchledger findings              # the live finding ledger

# ...fix the code...

patchledger scan .                # re-scan
patchledger verify                # proof — or an honest "inconclusive"
patchledger report --format html  # self-contained report
```

CI gate for any repository:

```bash
patchledger scan . --fail-on high --strict   # exit 2 on high+ findings,
                                             # exit 3 on incomplete scans
```

A real session against a deliberately vulnerable fixture repository:

```
$ patchledger scan ./demo_repo
┏━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool      ┃ Status      ┃ Version   ┃ Note                        ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ semgrep   │ ran         │ 1.185.0   │                             │
│ gitleaks  │ unavailable │ —         │ not found on PATH           │
│ bandit    │ ran         │ 1.9.4     │                             │
│ pip-audit │ ran         │ 2.10.1    │                             │
└───────────┴─────────────┴───────────┴─────────────────────────────┘

$ patchledger verify
  FIXED VERIFIED  fp2:56e15c…  all reporting scanners ran successfully
  INCONCLUSIVE    fp2:91ac…   scanner gitleaks did not run
```

The `unavailable` row is the point: PatchLedger tells you exactly what
coverage you have instead of pretending.

## Features

| | |
|---|---|
| **Honest coverage** | Every scan records which tools ran, failed, or were missing; reports are labelled incomplete when coverage isn't full. |
| **Stable fingerprints** | Versioned `fp2` identity — stable across line shifts, new exactly when the flagged code changes. |
| **Explainable scores** | Deterministic 0–100 with every adjustment listed. Never invents CVSS. |
| **Verification** | `fixed_verified` / `still_present` / `reintroduced` / `inconclusive` — with recorded reasons and caveats. |
| **Scan history** | Immutable scans, diffs, and a status audit trail in local SQLite. |
| **Remediation KB** | Offline guidance per rule family: why it matters, consequences, fix, secure pattern. |
| **Review prompts** | Offline AI-review prompt export with anti-fabrication constraints. |
| **Secret redaction** | Credential material redacted on ingest, before storage or rendering. |

## Supported scanners

| Scanner   | Adds                                  | Import formats     |
|-----------|---------------------------------------|--------------------|
| semgrep   | Broad community SAST rules            | JSON, SARIF        |
| bandit    | Python-specific issues                | JSON, SARIF        |
| pip-audit | Dependency vulnerabilities            | JSON, SARIF        |
| gitleaks  | Secrets in tree and git history       | JSON, SARIF        |
| trivy     | Filesystem vulnerabilities            | SARIF              |
| any tool  | Anything emitting SARIF 2.1.0         | SARIF              |

## Reports

`patchledger report` produces JSON, Markdown, or a **self-contained HTML
file** (dark theme, zero JavaScript, CSP-protected, fully escaped) — plus
**SARIF output** for GitHub code scanning. Generated examples with clearly
labelled synthetic data live in [`examples/`](examples/), and the
[live website](https://navairgap.github.io/patchledger/#report) shows the
report structure.

## Use in CI

Copy the ready-made workflow from
[`docs/example-workflow.md`](docs/example-workflow.md) into any repository:
push and PR triggers, severity thresholds, `--strict` incomplete-scan mode,
and report artifacts. PatchLedger's own CI runs the test matrix on Python
3.10–3.14 plus lint, type-check, and a wheel smoke test.

## Documentation

| Document | Contents |
|----------|----------|
| [Installation](docs/installation.md) | Per-scanner setup and requirements |
| [Usage handbook](docs/usage.md) | Every command, flag, and exit code |
| [Architecture](docs/architecture.md) | Data model, fingerprints, verification semantics |
| [Security model](docs/security-model.md) | Threat model, guarantees, honest limits |
| [FAQ](docs/faq.md) | The no-AI design, fingerprint behavior, sharing reports |
| [Releasing](docs/releasing.md) | Maintainer release process |

## Contributing

Contributions are welcome — parser adapters, remediation-knowledge entries,
documentation, platform support. See
[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: report privately per
[SECURITY.md](SECURITY.md).

## Roadmap

- **Now (v0.1)** — core pipeline, 5 parsers + generic SARIF, verification,
  four report formats, full CLI, CI recipe
- **Next** — PyPI release with trusted publishing, cross-CI-run baselines,
  more remediation knowledge
- **Later** — optional BYOK AI provider (disabled by default), native
  gitleaks/trivy JSON parsers
- **Non-goals** — hosted SaaS, telemetry, mandatory AI, automatic code
  modification

## License

[MIT](LICENSE) © 2026 navairgap and PatchLedger contributors.
