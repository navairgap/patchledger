> [!NOTE]
> **New: SARIF output.** `patchledger report --format sarif` now exports the
> verified ledger for GitHub code scanning and any SARIF 2.1.0 consumer —
> with patchledger fingerprints, raw severity, and coverage honesty included.

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/banner-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="./assets/banner-light.png">
  <img src="./assets/banner-dark.png" alt="PatchLedger — Security findings, verified fixed." width="100%">
</picture>

### PatchLedger is an evidence-first security finding and remediation verification platform.

-Run PatchLedger only against repositories you are authorized to assess-

It runs the scanners you already trust, unifies their findings into one
persistent, deduplicated ledger — and verifies that a vulnerability was
actually fixed, with scanner-coverage evidence, before calling it resolved.
**No proof, no "fixed."**

**This repository is PatchLedger: the full open-source CLI, run locally from
your command line.**

<p><strong>Launch PatchLedger</strong></p>

```bash
pipx install patchledger
patchledger init && patchledger scan .
```

<sub>The first scan records which of your scanners are visible — missing tools are reported, never hidden.</sub>

---

<a href="https://navairgap.github.io/patchledger/"><img src="./assets/github-button-site.png" height="46" alt="Live website"></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="https://navairgap.github.io/patchledger/#report"><img src="./assets/button-docs.png" height="46" alt="See an example report"></a>

</div>

> [!TIP]
> **Reviewing findings with an AI assistant or a colleague?** Run
> `patchledger export-ai` — it generates a reviewer-ready prompt with the
> evidence, the questions, and explicit constraints against inventing facts.
> Fully offline; bring your own reviewer.

## Table of Contents

- [What is PatchLedger?](#what-is-patchledger)
  - [Why PatchLedger exists](#why-patchledger-exists)
  - [Why "inconclusive" is a feature](#why-inconclusive-is-a-feature)
- [PatchLedger in action](#patchledger-in-action)
- [Quick start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Install and first scan](#install-and-first-scan)
  - [Verify a fix](#verify-a-fix)
- [Key capabilities](#key-capabilities)
- [Supported scanners](#supported-scanners)
- [Use in CI/CD](#use-in-cicd)
  - [GitHub Actions](#github-actions)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Safety, scope, and limitations](#safety-scope-and-limitations)
- [Common questions](#common-questions)
- [License](#license)

## What is PatchLedger?

PatchLedger is a local-first CLI that turns scattered scanner output into a
verifiable remediation ledger. It runs established security scanners against
your repository (or imports their existing reports), normalizes everything
into one consistent data model, and tracks every finding across scans — with
deterministic fingerprints, explainable risk scores, and an audit trail.

The verification step is the core: when a finding stops appearing in scans,
PatchLedger checks whether the scanners that detected it actually ran
successfully and covered the same target. Only then is the finding marked
**resolved**. Anything less is recorded as **inconclusive** — with the exact
reason attached.

<a id="why-patchledger-exists"></a>
<details>
<summary><strong>Why PatchLedger exists</strong></summary>

Teams ship code continuously but verify security fixes rarely — most pipelines
declare a finding "resolved" the moment it stops appearing in reports, even if
the scanner never ran, crashed, or didn't cover that file. False "resolved"
states are how regressions reach production unnoticed.

PatchLedger closes that gap: every scan is an immutable observation point, and
resolution claims must survive an evidence check. An honest *inconclusive*
costs one re-run; a false *fixed* costs a breach.

</details>

<a id="why-inconclusive-is-a-feature"></a>
<details>
<summary><strong>Why "inconclusive" is a feature</strong></summary>

A finding that disappears from a scan is only a <em>resolution candidate</em>.
PatchLedger verifies it against the evidence: did every scanner that ever
reported this fingerprint run successfully in the newer scan, against the same
target? Imported reports cannot assert coverage, so verifications against them
stay inconclusive by design. Scanner version changes are recorded as caveats.

Every verification decision — including the reasons and caveats — is stored in
an audit trail and rendered into reports.

</details>

## PatchLedger in action

Real output from a scan of a deliberately vulnerable fixture repository
([tests/fixtures/demo_repo](tests/fixtures/demo_repo)):

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
Scan 86d9e807 stored: 9 findings, 2 duplicates merged

$ patchledger verify
  FIXED VERIFIED  fp2:56e15c…  all reporting scanners ran successfully
  INCONCLUSIVE    fp2:91ac…   scanner gitleaks did not run
```

The `unavailable` row is the point: PatchLedger tells you exactly what
coverage you have instead of pretending. Generated example reports (JSON,
Markdown, HTML) with clearly labelled synthetic data are in
[`examples/`](examples/).

## Quick start

<a id="prerequisites"></a>

### Prerequisites

- Python **3.10+**
- Any standard installer (pipx, pip, uv)
- Scanners are **optional**: install what you want, PatchLedger reports what
  is missing (see [docs/installation.md](docs/installation.md))

<a id="install-and-first-scan"></a>

### Install and first scan

```bash
pipx install patchledger          # or: pip install patchledger

cd your-project
patchledger init                  # creates .patchledger/ (config + ledger db)
patchledger scan .                # runs installed scanners
patchledger findings              # the live finding ledger
patchledger history               # every recorded scan
```

<a id="verify-a-fix"></a>

### Verify a fix

```bash
# ...fix the code...

patchledger scan .                # re-scan
patchledger verify                # proof — or an honest "inconclusive"
patchledger report --format html  # self-contained report
patchledger report --format sarif # GitHub code scanning ingest
```

CI gate for any repository:

```bash
patchledger scan . --fail-on high --strict
# exit 2: findings at/above high · exit 3: incomplete scan (with --strict)
```

## Key capabilities

| Capability | What it means |
|------------|---------------|
| **Honest coverage** | Every scan records which tools ran, failed, or were missing; reports are labelled incomplete when coverage isn't full. |
| **Stable fingerprints** | Versioned `fp2` identity — stable across line shifts, new exactly when the flagged code changes. |
| **Evidence-based verification** | `fixed_verified` / `still_present` / `reintroduced` / `inconclusive`, each with recorded reasons and caveats. |
| **Explainable scores** | Deterministic 0–100 with every adjustment listed; never invents CVSS. |
| **Scan history & diffs** | Immutable scans, new/persistent/reintroduced/changed diffs, status audit trail in local SQLite. |
| **Remediation knowledge** | Offline guidance per rule family: explanation, consequences, fix, secure pattern. |
| **Offline review prompts** | `export-ai` builds a reviewer-ready prompt with anti-fabrication constraints. |
| **Secret redaction** | Credential material redacted on ingest — before storage or rendering. |
| **Four report formats** | JSON, Markdown, self-contained dark HTML (no JavaScript), SARIF 2.1.0 output. |

## Supported scanners

| Scanner   | Adds                                  | Import formats     |
|-----------|---------------------------------------|--------------------|
| semgrep   | Broad community SAST rules            | JSON, SARIF        |
| bandit    | Python-specific issues                | JSON, SARIF        |
| pip-audit | Dependency vulnerabilities            | JSON, SARIF        |
| gitleaks  | Secrets in tree and git history       | JSON, SARIF        |
| trivy     | Filesystem vulnerabilities            | SARIF              |
| any tool  | Anything emitting SARIF 2.1.0         | SARIF              |

## Use in CI/CD

<a id="github-actions"></a>

### GitHub Actions

Copy the ready-made workflow from
[`docs/example-workflow.md`](docs/example-workflow.md) into your repository:

```yaml
- name: Run security scan
  run: |
    patchledger init
    patchledger scan . --fail-on high
```

Push/PR triggers, severity thresholds, `--strict` incomplete-scan mode, and
report artifacts — documented in the guide. PatchLedger's own CI runs the
test matrix on Python 3.10–3.14 plus lint, type-check, and a wheel smoke test
([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Architecture

```
Scan/import ──► Normalize ──► Fingerprint (fp2) ──► Dedup ──► Score ──► SQLite ledger
                                                                    │
        Report (JSON · MD · HTML · SARIF) ◄── Verify ◄── Compare ◄──┘
```

Three runtime dependencies (`typer`, `pydantic`, `rich`), no server, no
telemetry, no network after installation. The full design — fingerprint
rationale, verification semantics, storage schema — is documented in
[docs/architecture.md](docs/architecture.md).

## Documentation

| Document | Contents |
|----------|----------|
| [Installation](docs/installation.md) | Per-scanner setup and requirements |
| [Usage handbook](docs/usage.md) | Every command, flag, and exit code |
| [Architecture](docs/architecture.md) | Data model, fingerprints, verification semantics |
| [Security model](docs/security-model.md) | Threat model, guarantees, honest limits |
| [FAQ](docs/faq.md) | The no-AI design, fingerprint behavior, sharing reports |
| [Releasing](docs/releasing.md) | Maintainer release process |

## Safety, scope, and limitations

- PatchLedger scans repositories **you are authorized to assess** and never
  transmits your code anywhere.
- It never downloads or executes scanner binaries on its own, never
  automatically modifies your files, and never suppresses findings without
  explicit configuration.
- **Scanning untrusted repositories:** PatchLedger itself does not execute
  repo scripts, but some scanners inherently do (e.g. pip-audit resolving
  dependencies can build sdists). Sandbox untrusted-target scans.
- Redaction is heuristic, not a guarantee — rotate leaked credentials.
- Full threat model and honest limits:
  [docs/security-model.md](docs/security-model.md).

## Common questions

**Does PatchLedger need an AI API?**
No. The entire engine is deterministic and offline. `export-ai` generates a
prompt you can paste into any assistant — the tool itself never calls one.
A bring-your-own-key integration may arrive later as an optional extension.

**Does it output SARIF?**
Yes — `patchledger report --format sarif` emits SARIF 2.1.0 with
patchledger fingerprints as `partialFingerprints`, raw severity in
properties, and coverage honesty as tool notifications.

**Why didn't my disappeared finding get marked "fixed"?**
Verification requires that every scanner which ever reported the finding ran
successfully against the same target in the newer scan. Missing tools, failed
runs, and imported reports produce `inconclusive` with the reason recorded.
Re-run the missing scanner and rescan.

**Can findings from different scanners be merged?**
No — fingerprints include scanner identity on purpose. Merging semgrep and
bandit sightings would destroy the per-tool evidence that verification
depends on.

**Can I run it fully offline?**
Yes. The only outbound network use is pip-audit querying the PyPI advisory
database.

## License

[MIT](LICENSE) © 2026 navairgap and PatchLedger contributors.
