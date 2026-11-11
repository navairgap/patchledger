# Architecture

This document explains how PatchLedger is built, why the pieces are shaped
the way they are, and where the documented limits live.

## The pipeline

```
Repository (your code, local)
      |
      v
Scanner runner  ─── semgrep / gitleaks / bandit / pip-audit / trivy
      |               (as installed; missing tools recorded honestly)
      v
Parsers ─────── SARIF 2.1.0 · semgrep JSON · gitleaks JSON · bandit JSON
      |         pip-audit JSON   (format auto-detected from content)
      v
Normalizer ──── severity maps · secret redaction · categories · remediation KB
      |
      v
Fingerprints (fp2) ──► Deduplication ──► Risk scoring
      |
      v
SQLite ledger ──── scans (immutable) · findings · occurrences · status_history
      |
      +──────────────┬───────────────────┐
      v              v                   v
Scan comparison  Patch verification  Reports (JSON / MD / HTML)
      |              |                   |
      └──────────────┴───────────────────┘
                     v
               CLI (Typer + Rich) · GitHub Actions integration
```

Source layout: `src/patchledger/` with one module per stage (mirrors the
diagram); tests under `tests/` with real scanner reports recorded as fixtures.

## Data model

* **`Finding`** — the normalized unit: fingerprint, scanner, rule, severity,
  confidence, category, title, description, location, evidence, remediation,
  score + score factors, status, and occurrences.
* **`Occurrence`** — one scanner's sighting. Deduplication merges findings
  that share a fingerprint but never discards occurrences; each keeps its own
  evidence and metadata (scanner metadata is preserved verbatim, never
  interpreted).
* **`Scan`** — one immutable observation point: target path, git commit/branch
  when available, source (`scan` or `import`), and per-tool statuses
  (`ran / failed / unavailable / skipped / imported`).
* **`status_history`** — an explicit audit trail of ledger transitions
  (resolved / inconclusive / reintroduced) with reasons and verification
  evidence as JSON.

## Storage

SQLite (WAL mode, foreign keys ON) at `.patchledger/patchledger.db`.
Schema versioning lives in `schema_meta.schema_version` with sequential
migrations in `storage.py`. Multi-row inserts are transactional: a crash
cannot leave a half-written scan. Scans carry a monotonic `seq` so
"latest scan" is deterministic even when two scans land in the same
clock second.

## Fingerprints (`fp2`)

```
fingerprint = "fp2:" + sha256(fp_version, scanner, rule_id, path, message, evidence)[:32hex]
```

* **Message + evidence, not line numbers.** The message carries rule
  semantics; the snippet distinguishes findings whose messages are generic
  (bandit's `B101` on several assert lines). Line numbers are excluded so
  edits above the finding don't change identity, while edits *to* the flagged
  line legitimately produce a new identity.
* **Scanner identity, not file format.** Importing semgrep output twice in
  different formats is stable *within* a format. Documented limit: formats
  that differ in whether they carry snippets produce different fingerprints
  (`tests/test_normalizer.py` demonstrates this). The primary pipeline always
  uses one consistent format per tool, so cross-scan fingerprints are stable.
* **Versioned.** The `fp2:` prefix lets future identity changes coexist with
  history.

## Verification semantics

The differentiator. A finding absent from the newer scan is a *resolution
candidate*. It becomes `resolved` only when **all** of:

1. Every scanner that ever reported the fingerprint appears in the current
   scan with status `ran` (a real local run).
2. The current scan targeted the same path as the last observation.
3. The current scan is not an imported report (imports cannot assert
   coverage).

Otherwise the state is `inconclusive` — explicitly *not* fixed — with the
reasons recorded. Scanner version changes between baseline and current are
recorded as caveats (rule sets may differ) without blocking verification.
All of these behaviors are pinned by `tests/test_verification.py`.

## Risk scoring

Deterministic and fully explained: a base score per normalized severity plus
documented adjustments for scanner confidence, evidence presence, and
category (secrets and injections weigh more). Every adjustment is listed on
the finding. PatchLedger never invents CVSS scores or escalates severity on
its own. Rules are configurable in `.patchledger/config.json`.

## Security posture of PatchLedger itself

See `docs/security-model.md` for the threat model. Headlines: argv-list
subprocess execution only (never a shell, never auto-downloaded tools),
parameterized SQL everywhere, strict size-capped JSON parsing, HTML reports
with zero JavaScript and a restrictive CSP, secret redaction on ingest, and
no network access after installation (except pip-audit's advisory DB).
