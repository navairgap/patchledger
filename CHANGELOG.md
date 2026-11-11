# Changelog

All notable changes to PatchLedger are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased (first release candidate)

### Added

- Core pipeline: scan → import → normalize → fingerprint → dedup → score →
  store → compare → verify → report.
- Scanner runner for semgrep, gitleaks, bandit, pip-audit, trivy with honest
  per-tool statuses (`ran` / `failed` / `unavailable` / `skipped` /
  `imported`) and argv-list subprocess execution (no shell, no auto-download).
- Report parsers: SARIF 2.1.0, semgrep JSON, gitleaks JSON, bandit JSON,
  pip-audit JSON — auto-detected from content, size-capped, strict.
- Normalization with explicit severity/confidence mapping tables, secret
  redaction on ingest, category classification, and a local remediation
  knowledge base (offline, no AI).
- Deterministic `fp2` fingerprints (scanner, rule, path, message, evidence —
  no line numbers, versioned) and evidence-preserving deduplication.
- Explainable deterministic risk scoring (0–100) with per-factor reasons and
  configurable rules.
- SQLite ledger: WAL, foreign keys, schema migrations, monotonic scan
  sequence, immutable scans, occurrences, and a status-history audit trail.
- Coverage-aware patch verification: resolutions verified only when every
  reporting scanner ran successfully on the same target; otherwise
  `inconclusive` with recorded reasons. Reintroduction detection across scan
  history.
- Reports: JSON, Markdown, and self-contained HTML (dark theme, no
  JavaScript, CSP, fully escaped) with honest coverage labeling.
- AI review prompt generator (Markdown/JSON) — offline, with explicit
  constraints against inventing evidence.
- Full CLI: `init`, `scan`, `import`, `findings`, `report`, `history`,
  `compare`, `verify`, `export-ai`, `doctor`, `version` with documented exit
  codes (0 ok / 1 error / 2 threshold / 3 incomplete+strict).
- GitHub Actions: repo CI (test matrix 3.10–3.14, ruff, mypy, wheel smoke
  test), GitHub Pages deployment for the website, and a copy-paste scan
  workflow for users' repositories.
- Static product website (hand-written, framework-free).
- Documentation: installation, usage, architecture, security model, FAQ,
  example CI workflow; community files (CONTRIBUTING, SECURITY, Code of
  Conduct, changelog, issue/PR templates).
- 102 tests covering parsers (incl. malformed/hostile input), fingerprints,
  normalization, dedup, scoring, storage persistence, comparison, all four
  verification guards, report XSS resistance, CLI commands, and live
  scanner validation against real semgrep/bandit/pip-audit output.

### Known limitations

- Imported reports cannot assert scanner coverage; verification against them
  is inconclusive by design.
- Cross-format imports of the same tool may produce different fingerprints
  when formats differ in snippet availability (documented in
  `docs/architecture.md`).
- Per-file scanner coverage is approximated per tool run.
- gitleaks/trivy live-scan behavior tested via fixtures when the binaries are
  absent.
