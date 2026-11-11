# Security model

PatchLedger is a security tool, so it is held to the standard it enforces.
This document states the threat model, the guarantees, and the honest limits.

## What PatchLedger is for

Scanning and verifying **repositories you are authorized to assess**. It is
a local CLI: source code, findings, and reports stay on your machine unless
you choose to publish them (e.g. upload a CI artifact).

## Guarantees

### Process execution
* Scanners run through `subprocess.run` with **argv lists** — never
  `shell=True`, never string interpolation into a command line.
* The executable is the one `shutil.which`/config resolved; argv[0] is pinned
  to the discovered path (no PATH re-resolution at exec time).
* Hard timeouts kill runaway scanners; stdout/stderr are captured, bounded,
  and only excerpted into notes on failure.
* PatchLedger **never downloads or executes** tools on its own. `doctor`
  reports availability; you install scanners yourself.

### Input handling
* Report files are size-capped (default 50 MB, hard absolute cap 512 MB),
  parsed strictly (`NaN`/`Infinity` rejected), with actionable errors for
  malformed input and clear behavior for adversarial nesting.
* Parser code treats report content as data only — no `eval`, no dynamic
  imports, no templated execution. SARIF URIs are URL-decoded and
  path-normalized, never executed or resolved into command lines.

### Storage
* Every SQL statement is parameterized; there is no string-built SQL.
* WAL mode + foreign keys ON; transactions wrap scan inserts so crashes
  cannot corrupt state.

### Secrets
* gitleaks material is redacted on ingest: raw `Secret`/`Match` values never
  reach storage; evidence carries prefix/suffix/length only.
* Secret-category evidence from any scanner has quoted literals, PEM blocks,
  and common token formats (AWS/GitHub/Slack/Stripe/GitLab) redacted.
* Redaction is best-effort and documented as such — **rotation is the real
  fix**; removing a value from reports does not un-leak anything.
* PatchLedger has no telemetry, no network calls at runtime (except
  pip-audit's advisory DB queries), and never transmits your code anywhere.

### Reports
* The HTML report contains **zero JavaScript** and ships a
  `Content-Security-Policy` of `default-src 'none'; style-src 'unsafe-inline'`
  — the script-injection sink does not exist. Every dynamic value passes
  through `html.escape`; hostile-payload tests pin this.
* Markdown reports escape table pipes so findings cannot break out of their
  structure.
* Example reports are clearly labelled **SYNTHETIC EXAMPLE DATA** and are
  generated from fabricated findings — never presented as real scans.

### Verification honesty
* A finding is `resolved` only with full scanner coverage (see
  `docs/architecture.md`). Missing tools, failed runs, different targets, and
  imported reports all yield **inconclusive** — never a silent "fixed".
* Incomplete scans are labelled as such in every report and in the CLI.

## Honest limits

* **Coverage is approximated per tool run**, not per file: if semgrep ran
  successfully on the target, its rules are considered to have covered the
  tree. Tools' internal ignore files (`.semgrepignore`, `.gitignore` for
  gitleaks) are not currently parsed; a rule that never sees a file can still
  allow a false-verified resolution in that corner.
* **Fingerprints are content-based.** Two byte-identical flagged snippets for
  the same rule at the same path merge (identical issues are the same issue);
  gitleaks secrets of the same type with identical prefix/suffix/length at
  the same path can collide.
* **Cross-format imports** of the same tool can produce different
  fingerprints when one format carries snippets the other doesn't.
* **Redaction is heuristic.** Novel secret formats may pass through in
  evidence; treat all PatchLedger output as containing the secrets your code
  contains until proven otherwise.
* **Risk scores are prioritization aids**, not measurements; they are
  deterministic and explainable but not a substitute for human triage.

## Dependencies

Runtime dependencies are deliberately minimal (`typer`, `pydantic`, `rich`)
and CI runs `pip-audit` on the project itself. Dependency advisories that
affect PatchLedger are treated as security bugs — see `SECURITY.md`.
