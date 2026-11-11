# Security Policy

PatchLedger is a security tool held to its own standard.

## Reporting a vulnerability

**Please report privately.** Use GitHub's "Report a vulnerability" feature on
the repository (Security tab → Advisories → New draft security advisory), or
contact the maintainer directly via the email on the GitHub profile.

Please include:

- Affected version/commit
- A minimal reproduction (synthetic data only — never real secrets)
- Your assessment of impact and severity

You will get an acknowledgement within 7 days and a status update at least
every 14 days until resolution. Credit in the changelog is yours unless you
prefer anonymity.

## Scope

In scope:

- Anything that lets PatchLedger execute unintended code (command injection,
  unsafe deserialization, template injection, …)
- SQL injection or ledger corruption
- HTML/Markdown injection that survives the report escaping
- Secret redaction bypasses that leak credential material into reports
- False resolution claims caused by logic errors (verification semantics)
- Unsafe file writes outside the designated paths
- Dependency vulnerabilities in the runtime dependency set
  (typer, pydantic, rich)

Out of scope:

- Vulnerabilities in the scanners PatchLedger invokes (report those upstream)
- The intentionally vulnerable test fixtures under `tests/fixtures/`
- Reports about synthetic example data
- Social engineering of scanner installations

## Supported versions

Security fixes land on the latest release line. Given the early stage
(0.1.x), upgrade to the newest patch release to receive fixes.

## Design commitments

For context on what the codebase already guarantees — argv-list subprocess
execution, parameterized SQL, size-capped strict parsing, zero-JavaScript
escaped reports with CSP, redaction on ingest — see
[docs/security-model.md](docs/security-model.md).
