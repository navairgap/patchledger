# Contributing to PatchLedger

Thank you for helping make PatchLedger better. This project is built to be
maintained — small, testable changes with honest tests are the culture.

## Development setup

```bash
git clone https://github.com/navairgap/patchledger
cd patchledger
uv venv && uv pip install -e ".[dev]"   # or: python -m venv .venv && pip install -e ".[dev]"
```

Optional but recommended for integration testing:

```bash
uv pip install bandit pip-audit semgrep   # the lightweight scanner set
```

## Development loop

```bash
pytest            # full suite — runs in seconds
ruff check src tests scripts
mypy
```

All three gates must pass. CI runs the same plus a wheel smoke test on a
Python 3.10–3.14 matrix.

## What makes a good PR

- **One logical change per PR.** Keep refactors separate from features.
- **Tests for behavior, not coverage theater.** New code paths need tests that
  would fail without the change. Verification-semantics changes *must* pin the
  false-resolution guards (see `tests/test_verification.py` for the pattern).
- **Honesty is a feature.** If your change affects coverage reporting,
  severity mapping, fingerprints, or verification, document the semantics and
  update `docs/architecture.md` / `docs/security-model.md`.
- **No new runtime dependencies without discussion.** The current list
  (typer, pydantic, rich) is deliberately short.

## Ideas that would help

- New parser adapters (trivy JSON, gitleaks native JSON, OSV, npm audit…)
- Remediation-knowledge entries in `src/patchledger/recommendations.py`
  (explanation, consequences, fix, secure pattern, references)
- SARIF *output* for GitHub code scanning
- Windows/macOS CI coverage

## Reporting bugs

Open a GitHub issue with: what you ran, what you expected, what happened,
and — importantly for scan issues — whether scanners were missing/failed (the
tool-coverage table tells you). Include synthetic reproductions, never real
secrets or proprietary code.

## Security issues

Please report privately — see [SECURITY.md](SECURITY.md). Do not open public
issues for vulnerabilities.

## Code of conduct

Be excellent to each other — see
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
