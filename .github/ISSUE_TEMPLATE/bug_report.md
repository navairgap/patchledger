---
name: Bug report
about: Something broke or behaved dishonestly
labels: bug
---

## What happened

A clear description of the problem.

## What you ran

```bash
# exact command(s), e.g.:
# patchledger scan . --fail-on high
```

## Output

```
# paste the relevant CLI output, including the scanner coverage table
# REDACT any real secrets — PatchLedger redacts, but double-check
```

## Environment

- PatchLedger version (`patchledger version`):
- Python version (`python --version`):
- OS:
- Scanners installed and their versions (from `patchledger doctor`):

## Expected behavior

What you expected instead.

## Notes

- If this involves verification/resolution claims: was the newer scan a local
  `patchledger scan` or an `import`?
- Synthetic reproductions only, please — no real secrets or proprietary code.
