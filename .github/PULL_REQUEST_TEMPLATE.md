## Summary

<!-- What does this PR change, in one or two sentences? -->

## Motivation

<!-- Which issue or problem does this address? Link the issue if there is one. -->

## Changes

<!-- Bullet list of the meaningful changes (code, docs, tests). -->

## Checklist

- [ ] `pytest` passes locally (full suite)
- [ ] `ruff check src tests scripts` passes
- [ ] `mypy` passes
- [ ] New behavior has tests that would fail without this change
- [ ] If verification/fingerprint/coverage semantics changed:
      `docs/architecture.md` and/or `docs/security-model.md` updated, and the
      false-resolution guard tests still pin the honesty guarantees
- [ ] If report output changed: XSS/hostile-input tests still pass
- [ ] No real secrets or proprietary code in fixtures, tests, or examples
- [ ] Docs/README updated where user-visible behavior changed

## Honest-change notes

<!-- Does this affect coverage reporting, severity mapping, fingerprints, or
verification semantics? Explain briefly — honesty is a feature here. -->
