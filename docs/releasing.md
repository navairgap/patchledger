# Releasing PatchLedger (maintainer guide)

## Checklist before tagging

1. `pytest`, `ruff check src tests scripts`, `mypy` — all green.
2. Update `CHANGELOG.md`: move the unreleased section to the new version and
   date; add any last entries.
3. Bump `version` in `pyproject.toml` (and `src/patchledger/__init__.py`),
   commit.
4. `uv build` and smoke-test in a fresh venv:

   ```bash
   uv venv /tmp/pl-check
   uv pip install --python /tmp/pl-check/bin/python dist/*.whl
   /tmp/pl-check/bin/patchledger version
   /tmp/pl-check/bin/patchledger doctor
   ```

## Tag and publish

```bash
git tag -a vX.Y.Z -m "PatchLedger vX.Y.Z"
git push origin vX.Y.Z
```

The `Release` workflow builds the distribution, smoke-tests the wheel, and
publishes a GitHub Release with generated notes plus both artifacts.

## PyPI (when enabled)

Publishing to PyPI is intentionally not automated until the project is
officially on PyPI. When it is: add an `pypi publish` job using trusted
publishing (PyPI OIDC, no API tokens) that uploads `dist/*` after the smoke
test, and switch the user-facing example workflow from the pinned git
install to `pip install patchledger`.

## After release

- Verify the GitHub Release page renders notes and assets.
- Update the website roadmap section if the release changed status claims.
- Announce with a link to the changelog, not to a marketing claim.
