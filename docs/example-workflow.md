# Example: run PatchLedger in your repository's CI

Copy this file into your repository as
`.github/workflows/patchledger-scan.yml`. It installs PatchLedger, scans the
repository on every push and pull request, uploads the HTML report as a
workflow artifact, and fails the job when findings meet or exceed the
severity threshold.

Notes:

* `--fail-on high` means: exit code 2 when any open/reintroduced finding is
  high or critical. Adjust to `medium`, `critical`, or `low`.
* Scanner availability is honest: if a scanner is not installed, PatchLedger
  reports it as unavailable instead of claiming a complete scan. Install the
  tools you want (see docs/installation.md) to widen coverage.
* The PatchLedger database lives in `.patchledger/` inside the runner
  workspace — it is ephemeral per CI run, which is fine for threshold gates.
  Durable scan history and patch verification work best from local runs.
* Once PatchLedger is published to PyPI you can replace the pip install line
  with `pip install patchledger`.

```yaml
name: PatchLedger security scan

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # full history helps gitleaks if it is installed

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install PatchLedger (pinned)
        run: pip install "patchledger @ git+https://github.com/navairgap/patchledger@v0.1.0"

      - name: Run security scan
        run: |
          patchledger init
          patchledger scan . --fail-on high

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: patchledger-report
          path: |
            patchledger-report-*.html
            patchledger-report-*.json
          if-no-files-found: ignore
```

## Customizing

* **Different threshold:** change `--fail-on` (severity: `critical`, `high`,
  `medium`, `low`). Exit code 2 fails the job; a clean scan exits 0.
* **Fail on incomplete scans:** add `--strict` to the scan step — the job
  then also fails (exit 3) when scanners were unavailable or failed.
* **Specific scanners only:** pass `--scanner bandit --scanner pip-audit`
  (repeatable flag) to override the configured scanner list.
* **Configuration file:** commit a `.patchledger/config.json` to your
  repository (created by `patchledger init`) to control scoring rules,
  disabled rules, and the default threshold. Rule suppression always
  requires this explicit file — PatchLedger never hides findings silently.
