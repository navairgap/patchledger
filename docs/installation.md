# Installation

PatchLedger is a local CLI tool. It has no server, no telemetry, and no
network requirement after installation (except pip-audit, which queries the
PyPI advisory database).

## Requirements

- Python **3.10+** (tested through 3.14)
- pip / pipx / uv — any standard installer works

## Install PatchLedger

```bash
# Recommended: isolated CLI install
pipx install patchledger

# or into your environment
pip install patchledger

# development install from a checkout
git clone https://github.com/navairgap/patchledger
cd patchledger
pip install -e ".[dev]"
```

Once published to PyPI, the version above is the stable path. Until then,
install from a pinned git ref:

```bash
pip install "patchledger @ git+https://github.com/navairgap/patchledger@v0.1.0"
```

## Install scanners (optional, per-scanner)

PatchLedger works with whatever is installed and **reports honestly what is
missing**. Install any of these to widen coverage:

| Scanner   | Install                            | Adds                                          |
|-----------|------------------------------------|-----------------------------------------------|
| bandit    | `pip install bandit`               | Python SAST findings                          |
| pip-audit | `pip install pip-audit`            | Known vulnerabilities in Python dependencies  |
| semgrep   | `pip install semgrep`              | Broad community SAST rules                    |
| gitleaks  | system package or [release binary](https://github.com/gitleaks/gitleaks/releases) | Secrets in the working tree / git history |
| trivy     | system package or [release binary](https://github.com/aquasecurity/trivy/releases) | Filesystem vulnerabilities via SARIF |

Check what PatchLedger can see:

```bash
patchledger doctor
```

## Initialize a project

In the repository you want to track (this creates `.patchledger/` with a
config and SQLite database):

```bash
cd your-repo
patchledger init
```

Add the ledger data to your `.gitignore` (PatchLedger suggests this but never
edits your files automatically):

```bash
echo ".patchledger/" >> .gitignore
```

## Python version support

The package targets Python 3.10+ and is tested on 3.10–3.14 in CI.
