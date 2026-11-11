"""Intentionally vulnerable example used ONLY by PatchLedger's own tests.

Do NOT copy this code into real projects. It exists so scanner integration
tests have deterministic findings to detect.
"""

import subprocess


def run_command(cmd):
    # Deliberate finding: shell=True (semgrep subprocess-shell-true / bandit B602)
    subprocess.run(cmd, shell=True)  # noqa: S602 — intentional vulnerable fixture
    return 0


def check(value):
    # Deliberate finding: assert used for control flow (bandit B101)
    assert value is not None
    return value
