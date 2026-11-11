"""Deterministic, stable finding fingerprints.

The fingerprint is the identity of a security issue across scans. It is built
from content-stable attributes only — never from line numbers or timestamps —
so findings survive code edits above the vulnerable line, and legitimately
disappear (new fingerprint) when the vulnerable content itself is changed.

Design (version ``fp2``):

    fingerprint = sha256(
        fp_version,
        scanner identity,        # "semgrep", "gitleaks", ... (not the file format)
        rule_id,
        normalized file path,    # POSIX-style; empty for dependency findings
        normalized message,
        normalized evidence      # code snippet; distinguishes same-rule
                                 # findings with generic messages (e.g. bandit
                                 # B101 on several assert lines)
    )

Rationale:

* The code snippet is part of the identity because some scanner messages are
  generic ("Use of assert detected...") — without the snippet, distinct
  findings on different lines of one file would collapse into one.
* Line numbers are deliberately excluded: edits above the finding shift lines
  without changing the issue, and the snippet at the flagged line only changes
  when the flagged code itself changes — exactly when a new finding identity
  is warranted.
* Dependency findings (no file) use ``package==version`` inside the message,
  so upgrading a package produces a new fingerprint (resolving the old one).
* Truncating the hash to 128 bits keeps identifiers short; collision risk is
  negligible for realistic finding volumes.

Known, documented limits:

* When the same scanner finding is imported through formats that differ in
  whether they carry code snippets (e.g. semgrep JSON has snippets, some SARIF
  exports do not), the fingerprints differ. PatchLedger's primary pipeline
  (``patchledger scan``) always runs tools with a consistent format, so
  fingerprints are stable across scans; mixing import formats for the same
  tool is discouraged and documented.
* Two byte-identical flagged snippets for the same rule at the same path merge
  into one fingerprint (identical issues are the same issue).
* Gitleaks secrets are fingerprinted via their redacted match; two different
  secrets of the same type, at the same path, with the same prefix/suffix/length
  can collide — see ``patchledger.normalizer`` redaction rules.
"""

from __future__ import annotations

import hashlib
import json
import re

FP_VERSION = "fp2"
FP_LENGTH = 32  # hex chars (128 bits)


def normalize_scanner_name(name: str) -> str:
    """Canonical, lowercase scanner identity.

    Examples: "Semgrep" -> "semgrep", "pip_audit" -> "pip-audit",
    "Trivy" -> "trivy". Unknown tools keep a cleaned lowercase form.
    """
    cleaned = re.sub(r"[\s_]+", "-", name.strip().lower())
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    collapsed = cleaned.replace("-", "")
    aliases = {"pipaudit": "pip-audit"}
    return aliases.get(collapsed, cleaned)


def normalize_path_for_fingerprint(path: str | None) -> str:
    """POSIX-style path with redundant separators removed (never resolved absolute)."""
    if not path:
        return ""
    cleaned = path.strip().replace("\\", "/")
    while "//" in cleaned:
        cleaned = cleaned.replace("//", "/")
    return cleaned.strip("/")


def normalize_text_for_fingerprint(text: str | None) -> str:
    """Collapse whitespace so small formatting differences do not change identity."""
    if not text:
        return ""
    return " ".join(text.split())


def compute_fingerprint(
    *,
    scanner: str,
    rule_id: str,
    file_path: str | None,
    message: str,
    evidence: str,
) -> str:
    """Compute the stable fingerprint for a finding.

    Both ``message`` and ``evidence`` participate: the message carries
    rule-specific semantics, the evidence distinguishes findings whose
    messages are generic. Whitespace is normalized so formatting noise does
    not change identity.
    """
    payload = json.dumps(
        [
            FP_VERSION,
            normalize_scanner_name(scanner),
            rule_id,
            normalize_path_for_fingerprint(file_path),
            normalize_text_for_fingerprint(message),
            normalize_text_for_fingerprint(evidence),
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:FP_LENGTH]
    return f"{FP_VERSION}:{digest}"
