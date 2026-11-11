"""Finding normalization: raw scanner output -> consistent data model.

The normalizer is the single place where scanner-specific values are mapped
onto PatchLedger's scale. All mappings are explicit tables — severity is never
invented, unknown values stay unknown, and scanner metadata is preserved
verbatim on the occurrence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from patchledger.config import PatchLedgerConfig
from patchledger.errors import ReportImportError
from patchledger.fingerprints import compute_fingerprint, normalize_scanner_name
from patchledger.models import Confidence, Finding, Occurrence, Severity
from patchledger.parsers.common import RawFinding
from patchledger.recommendations import get_recommendation

# ------------------------------------------------------------- severity maps
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "error": Severity.HIGH,
    "high": Severity.HIGH,
    "major": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "minor": Severity.LOW,
    "low": Severity.LOW,
    "note": Severity.INFO,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
}

_CONFIDENCE_MAP: dict[str, Confidence] = {
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}


def map_severity(hint: str | None) -> Severity:
    """Map a scanner-provided severity to the normalized scale (never invents)."""
    if not hint:
        return Severity.UNKNOWN
    return _SEVERITY_MAP.get(hint.strip().lower(), Severity.UNKNOWN)


def map_confidence(hint: str | None) -> Confidence:
    if not hint:
        return Confidence.UNKNOWN
    return _CONFIDENCE_MAP.get(hint.strip().lower(), Confidence.UNKNOWN)


# ------------------------------------------------------------ secret redaction
_BEGIN_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_KNOWN_TOKEN = re.compile(
    r"(?:AKIA[0-9A-Z]{16}"  # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{20,}"  # GitHub tokens
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"  # Slack tokens
    r"|sk-(?:live|test)_[A-Za-z0-9]{10,}"  # Stripe keys
    r"|glpat-[A-Za-z0-9\-_]{15,}"  # GitLab PAT
    r")"
)
_QUOTED_LITERAL = re.compile(r"([\"'])([A-Za-z0-9_\-/+=.#@]{8,})\1")


def redact_text(text: str) -> str:
    """Best-effort redaction of credential-like material in evidence text.

    Applied only to secret-category findings (config ``redact_secrets``).
    Redaction is deliberately conservative: real remediation still requires
    rotation even when no value remains in reports.
    """
    if not text:
        return text

    text = _PEM_BLOCK.sub("[redacted private key block]", text)
    text = _KNOWN_TOKEN.sub("[redacted-token]", text)

    def _quoted(match: re.Match[str]) -> str:
        value = match.group(2)
        if len(value) >= 12:
            kept = f"{value[:3]}…{value[-2:]}"
        else:
            kept = "*" * len(value)
        return f"{match.group(1)}{kept}{match.group(1)} [redacted]"

    return _QUOTED_LITERAL.sub(_quoted, text)


def redact_gitleaks_evidence(metadata: dict) -> str:
    """Build redacted evidence for a gitleaks finding from its raw material."""
    secret = metadata.get("raw_secret") or ""
    match = metadata.get("raw_match") or ""
    source = secret or match
    if not source:
        return ""
    n = len(source)
    if n >= 12:
        return f"[secret redacted: {source[:4]}…{source[-3:]} (length {n})]"
    return f"[secret redacted (length {n})]"


# ------------------------------------------------------------------ title
def _derive_title(raw: RawFinding) -> str:
    """Short human title, preferring scanner-provided descriptions."""
    if raw.description and len(raw.description) <= 120:
        return raw.description.strip()
    message = raw.message.strip()
    if message:
        first_line = message.splitlines()[0]
        if len(first_line) <= 120:
            return first_line
        return first_line[:117] + "…"
    return raw.rule_id


# -------------------------------------------------------------- the pipeline
@dataclass
class NormalizeResult:
    findings: list[Finding]
    suppressed: dict[str, int] = field(default_factory=dict)  # rule_id -> count
    warnings: list[str] = field(default_factory=list)


def normalize_finding(
    raw: RawFinding, config: PatchLedgerConfig, scan_root: str | None = None
) -> Finding | None:
    """Convert one raw finding into the normalized model.

    Returns None when the finding is suppressed by explicit ``disabled_rules``
    configuration (never silently: the caller reports what was suppressed).
    """
    scanner = normalize_scanner_name(raw.scanner)
    rule_id = raw.rule_id

    if rule_id in config.import_config.disabled_rules:
        return None

    category = get_recommendation(scanner, rule_id, raw.metadata, raw.message).category

    severity = map_severity(raw.severity_hint)
    confidence = map_confidence(raw.confidence_hint)

    evidence = raw.evidence
    if scanner == "gitleaks" and not evidence:
        evidence = redact_gitleaks_evidence(raw.metadata)
    if config.redact_secrets and category == "secret":
        evidence = redact_text(evidence)

    rec = get_recommendation(scanner, rule_id, raw.metadata, raw.message)
    references = list(raw.references) + list(rec.references)
    remediation_parts = [
        f"Why it matters: {rec.explanation}",
        f"Potential consequences: {rec.consequences}",
        f"Recommended fix: {rec.fix}",
    ]
    if rec.secure_pattern:
        remediation_parts.append(f"Secure pattern: {rec.secure_pattern}")
    if references:
        remediation_parts.append("References: " + "; ".join(dict.fromkeys(references)))
    if raw.fix:
        remediation_parts.append(f"Scanner-suggested fix: {raw.fix}")

    message = raw.message
    if not message and raw.description:
        message = raw.description

    fingerprint = compute_fingerprint(
        scanner=scanner,
        rule_id=rule_id,
        file_path=raw.file_path,
        message=message,
        evidence=raw.evidence,
    )

    occurrence = Occurrence(
        scanner=scanner,
        rule_id=rule_id,
        file_path=raw.file_path,
        start_line=raw.start_line,
        end_line=raw.end_line,
        evidence=evidence,
        message=message,
        metadata=dict(raw.metadata),
    )

    return Finding(
        fingerprint=fingerprint,
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        category=category,
        title=_derive_title(raw),
        description=message,
        file_path=raw.file_path,
        start_line=raw.start_line,
        end_line=raw.end_line,
        evidence=evidence,
        remediation="\n".join(remediation_parts),
        raw_severity=raw.severity_hint,
        metadata=dict(raw.metadata),
        occurrences=[occurrence],
    )


def normalize_findings(
    raw_findings: list[RawFinding],
    config: PatchLedgerConfig,
    scan_root: str | None = None,
) -> NormalizeResult:
    """Normalize a batch of raw findings with suppression accounting."""
    result = NormalizeResult(findings=[], suppressed={})
    for raw in raw_findings:
        try:
            finding = normalize_finding(raw, config, scan_root)
        except ReportImportError:
            raise
        except Exception as exc:  # defensive: one bad finding must not sink an import
            result.warnings.append(
                f"Could not normalize finding {raw.rule_id!r}: {exc.__class__.__name__}: {exc}"
            )
            continue
        if finding is None:
            rule = raw.rule_id
            result.suppressed[rule] = result.suppressed.get(rule, 0) + 1
            continue
        result.findings.append(finding)
    return result
