"""PatchLedger project configuration.

Configuration lives in ``.patchledger/config.json`` next to the database.
Everything has sane defaults so an empty project works out of the box.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from patchledger.errors import ConfigError

CONFIG_FILENAME = "config.json"
CONFIG_SCHEMA_VERSION = 1

DEFAULT_ENABLED_SCANNERS = ["semgrep", "gitleaks", "bandit", "pip-audit"]


class ScanningConfig(BaseModel):
    """Which scanners to run and how.

    Security note: configuration is DATA, not execution policy. Tool discovery
    intentionally has no config-controlled search paths — a config file that
    ships inside an untrusted repository must never be able to direct
    PatchLedger to execute a binary of the attacker's choosing.
    """

    model_config = ConfigDict(extra="ignore")

    enabled: list[str] = Field(default_factory=lambda: list(DEFAULT_ENABLED_SCANNERS))
    timeout_seconds: int = Field(default=600, ge=10, le=3600)


class ScoringConfig(BaseModel):
    """Deterministic, explainable risk scoring rules.

    Base score per severity plus additive adjustments. Every applied adjustment
    is recorded on the finding so scores are always explainable.
    """

    model_config = ConfigDict(extra="ignore")

    severity_base: dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 90,
            "high": 70,
            "medium": 45,
            "low": 20,
            "info": 5,
            "unknown": 30,
        }
    )
    confidence_adjustment: dict[str, int] = Field(
        default_factory=lambda: {"high": 5, "medium": 0, "low": -10, "unknown": 0}
    )
    evidence_present_adjustment: int = 5
    evidence_missing_adjustment: int = -5
    category_adjustment: dict[str, int] = Field(
        default_factory=lambda: {
            "secret": 10,  # directly exploitable if real
            "dependency": 5,  # publicly known vulnerability
            "injection": 10,
            "crypto": 5,
        }
    )


class VerificationConfig(BaseModel):
    """Patch verification strictness.

    Verification honesty is core behavior, not a knob: imported reports can
    never assert coverage (recorded with status ``imported``), so
    verifications against them are inconclusive by design. This section only
    carries tuning that cannot weaken the guarantee.
    """

    model_config = ConfigDict(extra="ignore")

    treat_version_change_as_caveat: bool = True


class ImportConfig(BaseModel):
    """Report import limits and rule suppression.

    Rule suppression requires explicit configuration — PatchLedger never
    silently hides findings.
    """

    model_config = ConfigDict(extra="ignore")

    max_report_size_mb: int = Field(default=50, ge=1, le=2048)
    disabled_rules: list[str] = Field(default_factory=list)


class PatchLedgerConfig(BaseModel):
    """Full project configuration."""

    model_config = ConfigDict(extra="ignore")

    schema_version: int = CONFIG_SCHEMA_VERSION
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    import_config: ImportConfig = Field(default_factory=ImportConfig)
    redact_secrets: bool = True
    fail_on: str = "high"  # CI severity threshold: critical|high|medium|low

    @classmethod
    def load(cls, directory: Path) -> PatchLedgerConfig:
        """Load config from a project directory, falling back to defaults."""
        path = directory / CONFIG_FILENAME
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"Cannot read config file {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Config file {path} is not valid JSON: {exc}") from exc
        try:
            return cls.model_validate(raw)
        except Exception as exc:
            raise ConfigError(f"Invalid configuration in {path}: {exc}") from exc

    def save(self, directory: Path) -> Path:
        """Write config to a project directory as pretty JSON."""
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / CONFIG_FILENAME
        path.write_text(
            json.dumps(self.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8"
        )
        return path


def validate_fail_on(value: str) -> str:
    """Validate a --fail-on threshold value."""
    allowed = {"critical", "high", "medium", "low", "info"}
    if value not in allowed:
        raise ConfigError(
            f"Invalid fail-on threshold '{value}'. Allowed: {', '.join(sorted(allowed))}"
        )
    return value
