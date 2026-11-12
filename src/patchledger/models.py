"""Core data models for PatchLedger.

All persisted or exchanged data flows through these Pydantic models so that
validation happens at the boundary and unknown scanner metadata is preserved
(never interpreted, never dropped).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    """Current UTC time as ISO-8601 with second precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    """Generate a random identifier (UUID4, hex, no dashes)."""
    return uuid.uuid4().hex


class Severity(str, Enum):
    """Normalized severity scale.

    Values are mapped from scanner-provided severities via explicit tables in
    ``patchledger.normalizer`` — PatchLedger never invents severity on its own.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    """Scanner-provided confidence where available."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ToolRunStatus(str, Enum):
    """Status of a scanner tool within a scan.

    ``ran``      — the tool executed and produced a report we could read.
    ``failed``   — the tool executed but failed (non-zero exit / errors).
    ``unavailable`` — the tool is not installed on this machine.
    ``skipped``  — the tool was deliberately not run (config) or not applicable.
    ``imported`` — results came from an imported report; the tool ran
                   somewhere else, so local coverage is *not* guaranteed.
    """

    RAN = "ran"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"
    IMPORTED = "imported"


class FindingStatus(str, Enum):
    """Lifecycle status of a finding in the project ledger.

    ``open``        — present in the latest scan.
    ``resolved``    — absent from the latest scan and resolution was verified
                      with scanner coverage evidence.
    ``reintroduced``— was resolved and has come back.
    ``inconclusive``— absent from the latest scan but resolution could not be
                      verified (scanner did not run / different target / import).
                      An inconclusive finding is NOT treated as fixed.
    """

    OPEN = "open"
    RESOLVED = "resolved"
    REINTRODUCED = "reintroduced"
    INCONCLUSIVE = "inconclusive"


class ScanSource(str, Enum):
    """How a scan entered the database."""

    SCAN = "scan"  # produced by `patchledger scan` on this machine
    IMPORT = "import"  # produced by `patchledger import` from report files


class Occurrence(BaseModel):
    """One scanner's sighting of a finding within one scan."""

    model_config = ConfigDict(extra="forbid")

    scanner: str
    rule_id: str
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    evidence: str = ""
    message: str = ""
    metadata: dict = Field(default_factory=dict)


class Finding(BaseModel):
    """A normalized security finding (deduplicated within a scan)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    fingerprint: str
    scanner: str
    rule_id: str
    severity: Severity
    confidence: Confidence = Confidence.UNKNOWN
    category: str = "other"
    title: str
    description: str = ""
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    evidence: str = ""
    remediation: str = ""
    raw_severity: str | None = None
    metadata: dict = Field(default_factory=dict)
    score: int = 0
    score_factors: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    first_seen: str | None = None
    last_seen: str | None = None
    occurrences: list[Occurrence] = Field(default_factory=list)

    @property
    def location_str(self) -> str:
        """Human-readable location, e.g. ``src/app.py:42``."""
        if not self.file_path:
            return "-"
        loc = self.file_path
        if self.start_line:
            loc += f":{self.start_line}"
        return loc


class ScanToolRun(BaseModel):
    """Record of one scanner tool's participation in a scan."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    status: ToolRunStatus
    version: str | None = None
    exit_code: int | None = None
    note: str | None = None


class Scan(BaseModel):
    """A scan: one immutable observation point of a project."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    project_id: str
    created_at: str = Field(default_factory=utc_now_iso)
    target_path: str
    source: ScanSource
    label: str | None = None
    git_commit: str | None = None
    git_branch: str | None = None
    tools: list[ScanToolRun] = Field(default_factory=list)
    duration_ms: int | None = None
    notes: str | None = None

    def tool_map(self) -> dict[str, ScanToolRun]:
        """Tools by normalized name."""
        return {t.tool: t for t in self.tools}


class Project(BaseModel):
    """A PatchLedger project bound to a repository root."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    name: str
    root_path: str
    created_at: str = Field(default_factory=utc_now_iso)
