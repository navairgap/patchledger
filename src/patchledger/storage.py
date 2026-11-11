"""SQLite storage layer.

Design:

* One database per project, stored at ``<root>/.patchledger/patchledger.db``.
* Scans are immutable observation points: findings belong to a scan and are
  never mutated after insert. History is a query across scans plus an
  explicit ``status_history`` audit table.
* WAL journaling + foreign keys ON; multi-row inserts run in a single
  transaction so a crash can never leave a half-written scan behind.
* Schema versioning: ``schema_meta.schema_version`` plus a sequential
  migration list. Future schema changes add a migration instead of
  rewriting history.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from patchledger.errors import StorageError
from patchledger.models import (
    Confidence,
    Finding,
    FindingStatus,
    Occurrence,
    Project,
    Scan,
    ScanSource,
    ScanToolRun,
    Severity,
    ToolRunStatus,
    new_id,
)

SCHEMA_VERSION = 1

_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    root_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    target_path TEXT NOT NULL,
    source TEXT NOT NULL,
    label TEXT,
    git_commit TEXT,
    git_branch TEXT,
    duration_ms INTEGER,
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id, created_at);

CREATE TABLE IF NOT EXISTS scan_tools (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    status TEXT NOT NULL,
    version TEXT,
    exit_code INTEGER,
    note TEXT,
    PRIMARY KEY (scan_id, tool)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    file_path TEXT,
    start_line INTEGER,
    end_line INTEGER,
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    raw_severity TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    score INTEGER NOT NULL DEFAULT 0,
    score_factors TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT,
    last_seen TEXT,
    UNIQUE (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(scan_id, severity);

CREATE TABLE IF NOT EXISTS occurrences (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    file_path TEXT,
    start_line INTEGER,
    end_line INTEGER,
    evidence TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_occurrences_finding ON occurrences(finding_id);

CREATE TABLE IF NOT EXISTS status_history (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    verification TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_status_history_fp ON status_history(project_id, fingerprint);
"""

_MIGRATIONS: list[tuple[int, str]] = [(1, _SCHEMA_V1)]


def _row_to_scan(row: sqlite3.Row, tools: list[ScanToolRun]) -> Scan:
    return Scan(
        id=row["id"],
        project_id=row["project_id"],
        created_at=row["created_at"],
        target_path=row["target_path"],
        source=ScanSource(row["source"]),
        label=row["label"],
        git_commit=row["git_commit"],
        git_branch=row["git_branch"],
        duration_ms=row["duration_ms"],
        notes=row["notes"],
        tools=tools,
    )


def _row_to_finding(row: sqlite3.Row, occurrences: list[Occurrence]) -> Finding:
    return Finding(
        id=row["id"],
        fingerprint=row["fingerprint"],
        scanner=row["scanner"],
        rule_id=row["rule_id"],
        severity=Severity(row["severity"]),
        confidence=Confidence(row["confidence"]),
        category=row["category"],
        title=row["title"],
        description=row["description"],
        file_path=row["file_path"],
        start_line=row["start_line"],
        end_line=row["end_line"],
        evidence=row["evidence"],
        remediation=row["remediation"],
        raw_severity=row["raw_severity"],
        metadata=json.loads(row["metadata"]),
        score=row["score"],
        score_factors=json.loads(row["score_factors"]),
        status=FindingStatus(row["status"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        occurrences=occurrences,
    )


class PatchLedgerDB:
    """Project database handle."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._migrate()
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot open database {self.db_path}: {exc}") from exc

    # ------------------------------------------------------------- lifecycle
    def _migrate(self) -> None:
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = self._conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            current = int(row["value"]) if row else 0
            for version, sql in _MIGRATIONS:
                if version > current:
                    self._conn.executescript(sql)
                    self._conn.execute(
                        "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (str(version),),
                    )
                    current = version

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error as exc:
            raise StorageError(f"Error closing database: {exc}") from exc

    def __enter__(self) -> PatchLedgerDB:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def health_check(self) -> bool:
        """Cheap query used by `patchledger doctor`."""
        try:
            self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    # -------------------------------------------------------------- projects
    def ensure_project(self, name: str, root_path: str) -> Project:
        """Return the project for root_path, creating it if needed."""
        try:
            row = self._conn.execute(
                "SELECT * FROM projects WHERE root_path = ?", (root_path,)
            ).fetchone()
            if row:
                return Project(
                    id=row["id"],
                    name=row["name"],
                    root_path=row["root_path"],
                    created_at=row["created_at"],
                )
            project = Project(name=name, root_path=root_path)
            with self._conn:
                self._conn.execute(
                    "INSERT INTO projects (id, name, root_path, created_at) VALUES (?, ?, ?, ?)",
                    (project.id, project.name, project.root_path, project.created_at),
                )
            return project
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot ensure project record: {exc}") from exc

    def get_project(self, project_id: str) -> Project:
        row = self._conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        if not row:
            raise StorageError(f"Project {project_id} not found")
        return Project(
            id=row["id"], name=row["name"], root_path=row["root_path"], created_at=row["created_at"]
        )

    # ----------------------------------------------------------------- scans
    def insert_scan(self, scan: Scan, findings: list[Finding]) -> None:
        """Insert a scan with tool runs, findings and occurrences atomically."""
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO scans (id, project_id, created_at, target_path, source, "
                    "label, git_commit, git_branch, duration_ms, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan.id,
                        scan.project_id,
                        scan.created_at,
                        scan.target_path,
                        scan.source.value,
                        scan.label,
                        scan.git_commit,
                        scan.git_branch,
                        scan.duration_ms,
                        scan.notes,
                    ),
                )
                for tool in scan.tools:
                    self._conn.execute(
                        "INSERT INTO scan_tools (scan_id, tool, status, version, exit_code, note) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            scan.id,
                            tool.tool,
                            tool.status.value,
                            tool.version,
                            tool.exit_code,
                            tool.note,
                        ),
                    )
                for finding in findings:
                    # Reassign a fresh row id per insert: the same fingerprint
                    # legitimately appears in many scans, and Finding objects
                    # may be reused by callers (ids are row handles, not identity).
                    stored = finding.model_copy(deep=True)
                    stored.id = new_id()
                    self._insert_finding(scan.id, stored)
        except sqlite3.IntegrityError as exc:
            raise StorageError(
                f"Scan rejected by database constraints (duplicate fingerprint in one scan?): {exc}"
            ) from exc
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot insert scan: {exc}") from exc

    def _insert_finding(self, scan_id: str, finding: Finding) -> None:
        self._conn.execute(
            "INSERT INTO findings (id, scan_id, fingerprint, scanner, rule_id, severity, "
            "confidence, category, title, description, file_path, start_line, end_line, "
            "evidence, remediation, raw_severity, metadata, score, score_factors, status, "
            "first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                scan_id,
                finding.fingerprint,
                finding.scanner,
                finding.rule_id,
                finding.severity.value,
                finding.confidence.value,
                finding.category,
                finding.title,
                finding.description,
                finding.file_path,
                finding.start_line,
                finding.end_line,
                finding.evidence,
                finding.remediation,
                finding.raw_severity,
                json.dumps(finding.metadata, ensure_ascii=False),
                finding.score,
                json.dumps(finding.score_factors, ensure_ascii=False),
                finding.status.value,
                finding.first_seen,
                finding.last_seen,
            ),
        )
        finding_id = finding.id  # occurrences reference the TEXT id, not the rowid
        for position, occ in enumerate(finding.occurrences):
            self._conn.execute(
                "INSERT INTO occurrences (id, finding_id, position, scanner, rule_id, "
                "file_path, start_line, end_line, evidence, message, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"{finding.id}:{position}",
                    finding_id,
                    position,
                    occ.scanner,
                    occ.rule_id,
                    occ.file_path,
                    occ.start_line,
                    occ.end_line,
                    occ.evidence,
                    occ.message,
                    json.dumps(occ.metadata, ensure_ascii=False),
                ),
            )

    def get_scan(self, scan_id: str) -> Scan:
        row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            raise StorageError(f"Scan {scan_id} not found")
        tools = [
            ScanToolRun(
                tool=t["tool"],
                status=ToolRunStatus(t["status"]),
                version=t["version"],
                exit_code=t["exit_code"],
                note=t["note"],
            )
            for t in self._conn.execute(
                "SELECT * FROM scan_tools WHERE scan_id = ? ORDER BY tool", (scan_id,)
            ).fetchall()
        ]
        return _row_to_scan(row, tools)

    def list_scans(self, project_id: str) -> list[Scan]:
        """Scans ordered oldest first (created_at, then id for stability)."""
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at ASC, id ASC",
            (project_id,),
        ).fetchall()
        scans: list[Scan] = []
        for row in rows:
            tools = [
                ScanToolRun(
                    tool=t["tool"],
                    status=ToolRunStatus(t["status"]),
                    version=t["version"],
                    exit_code=t["exit_code"],
                    note=t["note"],
                )
                for t in self._conn.execute(
                    "SELECT * FROM scan_tools WHERE scan_id = ? ORDER BY tool", (row["id"],)
                ).fetchall()
            ]
            scans.append(_row_to_scan(row, tools))
        return scans

    def latest_scan(self, project_id: str) -> Scan | None:
        scans = self.list_scans(project_id)
        return scans[-1] if scans else None

    def count_scans(self, project_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM scans WHERE project_id = ?", (project_id,)
        ).fetchone()
        return int(row["n"])

    # -------------------------------------------------------------- findings
    def get_findings(self, scan_id: str) -> list[Finding]:
        """Findings of one scan, ordered by severity rank, score, path."""
        rows = self._conn.execute(
            """
            SELECT * FROM findings WHERE scan_id = ?
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END,
                score DESC, file_path, start_line
            """,
            (scan_id,),
        ).fetchall()
        return [self._load_finding_row(row) for row in rows]

    def _load_finding_row(self, row: sqlite3.Row) -> Finding:
        occurrences = [
            Occurrence(
                scanner=o["scanner"],
                rule_id=o["rule_id"],
                file_path=o["file_path"],
                start_line=o["start_line"],
                end_line=o["end_line"],
                evidence=o["evidence"],
                message=o["message"],
                metadata=json.loads(o["metadata"]),
            )
            for o in self._conn.execute(
                "SELECT * FROM occurrences WHERE finding_id = ? ORDER BY position",
                (row["id"],),
            ).fetchall()
        ]
        return _row_to_finding(row, occurrences)

    def get_fingerprint_index(self, scan_id: str) -> dict[str, Finding]:
        """fingerprint -> Finding for one scan (lightweight, no occurrences)."""
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return {row["fingerprint"]: _row_to_finding(row, []) for row in rows}

    def fingerprint_history(self, project_id: str, fingerprint: str) -> list[dict]:
        """All (scan, finding) observations of a fingerprint, oldest first."""
        rows = self._conn.execute(
            """
            SELECT s.id AS scan_id, s.created_at AS scan_created_at, s.target_path,
                   f.id AS finding_id, f.severity, f.status, f.scanner, f.rule_id,
                   st.version AS tool_version
            FROM findings f JOIN scans s ON s.id = f.scan_id
            LEFT JOIN scan_tools st ON st.scan_id = s.id AND st.tool = f.scanner
            WHERE s.project_id = ? AND f.fingerprint = ?
            ORDER BY s.created_at ASC, s.id ASC
            """,
            (project_id, fingerprint),
        ).fetchall()
        return [dict(row) for row in rows]

    def project_findings(self, project_id: str) -> list[dict]:
        """All findings joined with their scan metadata, oldest scan first."""
        rows = self._conn.execute(
            """
            SELECT s.id AS scan_id, s.created_at AS scan_created_at, s.target_path,
                   f.id AS finding_id, f.fingerprint, f.severity, f.status, f.scanner,
                   f.rule_id, f.title, f.file_path, f.start_line, f.score
            FROM findings f JOIN scans s ON s.id = f.scan_id
            WHERE s.project_id = ?
            ORDER BY s.created_at ASC, s.id ASC, f.fingerprint ASC
            """,
            (project_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def project_fingerprints(self, project_id: str) -> set[str]:
        rows = self._conn.execute(
            """
            SELECT DISTINCT f.fingerprint FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE s.project_id = ?
            """,
            (project_id,),
        ).fetchall()
        return {row["fingerprint"] for row in rows}

    # -------------------------------------------------------- status history
    def record_status(
        self,
        project_id: str,
        fingerprint: str,
        scan_id: str,
        status: FindingStatus,
        reason: str,
        verification: dict | None = None,
        created_at: str | None = None,
    ) -> None:
        """Append one status_history entry (audit trail for the ledger)."""
        from patchledger.models import new_id, utc_now_iso

        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO status_history (id, project_id, fingerprint, scan_id, "
                    "status, reason, verification, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        new_id(),
                        project_id,
                        fingerprint,
                        scan_id,
                        status.value,
                        reason,
                        json.dumps(verification, ensure_ascii=False) if verification else None,
                        created_at or utc_now_iso(),
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot record status history: {exc}") from exc

    def status_history(self, project_id: str) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT * FROM status_history WHERE project_id = ?
            ORDER BY created_at ASC, rowid ASC
            """,
            (project_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def latest_statuses(self, project_id: str) -> dict[str, dict]:
        """Most recent status_history entry per fingerprint."""
        rows = self._conn.execute(
            """
            SELECT sh.* FROM status_history sh
            JOIN (
                SELECT fingerprint, MAX(rowid) AS max_rowid FROM status_history
                WHERE project_id = ? GROUP BY fingerprint
            ) latest ON sh.rowid = latest.max_rowid
            """,
            (project_id,),
        ).fetchall()
        return {row["fingerprint"]: dict(row) for row in rows}

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> None:
        """Update the stored status on a finding row (with FK enforcement)."""
        try:
            with self._conn:
                self._conn.execute(
                    "UPDATE findings SET status = ? WHERE id = ?", (status.value, finding_id)
                )
        except sqlite3.Error as exc:
            raise StorageError(f"Cannot update finding status: {exc}") from exc
