"""PatchLedger exception hierarchy."""

from __future__ import annotations


class PatchLedgerError(Exception):
    """Base class for all PatchLedger errors.

    The CLI catches this family and prints a friendly message instead of a
    traceback; ``--debug`` re-raises for real debugging.
    """


class ConfigError(PatchLedgerError):
    """Invalid or unreadable configuration."""


class ReportImportError(PatchLedgerError):
    """A scanner report could not be parsed or failed validation."""


class StorageError(PatchLedgerError):
    """SQLite storage failure."""


class ScannerError(PatchLedgerError):
    """Scanner execution failure (distinct from a scanner reporting findings)."""


class ProjectError(PatchLedgerError):
    """Project/database location problems."""
