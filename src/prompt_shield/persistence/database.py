"""Database connection manager for prompt-shield persistence."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from prompt_shield.exceptions import PersistenceError
from prompt_shield.persistence.migrations import CURRENT_VERSION, MIGRATIONS


class DatabaseManager:
    """Manages a SQLite database used for scan history, feedback, and audit logs.

    The manager enables WAL mode for concurrent read access and automatically
    applies any pending schema migrations on initialisation.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._ensure_parent_dir()
        self._conn = self._create_connection()
        self._apply_migrations()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_parent_dir(self) -> None:
        """Create the parent directory for the database file if it does not exist."""
        parent = Path(self._db_path).parent
        parent.mkdir(parents=True, exist_ok=True)

    def _create_connection(self) -> sqlite3.Connection:
        """Open a SQLite connection with WAL journal mode."""
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to open database at {self._db_path}: {exc}") from exc

    def _current_schema_version(self) -> int:
        """Return the highest applied schema version, or 0 if none."""
        cursor = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';"
        )
        if cursor.fetchone() is None:
            return 0
        row = self._conn.execute(
            "SELECT MAX(version) AS v FROM schema_version;"
        ).fetchone()
        return row["v"] if row["v"] is not None else 0

    def _apply_migrations(self) -> None:
        """Apply all unapplied migrations up to *CURRENT_VERSION*."""
        try:
            current = self._current_schema_version()
            for version in range(current + 1, CURRENT_VERSION + 1):
                sql = MIGRATIONS.get(version)
                if sql is None:
                    raise PersistenceError(
                        f"Missing migration for schema version {version}"
                    )
                self._conn.executescript(sql)
                self._conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?);",
                    (version,),
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Migration failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield the managed *sqlite3.Connection* with *Row* row-factory.

        The connection is shared across calls; callers should **not** close it.
        """
        if self._conn is None:
            raise PersistenceError("DatabaseManager has been closed")
        try:
            yield self._conn
        except sqlite3.Error as exc:
            self._conn.rollback()
            raise PersistenceError(f"Database operation failed: {exc}") from exc

    def prune_scan_history(self, retention_days: int) -> int:
        """Delete scan-history rows older than *retention_days* days.

        Returns the number of rows deleted.
        """
        try:
            cursor = self._conn.execute(
                "DELETE FROM scan_history "
                "WHERE timestamp < datetime('now', ? || ' days');",
                (f"-{retention_days}",),
            )
            self._conn.commit()
            return cursor.rowcount
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to prune scan history: {exc}") from exc

    def close(self) -> None:
        """Close the underlying database connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error as exc:
                raise PersistenceError(f"Error closing database: {exc}") from exc
            finally:
                self._conn = None
