"""Tests for the DatabaseManager."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from prompt_shield.persistence.database import DatabaseManager


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    """Return a temporary database file path."""
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    return str(db_dir / "test.db")


@pytest.fixture
def db(db_path: str) -> DatabaseManager:
    """Create a DatabaseManager with a temp database."""
    return DatabaseManager(db_path)


class TestDatabaseInit:
    """Tests for database initialization."""

    def test_database_init(self, db: DatabaseManager, db_path: str) -> None:
        """DatabaseManager should create the DB file and expected tables."""
        assert Path(db_path).exists()

        with db.connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            )
            tables = {row["name"] for row in cursor.fetchall()}

        expected_tables = {
            "schema_version",
            "scan_history",
            "feedback",
            "detector_tuning",
            "vault_log",
            "sync_history",
        }
        assert expected_tables.issubset(tables), (
            f"Missing tables: {expected_tables - tables}"
        )


class TestDatabaseConnection:
    """Tests for the connection context manager."""

    def test_database_connection(self, db: DatabaseManager) -> None:
        """connection() context manager should yield a usable connection."""
        with db.connection() as conn:
            assert conn is not None
            # Should be able to execute a simple query
            result = conn.execute("SELECT 1 AS val").fetchone()
            assert result["val"] == 1


class TestDatabaseInsert:
    """Tests for inserting and querying data."""

    def test_database_insert_scan(self, db: DatabaseManager) -> None:
        """Inserting a scan_history row should be queryable back."""
        scan_id = "test-scan-001"
        timestamp = datetime.now(timezone.utc).isoformat()

        with db.connection() as conn:
            conn.execute(
                """INSERT INTO scan_history
                   (id, timestamp, input_hash, input_length, overall_score,
                    action_taken, detectors_fired, vault_matched, scan_duration_ms, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    timestamp,
                    "abc123hash",
                    42,
                    0.85,
                    "block",
                    "[]",
                    0,
                    12.5,
                    "test",
                ),
            )
            conn.commit()

        with db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_history WHERE id = ?", (scan_id,)
            ).fetchone()

        assert row is not None
        assert row["id"] == scan_id
        assert row["input_hash"] == "abc123hash"
        assert row["overall_score"] == 0.85
        assert row["action_taken"] == "block"


class TestDatabasePrune:
    """Tests for pruning old scan history."""

    def test_database_prune(self, db: DatabaseManager) -> None:
        """Pruning should delete rows older than retention_days."""
        old_timestamp = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        recent_timestamp = datetime.now(timezone.utc).isoformat()

        with db.connection() as conn:
            # Insert an old row
            conn.execute(
                """INSERT INTO scan_history
                   (id, timestamp, input_hash, input_length, overall_score,
                    action_taken, detectors_fired, vault_matched, scan_duration_ms, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("old-scan", old_timestamp, "hash1", 10, 0.5, "pass", "[]", 0, 5.0, "test"),
            )
            # Insert a recent row
            conn.execute(
                """INSERT INTO scan_history
                   (id, timestamp, input_hash, input_length, overall_score,
                    action_taken, detectors_fired, vault_matched, scan_duration_ms, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("new-scan", recent_timestamp, "hash2", 20, 0.3, "pass", "[]", 0, 3.0, "test"),
            )
            conn.commit()

        deleted = db.prune_scan_history(retention_days=90)
        assert deleted >= 1

        with db.connection() as conn:
            remaining = conn.execute("SELECT id FROM scan_history").fetchall()
        remaining_ids = [r["id"] for r in remaining]
        assert "old-scan" not in remaining_ids
        assert "new-scan" in remaining_ids


class TestDatabaseWALMode:
    """Tests for WAL journal mode."""

    def test_database_wal_mode(self, db: DatabaseManager) -> None:
        """Database should be in WAL journal mode."""
        with db.connection() as conn:
            result = conn.execute("PRAGMA journal_mode;").fetchone()
            journal_mode = result[0] if isinstance(result, (tuple, list)) else result["journal_mode"]
        assert journal_mode.lower() == "wal"
