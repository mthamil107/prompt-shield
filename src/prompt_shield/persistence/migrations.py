"""Schema versioning for SQLite tables."""

from __future__ import annotations

CURRENT_VERSION: int = 1

MIGRATIONS: dict[int, str] = {
    1: """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            input_hash TEXT NOT NULL,
            input_length INTEGER NOT NULL,
            overall_score REAL NOT NULL,
            action_taken TEXT NOT NULL,
            detectors_fired TEXT NOT NULL,
            vault_matched INTEGER DEFAULT 0,
            scan_duration_ms REAL,
            source TEXT DEFAULT 'direct'
        );

        CREATE INDEX IF NOT EXISTS idx_scan_timestamp
            ON scan_history (timestamp);

        CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scan_history(id),
            detector_id TEXT NOT NULL,
            is_correct INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_feedback_detector
            ON feedback (detector_id);

        CREATE TABLE IF NOT EXISTS detector_tuning (
            detector_id TEXT PRIMARY KEY,
            adjusted_threshold REAL NOT NULL,
            original_threshold REAL NOT NULL,
            total_scans INTEGER DEFAULT 0,
            true_positives INTEGER DEFAULT 0,
            false_positives INTEGER DEFAULT 0,
            last_tuned_at DATETIME
        );

        CREATE TABLE IF NOT EXISTS vault_log (
            id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            attack_hash TEXT NOT NULL,
            source TEXT NOT NULL,
            detector_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sync_history (
            id TEXT PRIMARY KEY,
            feed_url TEXT NOT NULL,
            synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            threats_imported INTEGER DEFAULT 0,
            threats_skipped INTEGER DEFAULT 0,
            errors INTEGER DEFAULT 0
        );
    """,
}
