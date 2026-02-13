"""Persistent storage and querying for detector feedback."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime

from prompt_shield.exceptions import FeedbackError


class FeedbackStore:
    """Records and queries user feedback on detector results.

    Uses a standalone SQLite connection (WAL mode, ``Row`` factory) rather
    than going through :class:`~prompt_shield.persistence.database.DatabaseManager`
    so that feedback can be recorded independently of the main scan pipeline.

    Parameters
    ----------
    db_path:
        Filesystem path to the SQLite database file.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        """Return a fresh SQLite connection with WAL mode and Row factory."""
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        scan_id: str,
        detector_id: str,
        is_correct: bool,
        notes: str = "",
    ) -> None:
        """Insert a feedback row for a given scan/detector pair.

        Parameters
        ----------
        scan_id:
            The ``scan_history.id`` this feedback relates to.
        detector_id:
            Identifier of the detector being evaluated.
        is_correct:
            ``True`` if the detector result was correct, ``False`` otherwise.
        notes:
            Optional free-text notes from the reviewer.

        Raises
        ------
        FeedbackError
            If the database write fails.
        """
        feedback_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        try:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO feedback (id, scan_id, detector_id, is_correct, timestamp, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?);",
                    (feedback_id, scan_id, detector_id, 1 if is_correct else 0, timestamp, notes),
                )
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise FeedbackError(f"Failed to record feedback: {exc}") from exc

    def get_detector_stats(self, detector_id: str) -> dict:
        """Return accuracy statistics for a single detector.

        Returns
        -------
        dict
            ``{"total": int, "true_positives": int, "false_positives": int, "fp_rate": float}``
        """
        try:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT is_correct FROM feedback WHERE detector_id = ?;",
                    (detector_id,),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise FeedbackError(
                f"Failed to query feedback for detector '{detector_id}': {exc}"
            ) from exc

        total = len(rows)
        true_positives = sum(1 for r in rows if r["is_correct"] == 1)
        false_positives = total - true_positives
        fp_rate = false_positives / total if total > 0 else 0.0

        return {
            "total": total,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "fp_rate": fp_rate,
        }

    def get_all_stats(self) -> dict[str, dict]:
        """Return per-detector stats for every detector that has feedback.

        Returns
        -------
        dict[str, dict]
            Mapping of ``detector_id`` to the same stats dict produced by
            :meth:`get_detector_stats`.
        """
        try:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT DISTINCT detector_id FROM feedback;"
                ).fetchall()
                detector_ids = [r["detector_id"] for r in rows]
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise FeedbackError(f"Failed to query all feedback stats: {exc}") from exc

        return {did: self.get_detector_stats(did) for did in detector_ids}
