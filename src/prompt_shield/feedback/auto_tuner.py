"""Automatic threshold tuning driven by accumulated feedback."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from prompt_shield.exceptions import FeedbackError
from prompt_shield.feedback.feedback_store import FeedbackStore


class AutoTuner:
    """Adjusts detector confidence thresholds based on historical feedback.

    The tuner reads aggregate statistics from :class:`FeedbackStore` and
    writes updated thresholds into the ``detector_tuning`` table so that
    future scans can use :meth:`get_effective_threshold`.

    Parameters
    ----------
    db_path:
        Filesystem path to the SQLite database file.
    max_adjustment:
        Maximum absolute offset (positive or negative) from the original
        threshold.  Defaults to ``0.15``.
    """

    def __init__(self, db_path: str, max_adjustment: float = 0.15) -> None:
        self._db_path = db_path
        self._max_adjustment = max_adjustment
        self._feedback_store = FeedbackStore(db_path)

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

    def tune(self) -> dict[str, float]:
        """Run the tuning algorithm across all detectors with feedback.

        For each detector that has at least 10 feedback entries the tuner:

        * Raises the threshold by ``0.03`` when the false-positive rate
          exceeds 20%.
        * Lowers the threshold by ``0.01`` when the false-positive rate
          is below 5% **and** the detector has more than 20 true positives.

        Adjustments are clamped to ``[-max_adjustment, +max_adjustment]``
        relative to the original threshold stored in the ``detector_tuning``
        row.

        Returns
        -------
        dict[str, float]
            Mapping of ``detector_id`` to the newly written
            ``adjusted_threshold``.
        """
        all_stats = self._feedback_store.get_all_stats()
        results: dict[str, float] = {}

        try:
            conn = self._get_conn()
            try:
                for detector_id, stats in all_stats.items():
                    total: int = stats["total"]
                    if total < 10:
                        continue

                    fp_rate: float = stats["fp_rate"]
                    true_positives: int = stats["true_positives"]
                    false_positives: int = stats["false_positives"]

                    # Read current tuning row (if any) to get the original threshold
                    row = conn.execute(
                        "SELECT original_threshold, adjusted_threshold "
                        "FROM detector_tuning WHERE detector_id = ?;",
                        (detector_id,),
                    ).fetchone()

                    if row is not None:
                        original_threshold = row["original_threshold"]
                        current_threshold = row["adjusted_threshold"]
                    else:
                        # No prior tuning -- assume a default original of 0.5
                        original_threshold = 0.5
                        current_threshold = 0.5

                    # Determine adjustment direction
                    adjustment = current_threshold - original_threshold
                    if fp_rate > 0.20:
                        adjustment += 0.03
                    elif fp_rate < 0.05 and true_positives > 20:
                        adjustment -= 0.01

                    # Clamp to [-max_adjustment, +max_adjustment]
                    adjustment = max(-self._max_adjustment, min(self._max_adjustment, adjustment))
                    new_threshold = original_threshold + adjustment

                    # Upsert into detector_tuning
                    conn.execute(
                        "INSERT INTO detector_tuning "
                        "(detector_id, adjusted_threshold, original_threshold, "
                        "total_scans, true_positives, false_positives, last_tuned_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(detector_id) DO UPDATE SET "
                        "adjusted_threshold = excluded.adjusted_threshold, "
                        "total_scans = excluded.total_scans, "
                        "true_positives = excluded.true_positives, "
                        "false_positives = excluded.false_positives, "
                        "last_tuned_at = excluded.last_tuned_at;",
                        (
                            detector_id,
                            new_threshold,
                            original_threshold,
                            total,
                            true_positives,
                            false_positives,
                            datetime.utcnow().isoformat(),
                        ),
                    )
                    results[detector_id] = new_threshold

                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise FeedbackError(f"Failed to tune detectors: {exc}") from exc

        return results

    def get_effective_threshold(self, detector_id: str, default: float) -> float:
        """Look up the tuned threshold for *detector_id*.

        Parameters
        ----------
        detector_id:
            Detector to look up.
        default:
            Value to return when no tuning row exists.

        Returns
        -------
        float
            The ``adjusted_threshold`` from ``detector_tuning``, or
            *default* if the detector has not been tuned.
        """
        try:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT adjusted_threshold FROM detector_tuning WHERE detector_id = ?;",
                    (detector_id,),
                ).fetchone()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise FeedbackError(
                f"Failed to read threshold for detector '{detector_id}': {exc}"
            ) from exc

        if row is not None:
            return float(row["adjusted_threshold"])
        return default

    def reset(self, detector_id: str | None = None) -> None:
        """Remove tuning data for a specific detector, or all detectors.

        Parameters
        ----------
        detector_id:
            If provided only that detector's row is deleted.  When ``None``
            (the default) *all* rows in ``detector_tuning`` are removed.
        """
        try:
            conn = self._get_conn()
            try:
                if detector_id is not None:
                    conn.execute(
                        "DELETE FROM detector_tuning WHERE detector_id = ?;",
                        (detector_id,),
                    )
                else:
                    conn.execute("DELETE FROM detector_tuning;")
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise FeedbackError(f"Failed to reset tuning data: {exc}") from exc
