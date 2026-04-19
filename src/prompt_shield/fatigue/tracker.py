"""Adversarial fatigue tracker — detects probing campaigns via EWMA near-miss rate.

Cross-domain origin: materials-science S-N (stress-number-of-cycles) fatigue
curves predict structural failure under repeated stress below the
single-cycle threshold. We model adversarial prompt-injection the same way:
each individual scan may land just below the detection threshold, but a
sustained pattern of such near-misses from the same source is itself a
detection signal.

Mechanism:

1. For every scan, observe the (source, detector_id, confidence,
   base_threshold) tuple.
2. Classify each observation as a *near-miss* if
   ``base_threshold - near_miss_delta <= confidence < base_threshold``.
3. Update an exponentially weighted moving average (EWMA) of the near-miss
   indicator per (source, detector) pair.
4. When the EWMA exceeds ``trigger_ratio``, mark the pair as *hardened*.
   While hardened, ``get_effective_threshold`` returns
   ``base_threshold - harden_delta``, making it harder for near-boundary
   probes to evade detection.
5. When the pair has had no near-miss for ``cooldown_seconds``, restore the
   base threshold.

Default-off via ``fatigue.enabled``. When off the engine skips all
observe/get_effective_threshold calls (zero-overhead).

Thread-safety: the tracker uses a single ``threading.Lock`` around state
mutation, so the same instance is safe under the engine's parallel
detector execution.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Entry:
    """Per-(source, detector_id) fatigue state."""

    ewma_near_miss: float = 0.0
    last_near_miss_ts: float = 0.0  # monotonic-clock timestamp
    hardened: bool = False
    hardened_at_ts: float = 0.0  # monotonic-clock timestamp
    samples_seen: int = 0


@dataclass
class FatigueConfig:
    """Configuration values (parsed from the ``fatigue:`` config block)."""

    enabled: bool = False
    near_miss_delta: float = 0.15
    ewma_alpha: float = 0.3
    trigger_ratio: float = 0.4
    harden_delta: float = 0.10
    cooldown_seconds: float = 60.0
    min_samples_before_trigger: int = 8
    source_key: str = "source"

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> FatigueConfig:
        if not data:
            return cls()

        def _f(key: str, default: float) -> float:
            v = data.get(key, default)
            return float(v) if isinstance(v, (int, float, str)) else default

        def _i(key: str, default: int) -> int:
            v = data.get(key, default)
            return int(v) if isinstance(v, (int, float, str)) else default

        def _b(key: str, default: bool) -> bool:
            v = data.get(key, default)
            return bool(v) if isinstance(v, (bool, int)) else default

        def _s(key: str, default: str) -> str:
            v = data.get(key, default)
            return str(v) if isinstance(v, str) else default

        return cls(
            enabled=_b("enabled", False),
            near_miss_delta=_f("near_miss_delta", 0.15),
            ewma_alpha=_f("ewma_alpha", 0.3),
            trigger_ratio=_f("trigger_ratio", 0.4),
            harden_delta=_f("harden_delta", 0.10),
            cooldown_seconds=_f("cooldown_seconds", 60.0),
            min_samples_before_trigger=_i("min_samples_before_trigger", 8),
            source_key=_s("source_key", "source"),
        )


class FatigueTracker:
    """Per-(source, detector) EWMA near-miss tracker with threshold hardening.

    Cheap in both RAM and CPU: one small object per active (source, detector)
    pair, a dict lookup + constant-time math per scan observation. No disk,
    no network. State resets on process restart (intended — fatigue is a
    short-window signal, not a durable profile).
    """

    def __init__(self, config: FatigueConfig | None = None) -> None:
        self._config = config or FatigueConfig()
        self._entries: dict[tuple[str, str], _Entry] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ API

    @property
    def config(self) -> FatigueConfig:
        return self._config

    @property
    def source_key(self) -> str:
        return self._config.source_key

    def observe(
        self,
        source: str,
        detector_id: str,
        confidence: float,
        base_threshold: float,
        *,
        now: float | None = None,
    ) -> None:
        """Record a single scan observation.

        Parameters
        ----------
        source
            Caller-supplied identifier isolating one attacker/session/IP from
            another. Use ``"_global_"`` when the caller does not provide one.
        detector_id
            The detector whose confidence this observation describes.
        confidence
            Detector confidence in [0.0, 1.0].
        base_threshold
            The detector's threshold *before* fatigue hardening. Used to
            classify the observation as a near-miss or not.
        now
            Optional monotonic timestamp override — for tests.
        """
        if not self._config.enabled:
            return

        ts = now if now is not None else time.monotonic()
        key = (source, detector_id)

        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = _Entry()
                self._entries[key] = entry

            is_near_miss = self._is_near_miss(confidence, base_threshold)
            indicator = 1.0 if is_near_miss else 0.0
            alpha = self._config.ewma_alpha
            entry.ewma_near_miss = alpha * indicator + (1 - alpha) * entry.ewma_near_miss
            entry.samples_seen += 1
            if is_near_miss:
                entry.last_near_miss_ts = ts

            # Cooldown: if hardened and quiet for long enough, restore.
            # Also reset EWMA so we don't immediately re-trigger hardening on
            # the same observation — the semantic is "attacker has gone away,
            # forget what happened before; if they come back the EWMA
            # rebuilds from zero".
            if entry.hardened and not is_near_miss:
                quiet_for = ts - entry.last_near_miss_ts
                if quiet_for >= self._config.cooldown_seconds:
                    entry.hardened = False
                    entry.ewma_near_miss = 0.0
                    entry.samples_seen = 0

            # Trigger hardening if the near-miss EWMA exceeds threshold
            # AND we have enough samples for the signal to be meaningful.
            if (
                not entry.hardened
                and entry.samples_seen >= self._config.min_samples_before_trigger
                and entry.ewma_near_miss > self._config.trigger_ratio
            ):
                entry.hardened = True
                entry.hardened_at_ts = ts

    def get_effective_threshold(
        self,
        source: str,
        detector_id: str,
        base_threshold: float,
    ) -> float:
        """Return the threshold to use for this scan.

        Identical to ``base_threshold`` unless the (source, detector) pair is
        currently hardened, in which case the threshold is lowered by
        ``harden_delta`` (clamped to [0.0, 1.0]).
        """
        if not self._config.enabled:
            return base_threshold
        key = (source, detector_id)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or not entry.hardened:
                return base_threshold
            return max(0.0, min(1.0, base_threshold - self._config.harden_delta))

    def is_hardened(self, source: str, detector_id: str) -> bool:
        """Inspect current hardening state (observability + tests)."""
        if not self._config.enabled:
            return False
        with self._lock:
            entry = self._entries.get((source, detector_id))
            return bool(entry and entry.hardened)

    def snapshot(self) -> dict[tuple[str, str], dict[str, float | bool | int]]:
        """Return a deep snapshot of internal state — diagnostic use only."""
        with self._lock:
            return {
                key: {
                    "ewma_near_miss": e.ewma_near_miss,
                    "hardened": e.hardened,
                    "samples_seen": e.samples_seen,
                    "last_near_miss_ts": e.last_near_miss_ts,
                    "hardened_at_ts": e.hardened_at_ts,
                }
                for key, e in self._entries.items()
            }

    def reset(self) -> None:
        """Drop all state (used by tests; not normally called at runtime)."""
        with self._lock:
            self._entries.clear()

    # ----------------------------------------------------------------- help

    def _is_near_miss(self, confidence: float, base_threshold: float) -> bool:
        lower = base_threshold - self._config.near_miss_delta
        return lower <= confidence < base_threshold
