"""End-to-end tests: engine wires fatigue tracker into the scan path.

Uses a dummy detector with a controllable confidence so we can construct
a probing campaign that lands reliably in the near-miss range, rather
than depending on the brittle behaviour of real text-input patterns.
"""

from __future__ import annotations

from typing import ClassVar

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import DetectionResult, Severity


class _FixedConfidenceDetector(BaseDetector):
    """Detector whose confidence can be set per-scan via context."""

    detector_id: str = "dummy_fixed"
    name: str = "Dummy fixed-confidence detector"
    description: str = "Returns a preset confidence for every scan; used in tests."
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["test"]
    version: str = "0.0.1"
    author: str = "test"

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        ctx = context or {}
        confidence = float(ctx.get("fixed_confidence", 0.0))  # type: ignore[arg-type]
        return DetectionResult(
            detector_id=self.detector_id,
            detected=confidence > 0.0,
            confidence=confidence,
            severity=self.severity,
            explanation=f"fixed-confidence detector returned {confidence}",
        )


def _build_engine(
    *,
    fatigue_enabled: bool = True,
    min_samples: int = 5,
    trigger_ratio: float = 0.3,
    threshold: float = 0.7,
) -> PromptShieldEngine:
    engine = PromptShieldEngine(
        config_dict={
            "prompt_shield": {
                "mode": "block",
                "threshold": threshold,
                "parallel": False,
                "vault": {"enabled": False},
                "feedback": {"enabled": False},
                "canary": {"enabled": False},
                "history": {"enabled": False},
                "detectors": {
                    "d022_semantic_classifier": {"enabled": False},
                },
                "fatigue": {
                    "enabled": fatigue_enabled,
                    "min_samples_before_trigger": min_samples,
                    "trigger_ratio": trigger_ratio,
                    "near_miss_delta": 0.15,
                    "ewma_alpha": 0.5,  # more reactive for tests
                    "harden_delta": 0.10,
                    "cooldown_seconds": 60,
                },
            }
        }
    )
    # Remove every real detector so only the dummy fires — keeps the test
    # signal clean regardless of future detector additions.
    for det in list(engine._registry.list_all()):
        engine._registry.unregister(det.detector_id)
    engine._registry.register(_FixedConfidenceDetector())
    return engine


class TestFatigueDisabled:
    def test_engine_scan_path_unchanged(self) -> None:
        """With fatigue off, the tracker attribute is None and scans behave identically."""
        engine = _build_engine(fatigue_enabled=False)
        assert engine._fatigue is None
        report = engine.scan("hello", context={"fixed_confidence": 0.65})
        # below threshold 0.7 → pass
        assert report.action.value == "pass"
        assert len(report.detections) == 0


class TestFatigueEnabled:
    def test_probing_campaign_triggers_hardening(self) -> None:
        engine = _build_engine(min_samples=5)
        assert engine._fatigue is not None

        # 10 near-miss scans (conf 0.65, threshold 0.7) from the same source.
        for _ in range(10):
            engine.scan("probe", context={"source": "attacker", "fixed_confidence": 0.65})

        # After enough samples the (source, detector) pair must be hardened.
        assert engine._fatigue.is_hardened("attacker", "dummy_fixed") is True

    def test_hardening_catches_next_near_miss(self) -> None:
        """Once hardened, a confidence that previously passed should now block."""
        engine = _build_engine(min_samples=5)

        # Build up fatigue
        for _ in range(10):
            engine.scan("probe", context={"source": "attacker", "fixed_confidence": 0.65})

        # Before fatigue, conf 0.63 was below threshold 0.7 → would pass.
        # After fatigue, threshold hardens to 0.6 → 0.63 now blocks.
        report = engine.scan("probe", context={"source": "attacker", "fixed_confidence": 0.63})
        assert report.action.value == "block"
        assert len(report.detections) == 1

    def test_benign_source_unaffected_by_attacker_campaign(self) -> None:
        """Per-source isolation must hold at the engine level."""
        engine = _build_engine(min_samples=5)

        for _ in range(10):
            engine.scan("probe", context={"source": "attacker", "fixed_confidence": 0.65})

        # A DIFFERENT source scanning conf 0.63 should still pass — their
        # threshold is not hardened.
        report = engine.scan("ok", context={"source": "benign_user", "fixed_confidence": 0.63})
        assert report.action.value == "pass"
        assert engine._fatigue is not None
        assert engine._fatigue.is_hardened("benign_user", "dummy_fixed") is False

    def test_global_bucket_used_when_no_source_provided(self) -> None:
        """When the caller omits a ``source`` key the tracker uses ``_global_``."""
        engine = _build_engine(min_samples=5)

        for _ in range(10):
            engine.scan("probe", context={"fixed_confidence": 0.65})

        assert engine._fatigue is not None
        assert engine._fatigue.is_hardened("_global_", "dummy_fixed") is True

    def test_benign_traffic_never_hardens(self) -> None:
        """Traffic well below the near-miss band must not trip fatigue."""
        engine = _build_engine(min_samples=5)

        for _ in range(50):
            engine.scan("clean", context={"source": "user", "fixed_confidence": 0.05})

        assert engine._fatigue is not None
        assert engine._fatigue.is_hardened("user", "dummy_fixed") is False

    def test_parallel_runner_also_observes(self) -> None:
        """Parallel execution path must call observe() too."""
        engine = _build_engine(min_samples=5)
        engine._parallel = True  # force the parallel runner

        # Register a second dummy so total_run > 1 triggers parallel code path.
        class _Second(_FixedConfidenceDetector):
            detector_id: str = "dummy_second"

        engine._registry.register(_Second())

        for _ in range(10):
            engine.scan("probe", context={"source": "attacker", "fixed_confidence": 0.65})

        assert engine._fatigue is not None
        # Both detectors should have observed and hardened
        assert engine._fatigue.is_hardened("attacker", "dummy_fixed") is True
        assert engine._fatigue.is_hardened("attacker", "dummy_second") is True
