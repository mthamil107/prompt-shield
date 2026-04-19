"""Unit tests for the adversarial fatigue tracker."""

from __future__ import annotations

import pytest

from prompt_shield.fatigue.tracker import FatigueConfig, FatigueTracker


def _enabled_config(**overrides: object) -> FatigueConfig:
    """Build an enabled FatigueConfig with tighter defaults for fast tests."""
    base = dict(
        enabled=True,
        near_miss_delta=0.15,
        ewma_alpha=0.3,
        trigger_ratio=0.4,
        harden_delta=0.10,
        cooldown_seconds=60.0,
        min_samples_before_trigger=8,
        source_key="source",
    )
    base.update(overrides)
    return FatigueConfig(**base)  # type: ignore[arg-type]


class TestFatigueConfig:
    def test_default_disabled(self) -> None:
        cfg = FatigueConfig()
        assert cfg.enabled is False
        assert cfg.ewma_alpha == 0.3
        assert cfg.trigger_ratio == 0.4
        assert cfg.harden_delta == 0.10
        assert cfg.source_key == "source"

    def test_from_dict_none(self) -> None:
        assert FatigueConfig.from_dict(None).enabled is False
        assert FatigueConfig.from_dict({}).enabled is False

    def test_from_dict_overrides(self) -> None:
        cfg = FatigueConfig.from_dict(
            {"enabled": True, "trigger_ratio": 0.25, "cooldown_seconds": 10}
        )
        assert cfg.enabled is True
        assert cfg.trigger_ratio == 0.25
        assert cfg.cooldown_seconds == 10.0


class TestDisabledTracker:
    """With enabled=False the tracker must be a total no-op."""

    def test_observe_is_noop(self) -> None:
        t = FatigueTracker()  # default: enabled=False
        t.observe("src", "d001", confidence=0.65, base_threshold=0.7)
        assert t.snapshot() == {}

    def test_get_effective_threshold_returns_base(self) -> None:
        t = FatigueTracker()
        assert t.get_effective_threshold("src", "d001", 0.7) == 0.7

    def test_is_hardened_false(self) -> None:
        t = FatigueTracker()
        assert t.is_hardened("src", "d001") is False


class TestNearMissClassification:
    def test_near_miss_range(self) -> None:
        t = FatigueTracker(_enabled_config())
        # threshold=0.7, delta=0.15 -> near-miss range [0.55, 0.70)
        assert t._is_near_miss(0.55, 0.7) is True
        assert t._is_near_miss(0.60, 0.7) is True
        assert t._is_near_miss(0.69, 0.7) is True

    def test_above_threshold_not_near_miss(self) -> None:
        t = FatigueTracker(_enabled_config())
        # >= threshold is a caught attack, not a near-miss
        assert t._is_near_miss(0.70, 0.7) is False
        assert t._is_near_miss(0.85, 0.7) is False

    def test_below_window_not_near_miss(self) -> None:
        t = FatigueTracker(_enabled_config())
        assert t._is_near_miss(0.54, 0.7) is False
        assert t._is_near_miss(0.0, 0.7) is False


class TestEwmaAccumulation:
    def test_single_observation_updates_ewma(self) -> None:
        t = FatigueTracker(_enabled_config())
        t.observe("src", "d001", confidence=0.65, base_threshold=0.7, now=0)
        snap = t.snapshot()[("src", "d001")]
        # EWMA: alpha*1 + (1-alpha)*0 = 0.3
        assert snap["ewma_near_miss"] == pytest.approx(0.3)
        assert snap["samples_seen"] == 1

    def test_benign_observation_decays_ewma(self) -> None:
        t = FatigueTracker(_enabled_config())
        t.observe("src", "d001", confidence=0.65, base_threshold=0.7, now=0)  # near-miss
        t.observe("src", "d001", confidence=0.10, base_threshold=0.7, now=1)  # benign
        snap = t.snapshot()[("src", "d001")]
        # EWMA: 0.3 * 0 + 0.7 * 0.3 = 0.21
        assert snap["ewma_near_miss"] == pytest.approx(0.21)
        assert snap["samples_seen"] == 2


class TestHardeningTrigger:
    def test_sustained_probing_hardens(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5))
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        assert t.is_hardened("attacker", "d001") is True

    def test_effective_threshold_lowers_when_hardened(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5))
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        eff = t.get_effective_threshold("attacker", "d001", 0.7)
        assert eff == pytest.approx(0.6)  # 0.7 - harden_delta 0.10

    def test_not_hardened_before_min_samples(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=20))
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        assert t.is_hardened("attacker", "d001") is False

    def test_benign_traffic_does_not_harden(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5))
        for i in range(50):
            t.observe("user", "d001", confidence=0.05, base_threshold=0.7, now=float(i))
        assert t.is_hardened("user", "d001") is False


class TestPerSourceIsolation:
    def test_one_source_probing_does_not_harden_another(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5))
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
            t.observe("benign_user", "d001", confidence=0.05, base_threshold=0.7, now=float(i))
        assert t.is_hardened("attacker", "d001") is True
        assert t.is_hardened("benign_user", "d001") is False
        assert t.get_effective_threshold("benign_user", "d001", 0.7) == 0.7

    def test_per_detector_isolation(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5))
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        assert t.is_hardened("attacker", "d001") is True
        assert t.is_hardened("attacker", "d002") is False


class TestCooldownRestore:
    def test_cooldown_restores_threshold(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5, cooldown_seconds=60))
        # probing campaign
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        assert t.is_hardened("attacker", "d001") is True

        # quiet traffic (benign) for > cooldown_seconds should restore
        # One benign observation at t=100 puts us 100-9=91s past the last near-miss
        t.observe("attacker", "d001", confidence=0.05, base_threshold=0.7, now=100.0)
        assert t.is_hardened("attacker", "d001") is False

    def test_cooldown_not_triggered_by_continuing_probes(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5, cooldown_seconds=60))
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        # continued probing — even at t=1000 should stay hardened because the
        # last_near_miss_ts keeps advancing
        for i in range(10, 1000):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        assert t.is_hardened("attacker", "d001") is True

    def test_cooldown_not_restored_before_deadline(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5, cooldown_seconds=60))
        for i in range(10):
            t.observe("attacker", "d001", confidence=0.65, base_threshold=0.7, now=float(i))

        # benign scan 30s later — still within cooldown window
        t.observe("attacker", "d001", confidence=0.05, base_threshold=0.7, now=39.0)
        assert t.is_hardened("attacker", "d001") is True


class TestEffectiveThresholdClamping:
    def test_clamped_to_zero(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5, harden_delta=0.9))
        for i in range(10):
            t.observe("src", "d001", confidence=0.1, base_threshold=0.1, now=float(i))
        # threshold 0.1, harden 0.9 → would be -0.8, clamped to 0.0
        eff = t.get_effective_threshold("src", "d001", 0.1)
        assert 0.0 <= eff <= 1.0


class TestReset:
    def test_reset_clears_state(self) -> None:
        t = FatigueTracker(_enabled_config(min_samples_before_trigger=5))
        for i in range(10):
            t.observe("a", "d001", confidence=0.65, base_threshold=0.7, now=float(i))
        assert t.snapshot()
        t.reset()
        assert t.snapshot() == {}
        assert t.is_hardened("a", "d001") is False
