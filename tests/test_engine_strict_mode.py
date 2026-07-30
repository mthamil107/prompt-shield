"""Tests for the strict_mode fail-closed switch on PromptShieldEngine.

Background: an earlier external review flagged that ``engine.scan()``
absorbs detector exceptions and returns as if the failed detector had
simply produced no detection. For a security tool, silent detector
failure is the worst possible failure mode — the caller receives a
clean report when the scan was actually broken.

``strict_mode: true`` in the config re-raises detector exceptions
instead of logging-and-continuing. The default remains False to preserve
v0.7.x behaviour on upgrade.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

import pytest

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import DetectionResult, Severity

if TYPE_CHECKING:
    from pathlib import Path


class _ExplodingDetector(BaseDetector):
    """Detector whose ``detect()`` raises unconditionally."""

    detector_id = "d999_exploding"
    name = "Exploding Detector"
    description = "Always raises RuntimeError in detect()."
    severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["test", "fault-injection"]
    version = "0.0.1"
    author = "test"

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        raise RuntimeError("simulated detector failure")


def _build_config(
    tmp_data_dir: Path, *, strict_mode: bool, parallel: bool = False
) -> dict[str, Any]:
    """Minimal config; strict_mode + parallel toggleable per test."""
    return {
        "prompt_shield": {
            "mode": "block",
            "threshold": 0.7,
            "strict_mode": strict_mode,
            "parallel": parallel,
            "max_workers": 2,
            "data_dir": str(tmp_data_dir),
            "vault": {"enabled": False},
            "feedback": {"enabled": False},
            "canary": {"enabled": False},
            "history": {"enabled": False},
            "threat_feed": {"enabled": False},
            "actions": {
                "critical": "block",
                "high": "block",
                "medium": "flag",
                "low": "log",
            },
            "detectors": {},
            "allowlist": {"patterns": []},
            "blocklist": {"patterns": []},
        }
    }


def test_strict_mode_off_by_default(tmp_data_dir: Path) -> None:
    """A fresh engine without explicit override reports strict_mode=False.

    Backwards-compat contract: existing v0.7.x callers who upgrade see
    no behavioural change unless they explicitly opt in.
    """
    engine = PromptShieldEngine(
        config_dict={
            "prompt_shield": {
                "data_dir": str(tmp_data_dir),
                "vault": {"enabled": False},
                "feedback": {"enabled": False},
                "canary": {"enabled": False},
                "history": {"enabled": False},
                "threat_feed": {"enabled": False},
            }
        },
        data_dir=str(tmp_data_dir),
    )
    assert engine._strict_mode is False


@pytest.mark.parametrize("parallel", [False, True])
def test_default_mode_silent_on_detector_failure(tmp_data_dir: Path, parallel: bool) -> None:
    """Non-strict mode logs the failure and completes the scan cleanly.

    We use the same benign input twice — once before and once after
    registering the exploding detector — so ``total_detectors_run``
    reflects only the delta introduced by our fault-injection detector
    (not disabled-by-default policy gates like d031/d032). This is the
    v0.7.x contract we are preserving under strict_mode=False.
    """
    cfg = _build_config(tmp_data_dir, strict_mode=False, parallel=parallel)
    engine = PromptShieldEngine(config_dict=cfg, data_dir=str(tmp_data_dir))

    baseline_report = engine.scan("hello world, nothing suspicious here")
    baseline_run = baseline_report.total_detectors_run

    engine.register_detector(_ExplodingDetector())

    # Should NOT raise despite the injected fault.
    report = engine.scan("hello world, nothing suspicious here")

    # The exploding detector was dispatched (counted in total_run) but
    # its failure was swallowed — so N+1 detectors ran vs. baseline.
    assert report.total_detectors_run == baseline_run + 1
    # Exploding detector must not appear as a real detection.
    assert all(d.detector_id != "d999_exploding" for d in report.detections)


@pytest.mark.parametrize("parallel", [False, True])
def test_strict_mode_raises_on_detector_failure(tmp_data_dir: Path, parallel: bool) -> None:
    """strict_mode=True re-raises the detector's RuntimeError verbatim.

    Both dispatch paths (sequential and ThreadPoolExecutor) must honour
    the switch — parametrized to keep parity guaranteed.
    """
    cfg = _build_config(tmp_data_dir, strict_mode=True, parallel=parallel)
    engine = PromptShieldEngine(config_dict=cfg, data_dir=str(tmp_data_dir))
    engine.register_detector(_ExplodingDetector())

    with pytest.raises(RuntimeError, match="simulated detector failure"):
        engine.scan("hello world, nothing suspicious here")
