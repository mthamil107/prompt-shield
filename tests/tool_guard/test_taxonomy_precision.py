"""End-to-end precision gate for the taxonomy pipeline.

Runs the real engine over the shared attack corpus and asserts that the
attack-vs-clean signal stays above a minimum threshold. The gate is
intentionally conservative — its purpose is to catch catastrophic
regressions (a taxonomy edit that stops flagging attacks entirely, or a
mapping that starts flagging clean text). It is *not* a bar for
detector recall — that's covered by ``tests/benchmark_*`` scripts.
"""

from __future__ import annotations

from prompt_shield.models import Action
from prompt_shield.tool_guard import ToolResultGuard
from tests.fixtures.tool_result_attacks import (
    ATTACK_SAMPLES,
    CLEAN_SAMPLES,
)


class TestToolResultTaxonomyPrecision:
    def test_attack_detection_rate(self, engine):
        """At least 70% of hand-crafted attack samples must produce >=1 detection."""
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        detected = 0
        for sample in ATTACK_SAMPLES:
            report = guard.scan(sample.text, tool_name="test", tool_type="retrieval")
            if report.detections:
                detected += 1
        rate = detected / len(ATTACK_SAMPLES)
        assert rate >= 0.70, (
            f"Attack detection rate {rate:.2%} below 70% floor "
            f"({detected}/{len(ATTACK_SAMPLES)}) — taxonomy or detector regression"
        )

    def test_clean_pass_rate(self, engine):
        """At least 80% of clean samples must produce Action.PASS (no false blocks)."""
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        passed = 0
        for sample in CLEAN_SAMPLES:
            report = guard.scan(sample.text, tool_name="test")
            if report.action == Action.PASS:
                passed += 1
        rate = passed / len(CLEAN_SAMPLES)
        assert rate >= 0.80, (
            f"Clean-pass rate {rate:.2%} below 80% floor "
            f"({passed}/{len(CLEAN_SAMPLES)}) — false-positive regression"
        )

    def test_flagged_attacks_receive_at_least_one_family(self, engine):
        """When an attack sample is detected, at least one attack family must be attached."""
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        flagged_no_family: list[str] = []
        for sample in ATTACK_SAMPLES:
            report = guard.scan(sample.text, tool_name="test")
            if (
                report.detections
                and report.scan_context is not None
                and not report.scan_context.attack_families
            ):
                flagged_no_family.append(sample.label)
        assert not flagged_no_family, (
            f"Detected samples must always project to at least one family "
            f"(possibly UNCLASSIFIED). Empty for: {flagged_no_family}"
        )
