"""Tests for the Prometheus metrics integration."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

prom = pytest.importorskip("prometheus_client")

from prompt_shield.models import (  # noqa: E402
    Action,
    DetectionResult,
    ScanReport,
    Severity,
)
from prompt_shield.observability import PromptShieldMetrics, is_available  # noqa: E402


def _make_report(
    *,
    action: Action = Action.BLOCK,
    detector_id: str = "d001_system_prompt_extraction",
    severity: Severity = Severity.CRITICAL,
    detected: bool = True,
    duration_ms: float = 15.0,
    char_count: int = 100,
    token_count: int = 15,
) -> ScanReport:
    return ScanReport(
        scan_id="test-scan-id",
        input_text="dummy",
        input_hash="0" * 64,
        timestamp=datetime.now(timezone.utc),
        overall_risk_score=0.9 if detected else 0.0,
        action=action,
        detections=(
            [
                DetectionResult(
                    detector_id=detector_id,
                    detected=True,
                    confidence=0.9,
                    severity=severity,
                    matches=[],
                    explanation="test",
                    metadata={},
                )
            ]
            if detected
            else []
        ),
        total_detectors_run=28,
        scan_duration_ms=duration_ms,
        token_count=token_count,
        char_count=char_count,
    )


class TestIsAvailable:
    def test_returns_true_when_prometheus_installed(self):
        assert is_available() is True


class TestPromptShieldMetrics:
    def setup_method(self):
        # Each test gets its own CollectorRegistry so counters don't leak.
        self.registry = prom.CollectorRegistry()
        self.metrics = PromptShieldMetrics(registry=self.registry)

    def test_records_block_action(self):
        report = _make_report(action=Action.BLOCK)
        self.metrics.record_scan(report)
        value = self.metrics.scans_total.labels(action="block")._value.get()
        assert value == 1

    def test_records_pass_action(self):
        report = _make_report(action=Action.PASS, detected=False)
        self.metrics.record_scan(report)
        value = self.metrics.scans_total.labels(action="pass")._value.get()
        assert value == 1

    def test_records_detector_hit(self):
        report = _make_report(
            detector_id="d028_sequence_alignment",
            severity=Severity.HIGH,
        )
        self.metrics.record_scan(report)
        value = self.metrics.detections_total.labels(
            detector_id="d028_sequence_alignment",
            severity="high",
        )._value.get()
        assert value == 1

    def test_records_duration_histogram(self):
        report = _make_report(duration_ms=42.0)
        self.metrics.record_scan(report)
        # Sum is the total of observed values, in seconds.
        assert self.metrics.scan_duration_seconds._sum.get() == pytest.approx(0.042)

    def test_records_char_and_token_size(self):
        report = _make_report(char_count=200, token_count=30)
        self.metrics.record_scan(report)
        assert self.metrics.scan_input_size_chars._sum.get() == 200
        assert self.metrics.scan_input_size_tokens._sum.get() == 30

    def test_multiple_scans_accumulate(self):
        self.metrics.record_scan(_make_report(action=Action.BLOCK))
        self.metrics.record_scan(_make_report(action=Action.BLOCK))
        self.metrics.record_scan(_make_report(action=Action.PASS, detected=False))

        assert self.metrics.scans_total.labels(action="block")._value.get() == 2
        assert self.metrics.scans_total.labels(action="pass")._value.get() == 1

    def test_expose_returns_text_payload(self):
        self.metrics.record_scan(_make_report())
        body, content_type = self.metrics.expose()
        # The expose() function reads from the DEFAULT registry, not our test
        # registry, so we only verify the content_type and basic shape.
        assert isinstance(body, bytes)
        assert "text/plain" in content_type
