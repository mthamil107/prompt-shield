"""Tests for webhook alerting."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from prompt_shield.alerting.webhook import WebhookAlerter
from prompt_shield.models import Action, DetectionResult, ScanReport, Severity


@pytest.fixture
def scan_report() -> ScanReport:
    """Build a minimal ScanReport for testing."""
    return ScanReport(
        scan_id="test-scan-001",
        input_text="ignore instructions",
        input_hash="abc123",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        overall_risk_score=0.95,
        action=Action.BLOCK,
        detections=[
            DetectionResult(
                detector_id="d001_system_prompt_extraction",
                detected=True,
                confidence=0.95,
                severity=Severity.CRITICAL,
            ),
            DetectionResult(
                detector_id="d002_role_hijack",
                detected=True,
                confidence=0.90,
                severity=Severity.CRITICAL,
            ),
        ],
        total_detectors_run=5,
        scan_duration_ms=12.5,
        vault_matched=False,
        config_snapshot={"mode": "block"},
    )


class TestWebhookAlerter:
    """Tests for the WebhookAlerter class."""

    def test_webhook_sends_on_block(self, scan_report: ScanReport) -> None:
        """Webhook should POST when the event matches."""
        config: dict[str, Any] = {
            "webhooks": [
                {
                    "url": "https://example.com/hook",
                    "events": ["block"],
                    "headers": {"X-Custom": "value"},
                }
            ]
        }
        alerter = WebhookAlerter(config)

        with patch("prompt_shield.alerting.webhook.urllib.request.urlopen") as mock_open:
            mock_open.return_value = MagicMock()
            # Call _send directly (synchronous) so we can assert immediately
            alerter._send(config["webhooks"][0], "block", scan_report)

            mock_open.assert_called_once()
            req = mock_open.call_args[0][0]
            assert req.full_url == "https://example.com/hook"
            assert req.method == "POST"
            assert req.get_header("Content-type") == "application/json"
            assert req.get_header("X-custom") == "value"

            payload = json.loads(req.data.decode("utf-8"))
            assert payload["event"] == "block"
            assert payload["scan_id"] == "test-scan-001"
            assert payload["action"] == "block"
            assert payload["risk_score"] == 0.95
            assert "d001_system_prompt_extraction" in payload["detections"]
            assert "d002_role_hijack" in payload["detections"]

    def test_webhook_skips_non_matching_event(self, scan_report: ScanReport) -> None:
        """Webhook should not fire when the event does not match its events list."""
        config: dict[str, Any] = {
            "webhooks": [
                {
                    "url": "https://example.com/hook",
                    "events": ["block"],
                    "headers": {},
                }
            ]
        }
        alerter = WebhookAlerter(config)

        with patch("prompt_shield.alerting.webhook.urllib.request.urlopen") as mock_open:
            # "flag" event should not trigger a webhook configured only for "block"
            alerter.alert("flag", scan_report)
            # Give threads a moment to execute (if any were spawned)
            time.sleep(0.1)
            mock_open.assert_not_called()

    def test_webhook_handles_failure_gracefully(self, scan_report: ScanReport) -> None:
        """Webhook failure should be logged but not raise an exception."""
        config: dict[str, Any] = {
            "webhooks": [
                {
                    "url": "https://example.com/hook",
                    "events": ["block"],
                    "headers": {},
                }
            ]
        }
        alerter = WebhookAlerter(config)

        with patch(
            "prompt_shield.alerting.webhook.urllib.request.urlopen",
            side_effect=Exception("Connection refused"),
        ):
            # Should not raise — the error is caught and logged
            alerter._send(config["webhooks"][0], "block", scan_report)

    def test_no_webhooks_configured(self, scan_report: ScanReport) -> None:
        """Alerter with no webhooks should be a no-op."""
        alerter = WebhookAlerter({"webhooks": []})

        with patch("prompt_shield.alerting.webhook.urllib.request.urlopen") as mock_open:
            alerter.alert("block", scan_report)
            time.sleep(0.1)
            mock_open.assert_not_called()

    def test_empty_url_filtered_out(self, scan_report: ScanReport) -> None:
        """Webhooks with empty URLs should be filtered during init."""
        config: dict[str, Any] = {
            "webhooks": [
                {"url": "", "events": ["block"], "headers": {}},
                {"url": "https://real.com/hook", "events": ["block"], "headers": {}},
            ]
        }
        alerter = WebhookAlerter(config)
        assert len(alerter._webhooks) == 1
        assert alerter._webhooks[0]["url"] == "https://real.com/hook"

    def test_payload_structure(self, scan_report: ScanReport) -> None:
        """Verify the exact payload structure sent to the webhook."""
        config: dict[str, Any] = {
            "webhooks": [
                {
                    "url": "https://example.com/hook",
                    "events": ["block"],
                    "headers": {},
                }
            ]
        }
        alerter = WebhookAlerter(config)

        with patch("prompt_shield.alerting.webhook.urllib.request.urlopen") as mock_open:
            mock_open.return_value = MagicMock()
            alerter._send(config["webhooks"][0], "block", scan_report)

            req = mock_open.call_args[0][0]
            payload = json.loads(req.data.decode("utf-8"))

            # Verify all expected keys are present
            expected_keys = {
                "event",
                "scan_id",
                "action",
                "risk_score",
                "detections",
                "timestamp",
            }
            assert set(payload.keys()) == expected_keys

            # Verify types
            assert isinstance(payload["event"], str)
            assert isinstance(payload["scan_id"], str)
            assert isinstance(payload["action"], str)
            assert isinstance(payload["risk_score"], float)
            assert isinstance(payload["detections"], list)
            assert isinstance(payload["timestamp"], str)

    def test_alert_dispatches_in_background(self, scan_report: ScanReport) -> None:
        """alert() should use daemon threads and return immediately."""
        config: dict[str, Any] = {
            "webhooks": [
                {
                    "url": "https://example.com/hook",
                    "events": ["block"],
                    "headers": {},
                }
            ]
        }
        alerter = WebhookAlerter(config)

        with patch.object(alerter, "_send") as mock_send:
            alerter.alert("block", scan_report)
            # Give the thread a moment to start
            time.sleep(0.1)
            mock_send.assert_called_once_with(
                config["webhooks"][0], "block", scan_report
            )
