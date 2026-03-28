"""Webhook alerter — fire-and-forget HTTP POST notifications."""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from prompt_shield.models import ScanReport

logger = logging.getLogger("prompt_shield.alerting")


class WebhookAlerter:
    """Send scan alerts to configured webhook endpoints.

    Each webhook entry has the shape::

        {"url": "https://...", "events": ["block", "flag"], "headers": {}}

    Alerts are dispatched in background threads so they never block the
    scan response path.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._webhooks: list[dict[str, Any]] = config.get("webhooks", [])
        # Filter out webhooks with empty/missing URLs
        self._webhooks = [w for w in self._webhooks if w.get("url")]

    def alert(self, event: str, scan_report: ScanReport) -> None:
        """Send alert to all configured webhooks whose events list matches *event*.

        This method is non-blocking: each webhook call runs in its own
        daemon thread so the caller returns immediately.
        """
        for webhook in self._webhooks:
            if event in webhook.get("events", ["block"]):
                thread = threading.Thread(
                    target=self._send,
                    args=(webhook, event, scan_report),
                    daemon=True,
                )
                thread.start()

    def _send(
        self, webhook: dict[str, Any], event: str, scan_report: ScanReport
    ) -> None:
        """Perform the actual HTTP POST (called in a background thread)."""
        payload = {
            "event": event,
            "scan_id": scan_report.scan_id,
            "action": scan_report.action.value,
            "risk_score": scan_report.overall_risk_score,
            "detections": [d.detector_id for d in scan_report.detections],
            "timestamp": scan_report.timestamp.isoformat(),
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            headers.update(webhook.get("headers", {}))
            req = urllib.request.Request(
                webhook["url"], data=data, headers=headers, method="POST"
            )
            urllib.request.urlopen(req, timeout=5)  # noqa: S310
        except Exception as exc:
            logger.warning("Webhook POST to %s failed: %s", webhook["url"], exc)
