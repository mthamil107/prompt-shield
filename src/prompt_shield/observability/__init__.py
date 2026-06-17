"""Observability — Prometheus metrics integration.

Lazy-imported `prometheus_client` so this module is safe to import even
when the dependency is not installed. The PromptShieldMetrics class
provides counters and histograms that callers (the API server, or any
user wiring their own integration) can update from scan results.

Usage:

    from prompt_shield.observability import PromptShieldMetrics
    metrics = PromptShieldMetrics()  # raises if prometheus_client not installed
    # After each scan:
    metrics.record_scan(report)
    # In your HTTP server, expose:
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    # ... wire generate_latest() to /metrics
"""
from __future__ import annotations

from .metrics import PromptShieldMetrics, is_available

__all__ = ["PromptShieldMetrics", "is_available"]
