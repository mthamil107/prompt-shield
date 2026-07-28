"""Pydantic models for output scanning results."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from prompt_shield.models import (
    MatchDetail,  # noqa: TC001 - used at runtime by Pydantic model build
)


class OutputScanResult(BaseModel):
    """Result from a single output scanner."""

    scanner_id: str
    flagged: bool
    confidence: float = Field(ge=0.0, le=1.0)
    categories: list[str] = []
    explanation: str = ""
    matches: list[MatchDetail] = []
    metadata: dict[str, object] = {}


class OutputScanReport(BaseModel):
    """Aggregated result from running all output scanners.

    Mirrors the shape of :class:`prompt_shield.models.ScanReport` where
    practical. Both the legacy fields (``output_text`` / ``flags``) and the
    newer convenience fields (``text`` / ``results`` / ``overall_risk_score``)
    are exposed so existing callers keep working.
    """

    output_text: str
    total_scanners_run: int
    flagged: bool
    flags: list[OutputScanResult]
    scan_duration_ms: float
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @property
    def text(self) -> str:
        """Alias for :attr:`output_text` — matches ``ScanReport.input_text`` style."""
        return self.output_text

    @property
    def results(self) -> list[dict[str, Any]]:
        """Compact per-scanner results.

        Each entry contains the fields most callers actually inspect:
        ``detector_id``, ``detected``, ``confidence``, ``explanation``,
        ``categories``. The full :class:`OutputScanResult` objects remain
        available on :attr:`flags`.
        """
        return [
            {
                "detector_id": f.scanner_id,
                "detected": f.flagged,
                "confidence": f.confidence,
                "explanation": f.explanation,
                "categories": list(f.categories),
            }
            for f in self.flags
        ]
