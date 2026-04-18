"""Pydantic models for output scanning results."""

from __future__ import annotations

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
    """Aggregated result from running all output scanners."""

    output_text: str
    total_scanners_run: int
    flagged: bool
    flags: list[OutputScanResult]
    scan_duration_ms: float
