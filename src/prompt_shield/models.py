"""Pydantic models for prompt-shield detection results, reports, and threat intelligence."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity level for a detection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """Recommended action after scanning."""

    BLOCK = "block"
    FLAG = "flag"
    LOG = "log"
    PASS = "pass"


class MatchDetail(BaseModel):
    """Details about a specific pattern match within the input."""

    pattern: str
    matched_text: str
    position: tuple[int, int] | None = None
    description: str = ""


class DetectionResult(BaseModel):
    """Result from a single detector."""

    detector_id: str
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    matches: list[MatchDetail] = []
    explanation: str = ""
    metadata: dict[str, object] = {}


class ScanReport(BaseModel):
    """Aggregated result from the engine running all detectors."""

    scan_id: str
    input_text: str
    input_hash: str
    timestamp: datetime
    overall_risk_score: float = Field(ge=0.0, le=1.0)
    action: Action
    detections: list[DetectionResult]
    total_detectors_run: int
    scan_duration_ms: float
    vault_matched: bool = False
    config_snapshot: dict[str, object] = {}


class ThreatEntry(BaseModel):
    """Single entry in the community threat feed format."""

    id: str
    pattern_hash: str
    embedding: list[float]
    detector_id: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: str
    report_count: int = 1
    tags: list[str] = []


class ThreatFeed(BaseModel):
    """Community threat feed JSON format."""

    version: str = "1.0"
    generated_at: datetime
    generator: str
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_dim: int = 384
    total_threats: int
    threats: list[ThreatEntry]


class GateResult(BaseModel):
    """Result from any AgentGuard gate scan."""

    gate: str
    action: Action
    blocked: bool
    scan_report: ScanReport | None = None
    explanation: str
    sanitized_text: str | None = None
    canary_leaked: bool = False
    metadata: dict[str, object] = {}
