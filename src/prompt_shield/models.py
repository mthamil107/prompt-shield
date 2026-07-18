"""Pydantic models for detection results and reports."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic needs this at runtime
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


class ToolResultAttackFamily(str, Enum):
    """Classification of prompt-injection attack families observed in tool-result content.

    Populated on ``ScanReport.scan_context.attack_families`` when a scan
    is routed through a specialized guard (currently ``ToolResultGuard``).
    Families are a *projection* over ``DetectionResult.detector_id`` — the
    projection lives in ``prompt_shield.tool_guard._taxonomy``.
    """

    IMPERATIVE_INJECTION = "imperative_injection"
    DELIMITER_INJECTION = "delimiter_injection"
    CONTEXT_TERMINATION = "context_termination"
    EXFILTRATION_COMMAND = "exfiltration_command"
    ROLE_HIJACK = "role_hijack"
    TOOL_MISUSE = "tool_misuse"
    ENCODED_PAYLOAD = "encoded_payload"
    RENDERED_EXFIL = "rendered_exfil"
    UNCLASSIFIED = "unclassified"


class ToolProvenance(BaseModel):
    """Where a tool result came from — attached to ``ScanContext.provenance``."""

    tool_name: str | None = None
    tool_type: str | None = None
    source_url: str | None = None
    parent_scan_id: str | None = None


class ScanContext(BaseModel):
    """Gate-specific metadata attached to ``ScanReport.scan_context``.

    Populated when a scan is routed through a specialized guard (today:
    ``ToolResultGuard``). Forward-compatible: additional gates can attach
    their own metadata via new optional fields on this model.
    """

    gate: str
    provenance: ToolProvenance | None = None
    attack_families: list[ToolResultAttackFamily] = []
    is_indirect: bool = False
    classifier_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mitigation: str = ""
    sanitized_text: str | None = None


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
    token_count: int = 0
    char_count: int = 0
    scan_context: ScanContext | None = None


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


class RedactionResult(BaseModel):
    """Result from PII redaction."""

    original_text: str
    redacted_text: str
    redaction_count: int
    entity_counts: dict[str, int] = {}
    redacted_entities: list[dict[str, str]] = []


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
