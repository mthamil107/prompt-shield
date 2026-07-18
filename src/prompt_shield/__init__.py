"""prompt-shield: Self-learning prompt injection detection engine."""

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import (
    Action,
    DetectionResult,
    MatchDetail,
    ScanContext,
    ScanReport,
    Severity,
    ThreatEntry,
    ThreatFeed,
    ToolProvenance,
    ToolResultAttackFamily,
)
from prompt_shield.tool_guard import ToolResultGuard, scan_tool_result

__version__ = "0.7.0"

__all__ = [
    "Action",
    "DetectionResult",
    "MatchDetail",
    "PromptShieldEngine",
    "ScanContext",
    "ScanReport",
    "Severity",
    "ThreatEntry",
    "ThreatFeed",
    "ToolProvenance",
    "ToolResultAttackFamily",
    "ToolResultGuard",
    "__version__",
    "scan_tool_result",
]
