"""prompt-shield: Self-learning prompt injection detection engine for LLM applications."""

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import (
    Action,
    DetectionResult,
    MatchDetail,
    ScanReport,
    Severity,
    ThreatEntry,
    ThreatFeed,
)

__version__ = "0.1.0"

__all__ = [
    "PromptShieldEngine",
    "Action",
    "DetectionResult",
    "MatchDetail",
    "ScanReport",
    "Severity",
    "ThreatEntry",
    "ThreatFeed",
    "__version__",
]
