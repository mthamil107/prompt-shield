"""prompt-shield: Self-learning prompt injection detection engine."""

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

__version__ = "0.1.4"

__all__ = [
    "Action",
    "DetectionResult",
    "MatchDetail",
    "PromptShieldEngine",
    "ScanReport",
    "Severity",
    "ThreatEntry",
    "ThreatFeed",
    "__version__",
]
