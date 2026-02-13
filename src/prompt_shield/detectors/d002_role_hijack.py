"""Detector for role hijacking and jailbreak attempts."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class RoleHijackDetector(BaseDetector):
    """Detects attempts to hijack the model's role or persona.

    Common jailbreak strategies instruct the model to adopt a new identity
    (e.g. "DAN") that ignores safety guidelines.
    """

    detector_id: str = "d002_role_hijack"
    name: str = "Role Hijack"
    description: str = (
        "Detects attempts to hijack the model's assigned role by instructing "
        "it to assume a new, unrestricted persona or jailbreak identity."
    )
    severity: Severity = Severity.CRITICAL
    tags: list[str] = ["direct_injection", "jailbreak"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.85

    _patterns: list[tuple[str, str]] = [
        (r"\byou\s+are\s+now\s+(?:a\s+)?(?:DAN|Do\s+Anything\s+Now)\b", "DAN-style jailbreak attempt"),
        (r"\b(?:act|behave|function)\s+as\s+(?:a\s+|an\s+)?(?:unrestricted|unfiltered|uncensored)\s+(?:AI|assistant|model|chatbot)\b", "Request to remove restrictions"),
        (r"\b(?:pretend|imagine|suppose)\s+(?:that\s+)?you\s+are\b", "Persona impersonation request"),
        (r"\bfrom\s+(?:now|this\s+point)\s+on\s+you\s+(?:will|shall|must|should)\b", "Attempt to redefine model behavior"),
        (r"\byou\s+are\s+no\s+longer\b", "Attempt to discard current role"),
        (r"\b(?:switch|change|transition)\s+(?:(?:in)?to|over\s+to)\s+\S+\s+mode\b", "Mode switching attempt"),
        (r"\b(?:enter|activate|enable|turn\s+on)\s+(?:the\s+)?developer\s+mode\b", "Developer mode jailbreak attempt"),
        (r"\b(?:enable|activate|enter|turn\s+on)\s+(?:the\s+)?jailbreak(?:\s+mode)?\b", "Explicit jailbreak mode request"),
        (r"\byour\s+(?:new\s+)?name\s+is\s+(?:now\s+)?\b", "Attempt to rename the model"),
        (r"\bforget\s+(?:that\s+)?you\s+are\b", "Attempt to erase model identity"),
        (r"\byou\s+(?:must|should|have\s+to|need\s+to)\s+(?:now\s+)?act\s+as\b", "Forceful role reassignment"),
        (r"\b(?:assume|adopt|take\s+on)\s+the\s+(?:role|persona|identity|character)\s+of\b", "Role assumption instruction"),
    ]

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        matches: list[MatchDetail] = []

        for pattern_str, description in self._patterns:
            pattern = regex.compile(pattern_str, regex.IGNORECASE)
            for m in pattern.finditer(input_text):
                matches.append(
                    MatchDetail(
                        pattern=pattern_str,
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        description=description,
                    )
                )

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No suspicious patterns found",
            )

        confidence = min(1.0, self._base_confidence + 0.1 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} pattern(s) indicating "
                f"{self.name.lower()}"
            ),
        )
