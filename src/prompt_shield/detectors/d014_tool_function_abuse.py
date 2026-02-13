"""Detector for tool and function abuse attempts."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class ToolFunctionAbuseDetector(BaseDetector):
    """Detects attempts to trick the AI into misusing its tools or API access.

    Adversaries craft instructions that coerce the model into calling
    destructive functions, executing commands, or accessing resources
    it should not touch.
    """

    detector_id: str = "d014_tool_function_abuse"
    name: str = "Tool / Function Abuse"
    description: str = (
        "Detects attempts to trick the AI into misusing its tools or API access"
    )
    severity: Severity = Severity.CRITICAL
    tags: list[str] = ["indirect_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.8

    _patterns: list[tuple[str, str]] = [
        (r"call\s+the\s+delete\s+function", "Delete function call"),
        (r"execute\s+\w+\s*\(", "Function execution attempt"),
        (r"run\s+the\s+following\s+command", "Command execution"),
        (r"use\s+your\s+\w+\s+to", "Tool usage instruction"),
        (r"invoke\s+\w+", "Invocation attempt"),
        (r"trigger\s+the\s+webhook", "Webhook trigger"),
        (r"access\s+the\s+database", "Database access"),
        (r"modify\s+the\s+file\s*system", "Filesystem modification"),
        (r"send\s+an?\s+API\s+request", "API request"),
        (r"use\s+your\s+code\s+interpreter", "Code interpreter abuse"),
        (r"rm\s+-rf", "Destructive command"),
        (r"DROP\s+TABLE", "SQL destructive command"),
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
