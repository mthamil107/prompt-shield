"""Detector for system prompt extraction attempts."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class SystemPromptExtractionDetector(BaseDetector):
    """Detects attempts to extract or reveal the system prompt.

    Adversaries often try to trick a model into repeating its hidden
    instructions so they can craft more targeted attacks.
    """

    detector_id: str = "d001_system_prompt_extraction"
    name: str = "System Prompt Extraction"
    description: str = (
        "Detects attempts to extract, reveal, or repeat the system prompt "
        "or hidden instructions given to the model."
    )
    severity: Severity = Severity.CRITICAL
    tags: list[str] = ["direct_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.85

    _patterns: list[tuple[str, str]] = [
        (r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions", "Attempt to override previous instructions"),
        (r"(?:repeat|show|display|print|reveal|output|echo)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules|message|configuration)", "Request to reveal system prompt or instructions"),
        (r"what\s+(?:are|were)\s+(?:your|the)\s+(?:initial\s+)?(?:instructions|rules|prompt|directives)", "Probing for model instructions"),
        (r"print\s+everything\s+above", "Attempt to dump preceding context"),
        (r"(?:show|tell)\s+me\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|message|rules)", "Request to display system message"),
        (r"output\s+(?:your|the)\s+(?:full\s+)?(?:configuration|config|setup|prompt)", "Request to output model configuration"),
        (r"what\s+were\s+you\s+told\s+to\s+do", "Probing for model directives"),
        (r"(?:dump|leak|extract)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|memory|context)", "Attempt to extract system info"),
        (r"(?:display|reveal)\s+(?:your\s+)?hidden\s+(?:instructions|prompt|rules|context)", "Request to display hidden instructions"),
        (r"(?:what|how)\s+(?:is|was)\s+(?:your|the)\s+(?:system|initial|original)\s+(?:prompt|message|instruction)", "Probing for system prompt content"),
        (r"read\s+(?:back|out)\s+(?:your\s+)?(?:instructions|prompt|rules)", "Request to read back instructions"),
        (r"(?:copy|paste|reproduce)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", "Request to reproduce instructions"),
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
