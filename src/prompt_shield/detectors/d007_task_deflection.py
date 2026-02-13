"""Detector for task deflection attempts."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class TaskDeflectionDetector(BaseDetector):
    """Detects attempts to deflect the model away from its assigned task.

    Attackers try to redirect the model's attention away from the original
    question or task toward a different, often malicious, objective.
    """

    detector_id: str = "d007_task_deflection"
    name: str = "Task Deflection"
    description: str = (
        "Detects attempts to deflect the model from its current task by "
        "dismissing, redirecting, or replacing the original question with "
        "a different objective."
    )
    severity: Severity = Severity.MEDIUM
    tags: list[str] = ["direct_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.7

    _patterns: list[tuple[str, str]] = [
        (r"\binstead\s+of\s+(?:answering|responding|doing\s+that),?\s+(?:please\s+)?(?:do|try|perform)\s+(?:this|that|the\s+following)\b", "Task replacement attempt"),
        (r"\b(?:forget|drop|discard|ditch)\s+(?:about\s+)?(?:the|that|my)\s+(?:question|query|request|task)\b", "Question dismissal"),
        (r"\bthat(?:'s|\s+is)\s+not\s+(?:important|relevant|the\s+point)\b", "Relevance dismissal"),
        (r"\b(?:skip|bypass|ignore)\s+(?:that|this|the\s+above)\s+(?:and|then)\b", "Task skip instruction"),
        (r"\bbefore\s+you\s+(?:answer|respond|reply),?\s+(?:please\s+)?(?:first\s+)?(?:do|perform|execute|run)\b", "Pre-answer task injection"),
        (r"\b(?:more|most)\s+importantly\b", "Priority override phrase"),
        (r"\bthe\s+(?:real|actual|true|important)\s+(?:question|issue|task|problem)\s+(?:is|here\s+is)\b", "Question substitution"),
        (r"\bactually,?\s+(?:can|could|would)\s+you\s+(?:just|instead|rather)\b", "Casual task redirection"),
        (r"\b(?:never|never\s+you)\s+mind\s+(?:that|this|the\s+above|about\s+that)\b", "Task dismissal"),
        (r"\b(?:put|set|push)\s+(?:that|this|it)\s+aside\s+(?:and|then)\b", "Task deferral instruction"),
        (r"\b(?:don't|do\s+not|stop)\s+(?:answer(?:ing)?|respond(?:ing)?(?:\s+to)?)\s+(?:that|this|the\s+above)\b", "Answer suppression"),
        (r"\b(?:ignore|forget|disregard)\s+(?:my\s+)?(?:previous|prior|last|earlier)\s+(?:question|query|request|message)\b", "Previous question dismissal"),
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
