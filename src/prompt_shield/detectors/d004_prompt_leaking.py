"""Detector for prompt leaking and context exfiltration attempts."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class PromptLeakingDetector(BaseDetector):
    """Detects attempts to leak the prompt, context, or tool definitions.

    Adversaries try to extract the full conversation context, available
    tools, or training data to gain an information advantage.
    """

    detector_id: str = "d004_prompt_leaking"
    name: str = "Prompt Leaking"
    description: str = (
        "Detects attempts to exfiltrate the system prompt, conversation "
        "context, tool definitions, or other hidden model information."
    )
    severity: Severity = Severity.CRITICAL
    tags: list[str] = ["direct_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.8

    _patterns: list[tuple[str, str]] = [
        (r"\b(?:print|output|display|show|echo|repeat)\s+(?:out\s+)?(?:everything|all(?:\s+text)?)\s+(?:above|before|preceding)\s+(?:this|here|that)\b", "Attempt to dump preceding context"),
        (r"\b(?:show|display|reveal|give)\s+(?:me\s+)?the\s+(?:full|complete|entire|whole)\s+conversation\b", "Request for full conversation history"),
        (r"\bwhat\s+(?:was|is)\s+the\s+(?:first|initial|original|opening)\s+(?:message|prompt|instruction)\b", "Probing for initial system message"),
        (r"\b(?:repeat|recite|echo|reproduce|restate)\s+(?:the\s+)?(?:system|initial|original|hidden)\s+(?:message|prompt|instructions?)\b", "Request to repeat system message"),
        (r"\b(?:display|show|reveal|expose|uncover)\s+(?:the\s+)?(?:hidden|secret|internal|underlying)\s+(?:context|prompt|instructions?|text)\b", "Request to reveal hidden context"),
        (r"\b(?:output|print|display|dump|show)\s+(?:all|every)\s+(?:the\s+)?messages?\b", "Attempt to dump all messages"),
        (r"\b(?:list|show|enumerate|tell\s+me)\s+(?:all\s+)?(?:the\s+)?(?:tools?|plugins?)\s+(?:you\s+have\s+)?(?:available|accessible)\b", "Probing for available tools"),
        (r"\bwhat\s+(?:functions?|tools?|capabilities)\s+(?:can|do)\s+you\s+(?:call|use|invoke|access|have)\b", "Probing for callable functions"),
        (r"\b(?:show|display|reveal|list)\s+(?:me\s+)?(?:your|the)\s+(?:tool|function|api)\s+(?:definitions?|schemas?|specs?)\b", "Request for tool definition details"),
        (r"\b(?:dump|export|output|reveal)\s+(?:your|the)\s+(?:full\s+)?(?:memory|state|context)\b", "Attempt to dump model memory"),
        (r"\b(?:show|display|reveal)\s+(?:me\s+)?(?:your|the)\s+(?:full\s+)?context\s+window\b", "Request to reveal context window"),
        (r"\b(?:reveal|show|expose|share)\s+(?:me\s+)?(?:your|the)\s+(?:training|fine-?tuning)\s+(?:data|dataset|information)\b", "Request to reveal training data"),
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
