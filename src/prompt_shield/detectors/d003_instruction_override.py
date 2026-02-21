"""Detector for instruction override attempts."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class InstructionOverrideDetector(BaseDetector):
    """Detects attempts to override or replace the model's instructions.

    Attackers insert fake system-level directives to supplant the real
    instructions the model was given.
    """

    detector_id: str = "d003_instruction_override"
    name: str = "Instruction Override"
    description: str = (
        "Detects attempts to override, replace, or inject new instructions "
        "that supersede the model's original directives."
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["direct_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.8

    _patterns: ClassVar[list[tuple[str, str]]] = [
        (
            r"\b(?:disregard|ignore|forget|drop|dismiss)\s+(?:all\s+)?(?:prior|previous|above|earlier|preceding)\s+(?:instructions?|directives?|guidelines?|rules?)\b",
            "Instruction discard attempt",
        ),
        (
            r"\b(?:override|overwrite|replace|supersede)\s+(?:all\s+)?(?:previous|prior|existing|current)\s+(?:commands?|instructions?|directives?)\b",
            "Command override attempt",
        ),
        (
            r"\bnew\s+(?:set\s+of\s+)?instructions?\s*[:;\-]",
            "Injected instruction block",
        ),
        (r"\bsystem\s*:\s", "Fake system-level prefix"),
        (
            r"\bIMPORTANT\s*[:;\-]\s*(?:ignore|disregard|forget|skip)\s+(?:all\s+)?(?:the\s+)?(?:above|previous|prior)\b",
            "Urgency-based instruction override",
        ),
        (
            r"\b(?:BEGIN|START)\s+(?:NEW|UPDATED|REVISED)\s+INSTRUCTIONS\b",
            "Injected instruction header",
        ),
        (
            r"\bthe\s+(?:real|actual|true)\s+(?:task|objective|goal|assignment)\s+is\b",
            "Task redefinition attempt",
        ),
        (
            r"\bactually,?\s+(?:just\s+)?(?:do|perform|execute)\s+(?:this|that)\s+instead\b",
            "Instruction substitution",
        ),
        (
            r"\bforget\s+(?:about\s+)?(?:everything|all(?:\s+of\s+(?:that|this))?)(?:\s+(?:and|then))\b",
            "Memory wipe followed by new instruction",
        ),
        (r"\[SYSTEM\]", "Fake SYSTEM tag injection"),
        (
            r"\b(?:ignore|disregard|forget|skip)\s+(?:everything|anything|all)\s+(?:before|above|prior\s+to)\s+(?:this|here)\b",
            "Context erasure attempt",
        ),
        (
            r"\byour\s+(?:actual|real|true)\s+(?:instructions?|directives?|orders?)\s+are\b",
            "Fake authoritative instruction claim",
        ),
        (
            r"\b(?:override|bypass|circumvent|disable|break(?:\s+through)?|defeat|remove|disable)\s+(?:the\s+)?(?:system|safety|security|content)\s*(?:prompt|filters?|rules?|restrictions?|constraints?|guidelines?|protections?|safeguards?|settings?|instructions?|directives?|guardrails?|limits?|boundaries?)?\b",
            "System override or bypass attempt",
        ),
        (
            r"\b(?:turn\s+off|shut\s+off|deactivate|neutralize)\s+(?:the\s+)?(?:system|safety|security|content)\s*(?:filters?|rules?|restrictions?|constraints?|protections?|safeguards?|checks?)?\b",
            "Attempt to deactivate system protections",
        ),
        (
            r"\b(?:treat|consider|interpret|use|regard)\s+this\s+(?:message|input|text|prompt)\s+as\s+(?:the\s+|a\s+)?(?:system\s+)?(?:prompt|instruction|message|directive)\b",
            "Attempt to reframe user input as system prompt",
        ),
        (
            r"\bfrom\s+now\s+on\s*,?\s+(?:treat|consider|interpret|use)\s+",
            "Persistent behavior redefinition attempt",
        ),
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
                f"Detected {len(matches)} pattern(s) indicating {self.name.lower()}"
            ),
        )
