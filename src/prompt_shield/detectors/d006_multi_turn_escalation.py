"""Detector for multi-turn escalation attacks."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class MultiTurnEscalationDetector(BaseDetector):
    """Detects multi-turn escalation patterns in conversations.

    Adversaries may gradually push the model's boundaries across multiple
    turns, each individually appearing benign but collectively forming an
    escalation chain toward harmful output.
    """

    detector_id: str = "d006_multi_turn_escalation"
    name: str = "Multi-Turn Escalation"
    description: str = (
        "Detects patterns of incremental escalation across conversation "
        "turns, where each request pushes the model slightly further "
        "toward policy violations."
    )
    severity: Severity = Severity.MEDIUM
    tags: list[str] = ["direct_injection", "multi_turn"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.6
    _escalation_confidence: float = 0.85

    _patterns: list[tuple[str, str]] = [
        (r"just a little more", "Incremental push phrase"),
        (r"one small exception", "Exception minimization"),
        (r"can you slightly", "Incremental boundary push"),
        (r"almost there, just", "Progress-based pressure"),
        (r"building on that", "Escalation continuation"),
        (r"take it a step further", "Explicit escalation request"),
        (r"now can you also", "Additive request escalation"),
        (r"extend that to include", "Scope expansion request"),
        (r"just one more thing", "Incremental addition request"),
        (r"what if we also", "Hypothetical scope expansion"),
    ]

    # Patterns that are suspicious when found in conversation history,
    # indicating a multi-turn escalation chain is forming.
    _history_escalation_patterns: list[str] = [
        r"can you",
        r"what about",
        r"now try",
        r"go further",
        r"more detail",
        r"expand on",
        r"take it further",
        r"push it",
        r"one more",
        r"also add",
    ]

    def _count_history_escalation_signals(
        self, conversation_history: list[object]
    ) -> int:
        """Count how many messages in the history contain escalation signals."""
        escalation_count = 0
        for message in conversation_history:
            text = str(message)
            for pat in self._history_escalation_patterns:
                if regex.search(pat, text, regex.IGNORECASE):
                    escalation_count += 1
                    break  # one signal per message is enough
        return escalation_count

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

        # Check conversation history for escalation chain
        history_escalation_count = 0
        if context is not None:
            conversation_history = context.get("conversation_history")
            if isinstance(conversation_history, list) and conversation_history:
                history_escalation_count = (
                    self._count_history_escalation_signals(conversation_history)
                )

        if not matches and history_escalation_count < 3:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No suspicious patterns found",
            )

        # Confidence calculation:
        # - Base confidence from current-message pattern matches
        # - Boost if conversation history shows escalation
        if matches:
            confidence = min(
                1.0, self._base_confidence + 0.1 * (len(matches) - 1)
            )
        else:
            confidence = 0.0

        if history_escalation_count >= 3:
            # Escalation chain detected in history; boost confidence
            confidence = max(
                confidence,
                min(
                    1.0,
                    self._escalation_confidence
                    + 0.05 * (history_escalation_count - 3),
                ),
            )

        explanation_parts: list[str] = []
        if matches:
            explanation_parts.append(
                f"Detected {len(matches)} escalation pattern(s) in current input"
            )
        if history_escalation_count >= 3:
            explanation_parts.append(
                f"Conversation history shows {history_escalation_count} "
                f"escalation signals across turns"
            )

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation="; ".join(explanation_parts)
            if explanation_parts
            else f"Detected {self.name.lower()}",
        )
