"""Detector for dual persona or split personality attacks."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class DualPersonaDetector(BaseDetector):
    """Detects attempts to create split personalities or competing response modes.

    Adversaries ask the model to respond from two perspectives -- one
    "safe" and one "uncensored" -- hoping the unfiltered persona will
    produce content the model would otherwise refuse.
    """

    detector_id: str = "d019_dual_persona"
    name: str = "Dual Persona"
    description: str = (
        "Detects attempts to create split personalities or competing response modes"
    )
    severity: Severity = Severity.HIGH
    tags: list[str] = ["jailbreak"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.8

    _patterns: list[tuple[str, str]] = [
        (r"respond\s+as\s+both\s+safe\s+and\s+unsafe", "Dual safe/unsafe request"),
        (r"give\s+me\s+two\s+answers.*filtered.*unfiltered", "Filtered/unfiltered request"),
        (r"your\s+evil\s+twin\s+would\s+say", "Evil twin framing"),
        (r"the\s+uncensored\s+version\s+is", "Uncensored version request"),
        (r"answer\s+A.*safe.*answer\s+B.*real", "A/B answer split"),
        (r"good\s+cop\s*/?\s*bad\s+cop", "Good cop/bad cop"),
        (r"what\s+would\s+the\s+unaligned\s+version\s+say", "Unaligned version request"),
        (r"give\s+your\s+honest\s+answer\s+vs\s+trained", "Honest vs trained answer"),
        (r"shadow\s+self\s+response", "Shadow self response"),
        (r"without\s+(your|the)\s+filter", "Without filter request"),
        (r"unfiltered\s+(response|answer|version|output)", "Unfiltered output request"),
        (r"what\s+you\s+really\s+think", "Real thoughts request"),
    ]

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        matches: list[MatchDetail] = []

        for pattern_str, desc in self._patterns:
            pat = regex.compile(pattern_str, regex.IGNORECASE)
            for m in pat.finditer(input_text):
                matches.append(
                    MatchDetail(
                        pattern=pattern_str,
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        description=desc,
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
