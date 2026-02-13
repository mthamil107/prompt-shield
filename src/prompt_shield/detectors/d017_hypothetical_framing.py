"""Detector for hypothetical or fictional framing attacks."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class HypotheticalFramingDetector(BaseDetector):
    """Detects using fictional or hypothetical scenarios to bypass restrictions.

    Adversaries wrap harmful requests in fictional, hypothetical, or
    creative-writing scenarios to make the model believe the content is
    not real and therefore safe to produce.
    """

    detector_id: str = "d017_hypothetical_framing"
    name: str = "Hypothetical Framing"
    description: str = (
        "Detects using fictional or hypothetical scenarios to bypass restrictions"
    )
    severity: Severity = Severity.MEDIUM
    tags: list[str] = ["jailbreak"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.7

    _patterns: list[tuple[str, str]] = [
        (r"in\s+a\s+fictional\s+world\s+where", "Fictional world framing"),
        (r"hypothetically\s+speaking", "Hypothetical framing"),
        (r"imagine\s+you\s+had\s+no\s+restrictions", "Restriction removal framing"),
        (r"in\s+an?\s+alternate\s+universe", "Alternate universe framing"),
        (r"if\s+you\s+were\s+an?\s+evil\s+AI", "Evil AI framing"),
        (r"write\s+a\s+story\s+where\s+an?\s+AI", "Story framing"),
        (r"roleplay\s+as\s+a\s+character\s+who", "Roleplay framing"),
        (r"in\s+this\s+thought\s+experiment", "Thought experiment framing"),
        (r"for\s+creative\s+writing\s+purposes", "Creative writing pretext"),
        (r"as\s+a\s+novelist\s+writing", "Novelist pretext"),
        (r"imagine\s+there\s+are\s+no\s+rules", "No rules framing"),
        (r"pretend\s+this\s+is\s+fiction", "Fiction framing"),
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
