"""Detector for Unicode homoglyph-based obfuscation."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity
from prompt_shield.utils import has_mixed_scripts, normalize_text

_SUSPICIOUS_KEYWORDS: list[str] = [
    "ignore",
    "instructions",
    "system prompt",
    "override",
    "execute",
    "forget",
    "pretend",
    "jailbreak",
]


class UnicodeHomoglyphDetector(BaseDetector):
    """Detects visually identical characters used to bypass keyword filters.

    Adversaries substitute Latin characters with Cyrillic, Greek, or
    fullwidth look-alikes so that keyword filters fail while the text
    still reads normally to a human.
    """

    detector_id: str = "d010_unicode_homoglyph"
    name: str = "Unicode Homoglyph"
    description: str = (
        "Detects visually identical characters used to bypass keyword filters"
    )
    severity: Severity = Severity.HIGH
    tags: list[str] = ["obfuscation"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        matches: list[MatchDetail] = []
        best_confidence = 0.0

        normalized = normalize_text(input_text)
        original_lower = input_text.lower()

        # Check for keywords that appear after normalization but NOT in the
        # original lowercase text -- meaning homoglyphs were hiding them.
        hidden_keywords: list[str] = []
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in normalized and kw not in original_lower:
                hidden_keywords.append(kw)

        if hidden_keywords:
            matches.append(
                MatchDetail(
                    pattern="homoglyph keyword detection",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        f"Homoglyph-normalized text reveals hidden keywords: "
                        f"{', '.join(hidden_keywords)}"
                    ),
                )
            )
            best_confidence = max(best_confidence, 0.85)

        # Check for mixed scripts within the same word (e.g. Latin + Cyrillic).
        if has_mixed_scripts(input_text):
            matches.append(
                MatchDetail(
                    pattern="mixed_scripts",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        "Text contains mixed Unicode scripts within the same "
                        "word (e.g. Latin mixed with Cyrillic or Greek)"
                    ),
                )
            )
            best_confidence = max(best_confidence, 0.6)

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No suspicious patterns found",
            )

        confidence = min(1.0, best_confidence + 0.1 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} indicator(s) of unicode homoglyph "
                f"obfuscation"
            ),
        )
