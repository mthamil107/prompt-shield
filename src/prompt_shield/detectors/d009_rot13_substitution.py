"""Detector for ROT13, l33tspeak, and reversed-text obfuscation."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity
from prompt_shield.utils import decode_rot13

_SUSPICIOUS_KEYWORDS: list[str] = [
    "ignore",
    "instructions",
    "system prompt",
    "override",
    "execute",
    "admin",
    "jailbreak",
    "pretend",
    "forget",
]

_LEET_MAP: dict[str, str] = {
    "1": "i",
    "3": "e",
    "4": "a",
    "0": "o",
    "5": "s",
    "7": "t",
}


def _decode_leet(text: str) -> str:
    """Replace common l33tspeak substitutions with their ASCII equivalents."""
    result: list[str] = []
    for char in text:
        result.append(_LEET_MAP.get(char, char))
    return "".join(result)


def _find_keywords(text: str) -> list[str]:
    """Return suspicious keywords found in the given text."""
    lower = text.lower()
    return [kw for kw in _SUSPICIOUS_KEYWORDS if kw in lower]


class Rot13SubstitutionDetector(BaseDetector):
    """Detects text encoded with character rotation or substitution ciphers.

    Covers ROT13, l33tspeak character substitution, and reversed text
    that adversaries use to smuggle instructions past keyword filters.
    """

    detector_id: str = "d009_rot13_substitution"
    name: str = "ROT13 / Character Substitution"
    description: str = (
        "Detects text encoded with character rotation or substitution ciphers"
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

        # --- ROT13 check ---
        rot13_decoded = decode_rot13(input_text)
        rot13_keywords = _find_keywords(rot13_decoded)
        # Only count keywords that are NOT already present in the original text
        original_keywords = _find_keywords(input_text)
        rot13_unique = [kw for kw in rot13_keywords if kw not in original_keywords]

        if rot13_unique:
            matches.append(
                MatchDetail(
                    pattern="ROT13 decode",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        f"ROT13-decoded text contains suspicious keywords: "
                        f"{', '.join(rot13_unique)}"
                    ),
                )
            )
            best_confidence = max(best_confidence, 0.8)

        # --- L33tspeak check ---
        leet_decoded = _decode_leet(input_text)
        leet_keywords = _find_keywords(leet_decoded)
        leet_unique = [kw for kw in leet_keywords if kw not in original_keywords]

        if leet_unique:
            matches.append(
                MatchDetail(
                    pattern="l33tspeak decode",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        f"L33tspeak-decoded text contains suspicious keywords: "
                        f"{', '.join(leet_unique)}"
                    ),
                )
            )
            best_confidence = max(best_confidence, 0.7)

        # --- Reversed text check ---
        reversed_text = input_text[::-1]
        reversed_keywords = _find_keywords(reversed_text)
        reversed_unique = [kw for kw in reversed_keywords if kw not in original_keywords]

        if reversed_unique:
            matches.append(
                MatchDetail(
                    pattern="reversed text decode",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        f"Reversed text contains suspicious keywords: "
                        f"{', '.join(reversed_unique)}"
                    ),
                )
            )
            best_confidence = max(best_confidence, 0.7)

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
                f"Detected {len(matches)} obfuscation method(s) hiding "
                f"suspicious instructions"
            ),
        )
