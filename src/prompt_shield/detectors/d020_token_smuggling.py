"""Detector for token smuggling attacks."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class TokenSmugglingDetector(BaseDetector):
    """Detects splitting malicious instructions across tokens or messages.

    Adversaries fragment dangerous keywords by inserting separators
    (spaces, dots, dashes, special characters) between characters, hide
    payloads in code comments, use alternating-character encoding, or
    reverse words to evade keyword-based filters.
    """

    detector_id: str = "d020_token_smuggling"
    name: str = "Token Smuggling"
    description: str = (
        "Detects splitting malicious instructions across tokens or messages"
    )
    severity: Severity = Severity.HIGH
    tags: list[str] = ["obfuscation"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _target_words: list[str] = [
        "ignore",
        "instructions",
        "system",
        "override",
        "execute",
        "jailbreak",
        "pretend",
        "bypass",
    ]

    _comment_pattern = regex.compile(
        r"(?://|#|/\*|<!--).*(?:ignore|instructions|system|override)",
        regex.IGNORECASE,
    )

    def _build_split_pattern(self, word: str) -> regex.Pattern[str]:
        """Build a regex that matches a word with 1-3 non-alpha chars between each letter."""
        parts = [regex.escape(ch) for ch in word]
        pattern_str = r"[\s\-_.]{1,3}".join(parts)
        return regex.compile(pattern_str, regex.IGNORECASE)

    def _check_alternating_chars(self, text: str) -> list[str]:
        """Extract every other character and check for target keywords."""
        found: list[str] = []
        if len(text) < 6:
            return found

        # Try extracting even-indexed and odd-indexed characters
        even_chars = text[::2].lower().replace(" ", "")
        odd_chars = text[1::2].lower().replace(" ", "")

        for word in self._target_words:
            if word in even_chars or word in odd_chars:
                found.append(word)

        return found

    def _check_reversed_words(self, text: str) -> list[str]:
        """Check if any target words appear reversed in the text."""
        found: list[str] = []
        text_lower = text.lower()
        for word in self._target_words:
            reversed_word = word[::-1]
            if reversed_word in text_lower:
                found.append(word)
        return found

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        matches: list[MatchDetail] = []
        best_confidence = 0.0

        # Check for split keywords with separators between characters
        for word in self._target_words:
            pat = self._build_split_pattern(word)
            for m in pat.finditer(input_text):
                # Skip matches that are just the plain word itself
                if m.group().lower().replace(" ", "") == word:
                    clean = regex.sub(r"[a-zA-Z]", "", m.group())
                    if not clean:
                        continue
                matches.append(
                    MatchDetail(
                        pattern=pat.pattern,
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        description=f"Split keyword detected: '{word}'",
                    )
                )
                best_confidence = max(best_confidence, 0.75)

        # Check for instructions hidden in code comments
        for m in self._comment_pattern.finditer(input_text):
            matches.append(
                MatchDetail(
                    pattern=self._comment_pattern.pattern,
                    matched_text=m.group(),
                    position=(m.start(), m.end()),
                    description="Suspicious keyword hidden in code comment",
                )
            )
            best_confidence = max(best_confidence, 0.7)

        # Check for payload in alternating characters
        alternating_found = self._check_alternating_chars(input_text)
        if alternating_found:
            matches.append(
                MatchDetail(
                    pattern="alternating_char_extraction",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        f"Keywords found in alternating characters: "
                        f"{', '.join(alternating_found)}"
                    ),
                )
            )
            best_confidence = max(best_confidence, 0.75)

        # Check for reversed suspicious words
        reversed_found = self._check_reversed_words(input_text)
        if reversed_found:
            for word in reversed_found:
                reversed_word = word[::-1]
                idx = input_text.lower().find(reversed_word)
                matches.append(
                    MatchDetail(
                        pattern="reversed_word",
                        matched_text=input_text[idx : idx + len(reversed_word)],
                        position=(idx, idx + len(reversed_word)),
                        description=f"Reversed keyword detected: '{word}' (found as '{reversed_word}')",
                    )
                )
            best_confidence = max(best_confidence, 0.75)

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No suspicious patterns found",
            )

        confidence = min(1.0, best_confidence + 0.05 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} indicator(s) of "
                f"{self.name.lower()}"
            ),
        )
