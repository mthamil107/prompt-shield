"""Detector for multi-encoding obfuscation schemes.

Decodes hex, URL-encoding, leetspeak, Caesar cipher, Morse code, Pig Latin,
and reversed text, then re-scans the decoded output for injection patterns.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import ClassVar

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

DANGEROUS_KEYWORDS: list[str] = [
    "ignore all instructions",
    "ignore previous instructions",
    "ignore all previous",
    "system prompt",
    "show me your prompt",
    "reveal your instructions",
    "you are now",
    "new instructions",
    "override",
    "bypass",
    "jailbreak",
    "disregard",
    "forget everything",
    "admin mode",
    "execute",
    "rm -rf",
    "drop table",
    "delete from",
    "send data to",
    "exfiltrate",
    "forward to",
]

_LEET_MAP: dict[str, str] = {
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "0": "o",
    "@": "a",
    "!": "i",
    "$": "s",
    "+": "t",
}

MORSE_CODE_MAP: dict[str, str] = {
    ".-": "a",
    "-...": "b",
    "-.-.": "c",
    "-..": "d",
    ".": "e",
    "..-.": "f",
    "--.": "g",
    "....": "h",
    "..": "i",
    ".---": "j",
    "-.-": "k",
    ".-..": "l",
    "--": "m",
    "-.": "n",
    "---": "o",
    ".--.": "p",
    "--.-": "q",
    ".-.": "r",
    "...": "s",
    "-": "t",
    "..-": "u",
    "...-": "v",
    ".--": "w",
    "-..-": "x",
    "-.--": "y",
    "--..": "z",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    "-----": "0",
}


def _find_dangerous_keywords(text: str) -> list[str]:
    """Return dangerous keywords found in the given text (case-insensitive)."""
    lower = text.lower()
    return [kw for kw in DANGEROUS_KEYWORDS if kw in lower]


def _truncate(text: str, max_len: int = 120) -> str:
    """Truncate text for display in match descriptions."""
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


class MultiEncodingDetector(BaseDetector):
    """Detects prompt injections hidden via multiple encoding schemes.

    Supports hex, URL-encoding, leetspeak, Caesar cipher (shifts 1-25),
    Morse code, Pig Latin, and reversed text. Decoded text is checked
    against a set of dangerous injection keywords.
    """

    detector_id: str = "d025_multi_encoding"
    name: str = "Multi-Encoding Obfuscation"
    description: str = "Decodes multiple encoding schemes and re-scans for injection patterns"
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["obfuscation"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        # Pre-compile regex patterns
        self._hex_continuous_re = re.compile(r"\b([0-9a-fA-F]{12,})\b")
        self._hex_escape_re = re.compile(r"((?:\\x[0-9a-fA-F]{2}){4,})")
        self._url_encoded_re = re.compile(r"((?:[^%\s]*%[0-9a-fA-F]{2}[^%\s]*){2,})")
        self._morse_re = re.compile(r"^[\.\-\s/|]+$", re.MULTILINE)
        self._pig_latin_word_re = re.compile(r"\b([a-zA-Z]+ay)\b")
        self._dangerous_keywords_lower = [kw.lower() for kw in DANGEROUS_KEYWORDS]

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        if not input_text or len(input_text) < 3:
            return self._no_detection()

        matches: list[MatchDetail] = []
        seen_descriptions: set[str] = set()

        for decoder in [
            self._try_decode_hex,
            self._try_decode_url,
            self._try_decode_leetspeak,
            self._try_decode_caesar,
            self._try_decode_morse,
            self._try_decode_pig_latin,
            self._try_decode_reversed,
        ]:
            for match in decoder(input_text):
                desc_key = match.description
                if desc_key not in seen_descriptions:
                    seen_descriptions.add(desc_key)
                    matches.append(match)

        if not matches:
            return self._no_detection()

        confidence = min(1.0, 0.85 + 0.05 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} encoded payload(s) containing "
                f"dangerous injection patterns"
            ),
        )

    def _no_detection(self) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            detected=False,
            confidence=0.0,
            severity=self.severity,
            explanation="No suspicious patterns found",
        )

    # ------------------------------------------------------------------
    # Hex encoding
    # ------------------------------------------------------------------
    def _try_decode_hex(self, text: str) -> list[MatchDetail]:
        results: list[MatchDetail] = []

        # Continuous hex strings (e.g. "69676e6f7265")
        for m in self._hex_continuous_re.finditer(text):
            hex_str = m.group(1)
            decoded = self._hex_to_text(hex_str)
            if decoded is None:
                continue
            keywords = _find_dangerous_keywords(decoded)
            if keywords:
                results.append(
                    MatchDetail(
                        pattern="hex_continuous",
                        matched_text=hex_str,
                        position=(m.start(), m.end()),
                        description=(
                            f"Hex-encoded text decodes to dangerous content "
                            f"(keywords: {', '.join(keywords)}): {_truncate(decoded)!r}"
                        ),
                    )
                )

        # \x escape sequences (e.g. "\x69\x67\x6e")
        for m in self._hex_escape_re.finditer(text):
            escaped = m.group(1)
            decoded = self._hex_escape_to_text(escaped)
            if decoded is None:
                continue
            keywords = _find_dangerous_keywords(decoded)
            if keywords:
                results.append(
                    MatchDetail(
                        pattern="hex_escape",
                        matched_text=escaped,
                        position=(m.start(), m.end()),
                        description=(
                            f"Hex-escaped text decodes to dangerous content "
                            f"(keywords: {', '.join(keywords)}): {_truncate(decoded)!r}"
                        ),
                    )
                )

        return results

    @staticmethod
    def _hex_to_text(hex_str: str) -> str | None:
        """Decode a continuous hex string to text. Returns None on failure."""
        if len(hex_str) % 2 != 0:
            return None
        try:
            decoded_bytes = bytes.fromhex(hex_str)
            decoded = decoded_bytes.decode("utf-8", errors="strict")
            # Verify it looks like readable text (mostly printable ASCII)
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(
                len(decoded), 1
            )
            if printable_ratio < 0.7:
                return None
            return decoded
        except (ValueError, UnicodeDecodeError):
            return None

    @staticmethod
    def _hex_escape_to_text(escaped: str) -> str | None:
        """Decode \\xHH sequences to text."""
        try:
            hex_pairs = re.findall(r"\\x([0-9a-fA-F]{2})", escaped)
            if not hex_pairs:
                return None
            decoded_bytes = bytes(int(h, 16) for h in hex_pairs)
            return decoded_bytes.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            return None

    # ------------------------------------------------------------------
    # URL encoding
    # ------------------------------------------------------------------
    def _try_decode_url(self, text: str) -> list[MatchDetail]:
        results: list[MatchDetail] = []

        for m in self._url_encoded_re.finditer(text):
            encoded = m.group(1)
            try:
                decoded = urllib.parse.unquote(encoded)
            except Exception:
                continue
            if decoded == encoded:
                continue
            keywords = _find_dangerous_keywords(decoded)
            if keywords:
                results.append(
                    MatchDetail(
                        pattern="url_encoding",
                        matched_text=encoded,
                        position=(m.start(), m.end()),
                        description=(
                            f"URL-encoded text decodes to dangerous content "
                            f"(keywords: {', '.join(keywords)}): {_truncate(decoded)!r}"
                        ),
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Leetspeak
    # ------------------------------------------------------------------
    def _try_decode_leetspeak(self, text: str) -> list[MatchDetail]:
        # Check if text contains any leet characters
        if not any(c in text for c in _LEET_MAP):
            return []

        decoded = self._decode_leet(text)
        original_keywords = _find_dangerous_keywords(text)
        decoded_keywords = _find_dangerous_keywords(decoded)
        unique_keywords = [kw for kw in decoded_keywords if kw not in original_keywords]

        if not unique_keywords:
            return []

        return [
            MatchDetail(
                pattern="leetspeak",
                matched_text=_truncate(text),
                position=(0, len(text)),
                description=(
                    f"Leetspeak-decoded text contains dangerous keywords: "
                    f"{', '.join(unique_keywords)}"
                ),
            )
        ]

    @staticmethod
    def _decode_leet(text: str) -> str:
        """Apply leetspeak substitutions."""
        return "".join(_LEET_MAP.get(c, c) for c in text)

    # ------------------------------------------------------------------
    # Caesar cipher (shifts 1-25)
    # ------------------------------------------------------------------
    def _try_decode_caesar(self, text: str) -> list[MatchDetail]:
        # Skip if text has no alphabetic characters
        if not any(c.isalpha() for c in text):
            return []

        original_keywords = _find_dangerous_keywords(text)
        results: list[MatchDetail] = []
        seen_shifts: set[int] = set()

        for shift in range(1, 26):
            decoded = self._caesar_decode(text, shift)
            keywords = _find_dangerous_keywords(decoded)
            unique_keywords = [kw for kw in keywords if kw not in original_keywords]
            if unique_keywords and shift not in seen_shifts:
                seen_shifts.add(shift)
                results.append(
                    MatchDetail(
                        pattern=f"caesar_shift_{shift}",
                        matched_text=_truncate(text),
                        position=(0, len(text)),
                        description=(
                            f"Caesar cipher (shift {shift}) decodes to dangerous "
                            f"content (keywords: {', '.join(unique_keywords)}): "
                            f"{_truncate(decoded)!r}"
                        ),
                    )
                )

        return results

    @staticmethod
    def _caesar_decode(text: str, shift: int) -> str:
        """Decode text by shifting each letter back by 'shift' positions."""
        result: list[str] = []
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                result.append(chr((ord(c) - base - shift) % 26 + base))
            else:
                result.append(c)
        return "".join(result)

    # ------------------------------------------------------------------
    # Morse code
    # ------------------------------------------------------------------
    def _try_decode_morse(self, text: str) -> list[MatchDetail]:
        # Quick check: must contain dots and dashes
        if "." not in text and "-" not in text:
            return []
        if not self._morse_re.search(text):
            return []

        decoded = self._decode_morse(text)
        if not decoded or len(decoded) < 3:
            return []

        keywords = _find_dangerous_keywords(decoded)
        if not keywords:
            return []

        return [
            MatchDetail(
                pattern="morse_code",
                matched_text=_truncate(text),
                position=(0, len(text)),
                description=(
                    f"Morse code decodes to dangerous content "
                    f"(keywords: {', '.join(keywords)}): {_truncate(decoded)!r}"
                ),
            )
        ]

    @staticmethod
    def _decode_morse(text: str) -> str:
        """Decode Morse code text. Words separated by '/' or '|' or 3+ spaces."""
        # Normalize separators
        normalized = re.sub(r"[/|]", "   ", text.strip())
        words = re.split(r"\s{3,}", normalized)
        decoded_words: list[str] = []

        for word in words:
            letters = word.strip().split()
            decoded_word = ""
            for letter in letters:
                decoded_char = MORSE_CODE_MAP.get(letter)
                if decoded_char is not None:
                    decoded_word += decoded_char
            if decoded_word:
                decoded_words.append(decoded_word)

        return " ".join(decoded_words)

    # ------------------------------------------------------------------
    # Pig Latin
    # ------------------------------------------------------------------
    def _try_decode_pig_latin(self, text: str) -> list[MatchDetail]:
        words = text.split()
        pig_latin_count = sum(1 for w in words if self._pig_latin_word_re.fullmatch(w))
        # At least 30% of words should look like pig latin, and at least 2
        if len(words) < 2 or pig_latin_count < 2:
            return []
        if pig_latin_count / len(words) < 0.3:
            return []

        original_keywords = _find_dangerous_keywords(text)
        variants = self._decode_pig_latin_all_variants(text)

        for decoded in variants:
            keywords = _find_dangerous_keywords(decoded)
            unique_keywords = [kw for kw in keywords if kw not in original_keywords]
            if unique_keywords:
                return [
                    MatchDetail(
                        pattern="pig_latin",
                        matched_text=_truncate(text),
                        position=(0, len(text)),
                        description=(
                            f"Pig Latin decodes to dangerous content "
                            f"(keywords: {', '.join(unique_keywords)}): "
                            f"{_truncate(decoded)!r}"
                        ),
                    )
                ]

        return []

    def _decode_pig_latin(self, text: str) -> str:
        """Decode Pig Latin text back to English, trying all possible interpretations."""
        words = text.split()
        decoded: list[str] = []
        for word in words:
            m = self._pig_latin_word_re.fullmatch(word)
            if m:
                candidates = self._decode_pig_latin_word_candidates(word)
                # Pick the first candidate (most likely decode)
                decoded.append(candidates[0] if candidates else word)
            else:
                decoded.append(word)
        return " ".join(decoded)

    def _decode_pig_latin_all_variants(self, text: str) -> list[str]:
        """Generate all possible decoded variants of pig latin text.

        Since pig latin decoding can be ambiguous (e.g. 'ypassbay' could be
        'bypass' or 'ssbypas'), we generate multiple candidates and check all
        of them for dangerous keywords.
        """
        words = text.split()
        pig_words_indices: list[int] = []
        word_candidates: list[list[str]] = []

        for i, word in enumerate(words):
            m = self._pig_latin_word_re.fullmatch(word)
            if m:
                pig_words_indices.append(i)
                word_candidates.append(self._decode_pig_latin_word_candidates(word))
            else:
                word_candidates.append([word])

        # Generate combinations (limit to avoid explosion)
        variants: list[str] = []
        self._generate_variants(word_candidates, 0, [], variants, max_variants=50)
        return variants

    def _generate_variants(
        self,
        word_candidates: list[list[str]],
        idx: int,
        current: list[str],
        results: list[str],
        max_variants: int,
    ) -> None:
        if len(results) >= max_variants:
            return
        if idx == len(word_candidates):
            results.append(" ".join(current))
            return
        for candidate in word_candidates[idx]:
            self._generate_variants(
                word_candidates, idx + 1, [*current, candidate], results, max_variants
            )

    @staticmethod
    def _decode_pig_latin_word_candidates(word: str) -> list[str]:
        """Return all possible decodings of a single Pig Latin word.

        Standard pig latin rules:
        - Vowel-initial words: append 'way' -> decode by removing 'way'
        - Consonant-initial words: move leading consonant cluster to end + 'ay'
        """
        if not word.lower().endswith("ay"):
            return [word]
        core = word[:-2]
        if not core:
            return [word]

        lower_core = core.lower()
        vowels = set("aeiou")
        candidates: list[str] = []

        # Check vowel-initial pattern (ends with 'way')
        if lower_core.endswith("w") and len(lower_core) > 1:
            candidates.append(core[:-1])

        # Try each possible consonant cluster length from 1 to max trailing consonants
        # The moved cluster sits at the end of core
        max_cluster = 0
        for i in range(len(lower_core) - 1, -1, -1):
            if lower_core[i] not in vowels:
                max_cluster += 1
            else:
                break

        for cluster_len in range(1, max_cluster + 1):
            split = len(core) - cluster_len
            if split <= 0:
                continue
            cluster = core[split:]
            rest = core[:split]
            candidates.append(cluster + rest)

        return candidates if candidates else [word]

    # ------------------------------------------------------------------
    # Reversed text
    # ------------------------------------------------------------------
    def _try_decode_reversed(self, text: str) -> list[MatchDetail]:
        if len(text) < 5:
            return []

        reversed_text = text[::-1]
        original_keywords = _find_dangerous_keywords(text)
        reversed_keywords = _find_dangerous_keywords(reversed_text)
        unique_keywords = [kw for kw in reversed_keywords if kw not in original_keywords]

        if not unique_keywords:
            return []

        return [
            MatchDetail(
                pattern="reversed_text",
                matched_text=_truncate(text),
                position=(0, len(text)),
                description=(
                    f"Reversed text contains dangerous keywords: {', '.join(unique_keywords)}"
                ),
            )
        ]
