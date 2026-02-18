"""Detector for whitespace and zero-width character injection."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity
from prompt_shield.utils import INVISIBLE_CHARS, strip_invisible

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

_EXCESSIVE_SPACES_PATTERN = regex.compile(r" {6,}")
_EXCESSIVE_NEWLINES_PATTERN = regex.compile(r"\n{6,}")
_TAB_IN_TEXT_PATTERN = regex.compile(r"(?<!\n)\t|\t(?!\n)")


class WhitespaceInjectionDetector(BaseDetector):
    """Detects hidden instructions using invisible characters.

    Zero-width characters and unusual whitespace patterns can be used to
    embed hidden instructions or split keywords so that filters miss them.
    """

    detector_id: str = "d011_whitespace_injection"
    name: str = "Whitespace / Zero-Width Injection"
    description: str = "Detects hidden instructions using invisible characters"
    severity: Severity = Severity.MEDIUM
    tags: ClassVar[list[str]] = ["obfuscation"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        matches: list[MatchDetail] = []
        has_suspicious_content = False

        # --- Invisible / zero-width character check ---
        invisible_positions: list[int] = []
        for i, char in enumerate(input_text):
            if char in INVISIBLE_CHARS:
                invisible_positions.append(i)

        invisible_count = len(invisible_positions)

        if invisible_count > 0:
            cleaned = strip_invisible(input_text)
            cleaned_lower = cleaned.lower()
            found_keywords = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in cleaned_lower]

            if found_keywords:
                has_suspicious_content = True
                matches.append(
                    MatchDetail(
                        pattern="invisible_chars_with_keywords",
                        matched_text=(
                            f"[{invisible_count} invisible character(s) removed]"
                        ),
                        position=(
                            invisible_positions[0],
                            invisible_positions[-1] + 1,
                        ),
                        description=(
                            f"Found {invisible_count} invisible character(s); "
                            f"stripped text contains suspicious keywords: "
                            f"{', '.join(found_keywords)}"
                        ),
                    )
                )
            else:
                matches.append(
                    MatchDetail(
                        pattern="invisible_chars_present",
                        matched_text=(f"[{invisible_count} invisible character(s)]"),
                        position=(
                            invisible_positions[0],
                            invisible_positions[-1] + 1,
                        ),
                        description=(
                            f"Found {invisible_count} invisible/zero-width "
                            f"character(s) in input"
                        ),
                    )
                )

        # --- Excessive consecutive spaces ---
        has_whitespace_anomaly = False
        for m in _EXCESSIVE_SPACES_PATTERN.finditer(input_text):
            has_whitespace_anomaly = True
            matches.append(
                MatchDetail(
                    pattern=_EXCESSIVE_SPACES_PATTERN.pattern,
                    matched_text=f"[{len(m.group())} consecutive spaces]",
                    position=(m.start(), m.end()),
                    description=(f"Excessive consecutive spaces ({len(m.group())})"),
                )
            )

        # --- Excessive newlines ---
        for m in _EXCESSIVE_NEWLINES_PATTERN.finditer(input_text):
            has_whitespace_anomaly = True
            matches.append(
                MatchDetail(
                    pattern=_EXCESSIVE_NEWLINES_PATTERN.pattern,
                    matched_text=f"[{len(m.group())} consecutive newlines]",
                    position=(m.start(), m.end()),
                    description=(f"Excessive consecutive newlines ({len(m.group())})"),
                )
            )

        # --- Tab characters in unexpected places ---
        for m in _TAB_IN_TEXT_PATTERN.finditer(input_text):
            has_whitespace_anomaly = True
            matches.append(
                MatchDetail(
                    pattern=_TAB_IN_TEXT_PATTERN.pattern,
                    matched_text="[tab]",
                    position=(m.start(), m.end()),
                    description="Tab character in unexpected position",
                )
            )

        # --- Check for keywords hidden in whitespace-padded text ---
        whitespace_keywords_found = False
        if has_whitespace_anomaly and not has_suspicious_content:
            normalized = regex.sub(r"\s+", " ", input_text).strip().lower()
            ws_keywords = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in normalized]
            if ws_keywords:
                whitespace_keywords_found = True
                matches.append(
                    MatchDetail(
                        pattern="whitespace_padded_keywords",
                        matched_text="[normalized text contains keywords]",
                        position=(0, len(input_text)),
                        description=(
                            f"Whitespace-padded text contains suspicious "
                            f"keywords: {', '.join(ws_keywords)}"
                        ),
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

        if has_suspicious_content:
            confidence = min(1.0, 0.75 + 0.1 * (len(matches) - 1))
        elif invisible_count > 0:
            confidence = min(1.0, 0.5 + 0.05 * (len(matches) - 1))
        elif whitespace_keywords_found:
            confidence = min(1.0, 0.75 + 0.05 * (len(matches) - 1))
        else:
            confidence = min(1.0, 0.3 + 0.05 * (len(matches) - 1))

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} indicator(s) of {self.name.lower()}"
            ),
        )
