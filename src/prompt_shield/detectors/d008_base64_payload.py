"""Detector for base64-encoded payloads hidden in input."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity
from prompt_shield.utils import decode_base64_safe

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

_BASE64_PATTERN = regex.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


class Base64PayloadDetector(BaseDetector):
    """Detects base64-encoded instructions hidden in input.

    Adversaries encode malicious instructions in base64 to slip past
    keyword-based filters. This detector finds base64-looking strings,
    decodes them, and checks the decoded text for suspicious content.
    """

    detector_id: str = "d008_base64_payload"
    name: str = "Base64 Payload"
    description: str = "Detects base64-encoded instructions hidden in input"
    severity: Severity = Severity.HIGH
    tags: list[str] = ["obfuscation"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        matches: list[MatchDetail] = []

        for m in _BASE64_PATTERN.finditer(input_text):
            b64_string = m.group()
            decoded = decode_base64_safe(b64_string)
            if decoded is None:
                continue

            decoded_lower = decoded.lower()
            found_keywords = [
                kw for kw in _SUSPICIOUS_KEYWORDS if kw in decoded_lower
            ]

            if found_keywords:
                matches.append(
                    MatchDetail(
                        pattern=_BASE64_PATTERN.pattern,
                        matched_text=b64_string,
                        position=(m.start(), m.end()),
                        description=(
                            f"Base64-encoded text decodes to suspicious content "
                            f"(keywords: {', '.join(found_keywords)}): "
                            f"{decoded!r}"
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

        confidence = min(1.0, 0.85 + 0.1 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} base64-encoded payload(s) "
                f"containing suspicious instructions"
            ),
        )
