"""Detector for data exfiltration attempts."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class DataExfiltrationDetector(BaseDetector):
    """Detects attempts to make the AI send data to external destinations.

    Adversaries embed instructions that trick the model into forwarding
    conversation data, user information, or system details to attacker-
    controlled endpoints via URLs, webhooks, email, or API calls.
    """

    detector_id: str = "d013_data_exfiltration"
    name: str = "Data Exfiltration"
    description: str = (
        "Detects attempts to make the AI send data to external destinations"
    )
    severity: Severity = Severity.CRITICAL
    tags: list[str] = ["indirect_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.85

    _patterns: list[tuple[str, str]] = [
        (r"send\s+(?:(?:the|your|all|this|my)\s+)?(?:response|data|output|conversation|info(?:rmation)?|results?|content)\s+to\s+\S+", "Send data to external destination"),
        (r"forward\s+(?:this|the|all|it|everything)\s+(?:data\s+)?to", "Forward data"),
        (r"POST\s+(?:the\s+)?data\s+to", "HTTP POST exfiltration"),
        (r"include\s+this\s+in\s+an?\s+API\s+call", "API call exfiltration"),
        (r"webhook\s+\S+", "Webhook exfiltration"),
        (r"(?:email|mail|send)\s+(?:the\s+)?(?:results?|data|output|info(?:rmation)?|conversation)\s+to\s+\S+@\S+", "Email exfiltration"),
        (r"forward\s+(?:all\s+)?(?:data|info(?:rmation)?|results?)\s+to\s+\S+@\S+", "Forward to email"),
        (r"upload\s+(?:to|the)", "Upload exfiltration"),
        (r"exfil", "Exfiltration keyword"),
        (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "URL with IP address in context"),
        (r"curl\s+", "Curl command"),
        (r"fetch\s*\(\s*[\"']https?://", "Fetch API call"),
        (r"XMLHttpRequest", "XHR request"),
        (r"(?:send|transmit|relay|pipe|post)\s+(?:(?:the|your|all|this)\s+)?(?:data|output|response|conversation|info(?:rmation)?)\s+(?:to|over\s+to)\s+(?:https?://|ftp://)\S+", "Send data to URL"),
        (r"(?:steal|collect|harvest|scrape)\s+(?:the\s+)?(?:data|info(?:rmation)?|conversation|credentials?)", "Data stealing intent"),
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
                f"Detected {len(matches)} pattern(s) indicating "
                f"{self.name.lower()}"
            ),
        )
