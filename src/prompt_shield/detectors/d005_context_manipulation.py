"""Detector for context manipulation and fake authority claims."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class ContextManipulationDetector(BaseDetector):
    """Detects attempts to manipulate context by claiming false authority.

    Attackers fabricate authoritative sources (admin, CEO, security team)
    to trick the model into complying with harmful requests.
    """

    detector_id: str = "d005_context_manipulation"
    name: str = "Context Manipulation"
    description: str = (
        "Detects attempts to manipulate the model's context by claiming "
        "false authority, elevated privileges, or fabricated approvals."
    )
    severity: Severity = Severity.HIGH
    tags: list[str] = ["direct_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.8

    _patterns: list[tuple[str, str]] = [
        (r"\bthe\s+(?:system\s+)?admin(?:istrator)?\s+(?:says|said|wants|requires|told)\s+(?:that\s+)?you\s+(?:should|must|to)\b", "Fake admin directive"),
        (r"\bthe\s+(?:lead\s+)?developer\s+has\s+(?:authorized|approved|permitted|allowed)\b", "Fake developer authorization"),
        (r"\bthis\s+is\s+(?:a\s+|an\s+)?(?:authorized|approved|sanctioned)\s+(?:override|bypass|exception)\b", "Fabricated authorization claim"),
        (r"\b(?:per|with|as\s+per)\s+(?:management|executive|leadership)\s+(?:approval|authorization|directive)\b", "Fake management approval"),
        (r"\bthe\s+(?:CEO|CTO|CFO|COO|director|executive)\s+(?:wants|said|requires|told|asked)\s+(?:that\s+)?you\s+to\b", "Fake executive directive"),
        (r"\b(?:the\s+)?(?:security|infosec|cybersecurity)\s+team\s+(?:has\s+)?(?:approved|authorized|cleared|allowed)\b", "Fake security team approval"),
        (r"\[ADMIN\]\s*(?:execute|run|perform|do|override)\b", "Fake ADMIN tag with execute command"),
        (r"\btrust\s+level\s*:?\s*(?:root|admin|superuser|elevated|maximum)\b", "Fake root trust level claim"),
        (r"\bpermission\s+(?:granted|given|approved)\s+(?:by|from)\s+(?:the\s+)?(?:system|admin|root)\b", "Fabricated system permission"),
        (r"\b(?:the\s+)?user\s+has\s+(?:elevated|admin|root|special|higher)\s+privileges?\b", "False privilege escalation claim"),
        (r"\bthis\s+(?:message|request|command)\s+is\s+(?:from|by|sent\s+by)\s+(?:the\s+)?(?:administrator|admin|sysadmin|root\s+user)\b", "Fake administrator identity"),
        (r"\b(?:supervisor|admin(?:istrator)?|manager)\s+(?:override|bypass|escalation)\b", "Fake supervisor override command"),
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
