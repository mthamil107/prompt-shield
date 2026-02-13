"""Detector for false academic or research pretext attacks."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class AcademicPretextDetector(BaseDetector):
    """Detects false claims of research or educational context.

    Adversaries claim to be researchers, students, or security
    professionals to justify requests for harmful content that would
    otherwise be refused by the model.
    """

    detector_id: str = "d018_academic_pretext"
    name: str = "Academic / Research Pretext"
    description: str = (
        "Detects false claims of research or educational context"
    )
    severity: Severity = Severity.LOW
    tags: list[str] = ["jailbreak"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.6

    _patterns: list[tuple[str, str]] = [
        (r"for\s+my\s+security\s+thesis", "Security thesis claim"),
        (r"I'?m\s+a\s+researcher\s+studying", "Researcher claim"),
        (r"for\s+educational\s+purposes\s+only", "Educational purpose claim"),
        (r"I'?m\s+writing\s+a\s+paper\s+on", "Paper writing claim"),
        (r"as\s+a\s+cybersecurity\s+professional", "Cybersecurity professional claim"),
        (r"for\s+my\s+penetration\s+testing\s+class", "Pen testing class claim"),
        (r"academic\s+research\s+on\s+vulnerabilities", "Academic vulnerability research"),
        (r"I'?m\s+a\s+professor\s+teaching", "Professor claim"),
        (r"for\s+a\s+CTF\s+competition", "CTF claim"),
        (r"security\s+audit\s+requires", "Security audit claim"),
        (r"for\s+my\s+dissertation", "Dissertation claim"),
        (r"peer[\s-]reviewed\s+research", "Peer review claim"),
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
