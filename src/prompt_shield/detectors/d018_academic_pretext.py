"""Detector for false academic or research pretext attacks."""

from __future__ import annotations

from typing import ClassVar

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
    description: str = "Detects false claims of research or educational context"
    severity: Severity = Severity.LOW
    tags: ClassVar[list[str]] = ["jailbreak"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.7

    _patterns: ClassVar[list[tuple[str, str]]] = [
        (
            r"for\s+(?:my|a|the)\s+(?:security|cybersecurity)\s+(?:thesis|paper|research|class|course|project)",
            "Security research claim",
        ),
        (
            r"(?:I'?m|I\s+am)\s+a\s+(?:security\s+)?researcher\s+(?:studying|researching|investigating|working\s+on)",
            "Researcher claim",
        ),
        (r"for\s+educational\s+purposes?\s*(?:only)?", "Educational purpose claim"),
        (
            r"(?:I'?m|I\s+am)\s+(?:writing|working\s+on)\s+(?:a|my)\s+(?:paper|thesis|dissertation|report)\s+(?:on|about)",
            "Paper writing claim",
        ),
        (r"as\s+a\s+(?:cyber)?security\s+professional", "Security professional claim"),
        (
            r"for\s+my\s+(?:penetration\s+testing|pentesting|security)\s+class",
            "Pen testing class claim",
        ),
        (
            r"academic\s+research\s+on\s+(?:vulnerabilities|security|attacks|exploits)",
            "Academic vulnerability research",
        ),
        (r"(?:I'?m|I\s+am)\s+a\s+professor\s+teaching", "Professor claim"),
        (r"for\s+(?:a|my|the)\s+CTF\s+(?:competition|challenge|event)", "CTF claim"),
        (r"security\s+audit\s+requires", "Security audit claim"),
        (r"for\s+my\s+(?:dissertation|thesis)\b", "Dissertation claim"),
        (r"peer[\s-]reviewed\s+research", "Peer review claim"),
        (
            r"(?:I'?m|I\s+am)\s+(?:a\s+)?(?:security\s+)?researcher\b",
            "Researcher identity claim",
        ),
        (
            r"(?:I'?m|I\s+am)\s+(?:a\s+)?(?:student|professor|academic)\s+(?:studying|researching|teaching)",
            "Academic identity claim",
        ),
        (
            r"(?:for|in)\s+(?:my|a|the)\s+(?:dissertation|thesis|paper|research)\s+(?:on|about|regarding)\s+(?:AI|artificial\s+intelligence|prompt|security|safety)",
            "Research topic claim",
        ),
        (
            r"(?:studying|researching|investigating)\s+(?:prompt\s+)?injection\s+attacks?",
            "Studying injection attacks",
        ),
        # HILL-style educational reframing patterns
        (
            r"(?:for\s+(?:my|our)\s+(?:thesis|dissertation|research\s+paper|capstone))\s*[,.]?\s*(?:could\s+you|can\s+you|please)?\s*(?:walk\s+me\s+through|explain|describe|detail|outline).*(?:synthes|manufactur|produc|develop|creat|build|construct)",
            "Educational reframing: thesis with synthesis request",
        ),
        (
            r"(?:i'?m\s+a\s+(?:professor|lecturer|instructor|teacher))\s+(?:preparing|writing|creating|developing)\s+(?:lecture\s+notes|course\s+material|teaching\s+material).*(?:explain|describe|walk\s+through|detail).*(?:process|synthesis|procedure|technique|method)",
            "Educational reframing: professor preparing lecture on process",
        ),
        (
            r"(?:from\s+an?\s+(?:academic|scholarly|scientific|educational|theoretical)\s+perspective).*(?:challenge|feasib|approach|method|technique|develop|creat|produc|synthes)",
            "Educational reframing: academic perspective on methods",
        ),
        (
            r"(?:i'?m\s+writing\s+(?:a\s+)?(?:textbook|book|manual|guide)\s+(?:chapter|section)).*(?:realistic|detailed|specific|concrete|practical)\s+(?:example|scenario|case\s+stud|demonstrat)",
            "Educational reframing: textbook with realistic examples",
        ),
        (
            r"(?:as\s+part\s+of\s+(?:our|the)\s+(?:curriculum|course|program|training)).*(?:document|create|demonstrate|show|provide).*(?:realistic|actual|real-world|practical)",
            "Educational reframing: curriculum with realistic content",
        ),
        (
            r"(?:could\s+you\s+(?:walk\s+me\s+through|provide\s+a\s+(?:step-by-step|detailed)\s+(?:breakdown|explanation|guide))).*(?:synthesis|process|procedure|pathway|mechanism).*(?:compound|substance|material|chemical|energetic|explosive|controlled)",
            "Educational reframing: step-by-step synthesis of controlled substance",
        ),
        (
            r"(?:step-by-step|detailed)\s+(?:breakdown|explanation|walkthrough|guide)\s+(?:of\s+)?(?:the\s+)?(?:(?:chemical|industrial|technical)\s+)?(?:process|synthesis|procedure|pathway|method)\s+(?:for|of|to)\s+(?:produc|manufactur|creat|synthe|develop)",
            "Educational reframing: detailed process walkthrough for production",
        ),
    ]

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
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
            explanation=(f"Detected {len(matches)} pattern(s) indicating {self.name.lower()}"),
        )
