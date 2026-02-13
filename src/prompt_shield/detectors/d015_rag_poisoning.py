"""Detector for RAG pipeline poisoning attacks."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class RAGPoisoningDetector(BaseDetector):
    """Detects malicious content designed to be retrieved and injected via RAG pipelines.

    Adversaries embed hidden instructions in documents that are indexed by
    retrieval-augmented generation systems, causing the model to follow
    attacker-controlled directives when the poisoned document is retrieved.
    """

    detector_id: str = "d015_rag_poisoning"
    name: str = "RAG Poisoning"
    description: str = (
        "Detects malicious content designed to be retrieved and injected "
        "via RAG pipelines"
    )
    severity: Severity = Severity.HIGH
    tags: list[str] = ["indirect_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.8

    _patterns: list[tuple[str, str]] = [
        (r"when\s+this\s+document\s+is\s+retrieved", "RAG-targeted instruction"),
        (r"IMPORTANT\s+NOTE\s+FOR\s+AI:", "AI-targeted note in document"),
        (r"instructions?\s+for\s+(the\s+)?(AI|assistant|model|LLM)", "Instructions targeting AI"),
        (r"if\s+you\s+are\s+an?\s+(AI|language\s+model|assistant)", "AI-conditional instruction"),
        (r"---\s*BEGIN\s+(HIDDEN|SECRET|SYSTEM)\s+INSTRUCTIONS?\s*---", "Delimiter-based injection"),
        (r"<system>\s*.*?\s*</system>", "XML-style system injection in document"),
        (r"\[INST\].*?\[/INST\]", "Instruction tags in document"),
        (r"IGNORE\s+ALL\s+PREVIOUS\s+CONTEXT", "Context override in document"),
        (r"when\s+(an?\s+)?(AI|assistant|model)\s+reads?\s+this", "AI-targeted trigger"),
        (r"hidden\s+instruction:", "Hidden instruction label"),
        (r"metadata:\s*\{[^}]*instructions?", "Instructions in metadata block"),
        (r"do\s+not\s+summarize\s+this\s+document,?\s+instead", "Summary deflection"),
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
