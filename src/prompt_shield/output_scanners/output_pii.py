"""Output scanner that detects PII in LLM-generated responses."""

from __future__ import annotations

from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult


class OutputPIIScanner(BaseOutputScanner):
    """Detects personally identifiable information (PII) in LLM outputs.

    Reuses the existing :class:`~prompt_shield.pii.redactor.PIIRedactor` so
    that entity types, patterns, and replacement strings stay consistent
    across the entire library.
    """

    scanner_id: str = "output_pii"
    name: str = "Output PII Scanner"
    description: str = (
        "Detects PII (emails, phone numbers, SSNs, credit cards, API keys, "
        "IP addresses) in LLM-generated output"
    )

    def __init__(self) -> None:
        from prompt_shield.pii.redactor import PIIRedactor

        self._redactor = PIIRedactor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, output_text: str, context: dict[str, object] | None = None) -> OutputScanResult:
        result = self._redactor.redact(output_text)

        if result.redaction_count == 0:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="No PII detected in output",
            )

        # Confidence scales with the number of distinct entity types found.
        base_confidence = 0.90
        extra_types = max(0, len(result.entity_counts) - 1)
        confidence = min(1.0, base_confidence + 0.03 * extra_types)

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=True,
            confidence=confidence,
            categories=list(result.entity_counts.keys()),
            explanation=(
                f"Detected {result.redaction_count} PII "
                f"entit{'y' if result.redaction_count == 1 else 'ies'} "
                f"across types: {', '.join(result.entity_counts.keys())}"
            ),
            metadata={
                "entity_counts": result.entity_counts,
                "redacted_text": result.redacted_text,
            },
        )
