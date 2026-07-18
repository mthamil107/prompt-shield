"""Shared text sanitizer for tool results and agent gates.

Extracted from ``AgentGuard._sanitize_text`` so ``ToolResultGuard`` and
``AgentGuard`` share the same logic. PII detections route through the
entity-type-aware ``PIIRedactor`` (`d023_pii_detection`); other detections
get replaced with a generic placeholder string.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from prompt_shield.models import ScanReport


def sanitize_text(
    text: str,
    report: ScanReport,
    replacement: str = "[REDACTED by prompt-shield]",
) -> str:
    """Replace matched detection spans in ``text`` with a safe placeholder.

    PII spans use entity-type-aware redaction; other spans use ``replacement``.
    """
    if not report.detections:
        return text

    pii_detections = [d for d in report.detections if d.detector_id == "d023_pii_detection"]
    if pii_detections:
        from prompt_shield.pii.redactor import PIIRedactor

        redactor = PIIRedactor()
        pii_matches = []
        for det in pii_detections:
            for match in det.matches:
                pii_matches.append({"description": match.description, "position": match.position})
        text = redactor.redact_with_detections(text, pii_matches)

    non_pii = [d for d in report.detections if d.detector_id != "d023_pii_detection"]
    if non_pii:
        positions: list[tuple[int, int]] = []
        for det in non_pii:
            for match in det.matches:
                if match.position:
                    positions.append(match.position)
        positions.sort(key=lambda p: p[0], reverse=True)
        for start, end in positions:
            text = text[:start] + replacement + text[end:]

    return text


__all__ = ["sanitize_text"]
