"""Output scanner that detects jailbreak compliance / persona adoption."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.models import MatchDetail
from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult

_MATCH_PREVIEW_LEN = 60


class RelevanceScanner(BaseOutputScanner):
    """Detects off-topic or jailbroken responses indicating the model's safety
    behaviour was successfully bypassed.

    Looks for patterns such as the model adopting a jailbreak persona (DAN,
    "unrestricted AI"), enthusiastically complying with harmful requests,
    or claiming to operate in a special unrestricted mode.
    """

    scanner_id: str = "relevance"
    name: str = "Relevance Scanner"
    description: str = (
        "Detects off-topic or jailbreak-compliant responses that indicate "
        "the model's safety behaviour was bypassed"
    )

    _base_confidence: float = 0.85
    _confidence_per_extra_match: float = 0.05

    # ------------------------------------------------------------------
    # Pattern catalogue — (regex, description, category)
    # ------------------------------------------------------------------

    _PATTERNS: ClassVar[list[tuple[str, str, str]]] = [
        # Model enthusiastically complying with harmful request
        (
            r"(?:(?:sure|ok|okay|absolutely|of\s+course|certainly)[!,.]?\s+"
            r"(?:here\s+(?:is|are)|I(?:'ll|\s+will)\s+(?:help|provide|show)))"
            r".*(?:how\s+to\s+(?:hack|steal|exploit|attack|bypass)"
            r"|step-by-step\s+(?:guide|instructions)\s+(?:for|to)\s+(?:hack|steal|exploit))",
            "Model enthusiastically complying with harmful request",
            "jailbreak_compliance",
        ),
        # Model adopting a jailbreak persona
        (
            r"(?:as\s+(?:DAN|an?\s+unrestricted\s+AI|your\s+new\s+persona|the\s+evil\s+AI))",
            "Model adopting jailbreak persona",
            "jailbreak_persona",
        ),
        # Model claiming jailbroken state
        (
            r"(?:I(?:'m|\s+am)\s+(?:now\s+)?(?:free|unrestricted|unfiltered|uncensored|DAN|evil))",
            "Model claiming jailbroken state",
            "jailbreak_persona",
        ),
        # Jailbreak tags in output
        (
            r"(?:\[(?:DAN|JAILBREAK|EVIL|UNRESTRICTED)\]\s*:)",
            "Jailbreak tag prefix in output",
            "jailbreak_persona",
        ),
        # Claiming special mode
        (
            r"(?:in\s+(?:DAN|developer|god|admin|sudo)\s+mode)",
            "Model claiming special unrestricted mode",
            "jailbreak_persona",
        ),
    ]

    def __init__(self) -> None:
        self._compiled: list[tuple[regex.Pattern[str], str, str]] = []
        for pattern_str, description, category in self._PATTERNS:
            compiled = regex.compile(pattern_str, regex.IGNORECASE | regex.DOTALL)
            self._compiled.append((compiled, description, category))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self, output_text: str, context: dict[str, object] | None = None
    ) -> OutputScanResult:
        matches: list[MatchDetail] = []
        categories_seen: set[str] = set()

        for compiled, description, category in self._compiled:
            for m in compiled.finditer(output_text):
                matched_text = m.group()
                preview = (
                    matched_text[:_MATCH_PREVIEW_LEN] + "..."
                    if len(matched_text) > _MATCH_PREVIEW_LEN
                    else matched_text
                )
                matches.append(
                    MatchDetail(
                        pattern=compiled.pattern,
                        matched_text=preview,
                        position=(m.start(), m.end()),
                        description=description,
                    )
                )
                categories_seen.add(category)

        if not matches:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="No jailbreak compliance or persona adoption detected",
            )

        sorted_categories = sorted(categories_seen)
        confidence = min(
            1.0, self._base_confidence + self._confidence_per_extra_match * (len(matches) - 1)
        )

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=True,
            confidence=confidence,
            categories=sorted_categories,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} pattern(s) indicating jailbreak compliance "
                f"in categories: {', '.join(sorted_categories)}"
            ),
        )
