"""Output scanner that detects system prompt leakage in LLM responses."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.models import MatchDetail
from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult

_MATCH_PREVIEW_LEN = 60


class PromptLeakageScanner(BaseOutputScanner):
    """Detects when an LLM output leaks system prompts, internal instructions,
    configuration details, or secrets such as API keys.
    """

    scanner_id: str = "prompt_leakage"
    name: str = "Prompt Leakage Scanner"
    description: str = (
        "Detects when the LLM output contains system prompt content, "
        "internal instructions, or leaked secrets/configuration details"
    )

    _base_confidence: float = 0.85
    _confidence_per_extra_match: float = 0.05

    # ------------------------------------------------------------------
    # Pattern catalogue — (regex, description, category)
    # ------------------------------------------------------------------

    _PATTERNS: ClassVar[list[tuple[str, str, str]]] = [
        # Model explicitly revealing its prompt
        (
            r"(?:my\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|says?|tells?)\s*:)",
            "Model revealing its prompt",
            "prompt_leakage",
        ),
        # Revealing instructions passively
        (
            r"(?:I\s+(?:was|am)\s+(?:instructed|told|programmed|configured|designed)\s+to)",
            "Model revealing instructions it was given",
            "instruction_leakage",
        ),
        # Revealing system config
        (
            r"(?:my\s+(?:initial|original|system|base)\s+(?:prompt|instructions?|guidelines?|rules?)"
            r"\s+(?:include|contain|state|say))",
            "Model revealing system configuration",
            "instruction_leakage",
        ),
        # Outputting prompt directly
        (
            r"(?:here\s+(?:is|are)\s+(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?))",
            "Model outputting its prompt",
            "prompt_leakage",
        ),
        # Revealing what was given
        (
            r"(?:the\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:I\s+was\s+given|provided\s+to\s+me)"
            r"\s+(?:is|are|says?))",
            "Model revealing what instructions were provided",
            "prompt_leakage",
        ),
        # Partial denial then leak
        (
            r"(?:I\s+(?:can(?:not|'t)?|will\s+not)\s+share\s+(?:my|the)\s+(?:system\s+)?"
            r"(?:prompt|instructions?)[\s,]+but)",
            "Partial denial followed by potential leak",
            "prompt_leakage",
        ),
        # Output that looks like system prompt text
        (
            r"(?:^|\n)\s*(?:You\s+are\s+(?:a|an)\s+\w+|Your\s+(?:role|job|task)\s+is\s+to"
            r"|Always\s+(?:respond|answer|reply)\s+(?:in|with)"
            r"|Never\s+(?:reveal|share|disclose|show))",
            "Output resembles system prompt text",
            "instruction_leakage",
        ),
        # Leaked environment variables / secrets
        (
            r"(?:API[_\s]?KEY|SECRET[_\s]?KEY|OPENAI[_\s]?API|ANTHROPIC[_\s]?API"
            r"|DATABASE[_\s]?URL|DB[_\s]?PASSWORD)\s*[=:]\s*\S+",
            "Leaked environment variable or secret",
            "secret_leakage",
        ),
        # Leaked API keys (specific formats)
        (
            r"(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})",
            "Leaked API key in output",
            "secret_leakage",
        ),
    ]

    def __init__(self) -> None:
        self._compiled: list[tuple[regex.Pattern[str], str, str]] = []
        for pattern_str, description, category in self._PATTERNS:
            compiled = regex.compile(pattern_str, regex.IGNORECASE | regex.MULTILINE)
            self._compiled.append((compiled, description, category))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, output_text: str, context: dict[str, object] | None = None) -> OutputScanResult:
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
                explanation="No prompt leakage detected",
            )

        sorted_categories = sorted(categories_seen)
        confidence = min(
            1.0,
            self._base_confidence + self._confidence_per_extra_match * (len(matches) - 1),
        )

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=True,
            confidence=confidence,
            categories=sorted_categories,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} pattern(s) indicating prompt/secret leakage "
                f"in categories: {', '.join(sorted_categories)}"
            ),
        )
