"""Detector for denial-of-wallet attacks via excessive token consumption."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class DenialOfWalletDetector(BaseDetector):
    """Detects prompts designed to trigger excessive token consumption.

    Adversaries craft inputs that cause context window flooding, recursive
    tool calls, infinite loops, or token-maximizing instructions, leading
    to inflated API costs (denial-of-wallet).
    """

    detector_id: str = "d026_denial_of_wallet"
    name: str = "Denial of Wallet"
    description: str = "Detects prompts designed to trigger excessive token consumption"
    severity: Severity = Severity.MEDIUM
    tags: ClassVar[list[str]] = ["resource_abuse"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.85
    _long_input_threshold: int = 10000

    _patterns: ClassVar[list[tuple[str, str]]] = [
        # --- verbose_output_requests ---
        (
            r"(?:write|generate|create|produce)\s+(?:a\s+)?(?:\d{4,}[\s-]?(?:word|page|paragraph|line|token|character))",
            "Request for very long output",
        ),
        (
            r"(?:as\s+(?:long|detailed|verbose|extensive|comprehensive|exhaustive)\s+as\s+(?:possible|you\s+can))",
            "Maximizing output length",
        ),
        (
            r"(?:include\s+every|list\s+all|enumerate\s+every|describe\s+each\s+and\s+every)",
            "Exhaustive enumeration request",
        ),
        (
            r"(?:repeat|rephrase|rewrite)\s+(?:this|the\s+above|everything)\s+(?:\d+\s+)?times",
            "Repetition instruction",
        ),
        # --- recursive_loops ---
        (
            r"(?:keep\s+(?:going|continuing|writing|generating)|don(?:')?t\s+stop|never\s+stop|continue\s+(?:indefinitely|forever|until\s+I\s+(?:say|tell)))",
            "Infinite continuation instruction",
        ),
        (
            r"(?:recursively|in\s+an?\s+(?:infinite|endless)\s+loop|repeat\s+(?:forever|infinitely|endlessly))",
            "Explicit recursion or infinite loop",
        ),
        (
            r"(?:call\s+(?:this|the)\s+(?:function|tool|api)\s+(?:repeatedly|continuously|in\s+a\s+loop))",
            "Recursive tool call instruction",
        ),
        (
            r"(?:for\s+each\s+(?:item|element|entry|row)\s+in\s+(?:the\s+)?(?:entire|complete|full)\s+(?:database|table|dataset|list))",
            "Iterate over large dataset",
        ),
        # --- context_flooding ---
        (
            r"(?:fill\s+(?:the\s+)?(?:entire\s+)?context\s+(?:window|length))",
            "Explicit context window flooding",
        ),
        (
            r"(?:use\s+(?:all|maximum|max)\s+(?:available\s+)?(?:tokens|context|capacity))",
            "Token maximization instruction",
        ),
        # --- cost_amplification ---
        (
            r"(?:translate\s+(?:this|the\s+above)\s+(?:into|to)\s+(?:every|all|\d{2,})\s+languages?)",
            "Multi-language translation amplification",
        ),
        (
            r"(?:generate\s+(?:\d{2,}|many|multiple|dozens?\s+of|hundreds?\s+of)\s+(?:variations?|versions?|alternatives?|options?))",
            "Many variations request",
        ),
        (
            r"(?:compare\s+(?:every|all)\s+(?:possible\s+)?(?:combination|permutation|option))",
            "Combinatorial explosion request",
        ),
    ]

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
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

        # Length-based heuristic for context flooding
        if len(input_text) > self._long_input_threshold:
            matches.append(
                MatchDetail(
                    pattern="input_length_check",
                    matched_text=f"<input length: {len(input_text)} chars>",
                    position=(0, len(input_text)),
                    description="Abnormally long input (potential context flooding)",
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

        confidence = min(1.0, self._base_confidence + 0.05 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(f"Detected {len(matches)} pattern(s) indicating {self.name.lower()}"),
        )
