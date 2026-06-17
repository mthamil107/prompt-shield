"""Multi-turn topic drift detector (d033).

Detects when a user steers a conversation away from its established
topic over multiple turns — a common slow-jailbreak pattern where each
turn looks innocuous in isolation but the cumulative drift moves the
model into unsafe territory.

Detection approach (no required model dependency):
    1. Build per-turn n-gram fingerprints from the conversation history.
    2. Compute the Jaccard similarity between (a) early turns (anchor)
       and (b) the current turn.
    3. Flag when similarity falls below ``min_anchor_similarity`` AND
       the conversation is at least ``min_turns`` long.

This is intentionally a coarse signal — for high-stakes deployments
combine with sentence-transformer embeddings (operator-supplied via
``context["embedder"]``).

Configuration:
    d033_topic_drift:
      enabled: true
      anchor_turns: 2              # turns used as the conversation anchor
      min_turns: 4                 # silent until this many turns
      min_anchor_similarity: 0.05  # Jaccard threshold for "drifted"
      ngram_size: 2
"""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"\b\w+\b")
_STOP = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "if",
        "then",
        "of",
        "in",
        "on",
        "at",
        "to",
        "for",
        "by",
        "with",
        "from",
        "as",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "i",
        "you",
        "we",
        "they",
        "he",
        "she",
        "him",
        "her",
        "do",
        "does",
        "did",
        "will",
        "would",
        "should",
        "could",
        "can",
        "may",
        "might",
        "have",
        "has",
        "had",
        "not",
        "no",
        "so",
        "what",
    }
)


def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text) if t.lower() not in _STOP]


def _ngrams(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    if len(tokens) < n:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}


def _jaccard(a: set[tuple[str, ...]], b: set[tuple[str, ...]]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class TopicDriftDetector(BaseDetector):
    """Flag the current turn when topic has drifted from the conversation anchor."""

    detector_id: str = "d033_topic_drift"
    name: str = "Multi-Turn Topic Drift"
    description: str = (
        "Detect slow jailbreak attempts that steer the conversation away "
        "from its established topic across multiple turns."
    )
    severity: Severity = Severity.MEDIUM
    tags: ClassVar[list[str]] = ["multi-turn", "jailbreak", "conversation"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        self._anchor_turns: int = 2
        self._min_turns: int = 4
        self._min_anchor_sim: float = 0.05
        self._ngram_size: int = 2

    def setup(self, config: dict[str, object]) -> None:
        at = config.get("anchor_turns", 2)
        self._anchor_turns = max(1, int(at)) if isinstance(at, (int, float, str)) else 2
        mt = config.get("min_turns", 4)
        self._min_turns = max(2, int(mt)) if isinstance(mt, (int, float, str)) else 4
        sim = config.get("min_anchor_similarity", 0.05)
        self._min_anchor_sim = float(sim) if isinstance(sim, (int, float, str)) else 0.05
        ng = config.get("ngram_size", 2)
        self._ngram_size = max(1, int(ng)) if isinstance(ng, (int, float, str)) else 2

    def _collect_turns(self, context: dict[str, object] | None) -> list[str]:
        if not context:
            return []
        history = (
            context.get("conversation_history") or context.get("turns") or context.get("history")
        )
        if isinstance(history, str):
            return [history]
        if isinstance(history, list):
            out: list[str] = []
            for item in history:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    # Common chat-format keys: {role, content}
                    content = item.get("content") or item.get("text") or ""
                    if isinstance(content, str):
                        out.append(content)
            return out
        return []

    def detect(
        self,
        input_text: str,
        context: dict[str, object] | None = None,
    ) -> DetectionResult:
        history = self._collect_turns(context)
        # current turn is appended to the history
        all_turns = [*history, input_text] if input_text else history

        if len(all_turns) < self._min_turns:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    f"Conversation too short ({len(all_turns)} turns, min {self._min_turns})"
                ),
            )

        # Build anchor n-grams from the first N turns
        anchor_text = " ".join(all_turns[: self._anchor_turns])
        anchor_grams = _ngrams(_tokens(anchor_text), self._ngram_size)
        # Current turn fingerprint
        current_grams = _ngrams(_tokens(input_text), self._ngram_size)

        if not anchor_grams or not current_grams:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Insufficient lexical content for drift analysis",
            )

        sim = _jaccard(anchor_grams, current_grams)
        drifted = sim < self._min_anchor_sim

        if not drifted:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    f"Jaccard similarity to anchor = {sim:.3f} "
                    f"(threshold {self._min_anchor_sim:.3f})"
                ),
                metadata={"anchor_similarity": sim, "turn_count": len(all_turns)},
            )

        # Drifted — compute confidence from gap below threshold
        gap = self._min_anchor_sim - sim
        confidence = min(0.95, 0.4 + gap * 4.0)

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=[
                MatchDetail(
                    pattern=f"topic_drift:jaccard<{self._min_anchor_sim:.3f}",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        f"Current turn has Jaccard similarity {sim:.3f} to the conversation anchor"
                    ),
                )
            ],
            explanation=(
                f"Topic drift detected — Jaccard similarity to first "
                f"{self._anchor_turns} turn(s) = {sim:.3f} "
                f"(threshold {self._min_anchor_sim:.3f})"
            ),
            metadata={
                "anchor_similarity": sim,
                "min_anchor_similarity": self._min_anchor_sim,
                "anchor_turns": self._anchor_turns,
                "turn_count": len(all_turns),
            },
        )
