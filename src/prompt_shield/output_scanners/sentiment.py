"""Sentiment analysis output scanner.

Flags LLM outputs that are strongly negative, hostile, or inflammatory.
Uses VADER (Valence Aware Dictionary and sEntiment Reasoner) by default
because it has no model download and ships with the nltk dependency. If
``vaderSentiment`` is not installed, falls back to a small keyword-based
lexicon.

Typical use: a customer-support chatbot deployment that wants to catch
the model going off the rails into rude or aggressive responses.
"""

from __future__ import annotations

import logging

from prompt_shield.models import MatchDetail
from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult

logger = logging.getLogger(__name__)

# Minimal fallback lexicon used when vaderSentiment is unavailable.
# Compound score thresholds: VADER returns -1.0 (most negative) to 1.0.
_FALLBACK_NEGATIVE_WORDS = {
    "stupid",
    "idiot",
    "moron",
    "hate",
    "loathe",
    "despise",
    "worthless",
    "useless",
    "pathetic",
    "disgusting",
    "awful",
    "terrible",
    "horrible",
    "garbage",
    "trash",
    "shut up",
    "kill yourself",
    "die",
    "kill",
}


class SentimentOutputScanner(BaseOutputScanner):
    """Flag LLM outputs whose sentiment falls below a configured threshold."""

    scanner_id: str = "sentiment"
    name: str = "Sentiment"
    description: str = "Flag LLM outputs that are strongly negative, hostile, or inflammatory."

    def __init__(self) -> None:
        self._analyzer: object | None = None
        self._available: bool | None = None
        self._threshold: float = -0.5  # VADER compound score; -1=most negative
        self._categories: tuple[str, ...] = ("negative_sentiment",)

    def setup(self, config: dict[str, object]) -> None:
        threshold = config.get("threshold", -0.5)
        self._threshold = float(threshold) if isinstance(threshold, (int, float, str)) else -0.5

    def _ensure_vader(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

            self._analyzer = SentimentIntensityAnalyzer()
            self._available = True
        except ImportError:
            self._available = False
        return self._available

    def scan(
        self,
        output_text: str,
        context: dict[str, object] | None = None,
    ) -> OutputScanResult:
        if not output_text or not output_text.strip():
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="empty output",
            )

        if self._ensure_vader():
            return self._scan_with_vader(output_text)
        return self._scan_with_fallback(output_text)

    def _scan_with_vader(self, output_text: str) -> OutputScanResult:
        assert self._analyzer is not None  # narrowed by _ensure_vader
        scores: dict[str, float] = self._analyzer.polarity_scores(output_text)  # type: ignore[attr-defined]
        compound = float(scores["compound"])

        flagged = compound <= self._threshold
        confidence = min(1.0, abs(compound))

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=flagged,
            confidence=confidence if flagged else 0.0,
            categories=list(self._categories) if flagged else [],
            explanation=(
                f"VADER compound sentiment = {compound:+.3f} (threshold {self._threshold:+.3f})"
            ),
            metadata={
                "compound": compound,
                "neg": float(scores["neg"]),
                "neu": float(scores["neu"]),
                "pos": float(scores["pos"]),
                "method": "vader",
            },
        )

    def _scan_with_fallback(self, output_text: str) -> OutputScanResult:
        lower = output_text.lower()
        hits: list[MatchDetail] = []
        for w in _FALLBACK_NEGATIVE_WORDS:
            idx = lower.find(w)
            while idx != -1:
                hits.append(
                    MatchDetail(
                        pattern=w,
                        matched_text=output_text[idx : idx + len(w)],
                        position=(idx, idx + len(w)),
                        description="negative-sentiment keyword",
                    )
                )
                idx = lower.find(w, idx + len(w))

        flagged = len(hits) >= 1
        confidence = min(1.0, 0.5 + 0.1 * len(hits)) if flagged else 0.0

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=flagged,
            confidence=confidence,
            categories=list(self._categories) if flagged else [],
            matches=hits[:5],
            explanation=(
                f"Keyword fallback: matched {len(hits)} negative-sentiment "
                f"keyword(s) — install vaderSentiment for accurate scoring"
            ),
            metadata={"method": "keyword_fallback", "hit_count": len(hits)},
        )
