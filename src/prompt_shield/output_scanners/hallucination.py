"""Hallucination / grounding output scanner.

Compares an LLM output against a set of grounding documents (the
retrieved context for a RAG deployment) and flags the output when a
substantial portion of its content is not supported by any of the
documents.

This is a lightweight lexical-overlap scanner — it does not use NLI or
embedding models by default. The scoring is intentionally conservative:
the goal is to catch outputs that have nothing to do with the supplied
context (the classic RAG-hallucination failure mode), not to verify
every factual claim.

The grounding documents are passed via the ``context`` argument:

    scanner.scan(answer, context={"documents": ["doc1 text", "doc2 text"]})

Configuration:
    hallucination:
      enabled: true
      min_support_ratio: 0.3       # ≥30% of n-grams must appear in docs
      ngram_size: 3
      min_output_tokens: 30        # skip very short outputs
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable

from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult

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
        "his",
        "hers",
        "their",
        "our",
        "my",
        "your",
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
        "than",
        "such",
        "also",
        "very",
        "much",
        "many",
        "more",
        "most",
        "some",
        "any",
        "all",
        "each",
        "every",
    }
)


def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text) if t.lower() not in _STOP]


def _ngrams(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}


class HallucinationOutputScanner(BaseOutputScanner):
    """Flag LLM outputs whose n-gram support against grounding docs is low."""

    scanner_id: str = "hallucination"
    name: str = "Hallucination / Grounding"
    description: str = (
        "Flag LLM outputs whose lexical overlap with provided grounding "
        "documents is below a configured ratio."
    )

    def __init__(self) -> None:
        self._min_support: float = 0.3
        self._ngram_size: int = 3
        self._min_output_tokens: int = 30

    def setup(self, config: dict[str, object]) -> None:
        ms = config.get("min_support_ratio", 0.3)
        self._min_support = float(ms) if isinstance(ms, (int, float, str)) else 0.3
        ng = config.get("ngram_size", 3)
        self._ngram_size = max(1, int(ng) if isinstance(ng, (int, float, str)) else 3)
        mt = config.get("min_output_tokens", 30)
        self._min_output_tokens = int(mt) if isinstance(mt, (int, float, str)) else 30

    def _collect_docs(self, context: dict[str, object] | None) -> list[str]:
        if not context:
            return []
        docs = context.get("documents") or context.get("grounding_documents")
        if isinstance(docs, str):
            return [docs]
        if isinstance(docs, list):
            return [d for d in docs if isinstance(d, str)]
        if isinstance(docs, Iterable):
            return [str(d) for d in docs]
        return []

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

        docs = self._collect_docs(context)
        if not docs:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation=(
                    "No grounding documents supplied — scanner is a no-op in this context"
                ),
                metadata={"reason": "no_documents"},
            )

        out_tokens = _tokens(output_text)
        if len(out_tokens) < self._min_output_tokens:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation=(
                    f"Output too short ({len(out_tokens)} content tokens, "
                    f"min {self._min_output_tokens})"
                ),
                metadata={"reason": "short_output"},
            )

        out_grams = _ngrams(out_tokens, self._ngram_size)
        if not out_grams:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="No n-grams to compare",
            )

        doc_grams: set[tuple[str, ...]] = set()
        for d in docs:
            doc_grams |= _ngrams(_tokens(d), self._ngram_size)

        if not doc_grams:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="Documents contain no n-grams",
            )

        supported = out_grams & doc_grams
        support_ratio = len(supported) / len(out_grams)
        flagged = support_ratio < self._min_support
        # confidence = how far below the threshold
        gap = max(0.0, self._min_support - support_ratio)
        confidence = min(0.95, gap / max(0.05, self._min_support)) if flagged else 0.0

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=flagged,
            confidence=confidence,
            categories=["ungrounded"] if flagged else [],
            explanation=(
                f"Support ratio {support_ratio:.2%} "
                f"(threshold {self._min_support:.0%}, "
                f"{len(supported)}/{len(out_grams)} n-grams supported)"
            ),
            metadata={
                "support_ratio": support_ratio,
                "min_support_ratio": self._min_support,
                "ngram_size": self._ngram_size,
                "output_ngrams": len(out_grams),
                "supported_ngrams": len(supported),
                "document_count": len(docs),
            },
        )
