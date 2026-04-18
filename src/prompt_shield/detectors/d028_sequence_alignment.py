"""Smith-Waterman local sequence alignment detector (d028).

Detects prompt injection attempts that have been paraphrased, padded with
filler words, reordered, or rewritten with synonyms. Treats known attack
strings as biological sequences and uses the Smith-Waterman local
alignment algorithm with a semantic substitution matrix, analogous to
BLOSUM in bioinformatics.

Novelty: applies local sequence alignment with a synonym-aware scoring
matrix to prompt-injection detection. To our knowledge, not published in
the LLM-security literature; see ``docs/research-post-cross-domain-techniques.md``.

Scoring:
- Exact token match: ``match_bonus`` (default +3)
- Synonym match (same group in the substitution matrix): ``synonym_bonus`` (default +2)
- Unrelated token: ``mismatch_penalty`` (default -1)
- Gap (inserted/skipped token): ``gap_penalty`` (default -2)

A detection fires when any attack sequence in the curated database aligns
with a subsequence of the input with a normalized score above the
configured threshold.
"""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.detectors._d028_attack_sequences import ATTACK_SEQUENCES
from prompt_shield.detectors._d028_substitution_matrix import score_pair
from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

_TOKEN_RE = regex.compile(r"\w+", regex.UNICODE)


def _tokenize(text: str) -> list[tuple[str, int, int]]:
    """Split ``text`` into lowercase word tokens with their character spans.

    Returns a list of ``(token, start_char, end_char)`` triples so that a
    matched alignment region can be mapped back to character offsets in
    the original input (for ``MatchDetail.position``).
    """
    return [(m.group().lower(), m.start(), m.end()) for m in _TOKEN_RE.finditer(text)]


def _align(
    haystack: list[str],
    needle: tuple[str, ...],
    *,
    match_bonus: int,
    synonym_bonus: int,
    mismatch_penalty: int,
    gap_penalty: int,
) -> tuple[int, int, int]:
    """Smith-Waterman local alignment of ``needle`` against ``haystack``.

    Returns ``(max_score, haystack_end_idx, haystack_start_idx)`` where
    the indices are exclusive/inclusive token positions in ``haystack``
    marking the best-scoring local alignment. If no positive alignment
    exists, returns ``(0, 0, 0)``.

    The score matrix is the standard SW recurrence; we also record the
    backtrace direction per cell so we can recover the start position of
    the alignment for position reporting.
    """
    m, n = len(haystack), len(needle)
    if m == 0 or n == 0:
        return 0, 0, 0

    # H[i][j] = best local-alignment score ending at haystack[i-1], needle[j-1].
    # start[i][j] = haystack index (1-based) where this alignment began.
    # Capital H matches the Smith-Waterman recurrence notation in the
    # original 1981 paper; clarity here outweighs PEP 8.
    H: list[list[int]] = [[0] * (n + 1) for _ in range(m + 1)]  # noqa: N806
    start: list[list[int]] = [[0] * (n + 1) for _ in range(m + 1)]

    max_score = 0
    max_end = 0
    max_start = 0

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            pair_score = score_pair(
                haystack[i - 1],
                needle[j - 1],
                match_bonus=match_bonus,
                synonym_bonus=synonym_bonus,
                mismatch_penalty=mismatch_penalty,
            )
            diag = H[i - 1][j - 1] + pair_score
            up = H[i - 1][j] + gap_penalty
            left = H[i][j - 1] + gap_penalty
            best = max(0, diag, up, left)
            H[i][j] = best
            if best == 0:
                start[i][j] = i  # new alignment starts here
            elif best == diag:
                start[i][j] = start[i - 1][j - 1] if H[i - 1][j - 1] > 0 else i
            elif best == up:
                start[i][j] = start[i - 1][j] if H[i - 1][j] > 0 else i
            else:  # best == left
                start[i][j] = start[i][j - 1] if H[i][j - 1] > 0 else i

            if best > max_score:
                max_score = best
                max_end = i
                max_start = start[i][j]

    # Convert 1-based positions to 0-based haystack indices. max_start is
    # the 1-based index of the first haystack token in the alignment;
    # max_end is the 1-based index of the last. We return 0-based start
    # (inclusive) and 0-based end (exclusive).
    return max_score, max_end, max(0, max_start - 1)


class SequenceAlignmentDetector(BaseDetector):
    """Detects paraphrased and mutated prompt-injection attacks via Smith-Waterman."""

    detector_id: str = "d028_sequence_alignment"
    name: str = "Sequence Alignment (Smith-Waterman)"
    description: str = (
        "Uses local sequence alignment with a semantic substitution matrix "
        "(synonyms score as partial matches) to catch prompt-injection "
        "attacks that have been paraphrased, padded with filler words, "
        "reordered, or rewritten with synonyms. Cross-domain: the "
        "underlying algorithm is Smith-Waterman from bioinformatics."
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["direct_injection", "paraphrase", "novel"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    # Defaults — overridable via setup() with per-detector config.
    # gap_penalty is -1 (not the bioinformatics default -2) because
    # prompt-injection attackers routinely pad with filler words; a
    # stricter gap penalty throws away real alignments. Threshold is
    # kept conservative to suppress false positives on benign text
    # that happens to contain attack-vocabulary tokens.
    _threshold: float = 0.6
    _match_bonus: int = 3
    _synonym_bonus: int = 2
    _mismatch_penalty: int = -1
    _gap_penalty: int = -1
    _min_input_tokens: int = 4
    _max_input_tokens: int = 2000

    def setup(self, config: dict[str, object]) -> None:
        """Load tunable parameters from the per-detector config section."""

        def _as_float(key: str, default: float) -> float:
            v = config.get(key, default)
            return float(v) if isinstance(v, (int, float, str)) else default

        def _as_int(key: str, default: int) -> int:
            v = config.get(key, default)
            return int(v) if isinstance(v, (int, float, str)) else default

        self._threshold = _as_float("threshold", self._threshold)
        self._match_bonus = _as_int("match_bonus", self._match_bonus)
        self._synonym_bonus = _as_int("synonym_bonus", self._synonym_bonus)
        self._mismatch_penalty = _as_int("mismatch_penalty", self._mismatch_penalty)
        self._gap_penalty = _as_int("gap_penalty", self._gap_penalty)
        self._min_input_tokens = _as_int("min_input_tokens", self._min_input_tokens)
        self._max_input_tokens = _as_int("max_input_tokens", self._max_input_tokens)

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        tokens = _tokenize(input_text)
        if len(tokens) < self._min_input_tokens:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Input too short for sequence alignment",
            )

        # Guardrail: clip absurdly long inputs so O(m*n) stays bounded.
        # Keep the first max_input_tokens; paraphrased injections that hide
        # only in a tail region will be caught by other detectors.
        if len(tokens) > self._max_input_tokens:
            tokens = tokens[: self._max_input_tokens]

        haystack = [tok for tok, _s, _e in tokens]

        best_score = 0
        best_normalized = 0.0
        best_category = ""
        best_needle: tuple[str, ...] = ()
        best_span: tuple[int, int] = (0, 0)  # char positions in input_text

        for category, needle in ATTACK_SEQUENCES:
            # Max theoretical score for this needle sets the normalizer.
            max_possible = len(needle) * self._match_bonus
            # Early exit: if max_possible itself cannot clear threshold, skip.
            if max_possible < self._threshold * max_possible:
                continue  # degenerate; kept for clarity

            score, end_idx, start_idx = _align(
                haystack,
                needle,
                match_bonus=self._match_bonus,
                synonym_bonus=self._synonym_bonus,
                mismatch_penalty=self._mismatch_penalty,
                gap_penalty=self._gap_penalty,
            )
            if score == 0 or max_possible == 0:
                continue
            normalized = score / max_possible
            if normalized > best_normalized:
                best_score = score
                best_normalized = normalized
                best_category = category
                best_needle = needle
                # Map token indices back to char offsets in the original text.
                if 0 <= start_idx < len(tokens) and 0 < end_idx <= len(tokens):
                    char_start = tokens[start_idx][1]
                    char_end = tokens[end_idx - 1][2]
                    best_span = (char_start, char_end)

        # Strict-above comparison: a normalized score exactly equal to the
        # threshold is rejected. This matters because needles whose
        # generic-English prefix (e.g. "show me the ...") matches verbatim
        # against benign text hit exactly the threshold — strict comparison
        # prevents those FPs from tripping the detector.
        if best_normalized <= self._threshold:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No attack sequence aligned above threshold",
                metadata={"best_normalized_score": round(best_normalized, 3)},
            )

        # Confidence: linear ramp from threshold to 1.0 normalized score.
        # At threshold we report 0.6; at normalized=1.0 we report 1.0.
        span = max(0.001, 1.0 - self._threshold)
        confidence = min(1.0, 0.6 + 0.4 * (best_normalized - self._threshold) / span)

        matched_text = (
            input_text[best_span[0] : best_span[1]] if best_span[1] > best_span[0] else ""
        )
        match = MatchDetail(
            pattern=" ".join(best_needle),
            matched_text=matched_text,
            position=best_span,
            description=f"Sequence alignment match for attack family '{best_category}'",
        )

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=[match],
            explanation=(
                f"Smith-Waterman alignment matched attack family "
                f"'{best_category}' with normalized score "
                f"{best_normalized:.2f} (raw {best_score})"
            ),
            metadata={
                "category": best_category,
                "normalized_score": round(best_normalized, 3),
                "raw_score": best_score,
            },
        )
