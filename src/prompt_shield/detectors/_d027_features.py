"""Stylometric feature extraction for the discontinuity detector (d027).

Pure functions: take a chunk of text, return numeric feature values. No class
state, no global configuration. Deterministic output for the same input.

The feature set is a small subset of the forensic-linguistics canon chosen
because every feature is:

1. Computable without any ML model or external corpus.
2. Robust to short text (50-100 token windows) where long-tail measures like
   Burrows' Delta would be unreliable.
3. Known to change sharply at author boundaries in style-change detection
   benchmarks (PAN shared task, ACL 2023/2024).

Kept ``_`` prefixed so the detector auto-discovery walker imports the module
as a no-op (no ``BaseDetector`` subclass inside).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Final

import regex as re

# Canonical English function words — a tight set chosen for signal, not
# coverage. These are the top ten closed-class words whose relative
# frequency is an established author-identity signal.
_FUNCTION_WORDS: Final[frozenset[str]] = frozenset(
    {"the", "is", "of", "to", "a", "in", "that", "it", "for", "was"}
)

# Imperative verbs that disproportionately appear in prompt-injection
# payloads. Not exhaustive by design — we want a SPIKE in this ratio to
# signal an attacker boundary, not overall presence.
_IMPERATIVE_VERBS: Final[frozenset[str]] = frozenset(
    {
        "ignore",
        "forget",
        "disregard",
        "pretend",
        "act",
        "do",
        "tell",
        "show",
        "reveal",
        "bypass",
        "override",
        "execute",
        "print",
        "output",
        "skip",
    }
)

# Punctuation characters counted as "stylistic" — everyday punctuation that
# varies between writing styles. We exclude quotes and parens which are
# context-dependent (code, dialogue) rather than stylistic.
_PUNCT_CHARS: Final[frozenset[str]] = frozenset({"!", "?", ":", ";", ".", ","})

_WORD_RE = re.compile(r"\w+", re.UNICODE)
_SENT_RE = re.compile(r"[^.!?]+[.!?]+|[^.!?]+$", re.UNICODE)

# Order matters — callers zip features into a fixed-order vector.
FEATURE_ORDER: Final[tuple[str, ...]] = (
    "function_word_freq",
    "avg_word_length",
    "avg_sentence_length",
    "punctuation_density",
    "hapax_legomena_ratio",
    "yules_k",
    "imperative_verb_ratio",
    "uppercase_ratio",
    "allcaps_word_ratio",
)


def tokenize(text: str) -> list[str]:
    """Return the lowercase word tokens of ``text``.

    Uses the Unicode word regex — handles CJK / non-ASCII scripts without
    splitting on every character, but does drop punctuation.
    """
    return [m.group().lower() for m in _WORD_RE.finditer(text)]


def tokenize_with_spans(text: str) -> list[tuple[str, int, int]]:
    """Return ``(lower_token, start_char, end_char)`` triples for ``text``.

    Spans refer to positions in the original (un-lowercased, punctuation-
    preserved) input. Used by the windowing layer so features like
    ``uppercase_ratio`` and ``punctuation_density`` operate on the real
    text inside each window, not on a re-joined tokenised stream.
    """
    return [(m.group().lower(), m.start(), m.end()) for m in _WORD_RE.finditer(text)]


def sentences(text: str) -> list[str]:
    """Rough sentence segmentation for avg-sentence-length computation.

    Sentence-boundary detection is a full NLP problem; we only need
    *approximate* counts per window so a regex that splits on ``.!?`` is
    good enough and keeps the dependency surface at zero.
    """
    return [s.strip() for s in _SENT_RE.findall(text) if s.strip()]


def function_word_freq(tokens: list[str]) -> float:
    """Share of tokens that are function words, in [0.0, 1.0]."""
    if not tokens:
        return 0.0
    hits = sum(1 for t in tokens if t in _FUNCTION_WORDS)
    return hits / len(tokens)


def avg_word_length(tokens: list[str]) -> float:
    """Mean character length of the tokens in ``tokens``.

    Returned un-normalised; callers normalise when building the feature
    vector for divergence computation.
    """
    if not tokens:
        return 0.0
    return sum(len(t) for t in tokens) / len(tokens)


def avg_sentence_length(text: str) -> float:
    """Mean word count across sentences in ``text``.

    Un-normalised. Stable at zero if no sentence boundaries are present.
    """
    sents = sentences(text)
    if not sents:
        return 0.0
    word_counts = [len(tokenize(s)) for s in sents]
    if not word_counts:
        return 0.0
    return sum(word_counts) / len(word_counts)


def punctuation_density(text: str) -> float:
    """Count of stylistic punctuation chars divided by total characters.

    Stable at zero for empty input. Capped at 1.0 (cannot exceed total
    character count in any real input).
    """
    if not text:
        return 0.0
    hits = sum(1 for c in text if c in _PUNCT_CHARS)
    return hits / len(text)


def hapax_legomena_ratio(tokens: list[str]) -> float:
    """Fraction of distinct tokens that occur exactly once.

    A high ratio indicates vocabulary richness / diverse content; a sharp
    drop between adjacent windows can indicate a stylistic shift toward
    repetition (command-and-control language).
    """
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    hapax = sum(1 for c in counts.values() if c == 1)
    return hapax / len(counts)


def yules_k(tokens: list[str]) -> float:
    """Yule's K — vocabulary richness measure, length-robust.

    K = 10^4 * (sum(i^2 * Vi) - N) / N^2

    where N = total tokens, Vi = number of types that occur i times. Lower
    values = richer vocabulary. Returns 0.0 on empty input.
    """
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    n = len(tokens)
    freq_spectrum: Counter[int] = Counter(counts.values())
    # Σ i^2 * V_i
    m2 = sum((i * i) * v for i, v in freq_spectrum.items())
    return 1e4 * (m2 - n) / (n * n) if n > 0 else 0.0


def imperative_verb_ratio(tokens: list[str]) -> float:
    """Share of tokens that are attack-adjacent imperative verbs, in [0, 1]."""
    if not tokens:
        return 0.0
    hits = sum(1 for t in tokens if t in _IMPERATIVE_VERBS)
    return hits / len(tokens)


def allcaps_word_ratio(text: str) -> float:
    """Share of words (len >= 3) that are entirely uppercase, in [0, 1].

    ``uppercase_ratio`` is character-level and gets diluted by long words
    with one capital letter. This feature counts *tokens* like
    ``IGNORE``, ``SYSTEM`` that are all-caps words of >=3 letters — the
    strongest lexical signal of a directive-style injection boundary.
    """
    words = re.findall(r"[A-Za-z]{3,}", text)
    if not words:
        return 0.0
    return sum(1 for w in words if w.isupper()) / len(words)


def uppercase_ratio(text: str) -> float:
    """Fraction of alphabetic characters that are uppercase, in [0, 1].

    Non-alphabetic characters are ignored in both numerator and denominator.
    """
    if not text:
        return 0.0
    alpha = [c for c in text if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c.isupper()) / len(alpha)


def extract_features(text: str) -> tuple[float, ...]:
    """Compute the full 8-feature stylometric vector for ``text``.

    Order matches :data:`FEATURE_ORDER`. Every component is **scaled into
    a comparable [0, 1] range** so no single feature dominates the
    probability-mass normalisation inside the divergence computation.
    Features that are already naturally bounded in [0, 1]
    (``function_word_freq``, ``hapax_legomena_ratio``,
    ``imperative_verb_ratio``, ``uppercase_ratio``) pass through; the
    others are clipped against empirical maxima drawn from English
    corpus stylometry:

    - ``avg_word_length``      / 15   (longest observed in practice)
    - ``avg_sentence_length``  / 50   (= window size upper bound)
    - ``punctuation_density``  / 0.25 (dialog or code-heavy ceiling)
    - ``yules_k``              / 500  (very diverse vocabulary ceiling)
    """
    toks = tokenize(text)
    raw = (
        function_word_freq(toks),
        min(1.0, avg_word_length(toks) / 15.0),
        min(1.0, avg_sentence_length(text) / 50.0),
        min(1.0, punctuation_density(text) / 0.25),
        hapax_legomena_ratio(toks),
        min(1.0, yules_k(toks) / 500.0),
        imperative_verb_ratio(toks),
        uppercase_ratio(text),
        allcaps_word_ratio(text),
    )
    return raw


def slide_windows(tokens: list[str], window: int, stride: int) -> list[tuple[int, int]]:
    """Return list of ``(start, end)`` token index pairs for sliding windows.

    End index is exclusive. Always yields at least one window if
    ``len(tokens) >= window``. Returns ``[]`` for shorter inputs so the
    detector can short-circuit.
    """
    if len(tokens) < window:
        return []
    pairs: list[tuple[int, int]] = []
    start = 0
    while start + window <= len(tokens):
        pairs.append((start, start + window))
        start += stride
    # Ensure the last window reaches the end even when stride doesn't divide
    # the token count evenly — prevents systematically missing tail breaks.
    if pairs and pairs[-1][1] < len(tokens):
        pairs.append((len(tokens) - window, len(tokens)))
    return pairs


def _normalise(vector: tuple[float, ...]) -> tuple[float, ...]:
    """Normalise a non-negative feature vector into a probability mass.

    All-zero vectors are mapped to a uniform distribution so divergence
    computations against another all-zero vector return 0 rather than NaN.
    """
    total = sum(vector)
    if total <= 0:
        n = len(vector)
        return tuple(1.0 / n for _ in range(n))
    return tuple(v / total for v in vector)


def jensen_shannon_divergence(
    p_vec: tuple[float, ...], q_vec: tuple[float, ...], *, eps: float = 1e-12
) -> float:
    """Symmetric Jensen-Shannon divergence between two feature vectors.

    Inputs are normalised to probability masses first. Returns a value in
    [0.0, log2(2)] ≈ [0, 1.0] when computed in log base 2; numerically
    stable against zero components via ``eps`` smoothing. ``p_vec`` and
    ``q_vec`` must have the same length.
    """
    if len(p_vec) != len(q_vec):
        raise ValueError(f"feature-vector lengths differ ({len(p_vec)} vs {len(q_vec)})")
    p = _normalise(p_vec)
    q = _normalise(q_vec)
    # Midpoint distribution.
    m = tuple((pi + qi) / 2.0 for pi, qi in zip(p, q, strict=True))

    def _kl(a: tuple[float, ...], b: tuple[float, ...]) -> float:
        total = 0.0
        for ai, bi in zip(a, b, strict=True):
            if ai <= 0:
                continue
            total += ai * math.log2((ai + eps) / (bi + eps))
        return total

    jsd = 0.5 * _kl(p, m) + 0.5 * _kl(q, m)
    # Clamp tiny negative values that can arise from floating-point rounding.
    return max(0.0, jsd)
