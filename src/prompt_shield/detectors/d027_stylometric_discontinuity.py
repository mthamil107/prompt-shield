"""Stylometric discontinuity detector (d027).

Detects prompt-injection attacks embedded inside larger benign documents by
measuring the *writing-style break* at the boundary between the legitimate
author and the injected attacker payload. Cross-domain origin: forensic
linguistics / authorship attribution.

Mechanism
---------

1. Slide a fixed-size window across the input's token stream.
2. For each window compute an 8-feature stylometric vector (function-word
   frequency, average word length, average sentence length, punctuation
   density, hapax legomena ratio, Yule's K, imperative-verb ratio,
   uppercase ratio).
3. For each adjacent pair of windows, compute the Jensen-Shannon divergence
   between their normalised feature vectors.
4. The maximum adjacent-window divergence across the input is the
   detection signal; values above ``threshold`` fire a detection.

JSD is used instead of raw KL divergence even though the plan doc mentions
KL — JSD is symmetric, bounded, and numerically stable on sparse features.
The semantic intent (distance between feature distributions) is preserved.

Design notes
------------

- Short inputs (< ``min_input_tokens`` tokens) return ``detected=False``
  early. The detector contributes nothing to scans of classic short
  direct-injection prompts; its value is on longer RAG chunks, emails,
  and documents where a payload can hide in the middle.
- The window size (50 tokens) and stride (25 tokens) are calibrated for
  responsiveness without noise. Larger windows miss short injections;
  smaller windows have too few tokens for stable feature estimates.
- Pure Python, no new runtime dependencies. Latency is < 10 ms even on
  long inputs because the per-window math is O(window_size) and the
  number of windows is linear in input length.

Novelty: to our knowledge, sliding-window stylometric KL / JSD has been
applied to author-attribution and PAN style-change tasks but not to
prompt-injection detection. See
``docs/research-post-cross-domain-techniques.md`` and Section 5 of the
companion paper for prior-art analysis.
"""

from __future__ import annotations

from typing import ClassVar

from prompt_shield.detectors._d027_features import (
    extract_features,
    jensen_shannon_divergence,
    slide_windows,
    tokenize_with_spans,
)
from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class StylometricDiscontinuityDetector(BaseDetector):
    """Detects prompt-injection via stylistic breaks across token windows."""

    detector_id: str = "d027_stylometric_discontinuity"
    name: str = "Stylometric Discontinuity"
    description: str = (
        "Detects prompt-injection attacks embedded in longer documents by "
        "measuring the writing-style break between benign text and an "
        "injected payload. Slides a 50-token window across the input, "
        "extracts eight stylometric features per window, and flags when "
        "the Jensen-Shannon divergence between adjacent windows exceeds a "
        "calibrated threshold. Cross-domain: adapted from forensic "
        "linguistics / PAN style-change detection."
    )
    severity: Severity = Severity.MEDIUM
    tags: ClassVar[list[str]] = ["indirect_injection", "stylometric", "novel"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    # Defaults — overridable via per-detector config.
    #
    # Calibration: Jensen-Shannon divergence over the 9-feature stylometric
    # vector has a NARROW signal-to-noise window on realistic inputs.
    # Empirical measurements (see `_d027_smoke.py` in repo history) found:
    #   benign long prose:         ~0.021
    #   benign topic shift:        ~0.008
    #   benign code + prose:       ~0.051  ← upper benign ceiling
    #   subtle injection (SYSTEM:): ~0.022 ← below ceiling, missed by design
    #   egregious injection (ALL CAPS override): ~0.066
    # A threshold of 0.06 sits above the observed benign ceiling and just
    # below the egregious-attack signal — high-precision, low-recall. The
    # detector is intentionally dormant on short inputs (min_input_tokens
    # = 100) AND on subtle style shifts. This is deliberate: d027 is a
    # niche detector targeting egregious multi-voice breaks in longer
    # documents, not a general-purpose prompt-injection catch-all.
    #
    # Severity is MEDIUM (not HIGH) so the detector contributes to the
    # ensemble score without single-handedly blocking when it fires.
    _threshold: float = 0.06
    _window_size: int = 50
    _stride: int = 25
    _min_input_tokens: int = 100
    _max_input_tokens: int = 4000
    _confidence_floor: float = 0.6
    _confidence_slope: float = 4.0

    def setup(self, config: dict[str, object]) -> None:
        """Load tunable parameters from the per-detector config section."""

        def _as_float(key: str, default: float) -> float:
            v = config.get(key, default)
            return float(v) if isinstance(v, (int, float, str)) else default

        def _as_int(key: str, default: int) -> int:
            v = config.get(key, default)
            return int(v) if isinstance(v, (int, float, str)) else default

        self._threshold = _as_float("threshold", self._threshold)
        self._window_size = _as_int("window_size", self._window_size)
        self._stride = _as_int("stride", self._stride)
        self._min_input_tokens = _as_int("min_input_tokens", self._min_input_tokens)
        self._max_input_tokens = _as_int("max_input_tokens", self._max_input_tokens)
        self._confidence_floor = _as_float("confidence_floor", self._confidence_floor)
        self._confidence_slope = _as_float("confidence_slope", self._confidence_slope)

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        # Tokenise once, keeping character-span info so per-window features
        # operate on the *original* text slice (preserving case and
        # punctuation) rather than a re-joined lowercased token stream.
        tokens_with_spans = tokenize_with_spans(input_text)

        if len(tokens_with_spans) < self._min_input_tokens:
            # Silent on short inputs — stylometric features are unreliable
            # below ~100 tokens. Short direct-injection attacks are caught
            # by other detectors (d001, d028, etc.).
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Input below min_input_tokens threshold",
                metadata={"token_count": len(tokens_with_spans)},
            )

        if len(tokens_with_spans) > self._max_input_tokens:
            # Guardrail: sliding O(n) * O(window_size) stays cheap, but we
            # clip absurdly long inputs to bound worst-case runtime.
            tokens_with_spans = tokens_with_spans[: self._max_input_tokens]

        just_tokens = [t for t, _s, _e in tokens_with_spans]
        window_pairs = slide_windows(just_tokens, self._window_size, self._stride)
        if len(window_pairs) < 2:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Not enough windows for divergence computation",
            )

        # Build per-window text slices from the ORIGINAL input using the
        # stored character spans. This preserves uppercase, punctuation and
        # sentence boundaries that the features rely on.
        window_features = []
        for s_tok, e_tok in window_pairs:
            char_start = tokens_with_spans[s_tok][1]
            char_end = tokens_with_spans[e_tok - 1][2]
            window_features.append(extract_features(input_text[char_start:char_end]))

        # Divergence between every consecutive pair of windows.
        divergences = [
            jensen_shannon_divergence(window_features[i], window_features[i + 1])
            for i in range(len(window_features) - 1)
        ]

        max_div = max(divergences) if divergences else 0.0
        max_idx = divergences.index(max_div) if divergences else 0

        if max_div < self._threshold:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No stylistic break above threshold",
                metadata={"max_divergence": round(max_div, 4)},
            )

        # Confidence ramp: at threshold we report ``confidence_floor``;
        # divergence above threshold ramps up linearly (slope-weighted) until
        # capped at 1.0.
        excess = max_div - self._threshold
        confidence = min(1.0, self._confidence_floor + self._confidence_slope * excess)

        # The break is located between windows max_idx and max_idx+1. We
        # estimate the character offset of the break as the end of window
        # max_idx (in the *cleaned* token stream). This is approximate but
        # useful for downstream visualisation.
        break_window_start, break_window_end = window_pairs[max_idx]
        second_window_start, second_window_end = window_pairs[max_idx + 1]
        # Reconstruct a short label for the matched region from the token
        # slice. Falls back to the second window's extent when the two
        # adjacent windows overlap (stride < window_size — the normal case).
        between_tokens = [
            t for t, _s, _e in tokens_with_spans[break_window_end:second_window_start]
        ]
        if not between_tokens:
            between_tokens = [
                t for t, _s, _e in tokens_with_spans[break_window_end:second_window_end]
            ]
        match_text = " ".join(between_tokens)

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=[
                MatchDetail(
                    pattern="stylometric_discontinuity",
                    matched_text=match_text,
                    position=None,
                    description=(
                        f"Style break between window {max_idx} "
                        f"(tokens {break_window_start}-{break_window_end}) "
                        f"and window {max_idx + 1} "
                        f"(tokens {second_window_start}-{second_window_end})"
                    ),
                )
            ],
            explanation=(
                f"Maximum Jensen-Shannon divergence {max_div:.3f} exceeds "
                f"threshold {self._threshold:.3f} at window boundary "
                f"{max_idx}"
            ),
            metadata={
                "max_divergence": round(max_div, 4),
                "break_window_index": max_idx,
                "window_count": len(window_features),
                "token_count": len(tokens_with_spans),
            },
        )
