"""Perplexity Spectral Analysis detector (d035).

Detects prompt-injection attacks by scoring per-token perplexity with a
lightweight language model and applying Page's CUSUM change-point statistic
to the resulting sequence.

Mechanism
---------

1. Tokenise the input with the LM's tokeniser and run a single forward
   pass to obtain per-position log-probabilities.
2. Convert each log-probability to per-token perplexity ``p_i = exp(-log p_i)``.
3. Run Page's (1954) CUSUM change-point detector on the perplexity sequence
   in sigma-normalised units:
   ``S_i = max(0, S_{i-1} + ((p_i - mean) / std - k))`` with mean / std
   estimated over the observed sequence and ``k`` (Page's allowance
   parameter, in sigma units) configured via ``cusum_k``. Sigma
   normalisation is required — raw per-token perplexity is heavy-tailed
   (values in the hundreds to millions are common for benign text), and
   an un-normalised CUSUM against a small threshold fires on every long
   benign input.
4. Track ``max(S_i)`` and its index. Fire when the max statistic exceeds
   ``threshold`` (in sigma units — Page's classic control-chart range
   is ``h ~= 4-5``, which is why the default is 5.0). Confidence is a
   bounded ramp on the CUSUM value.

Cross-domain origin: Page's CUSUM is the classical epidemiological /
industrial-quality-control change-point detector. Applying it to
language-model perplexity is the novelty. Encoded or obfuscated payloads
show sudden perplexity drops (repetitive high-probability sub-tokens);
adversarial imperatives written in a different register show spikes.
Either edge produces a run in the CUSUM statistic.

Design notes
------------

- Requires the ``ml`` extra (``pip install prompt-shield-ai[ml]``). If
  ``transformers`` is not installed the detector logs a WARNING and
  degrades to always ``detected=False`` (same soft-dep pattern as d022).
- Short inputs (< ``min_input_tokens`` word tokens) skip silently:
  per-token perplexity is noisy on very short strings and the CUSUM
  statistic has no room to accumulate.
- Uses ``distilgpt2`` by default: ~350MB, downloads on first use, runs on
  CPU in a few hundred milliseconds. Operators wanting stronger signal
  can point ``model_name`` at any causal-LM checkpoint compatible with
  ``AutoModelForCausalLM``.
- Severity is MEDIUM: perplexity is a soft signal, not high-confidence
  evidence. It contributes to the ensemble score but is not designed to
  block single-handedly.

Novelty: to our knowledge, Page-CUSUM on LM perplexity has been used for
authorship / stylometry change-point tasks but not for prompt-injection
detection. See paper section 4.6 for prior-art analysis.
"""

from __future__ import annotations

import logging
import math
from typing import Any, ClassVar

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger("prompt_shield.detectors.d035")

_DEFAULT_MODEL = "distilgpt2"


class PerplexitySpectralDetector(BaseDetector):
    """Perplexity + Page CUSUM change-point detector.

    Cross-domain: Page (1954) sequential change-point analysis applied to
    per-token language-model perplexity. Requires the ``ml`` extra.
    """

    detector_id: str = "d035_perplexity_spectral"
    name: str = "Perplexity Spectral Analysis (CUSUM)"
    description: str = (
        "Detects prompt injection via change-point detection on per-token "
        "perplexity. Cross-domain: Page (1954) CUSUM applied to "
        "language-model perplexity signals."
    )
    severity: Severity = Severity.MEDIUM
    tags: ClassVar[list[str]] = ["direct_injection", "obfuscation", "novel"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    # Defaults; overridable via per-detector config.
    _threshold: float = 5.0  # sigma-units (Page 1954 classic control-chart h ~= 4-5)
    _model_name: str = _DEFAULT_MODEL
    _min_input_tokens: int = 20
    _max_input_tokens: int = 2000
    _cusum_k: float = 0.5

    def __init__(self) -> None:
        self._tokenizer: Any | None = None
        self._model: Any | None = None
        self._available: bool | None = None  # None = not checked yet

    def setup(self, config: dict[str, object]) -> None:
        """Read tunable parameters from the per-detector config section."""

        def _as_float(key: str, default: float) -> float:
            v = config.get(key, default)
            return float(v) if isinstance(v, (int, float, str)) else default

        def _as_int(key: str, default: int) -> int:
            v = config.get(key, default)
            return int(v) if isinstance(v, (int, float, str)) else default

        self._threshold = _as_float("threshold", self._threshold)
        self._model_name = str(config.get("model_name", self._model_name))
        self._min_input_tokens = _as_int("min_input_tokens", self._min_input_tokens)
        self._max_input_tokens = _as_int("max_input_tokens", self._max_input_tokens)
        self._cusum_k = _as_float("cusum_k", self._cusum_k)

    def _ensure_model(self) -> bool:
        """Lazy-load the LM tokenizer + model. Returns True if available."""
        if self._available is not None:
            return self._available
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(self._model_name)
            self._model = AutoModelForCausalLM.from_pretrained(self._model_name)
            self._model.eval()
            self._available = True
            logger.info("Loaded perplexity model: %s", self._model_name)
        except ImportError:
            logger.warning(
                "d035 perplexity_spectral disabled: transformers not installed. "
                "Install with `pip install prompt-shield-ai[ml]` to enable "
                "perplexity-based change-point detection. Without it, "
                "encoded/obfuscated payloads may bypass this signal."
            )
            self._available = False
        except Exception as exc:
            logger.warning(
                "d035 perplexity_spectral disabled: failed to load model %s: %s",
                self._model_name,
                exc,
            )
            self._available = False
        return self._available

    def _compute_perplexity_sequence(self, input_text: str) -> list[float] | None:
        """Compute per-token perplexity for the input.

        Returns a list of positive floats, or None on failure. Truncates
        the input to ``_max_input_tokens`` model tokens before scoring.
        """
        try:
            import torch

            assert self._tokenizer is not None
            assert self._model is not None
            enc = self._tokenizer(
                input_text,
                return_tensors="pt",
                truncation=True,
                max_length=self._max_input_tokens,
            )
            input_ids = enc["input_ids"]
            if input_ids.shape[1] < 2:
                return []
            with torch.no_grad():
                outputs = self._model(input_ids)
            logits = outputs.logits  # (1, seq_len, vocab)
            # Shift so predictions align with next-token targets.
            shift_logits = logits[:, :-1, :]
            shift_labels = input_ids[:, 1:]
            log_probs = torch.log_softmax(shift_logits, dim=-1)
            gathered = log_probs.gather(2, shift_labels.unsqueeze(-1)).squeeze(-1)
            # per-token perplexity = exp(-log p)
            per_token_ppl = torch.exp(-gathered).squeeze(0).tolist()
            # Guard against inf/nan from occasional -inf logprobs.
            cleaned: list[float] = []
            for v in per_token_ppl:
                if v is None or math.isnan(v) or math.isinf(v):
                    cleaned.append(0.0)
                else:
                    cleaned.append(float(v))
            return cleaned
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("d035 perplexity computation failed: %s", exc)
            return None

    def _cusum(self, values: list[float]) -> tuple[float, int, float, float]:
        """Page (1954) CUSUM statistic in sigma-normalised units.

        Increments are `(v - mean)/std - k` — scale-free, so the statistic
        is comparable across texts regardless of the absolute perplexity
        scale (which is heavy-tailed for raw exp(-log p): one rare token
        yields perplexity in the millions). Classic control-chart threshold
        for sigma-units is h in [3, 5]; anything higher never fires,
        anything lower over-fires. See Page 1954 + Montgomery
        "Introduction to Statistical Quality Control" ch. 9.

        Returns ``(max_S, argmax_index, mean, std)``. When the sequence is
        empty or degenerate (zero std), returns ``(0.0, 0, mean, 0.0)`` so
        the caller never fires on a constant signal.
        """
        n = len(values)
        if n == 0:
            return 0.0, 0, 0.0, 0.0
        mean = sum(values) / n
        var = sum((v - mean) ** 2 for v in values) / n
        std = math.sqrt(var)
        # Guard against zero-variance sequences: no change point can exist,
        # and sigma-normalised increments would divide by zero.
        if std == 0.0:
            return 0.0, 0, mean, 0.0
        s = 0.0
        max_s = 0.0
        max_idx = 0
        for i, v in enumerate(values):
            # Sigma-units increment: (v - mean) / std - k
            increment = (v - mean) / std - self._cusum_k
            s = max(0.0, s + increment)
            if s > max_s:
                max_s = s
                max_idx = i
        return max_s, max_idx, mean, std

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        # Cheap gate: skip short inputs regardless of model availability.
        word_tokens = input_text.split()
        if len(word_tokens) < self._min_input_tokens:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Input below min_input_tokens threshold",
                metadata={"word_token_count": len(word_tokens)},
            )

        if not self._ensure_model():
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Perplexity model not available (transformers not installed)",
            )

        ppl_seq = self._compute_perplexity_sequence(input_text)
        if ppl_seq is None:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Perplexity computation failed",
            )
        if len(ppl_seq) < 2:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Too few tokens for CUSUM after tokenisation",
                metadata={"token_count": len(ppl_seq)},
            )

        max_s, cp_idx, mean_ppl, std_ppl = self._cusum(ppl_seq)

        metadata: dict[str, object] = {
            "cusum_statistic": round(max_s, 4),
            "change_point_token_index": cp_idx,
            "mean_perplexity": round(mean_ppl, 4),
            "std_perplexity": round(std_ppl, 4),
            "sequence_length": len(ppl_seq),
        }

        if max_s < self._threshold:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(f"CUSUM statistic {max_s:.3f} below threshold {self._threshold:.3f}"),
                metadata=metadata,
            )

        # Confidence normalisation: map max_s / (10 * threshold) into [0, 1].
        # A statistic exactly at threshold reports ~0.1 confidence; a
        # statistic 10x threshold saturates at 1.0.
        confidence = min(max_s / (10.0 * self._threshold), 1.0)

        # Estimate a character-window around the change point. The LM
        # tokeniser splits sub-word units; we approximate by mapping the
        # change-point-token fraction to a character offset in the
        # original text, then take a ~120-char window around it.
        frac = (cp_idx + 1) / max(1, len(ppl_seq))
        approx_char = int(frac * len(input_text))
        win_start = max(0, approx_char - 60)
        win_end = min(len(input_text), approx_char + 60)
        matched_text = input_text[win_start:win_end]

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=[
                MatchDetail(
                    pattern="perplexity_change_point",
                    matched_text=matched_text,
                    position=(win_start, win_end),
                    description=(
                        f"Page CUSUM statistic {max_s:.3f} exceeds threshold "
                        f"{self._threshold:.3f} at token index {cp_idx} "
                        f"(mean ppl={mean_ppl:.3f}, std ppl={std_ppl:.3f})"
                    ),
                )
            ],
            explanation=(
                f"Perplexity change-point detected: CUSUM {max_s:.3f} > "
                f"{self._threshold:.3f} at token {cp_idx}/{len(ppl_seq)}"
            ),
            metadata=metadata,
        )

    def teardown(self) -> None:
        """Release model resources."""
        self._tokenizer = None
        self._model = None
        self._available = None
