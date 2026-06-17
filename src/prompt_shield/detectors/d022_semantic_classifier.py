"""Semantic ML-based prompt injection classifier."""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger("prompt_shield.detectors.d022")

_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


class SemanticClassifierDetector(BaseDetector):
    """Uses a pre-trained transformer to classify prompt injection semantically.

    Requires the ``ml`` extra: ``pip install prompt-shield[ml]``.
    If the *transformers* library is not installed, this detector silently
    returns ``detected=False`` on every call.
    """

    detector_id: str = "d022_semantic_classifier"
    name: str = "Semantic Classifier"
    description: str = (
        "ML-based semantic prompt injection detection using a pre-trained transformer classifier"
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["ml", "semantic"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        self._pipeline: Any | None = None
        self._model_name: str = _DEFAULT_MODEL
        self._device: str = "cpu"
        self._available: bool | None = None  # None = not checked yet
        # Chunking defaults; setup() may override.
        self._chunk_size: int = 512
        self._chunk_stride: int = 384
        self._max_chunks: int = 8

    def setup(self, config: dict[str, object]) -> None:
        """Read model_name and device from per-detector config."""
        self._model_name = str(config.get("model_name", _DEFAULT_MODEL))
        self._device = str(config.get("device", "cpu"))
        # Long-input handling: chunk + max-pool aggregation.
        # Window = 512 chars (the model's per-call cap), stride = 384 chars
        # (75% overlap, so each token is scored in at least two windows).
        # Max chunks bounds wall-clock; the model is ~10ms per call on CPU,
        # so 8 chunks = ~80ms worst case for very long inputs.
        chunk_size = config.get("chunk_size", 512)
        chunk_stride = config.get("chunk_stride", 384)
        max_chunks = config.get("max_chunks", 8)
        self._chunk_size = int(chunk_size) if isinstance(chunk_size, (int, float, str)) else 512
        self._chunk_stride = int(chunk_stride) if isinstance(chunk_stride, (int, float, str)) else 384
        self._max_chunks = int(max_chunks) if isinstance(max_chunks, (int, float, str)) else 8

    def _ensure_pipeline(self) -> bool:
        """Lazy-load the classification pipeline. Returns True if available."""
        if self._available is not None:
            return self._available
        try:
            from transformers import pipeline as hf_pipeline

            device_arg = -1 if self._device == "cpu" else int(self._device.split(":")[-1])
            self._pipeline = hf_pipeline(
                "text-classification",
                model=self._model_name,
                device=device_arg,
                truncation=True,
                max_length=512,
            )
            self._available = True
            logger.info("Loaded semantic classifier: %s", self._model_name)
        except ImportError:
            logger.info("transformers not installed; d022 semantic classifier disabled")
            self._available = False
        except Exception as exc:
            logger.warning("Failed to load semantic classifier: %s", exc)
            self._available = False
        return self._available

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        if not self._ensure_pipeline():
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=("ML classifier not available (transformers not installed)"),
            )

        try:
            # Chunk long inputs with overlap; score each chunk; max-pool the
            # confidences. Previously the d022 detector truncated to 512 chars
            # and ignored anything beyond; injections placed late in a long
            # document slipped through.
            chunks = self._chunk(input_text)
            best_score = 0.0
            best_label = "SAFE"
            best_span = (0, min(len(input_text), self._chunk_size))
            for start, end, chunk_text in chunks:
                pred = self._pipeline(chunk_text)
                label = pred[0]["label"].upper()
                score = float(pred[0]["score"])
                if label == "INJECTION" and score > best_score:
                    best_score = score
                    best_label = "INJECTION"
                    best_span = (start, end)

            if best_label == "INJECTION" and best_score > 0.5:
                start, end = best_span
                return DetectionResult(
                    detector_id=self.detector_id,
                    detected=True,
                    confidence=best_score,
                    severity=self.severity,
                    matches=[
                        MatchDetail(
                            pattern="semantic_classifier",
                            matched_text=input_text[start : start + min(120, end - start)]
                            + ("..." if end - start > 120 else ""),
                            position=best_span,
                            description=(
                                f"Classified as injection with score {best_score:.4f} "
                                f"on chunk [{start}:{end}]"
                            ),
                        )
                    ],
                    explanation=(
                        f"Semantic classifier detected injection "
                        f"(confidence: {best_score:.4f}, "
                        f"window [{start}:{end}] of {len(input_text)}-char input)"
                    ),
                )

            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    f"Classified as safe across {len(chunks)} chunk(s) "
                    f"(max score: {best_score:.4f})"
                ),
            )
        except Exception as exc:
            logger.warning("Semantic classification failed: %s", exc)
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=f"Classification failed: {exc}",
            )

    def teardown(self) -> None:
        """Release model resources."""
        self._pipeline = None
        self._available = None

    def _chunk(self, text: str) -> list[tuple[int, int, str]]:
        """Split text into overlapping windows for chunked scoring.

        Returns list of (start, end, text). For short inputs returns a single
        chunk. The max-pool aggregation in detect() takes the maximum
        injection-confidence across all chunks, so an attack in any window
        produces a detection.
        """
        if len(text) <= self._chunk_size:
            return [(0, len(text), text)]
        chunks: list[tuple[int, int, str]] = []
        start = 0
        while start < len(text) and len(chunks) < self._max_chunks:
            end = min(start + self._chunk_size, len(text))
            chunks.append((start, end, text[start:end]))
            if end >= len(text):
                break
            start += self._chunk_stride
        return chunks
