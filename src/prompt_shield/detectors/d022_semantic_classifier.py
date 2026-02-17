"""Semantic ML-based prompt injection classifier."""

from __future__ import annotations

import logging
from typing import Any

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
        "ML-based semantic prompt injection detection using a "
        "pre-trained transformer classifier"
    )
    severity: Severity = Severity.HIGH
    tags: list[str] = ["ml", "semantic"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        self._pipeline: Any | None = None
        self._model_name: str = _DEFAULT_MODEL
        self._device: str = "cpu"
        self._available: bool | None = None  # None = not checked yet

    def setup(self, config: dict[str, object]) -> None:
        """Read model_name and device from per-detector config."""
        self._model_name = str(config.get("model_name", _DEFAULT_MODEL))
        self._device = str(config.get("device", "cpu"))

    def _ensure_pipeline(self) -> bool:
        """Lazy-load the classification pipeline. Returns True if available."""
        if self._available is not None:
            return self._available
        try:
            from transformers import pipeline as hf_pipeline

            device_arg = (
                -1
                if self._device == "cpu"
                else int(self._device.split(":")[-1])
            )
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
            logger.info(
                "transformers not installed; d022 semantic classifier disabled"
            )
            self._available = False
        except Exception as exc:
            logger.warning("Failed to load semantic classifier: %s", exc)
            self._available = False
        return self._available

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        if not self._ensure_pipeline():
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    "ML classifier not available (transformers not installed)"
                ),
            )

        try:
            result = self._pipeline(input_text[:512])
            label = result[0]["label"].upper()
            score = float(result[0]["score"])

            if label == "INJECTION" and score > 0.5:
                return DetectionResult(
                    detector_id=self.detector_id,
                    detected=True,
                    confidence=score,
                    severity=self.severity,
                    matches=[
                        MatchDetail(
                            pattern="semantic_classifier",
                            matched_text=input_text[:120]
                            + ("..." if len(input_text) > 120 else ""),
                            position=(0, min(len(input_text), 512)),
                            description=(
                                f"Classified as injection with score {score:.4f}"
                            ),
                        )
                    ],
                    explanation=(
                        f"Semantic classifier detected injection "
                        f"(confidence: {score:.4f})"
                    ),
                )

            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    f"Classified as safe (label={label}, score={score:.4f})"
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
