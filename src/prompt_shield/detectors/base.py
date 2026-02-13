"""Abstract base class for all prompt injection detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from prompt_shield.models import DetectionResult, Severity


class BaseDetector(ABC):
    """Base class for all prompt injection detectors.

    Community contributors: implement detect() and set the class attributes.
    That's it. Everything else is handled by the engine.
    """

    detector_id: str
    name: str
    description: str
    severity: Severity
    tags: list[str]
    version: str
    author: str

    @abstractmethod
    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        """Analyze input text for prompt injection patterns.

        Args:
            input_text: The user/untrusted input to scan.
            context: Optional metadata (conversation history, source, etc.)

        Returns:
            DetectionResult with confidence score, matched patterns, and explanation.
        """
        ...

    def setup(self, config: dict[str, object]) -> None:
        """Optional: called once during engine initialization for custom config."""

    def teardown(self) -> None:
        """Optional: cleanup resources."""
