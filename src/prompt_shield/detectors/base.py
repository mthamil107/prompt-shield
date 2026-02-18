"""Abstract base class for all prompt injection detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
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
    tags: ClassVar[list[str]]
    version: str
    author: str

    @abstractmethod
    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        """Analyze input text for prompt injection patterns.

        Args:
            input_text: The user/untrusted input to scan.
            context: Optional metadata (conversation history, source, etc.)

        Returns:
            DetectionResult with confidence score, matched patterns, and explanation.
        """
        ...

    def setup(self, config: dict[str, object]) -> None:  # noqa: B027
        """Optional: called once during engine initialization for custom config."""

    def teardown(self) -> None:  # noqa: B027
        """Optional: cleanup resources."""
