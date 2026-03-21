"""Abstract base class for all output scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from prompt_shield.output_scanners.models import OutputScanResult


class BaseOutputScanner(ABC):
    """Base class for output scanners that analyse LLM-generated text.

    Subclasses must set the class attributes and implement :meth:`scan`.
    """

    scanner_id: str
    name: str
    description: str

    @abstractmethod
    def scan(
        self, output_text: str, context: dict[str, object] | None = None
    ) -> OutputScanResult:
        """Scan *output_text* for harmful or policy-violating content.

        Args:
            output_text: The LLM-generated text to analyse.
            context: Optional metadata (conversation history, user role, etc.)

        Returns:
            An :class:`OutputScanResult` indicating whether the text was flagged.
        """
        ...

    def setup(self, config: dict[str, object]) -> None:  # noqa: B027
        """Optional: called once during initialisation for custom config."""
