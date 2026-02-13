"""LlamaIndex handler for prompt-shield scanning."""

from __future__ import annotations
import logging
from typing import Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action

logger = logging.getLogger("prompt_shield.llamaindex")


class PromptShieldHandler:
    """LlamaIndex integration that scans queries and retrieved content."""

    def __init__(
        self,
        engine: PromptShieldEngine | None = None,
        mode: str = "block",
        scan_retrieved: bool = True,
    ) -> None:
        self.engine = engine or PromptShieldEngine()
        self.mode = mode
        self.scan_retrieved = scan_retrieved

    def scan_query(self, query: str) -> None:
        """Scan user query before processing."""
        report = self.engine.scan(query, context={"gate": "input", "source": "llamaindex"})
        if report.action == Action.BLOCK and self.mode == "block":
            raise ValueError(f"Prompt injection detected by prompt-shield: {report.scan_id}")

    def scan_retrieved_nodes(self, nodes: list[Any]) -> list[Any]:
        """Scan retrieved nodes for indirect injection. Returns filtered list."""
        if not self.scan_retrieved:
            return nodes
        safe_nodes = []
        for node in nodes:
            text = getattr(node, "text", str(node))
            report = self.engine.scan(text, context={"gate": "tool_result", "source": "llamaindex"})
            if report.action == Action.BLOCK:
                logger.warning("Blocked poisoned node: %s", report.scan_id)
                continue
            safe_nodes.append(node)
        return safe_nodes

    def scan_response(self, response_text: str) -> None:
        """Scan final response."""
        report = self.engine.scan(response_text, context={"gate": "output", "source": "llamaindex"})
        if report.detections:
            logger.warning("Suspicious patterns in response: %s", report.scan_id)
