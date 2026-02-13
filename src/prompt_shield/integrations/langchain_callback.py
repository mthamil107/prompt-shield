"""LangChain callback handler for prompt-shield scanning."""

from __future__ import annotations
import logging
from typing import Any, TYPE_CHECKING

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError("Install langchain extras: pip install prompt-shield[langchain]")

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action

logger = logging.getLogger("prompt_shield.langchain")


class PromptShieldCallback(BaseCallbackHandler):
    """LangChain callback that scans prompts, tool results, and outputs."""

    def __init__(
        self,
        engine: PromptShieldEngine | None = None,
        mode: str = "block",
        scan_tool_results: bool = True,
        tool_result_mode: str = "sanitize",
        enable_canary: bool = False,
    ) -> None:
        self.engine = engine or PromptShieldEngine()
        self.mode = mode
        self.scan_tool_results = scan_tool_results
        self.tool_result_mode = tool_result_mode
        self.enable_canary = enable_canary
        self._canary_token: str | None = None

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        """Scan prompts before sending to LLM (input gate)."""
        for prompt in prompts:
            report = self.engine.scan(prompt, context={"gate": "input", "source": "langchain"})
            if report.action == Action.BLOCK and self.mode == "block":
                raise ValueError(f"Prompt injection detected by prompt-shield: {report.scan_id}")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Scan tool output (data gate)."""
        if not self.scan_tool_results:
            return
        report = self.engine.scan(str(output), context={"gate": "tool_result", "source": "langchain"})
        if report.action == Action.BLOCK and self.tool_result_mode == "block":
            raise ValueError(f"Injection detected in tool result: {report.scan_id}")
        if report.detections:
            logger.warning("Suspicious content in tool result: %s", report.scan_id)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Check output for canary leakage (output gate)."""
        if not self.enable_canary or not self._canary_token:
            return
        text = str(response)
        if self.engine.check_canary(text, self._canary_token):
            logger.critical("Canary token leaked in LLM response!")

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        """Log chain errors that may be from prompt-shield blocks."""
        if "prompt-shield" in str(error):
            logger.warning("Chain blocked by prompt-shield: %s", error)
