"""Anthropic client wrapper for automatic prompt-shield scanning."""

from __future__ import annotations

import logging
from typing import Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action
from prompt_shield.tool_guard.guard import ToolResultGuard

logger = logging.getLogger("prompt_shield.anthropic")


def _extract_tool_result_text(content: Any) -> str:
    """Anthropic's ``tool_result`` block content may be a string, a list of
    ``{"type": "text", "text": ...}`` (and ``"image"``) blocks, or omitted.
    Concatenate all text portions; ignore non-text blocks."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


class PromptShieldAnthropic:
    """Wraps an Anthropic client to auto-scan inputs, outputs, and tool results.

    v0.7.0 adds ``tool_result`` block scanning: when the ``messages`` list
    contains a user message whose content includes one or more
    ``{"type": "tool_result", "content": ...}`` blocks (Anthropic's native
    shape for agent tool outputs), each block's text is scanned through
    ``ToolResultGuard`` before the request is forwarded. Blocks are
    classified into ``ToolResultAttackFamily`` values available via
    ``report.scan_context.attack_families``.

    Usage::

        from anthropic import Anthropic
        from prompt_shield.integrations.anthropic_wrapper import PromptShieldAnthropic

        client = Anthropic()
        shield = PromptShieldAnthropic(client=client, mode="block")
        response = shield.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(
        self,
        client: Any = None,
        engine: PromptShieldEngine | None = None,
        mode: str = "block",
        scan_responses: bool = False,
        scan_tool_results: bool = True,
        tool_result_mode: str = "block",
    ) -> None:
        if client is None:
            try:
                from anthropic import Anthropic

                client = Anthropic()
            except ImportError as exc:
                raise ImportError(
                    "Install anthropic extras: pip install prompt-shield[anthropic]"
                ) from exc
        self._client = client
        self._engine = engine or PromptShieldEngine()
        self.mode = mode
        self.scan_responses = scan_responses
        self.scan_tool_results = scan_tool_results
        self.tool_result_mode = tool_result_mode
        # mode="log" so this wrapper controls block/flag via tool_result_mode.
        self._tool_guard = ToolResultGuard(engine=self._engine, mode="log")

    def create(self, **kwargs: Any) -> Any:
        """Scan messages, call ``messages.create``, optionally scan response.

        v0.7.0: also scans ``tool_result`` blocks inside a message's
        content list (Anthropic's native shape for agent tool outputs).
        """
        messages = kwargs.get("messages", [])

        for msg in messages:
            content = msg.get("content")

            if isinstance(content, list):
                self._scan_tool_result_blocks(content, role=msg.get("role", "unknown"))

            if isinstance(content, str):
                texts = [content]
            elif isinstance(content, list):
                texts = [
                    block.get("text", "")
                    if isinstance(block, dict) and block.get("type") != "tool_result"
                    else ""
                    for block in content
                ]
            else:
                continue

            for text in texts:
                if not text:
                    continue
                report = self._engine.scan(
                    text,
                    context={
                        "gate": "input",
                        "source": "anthropic",
                        "role": msg.get("role", "unknown"),
                    },
                )
                if report.action == Action.BLOCK and self.mode == "block":
                    raise ValueError(
                        f"Prompt injection detected by prompt-shield: "
                        f"{report.scan_id} "
                        f"(risk={report.overall_risk_score:.2f})"
                    )
                if report.detections:
                    logger.warning(
                        "Suspicious content in %s message: %s",
                        msg.get("role", "unknown"),
                        report.scan_id,
                    )

        response = self._client.messages.create(**kwargs)

        if self.scan_responses and hasattr(response, "content"):
            for block in response.content:
                text = getattr(block, "text", None)
                if text:
                    resp_report = self._engine.scan(
                        text,
                        context={"gate": "output", "source": "anthropic"},
                    )
                    if resp_report.detections:
                        logger.warning(
                            "Suspicious content in response: %s",
                            resp_report.scan_id,
                        )

        return response

    def _scan_tool_result_blocks(self, content: list[Any], role: str) -> None:
        """Scan every ``{"type": "tool_result", ...}`` block in a message's content list."""
        if not self.scan_tool_results:
            return
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            text = _extract_tool_result_text(block.get("content"))
            if not text:
                continue
            tool_use_id = block.get("tool_use_id")
            report = self._tool_guard.scan(
                text,
                tool_name=tool_use_id if isinstance(tool_use_id, str) else None,
                tool_type="anthropic_tool",
            )
            if report.action == Action.BLOCK and self.tool_result_mode == "block":
                families = (
                    [f.value for f in report.scan_context.attack_families]
                    if report.scan_context
                    else []
                )
                raise ValueError(
                    f"prompt-shield BLOCKED tool_result block "
                    f"(scan_id={report.scan_id}, tool_use_id={tool_use_id}, "
                    f"families={families})"
                )
            if report.detections:
                families = (
                    [f.value for f in report.scan_context.attack_families]
                    if report.scan_context
                    else []
                )
                logger.warning(
                    "Suspicious content in tool_result block (role=%s, tool_use_id=%s): "
                    "%s (families=%s)",
                    role,
                    tool_use_id,
                    report.scan_id,
                    families,
                )

    @property
    def engine(self) -> PromptShieldEngine:
        """Access the underlying scanning engine."""
        return self._engine
