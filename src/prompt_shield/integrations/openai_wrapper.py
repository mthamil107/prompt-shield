"""OpenAI client wrapper for automatic prompt-shield scanning."""

from __future__ import annotations

import logging
from typing import Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action
from prompt_shield.tool_guard.guard import ToolResultGuard

logger = logging.getLogger("prompt_shield.openai")


def _extract_openai_message_text(content: Any) -> str:
    """Extract string text from OpenAI message content (string or list of content parts)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join(parts)
    return str(content)


class PromptShieldOpenAI:
    """Wraps an OpenAI client to auto-scan inputs, outputs, and tool results.

    v0.8.0 adds ``role="tool"`` and ``role="function"`` message scanning:
    when the ``messages`` list contains messages with ``role="tool"`` or
    ``role="function"`` (OpenAI's tool/function result message format),
    each message's text is scanned through ``ToolResultGuard`` before the
    request is forwarded. ``tool_result_mode`` controls tool result scanning
    ('block', 'flag', 'log', 'monitor'); 'sanitize' is not supported by this wrapper.

    Usage::

        from openai import OpenAI
        from prompt_shield.integrations.openai_wrapper import PromptShieldOpenAI

        client = OpenAI()
        shield = PromptShieldOpenAI(client=client, mode="block")
        response = shield.create(model="gpt-4o", messages=[...])
    """

    def __init__(
        self,
        client: Any = None,
        engine: PromptShieldEngine | None = None,
        mode: str = "block",
        scan_responses: bool = False,
        scan_tool_results: bool = True,
        tool_result_mode: str | None = None,
    ) -> None:
        if client is None:
            try:
                from openai import OpenAI

                client = OpenAI()
            except ImportError as exc:
                raise ImportError(
                    "Install openai extras: pip install prompt-shield[openai]"
                ) from exc
        self._client = client
        self._engine = engine or PromptShieldEngine()
        self.mode = mode
        self.scan_responses = scan_responses
        self.scan_tool_results = scan_tool_results

        effective_tool_mode = mode if tool_result_mode is None else tool_result_mode
        if effective_tool_mode == "sanitize":
            raise ValueError("tool_result_mode='sanitize' is not supported by PromptShieldOpenAI")
        valid_modes = ("block", "flag", "log", "monitor")
        if effective_tool_mode not in valid_modes:
            raise ValueError(
                f"tool_result_mode must be one of {valid_modes}, got {effective_tool_mode!r}"
            )
        self.tool_result_mode = effective_tool_mode
        # mode="log" so this wrapper controls block/flag via tool_result_mode.
        self._tool_guard = ToolResultGuard(engine=self._engine, mode="log")

    def create(self, **kwargs: Any) -> Any:
        """Scan messages, call ``chat.completions.create``, optionally scan response."""
        messages = kwargs.get("messages", [])

        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content")

            if role in ("tool", "function"):
                if not self.scan_tool_results:
                    continue
                text = _extract_openai_message_text(content)
                if not text:
                    continue
                tool_name = msg.get("name") or msg.get("tool_call_id")
                if not isinstance(tool_name, str):
                    tool_name = None
                report = self._tool_guard.scan(
                    text,
                    tool_name=tool_name,
                    tool_type="openai_tool",
                )
                if report.action == Action.BLOCK and self.tool_result_mode == "block":
                    families = (
                        [f.value for f in report.scan_context.attack_families]
                        if report.scan_context
                        else []
                    )
                    raise ValueError(
                        f"prompt-shield BLOCKED tool_result message "
                        f"(scan_id={report.scan_id}, tool_name={tool_name}, "
                        f"families={families})"
                    )
                if report.detections:
                    families = (
                        [f.value for f in report.scan_context.attack_families]
                        if report.scan_context
                        else []
                    )
                    logger.warning(
                        "Suspicious content in tool_result message (role=%s, tool_name=%s): "
                        "%s (families=%s)",
                        role,
                        tool_name,
                        report.scan_id,
                        families,
                    )
                continue

            if not content:
                continue
            text = _extract_openai_message_text(content)
            if not text:
                continue

            report = self._engine.scan(
                text,
                context={
                    "gate": "input",
                    "source": "openai",
                    "role": role,
                },
            )
            if report.action == Action.BLOCK and self.mode == "block":
                raise ValueError(
                    f"Prompt injection detected by prompt-shield: "
                    f"{report.scan_id} (risk={report.overall_risk_score:.2f})"
                )
            if report.detections:
                logger.warning(
                    "Suspicious content in %s message: %s",
                    role,
                    report.scan_id,
                )

        response = self._client.chat.completions.create(**kwargs)

        if self.scan_responses and hasattr(response, "choices"):
            for choice in response.choices:
                text = getattr(getattr(choice, "message", None), "content", None)
                if text:
                    resp_report = self._engine.scan(
                        text,
                        context={"gate": "output", "source": "openai"},
                    )
                    if resp_report.detections:
                        logger.warning(
                            "Suspicious content in response: %s",
                            resp_report.scan_id,
                        )

        return response

    @property
    def engine(self) -> PromptShieldEngine:
        """Access the underlying scanning engine."""
        return self._engine
