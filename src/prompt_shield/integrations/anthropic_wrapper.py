"""Anthropic client wrapper for automatic prompt-shield scanning."""

from __future__ import annotations

import logging
from typing import Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action

logger = logging.getLogger("prompt_shield.anthropic")


class PromptShieldAnthropic:
    """Wraps an Anthropic client to auto-scan inputs and outputs.

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
    ) -> None:
        if client is None:
            try:
                from anthropic import Anthropic

                client = Anthropic()
            except ImportError as exc:
                raise ImportError(
                    "Install anthropic extras: "
                    "pip install prompt-shield[anthropic]"
                ) from exc
        self._client = client
        self._engine = engine or PromptShieldEngine()
        self.mode = mode
        self.scan_responses = scan_responses

    def create(self, **kwargs: Any) -> Any:
        """Scan messages, call ``messages.create``, optionally scan response."""
        messages = kwargs.get("messages", [])

        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                texts = [content]
            elif isinstance(content, list):
                texts = [
                    block.get("text", "")
                    if isinstance(block, dict)
                    else str(block)
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

    @property
    def engine(self) -> PromptShieldEngine:
        """Access the underlying scanning engine."""
        return self._engine
