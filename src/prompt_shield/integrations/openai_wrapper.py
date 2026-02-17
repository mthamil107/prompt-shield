"""OpenAI client wrapper for automatic prompt-shield scanning."""

from __future__ import annotations

import logging
from typing import Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action

logger = logging.getLogger("prompt_shield.openai")


class PromptShieldOpenAI:
    """Wraps an OpenAI client to auto-scan inputs and outputs.

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

    def create(self, **kwargs: Any) -> Any:
        """Scan messages, call ``chat.completions.create``, optionally scan response."""
        messages = kwargs.get("messages", [])

        for msg in messages:
            content = msg.get("content")
            if not content or not isinstance(content, str):
                continue
            report = self._engine.scan(
                content,
                context={
                    "gate": "input",
                    "source": "openai",
                    "role": msg.get("role", "unknown"),
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
                    msg.get("role", "unknown"),
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
