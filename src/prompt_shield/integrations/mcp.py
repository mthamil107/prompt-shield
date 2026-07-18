"""MCP tool result filter — wraps MCP servers to auto-scan tool outputs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from prompt_shield.models import Action
from prompt_shield.tool_guard._sanitize import sanitize_text
from prompt_shield.tool_guard.guard import ToolResultGuard

if TYPE_CHECKING:
    from prompt_shield.engine import PromptShieldEngine


class PromptShieldMCPFilter:
    """Transparent MCP proxy that scans tool results for indirect injection."""

    def __init__(
        self,
        server: Any,
        engine: PromptShieldEngine,
        scan_results: bool = True,
        scan_tool_args: bool = True,
        mode: str = "sanitize",
        exempt_tools: list[str] | None = None,
        sanitize_replacement: str = "[REDACTED by prompt-shield]",
    ) -> None:
        self._server = server
        self._engine = engine
        self.scan_results = scan_results
        self.scan_tool_args = scan_tool_args
        self.mode = mode
        self.exempt_tools = set(exempt_tools or [])
        self.sanitize_replacement = sanitize_replacement
        self._stats = {"total_calls": 0, "blocked": 0, "sanitized": 0, "passed": 0}
        # Delegate tool-result scanning to the first-class primitive.
        self._tool_guard = ToolResultGuard(
            engine=engine, mode="log", sanitize_replacement=sanitize_replacement
        )

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        self._stats["total_calls"] += 1

        # Scan tool args
        if self.scan_tool_args and tool_name not in self.exempt_tools:
            import json

            args_text = json.dumps(arguments, default=str)
            args_report = self._engine.scan(
                args_text, context={"gate": "tool_call", "tool": tool_name}
            )
            if args_report.action == Action.BLOCK:
                self._stats["blocked"] += 1
                return f"[Tool call blocked by prompt-shield: {tool_name}]"

        # Forward to real server
        result = await self._server.call_tool(tool_name, arguments)

        # Scan results
        if self.scan_results and tool_name not in self.exempt_tools:
            result_text = str(result)
            report = self._tool_guard.scan(result_text, tool_name=tool_name)

            if report.detections:
                if self.mode == "block":
                    self._stats["blocked"] += 1
                    return (
                        f"[Tool result blocked by prompt-shield: injection detected in {tool_name}]"
                    )
                elif self.mode == "sanitize":
                    self._stats["sanitized"] += 1
                    return sanitize_text(result_text, report, replacement=self.sanitize_replacement)
                # flag/log modes pass through

        self._stats["passed"] += 1
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        return self._server.list_tools()

    @property
    def scan_stats(self) -> dict[str, int]:
        return dict(self._stats)
