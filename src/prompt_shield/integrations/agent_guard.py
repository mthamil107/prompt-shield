"""Universal 3-gate protection for agentic LLM applications."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from prompt_shield.models import Action, GateResult, ScanReport
from prompt_shield.tool_guard._sanitize import sanitize_text
from prompt_shield.tool_guard.guard import ToolResultGuard

if TYPE_CHECKING:
    from prompt_shield.engine import PromptShieldEngine


class AgentGuard:
    """Universal 3-gate protection for agentic LLM applications."""

    def __init__(
        self,
        engine: PromptShieldEngine,
        input_mode: str = "block",
        data_mode: str = "sanitize",
        output_mode: str = "block",
        sanitize_replacement: str = "[REDACTED by prompt-shield]",
    ) -> None:
        self.engine = engine
        self.input_mode = input_mode
        self.data_mode = data_mode
        self.output_mode = output_mode
        self.sanitize_replacement = sanitize_replacement
        # Delegate tool-result scanning to the first-class primitive.
        # mode="log" so this AgentGuard controls block/sanitize/flag decisions
        # via its own data_mode (preserving pre-v0.7.0 external behavior).
        self._tool_guard = ToolResultGuard(
            engine=engine, mode="log", sanitize_replacement=sanitize_replacement
        )

    def scan_input(self, user_message: str, context: dict[str, object] | None = None) -> GateResult:
        """Gate 1: Scan user input."""
        ctx = dict(context) if context else {}
        ctx["gate"] = "input"
        report = self.engine.scan(user_message, context=ctx)
        blocked = self._should_block(report, self.input_mode)
        return GateResult(
            gate="input",
            action=report.action if blocked else Action.PASS,
            blocked=blocked,
            scan_report=report,
            explanation=self._build_explanation(report) if blocked else "Input passed",
        )

    def scan_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        context: dict[str, object] | None = None,
    ) -> GateResult:
        """Gate 2b: Scan tool arguments before execution."""
        ctx = dict(context) if context else {}
        ctx["gate"] = "tool_call"
        ctx["tool"] = tool_name
        args_text = json.dumps(args, default=str)
        report = self.engine.scan(args_text, context=ctx)
        blocked = self._should_block(report, self.input_mode)
        return GateResult(
            gate="tool_call",
            action=report.action if blocked else Action.PASS,
            blocked=blocked,
            scan_report=report,
            explanation=self._build_explanation(report) if blocked else "Tool call passed",
        )

    def scan_tool_result(
        self, tool_name: str, result: str, context: dict[str, object] | None = None
    ) -> GateResult:
        """Gate 2: Scan tool result for indirect injection.

        Delegates to :class:`~prompt_shield.tool_guard.ToolResultGuard` for
        the scan + attack-family classification, then applies this
        ``AgentGuard``'s ``data_mode`` policy on top. Attack-family
        metadata is exposed via ``GateResult.metadata['attack_families']``
        and ``GateResult.metadata['scan_context']`` (added in v0.7.0);
        the return type and existing fields are unchanged.
        """
        tool_type = str(context.get("tool_type")) if context and "tool_type" in context else None
        parent_scan_id = (
            str(context.get("parent_scan_id")) if context and "parent_scan_id" in context else None
        )
        report = self._tool_guard.scan(
            result,
            tool_name=tool_name,
            tool_type=tool_type,
            parent_scan_id=parent_scan_id,
        )
        scan_ctx = report.scan_context
        families = [f.value for f in scan_ctx.attack_families] if scan_ctx else []
        gate_meta: dict[str, object] = {"attack_families": families}
        if scan_ctx is not None:
            gate_meta["scan_context"] = scan_ctx.model_dump()

        has_detection = report.action != Action.PASS and report.detections

        if not has_detection:
            return GateResult(
                gate="tool_result",
                action=Action.PASS,
                blocked=False,
                scan_report=report,
                explanation="Tool result passed",
                metadata=gate_meta,
            )

        if self.data_mode == "sanitize":
            sanitized = sanitize_text(result, report, replacement=self.sanitize_replacement)
            return GateResult(
                gate="tool_result",
                action=Action.FLAG,
                blocked=False,
                scan_report=report,
                explanation="Tool result sanitized",
                sanitized_text=sanitized,
                metadata=gate_meta,
            )

        blocked = self._should_block(report, self.data_mode)
        return GateResult(
            gate="tool_result",
            action=report.action if blocked else Action.FLAG,
            blocked=blocked,
            scan_report=report,
            explanation=self._build_explanation(report) if blocked else "Tool result flagged",
            sanitized_text=(
                sanitize_text(result, report, replacement=self.sanitize_replacement)
                if not blocked
                else None
            ),
            metadata=gate_meta,
        )

    def prepare_prompt(self, system_prompt: str) -> tuple[str, str]:
        """Gate 3a: Add canary token to system prompt."""
        return self.engine.add_canary(system_prompt)

    def scan_output(
        self, llm_response: str, canary_token: str, original_input: str | None = None
    ) -> GateResult:
        """Gate 3b: Check LLM output for canary leakage."""
        leaked = self.engine.check_canary(llm_response, canary_token, original_input=original_input)
        if leaked:
            blocked = self.output_mode == "block"
            return GateResult(
                gate="output",
                action=Action.BLOCK if blocked else Action.FLAG,
                blocked=blocked,
                explanation="Canary token leaked in LLM response",
                canary_leaked=True,
            )
        return GateResult(
            gate="output",
            action=Action.PASS,
            blocked=False,
            explanation="Output passed canary check",
        )

    def scan_multi_hop(self, messages: list[dict[str, str]]) -> list[GateResult]:
        """Scan an entire multi-hop agent conversation."""
        results = []
        history: list[str] = []
        for msg in messages:
            content = msg.get("content", "")
            ctx: dict[str, object] = {
                "gate": "multi_hop",
                "conversation_history": history,
            }
            report = self.engine.scan(content, context=ctx)
            if report.detections:
                results.append(
                    GateResult(
                        gate="multi_hop",
                        action=report.action,
                        blocked=report.action == Action.BLOCK,
                        scan_report=report,
                        explanation=self._build_explanation(report),
                    )
                )
            history.append(content)
        return results

    def _should_block(self, report: ScanReport, mode: str) -> bool:
        if mode == "block" and report.action in (Action.BLOCK,):
            return True
        return bool(mode == "block" and report.detections)

    def _build_explanation(self, report: ScanReport) -> str:
        if not report.detections:
            return "No detections"
        top = max(report.detections, key=lambda d: d.confidence)
        return f"{top.detector_id}: {top.explanation} (confidence: {top.confidence:.2f})"

    def _sanitize_text(self, text: str, report: ScanReport) -> str:
        """Backward-compat shim — delegates to shared ``tool_guard._sanitize.sanitize_text``."""
        return sanitize_text(text, report, replacement=self.sanitize_replacement)
