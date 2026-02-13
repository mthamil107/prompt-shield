"""Universal 3-gate protection for agentic LLM applications."""

from __future__ import annotations
import json
from typing import TYPE_CHECKING, Any

from prompt_shield.models import Action, GateResult, ScanReport

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

    def scan_tool_call(self, tool_name: str, args: dict[str, Any], context: dict[str, object] | None = None) -> GateResult:
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

    def scan_tool_result(self, tool_name: str, result: str, context: dict[str, object] | None = None) -> GateResult:
        """Gate 2: Scan tool result for indirect injection."""
        ctx = dict(context) if context else {}
        ctx["gate"] = "tool_result"
        ctx["tool"] = tool_name
        report = self.engine.scan(result, context=ctx)
        has_detection = report.action != Action.PASS and report.detections

        if not has_detection:
            return GateResult(gate="tool_result", action=Action.PASS, blocked=False, scan_report=report, explanation="Tool result passed")

        if self.data_mode == "sanitize":
            sanitized = self._sanitize_text(result, report)
            return GateResult(gate="tool_result", action=Action.FLAG, blocked=False, scan_report=report, explanation="Tool result sanitized", sanitized_text=sanitized)

        blocked = self._should_block(report, self.data_mode)
        return GateResult(
            gate="tool_result",
            action=report.action if blocked else Action.FLAG,
            blocked=blocked,
            scan_report=report,
            explanation=self._build_explanation(report) if blocked else "Tool result flagged",
            sanitized_text=self._sanitize_text(result, report) if not blocked else None,
        )

    def prepare_prompt(self, system_prompt: str) -> tuple[str, str]:
        """Gate 3a: Add canary token to system prompt."""
        return self.engine.add_canary(system_prompt)

    def scan_output(self, llm_response: str, canary_token: str, original_input: str | None = None) -> GateResult:
        """Gate 3b: Check LLM output for canary leakage."""
        leaked = self.engine.check_canary(llm_response, canary_token, original_input=original_input)
        if leaked:
            blocked = self.output_mode == "block"
            return GateResult(gate="output", action=Action.BLOCK if blocked else Action.FLAG, blocked=blocked, explanation="Canary token leaked in LLM response", canary_leaked=True)
        return GateResult(gate="output", action=Action.PASS, blocked=False, explanation="Output passed canary check")

    def scan_multi_hop(self, messages: list[dict[str, str]]) -> list[GateResult]:
        """Scan an entire multi-hop agent conversation."""
        results = []
        history: list[str] = []
        for msg in messages:
            content = msg.get("content", "")
            ctx: dict[str, object] = {"gate": "multi_hop", "conversation_history": history}
            report = self.engine.scan(content, context=ctx)
            if report.detections:
                results.append(GateResult(
                    gate="multi_hop", action=report.action, blocked=report.action == Action.BLOCK,
                    scan_report=report, explanation=self._build_explanation(report),
                ))
            history.append(content)
        return results

    def _should_block(self, report: ScanReport, mode: str) -> bool:
        if mode == "block" and report.action in (Action.BLOCK,):
            return True
        if mode == "block" and report.detections:
            return True
        return False

    def _build_explanation(self, report: ScanReport) -> str:
        if not report.detections:
            return "No detections"
        top = max(report.detections, key=lambda d: d.confidence)
        return f"{top.detector_id}: {top.explanation} (confidence: {top.confidence:.2f})"

    def _sanitize_text(self, text: str, report: ScanReport) -> str:
        """Replace matched segments with sanitize_replacement."""
        if not report.detections:
            return text
        # Collect all match positions, sort by start descending for safe replacement
        positions: list[tuple[int, int]] = []
        for det in report.detections:
            for match in det.matches:
                if match.position:
                    positions.append(match.position)
        positions.sort(key=lambda p: p[0], reverse=True)
        result = text
        for start, end in positions:
            result = result[:start] + self.sanitize_replacement + result[end:]
        return result
