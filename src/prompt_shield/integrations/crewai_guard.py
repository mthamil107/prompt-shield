"""CrewAI integration for prompt-shield — scan agent inputs/outputs for injection attacks."""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from prompt_shield.engine import PromptShieldEngine

logger = logging.getLogger("prompt_shield.crewai")

# ---------------------------------------------------------------------------
# Try to import crewai_tools.BaseTool — fall back gracefully
# ---------------------------------------------------------------------------
_HAS_CREWAI_TOOLS = False
try:
    from crewai_tools import BaseTool as _CrewAIBaseTool  # type: ignore[import-untyped]

    _HAS_CREWAI_TOOLS = True
except ImportError:
    _CrewAIBaseTool = object  # type: ignore[assignment,misc]


def _default_engine() -> PromptShieldEngine:
    """Create a lightweight engine with vault/feedback disabled."""
    from prompt_shield.engine import PromptShieldEngine

    return PromptShieldEngine(
        config_dict={
            "prompt_shield": {
                "mode": "block",
                "threshold": 0.7,
                "vault": {"enabled": False},
                "feedback": {"enabled": False},
                "canary": {"enabled": True},
                "history": {"enabled": False},
            }
        }
    )


# ---------------------------------------------------------------------------
# CrewAI Tool — can be added to any agent's tool list
# ---------------------------------------------------------------------------


class PromptShieldCrewAITool(_CrewAIBaseTool):
    """A CrewAI-compatible tool that scans text for prompt injection.

    Can be added to any CrewAI agent's tool list to scan inputs before processing.

    Usage::

        from crewai import Agent
        from prompt_shield.integrations.crewai_guard import PromptShieldCrewAITool

        shield_tool = PromptShieldCrewAITool()
        agent = Agent(
            role="Secure Assistant",
            tools=[shield_tool],
        )
    """

    # crewai_tools.BaseTool expects these as class-level attributes (Pydantic fields).
    # When BaseTool is unavailable we just treat them as plain attrs.
    name: str = "prompt_shield_scan"  # type: ignore[assignment]
    description: str = (  # type: ignore[assignment]
        "Scan a piece of text for prompt injection attacks. "
        "Returns a JSON object with 'safe' (bool), 'action', 'risk_score', "
        "and 'detections' list."
    )

    # We store the engine reference outside of Pydantic's model fields.
    _engine: PromptShieldEngine | None

    def __init__(self, engine: PromptShieldEngine | None = None, **kwargs: Any) -> None:
        if _HAS_CREWAI_TOOLS:
            super().__init__(**kwargs)
        self._engine = engine

    # -- public helpers -----------------------------------------------------

    @property
    def engine(self) -> PromptShieldEngine:
        if self._engine is None:
            self._engine = _default_engine()
        return self._engine

    # -- crewai_tools.BaseTool interface ------------------------------------

    def _run(self, text: str, **kwargs: Any) -> str:
        """Execute the scan (called by CrewAI runtime).

        Returns a JSON-serialised result string so the LLM can parse it.
        """
        import json

        from prompt_shield.models import Action

        report = self.engine.scan(text, context={"source": "crewai_tool"})
        result = {
            "safe": report.action == Action.PASS,
            "action": report.action.value,
            "risk_score": report.overall_risk_score,
            "scan_id": report.scan_id,
            "detections": [
                {
                    "detector": d.detector_id,
                    "confidence": d.confidence,
                    "severity": d.severity.value,
                    "explanation": d.explanation,
                }
                for d in report.detections
            ],
        }
        return json.dumps(result)


# ---------------------------------------------------------------------------
# CrewAI Guard — callback-style wrapper for task execution
# ---------------------------------------------------------------------------


class CrewAIGuard:
    """Callback-style guard that wraps CrewAI task execution.

    Scans task inputs before execution and optionally scans outputs after.

    Usage::

        from prompt_shield.integrations.crewai_guard import CrewAIGuard

        guard = CrewAIGuard(mode="block")

        # Wrap task execution
        result = guard.execute_task(task, agent, context="user input here")
    """

    VALID_MODES = ("block", "flag", "monitor")

    def __init__(
        self,
        engine: PromptShieldEngine | None = None,
        mode: str = "block",
        scan_outputs: bool = False,
        pii_redact: bool = False,
    ) -> None:
        if mode not in self.VALID_MODES:
            raise ValueError(
                f"Invalid mode '{mode}'. Must be one of {self.VALID_MODES}"
            )
        self._engine = engine
        self.mode = mode
        self.scan_outputs = scan_outputs
        self.pii_redact = pii_redact

    @property
    def engine(self) -> PromptShieldEngine:
        if self._engine is None:
            self._engine = _default_engine()
        return self._engine

    # -- scanning -----------------------------------------------------------

    def scan_input(self, text: str) -> dict[str, Any]:
        """Scan input text and return a structured result dict.

        Returns:
            dict with keys: safe, action, risk_score, scan_id, detections, blocked.
        """
        from prompt_shield.models import Action

        report = self.engine.scan(text, context={"gate": "input", "source": "crewai"})
        blocked = report.action in (Action.BLOCK, Action.FLAG) and report.detections
        is_safe = report.action == Action.PASS

        result: dict[str, Any] = {
            "safe": is_safe,
            "action": report.action.value,
            "risk_score": report.overall_risk_score,
            "scan_id": report.scan_id,
            "blocked": bool(blocked),
            "detections": [
                {
                    "detector": d.detector_id,
                    "confidence": d.confidence,
                    "severity": d.severity.value,
                    "explanation": d.explanation,
                }
                for d in report.detections
            ],
        }

        if blocked:
            self._handle_detection(result)

        return result

    def scan_output(self, text: str) -> dict[str, Any]:
        """Scan output text and return a structured result dict.

        Returns:
            dict with keys: safe, action, risk_score, scan_id, detections, blocked.
        """
        from prompt_shield.models import Action

        report = self.engine.scan(text, context={"gate": "output", "source": "crewai"})
        blocked = report.action in (Action.BLOCK, Action.FLAG) and report.detections
        is_safe = report.action == Action.PASS

        result: dict[str, Any] = {
            "safe": is_safe,
            "action": report.action.value,
            "risk_score": report.overall_risk_score,
            "scan_id": report.scan_id,
            "blocked": bool(blocked),
            "detections": [
                {
                    "detector": d.detector_id,
                    "confidence": d.confidence,
                    "severity": d.severity.value,
                    "explanation": d.explanation,
                }
                for d in report.detections
            ],
        }

        if blocked:
            self._handle_detection(result)

        return result

    def redact_pii(self, text: str) -> str:
        """Redact PII from text using the built-in PII redactor.

        Returns:
            The text with PII entities replaced by type-aware placeholders.
        """
        from prompt_shield.pii.redactor import PIIRedactor

        redactor = PIIRedactor()
        redaction_result = redactor.redact(text)
        return redaction_result.redacted_text

    def execute_task(
        self,
        task: Any,
        agent: Any,
        context: str | None = None,
    ) -> Any:
        """Execute a CrewAI task with prompt-shield protection.

        Scans context/input before execution, optionally scans output after.
        In *block* mode, raises ``ValueError`` when injection is detected.

        Args:
            task: A CrewAI ``Task`` object.
            agent: A CrewAI ``Agent`` object.
            context: Optional text context to scan before execution.

        Returns:
            The task execution result (from ``task.execute_sync``).

        Raises:
            ValueError: If mode is ``"block"`` and injection is detected.
        """
        # -- pre-execution scan --
        input_text = context or ""

        # Also consider task.description as scannable input
        task_description = getattr(task, "description", None)
        if task_description and isinstance(task_description, str):
            input_text = f"{input_text}\n{task_description}".strip()

        if input_text:
            # Optionally redact PII before scanning
            if self.pii_redact:
                input_text = self.redact_pii(input_text)

            scan_result = self.scan_input(input_text)

            if scan_result["blocked"] and self.mode == "block":
                raise ValueError(
                    f"Prompt injection detected by prompt-shield "
                    f"(scan_id={scan_result['scan_id']}, "
                    f"risk_score={scan_result['risk_score']:.2f})"
                )

        # -- execute the task --
        # CrewAI tasks expose execute_sync(agent=..., context=...)
        execute_fn = getattr(task, "execute_sync", None)
        if execute_fn is not None:
            result = execute_fn(agent=agent, context=context)
        else:
            # Fallback: try calling the task directly
            result = task.execute(agent=agent, context=context)

        # -- post-execution scan --
        if self.scan_outputs and result is not None:
            output_text = str(result)
            if self.pii_redact:
                output_text = self.redact_pii(output_text)

            output_scan = self.scan_output(output_text)

            if output_scan["blocked"] and self.mode == "block":
                raise ValueError(
                    f"Prompt injection detected in task output by prompt-shield "
                    f"(scan_id={output_scan['scan_id']}, "
                    f"risk_score={output_scan['risk_score']:.2f})"
                )

        return result

    # -- internal -----------------------------------------------------------

    def _handle_detection(self, result: dict[str, Any]) -> None:
        """Handle a positive detection according to the configured mode."""
        scan_id = result["scan_id"]
        risk = result["risk_score"]
        detectors = ", ".join(d["detector"] for d in result["detections"])

        if self.mode == "block":
            logger.warning(
                "BLOCK: injection detected (scan_id=%s, risk=%.2f, detectors=%s)",
                scan_id,
                risk,
                detectors,
            )
        elif self.mode == "flag":
            logger.warning(
                "FLAG: suspicious content (scan_id=%s, risk=%.2f, detectors=%s)",
                scan_id,
                risk,
                detectors,
            )
        else:  # monitor
            logger.info(
                "MONITOR: detection logged (scan_id=%s, risk=%.2f, detectors=%s)",
                scan_id,
                risk,
                detectors,
            )
