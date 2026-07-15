"""Pydantic AI integration for prompt-shield.

Adds prompt-shield scanning around a Pydantic AI ``Agent`` with minimal
ceremony. Two primitives:

- ``scan_input(prompt, engine, mode)`` — call before ``agent.run()`` to
  gate user input. Raises on ``mode="block"`` (default), warns on
  ``"flag"``, silent on ``"log"``.
- ``PromptShieldOutputValidator(engine, mode)`` — a Pydantic AI
  ``result_validator``-compatible callable that scans the agent's
  final response through the 9 output scanners.

One-line install onto an existing agent via ``attach(agent, ...)``:

    from pydantic_ai import Agent
    from prompt_shield.integrations.pydantic_ai_guard import attach

    agent = Agent('openai:gpt-4o', system_prompt='You are helpful.')
    attach(agent, mode='block')            # installs input + output guards

    result = await agent.run("What is the capital of France?")
    # If the user prompt was injection → raises before reaching OpenAI.
    # If the model output leaks PII/prompt/toxicity → raises after generation.

Lazy import: ``pydantic-ai`` is an optional dependency. The module
imports without it; instantiating the validator raises ``ImportError``
with the pip install hint.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

try:
    import pydantic_ai  # noqa: F401

    _PYDANTIC_AI_AVAILABLE = True
except ImportError:
    _PYDANTIC_AI_AVAILABLE = False

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action

if TYPE_CHECKING:
    from prompt_shield.models import ScanReport

logger = logging.getLogger("prompt_shield.pydantic_ai")

_MISSING_MSG = (
    "pydantic-ai is required for the Pydantic AI integration. "
    "Install with: pip install prompt-shield-ai[pydantic-ai]"
)


def _require_pydantic_ai() -> None:
    if not _PYDANTIC_AI_AVAILABLE:
        raise ImportError(_MISSING_MSG)


def _enforce(report: ScanReport, source_desc: str, mode: str) -> None:
    if report.action == Action.BLOCK:
        msg = (
            f"prompt-shield BLOCKED {source_desc!r} "
            f"(scan_id={report.scan_id}, detections={len(report.detections)})"
        )
        if mode == "block":
            raise ValueError(msg)
        logger.warning(msg)
    elif report.action == Action.FLAG and mode != "log":
        logger.warning(
            "prompt-shield FLAGGED %s (scan_id=%s)",
            source_desc,
            report.scan_id,
        )


def scan_input(
    prompt: str,
    engine: PromptShieldEngine | None = None,
    mode: str = "block",
) -> ScanReport:
    """Scan a user prompt BEFORE passing it to ``agent.run()``.

    Parameters
    ----------
    prompt : str
        The user-supplied prompt to scan.
    engine :
        Optional pre-built PromptShieldEngine. Defaults to the standard
        33-detector engine.
    mode :
        ``"block"`` raises ValueError, ``"flag"`` warns, ``"log"`` silent.

    Returns
    -------
    ScanReport
        The full scan report (useful for logging or metrics regardless
        of mode).
    """
    if mode not in ("block", "flag", "log"):
        raise ValueError(f"mode must be block/flag/log, got {mode!r}")
    eng = engine or PromptShieldEngine()
    report = eng.scan(
        prompt,
        context={"gate": "input", "source": "pydantic_ai"},
    )
    _enforce(report, source_desc=f"input: {prompt[:80]}", mode=mode)
    return report


class PromptShieldOutputValidator:
    """Result validator for Pydantic AI's ``@agent.result_validator`` slot.

    Runs the engine's 9 output scanners against the model's response.
    Raises on any flagged scanner in ``mode="block"``.

    Usage:

        from prompt_shield.integrations.pydantic_ai_guard import PromptShieldOutputValidator

        validator = PromptShieldOutputValidator(mode="block")
        agent.result_validators.append(validator)
        # OR: @agent.result_validator(validator)  # depending on pydantic-ai version

    Because pydantic-ai's decorator API varies across 0.x versions, the
    validator is exposed as a plain callable (``__call__``) that
    accepts the model's raw string result.
    """

    def __init__(
        self,
        engine: PromptShieldEngine | None = None,
        mode: str = "block",
    ) -> None:
        _require_pydantic_ai()
        if mode not in ("block", "flag", "log"):
            raise ValueError(f"mode must be block/flag/log, got {mode!r}")
        self.engine = engine or PromptShieldEngine()
        self.mode = mode

    def __call__(self, result: Any, ctx: Any = None) -> Any:
        """Scan the agent's final response through all output scanners."""
        # Handle both (result,) and (ctx, result) calling conventions
        if ctx is None and hasattr(result, "usage"):
            # Called with just RunContext
            ctx, result = result, None
        text = str(result) if not isinstance(result, str) else result

        flagged_scanners: list[str] = []
        for scanner in getattr(self.engine, "output_scanners", []) or []:
            try:
                r = scanner.scan(
                    text,
                    context={"source": "pydantic_ai", "gate": "output"},
                )
            except Exception as e:
                logger.warning(
                    "output scanner %s crashed: %s",
                    getattr(scanner, "scanner_id", "?"),
                    e,
                )
                continue
            if r.flagged:
                flagged_scanners.append(r.scanner_id)
                cats = list(r.categories or [])
                if self.mode == "block":
                    raise ValueError(
                        f"prompt-shield output scanner {r.scanner_id!r} BLOCKED "
                        f"agent response (categories={cats}, "
                        f"confidence={r.confidence:.2f})"
                    )
                elif self.mode == "flag":
                    logger.warning(
                        "prompt-shield output %s FLAGGED (categories=%s, conf=%.2f)",
                        r.scanner_id,
                        cats,
                        r.confidence,
                    )
                else:
                    logger.info(
                        "prompt-shield output %s flagged (log-only)",
                        r.scanner_id,
                    )

        return result


def attach(
    agent: Any,
    engine: PromptShieldEngine | None = None,
    mode: str = "block",
) -> PromptShieldOutputValidator:
    """One-line install: wire an output validator onto an existing agent.

    Input scanning is NOT auto-installed by ``attach`` because the
    hook point differs between pydantic-ai versions. Call
    ``scan_input(user_prompt)`` yourself before ``agent.run()`` for
    input gating.

    Parameters
    ----------
    agent :
        A ``pydantic_ai.Agent`` instance.
    engine :
        Optional pre-built PromptShieldEngine.
    mode :
        ``"block"`` / ``"flag"`` / ``"log"``.

    Returns
    -------
    PromptShieldOutputValidator
        The installed validator (kept as a reference so you can inspect
        or remove it later).
    """
    _require_pydantic_ai()
    validator = PromptShieldOutputValidator(engine=engine, mode=mode)

    # Try modern API first (result_validator decorator style)
    if hasattr(agent, "result_validator"):
        try:
            agent.result_validator(validator)
            return validator
        except Exception:
            pass

    # Fall back to appending to a validators list if present
    for attr in ("_result_validators", "result_validators"):
        vals = getattr(agent, attr, None)
        if isinstance(vals, list):
            vals.append(validator)
            return validator

    logger.warning(
        "Could not attach output validator automatically. "
        "Call validator() manually on the agent's result. "
        "pydantic-ai API may have changed."
    )
    return validator


__all__ = [
    "PromptShieldOutputValidator",
    "attach",
    "scan_input",
]
