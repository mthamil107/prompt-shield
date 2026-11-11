"""Pydantic AI integration for prompt-shield.

Adds prompt-shield scanning around a Pydantic AI ``Agent`` with minimal
ceremony. Four primitives:

- ``scan_input(prompt, engine, mode)`` — call before ``agent.run()`` to
  gate user input. Raises on ``mode="block"`` (default), warns on
  ``"flag"``, silent on ``"log"``.
- ``PromptShieldOutputValidator(engine, mode)`` — a Pydantic AI
  ``result_validator``-compatible callable that scans the agent's
  final response through the 9 output scanners.
- ``scan_tool_result(content, tool_name, engine, mode)`` — manually
  scan a tool return value through ``ToolResultGuard``.
- ``PromptShieldToolset(toolset, engine, mode)`` — wrap a Pydantic AI
  toolset so results from tools registered with that toolset are scanned
  before they return to the model. Tools registered directly with
  ``@agent.tool`` or ``@agent.tool_plain`` are outside the wrapper.

One-line install onto an existing agent via ``attach(agent, ...)``:

    from pydantic_ai import Agent
    from prompt_shield.integrations.pydantic_ai_guard import attach, scan_input

    agent = Agent('openai:gpt-4o', system_prompt='You are helpful.')
    attach(agent, mode='block')            # installs the output guard

    prompt = "What is the capital of France?"
    scan_input(prompt, mode='block')        # explicit input gate
    result = await agent.run(prompt)
    # If the user prompt was injection → scan_input raises before OpenAI.
    # If the model output leaks PII/prompt/toxicity → raises after generation.

Lazy import: ``pydantic-ai`` is an optional dependency. The module
imports without it; instantiating the validator raises ``ImportError``
with the pip install hint.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Any

try:
    import pydantic_ai  # noqa: F401

    _PYDANTIC_AI_AVAILABLE = True
except ImportError:
    _PYDANTIC_AI_AVAILABLE = False


try:
    from pydantic_ai import ToolReturn as _PydanticAIToolReturn
    from pydantic_ai import WrapperToolset as _WrapperToolset
    from pydantic_ai.messages import ToolReturnPart as _PydanticAIToolReturnPart

    _PYDANTIC_AI_TOOLSET_AVAILABLE = True
except ImportError:
    _PYDANTIC_AI_TOOLSET_AVAILABLE = False
    _PydanticAIToolReturn = None  # type: ignore[assignment,misc]
    _PydanticAIToolReturnPart = None  # type: ignore[assignment,misc]

    class _WrapperToolset:  # type: ignore[no-redef]
        """Import-safe stand-in used when the optional dependency is absent."""

        def __init__(self, wrapped: Any) -> None:
            self.wrapped = wrapped


from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action
from prompt_shield.tool_guard import ToolResultGuard

if TYPE_CHECKING:
    from pydantic_ai import AbstractToolset, RunContext, ToolsetTool

    from prompt_shield.models import ScanReport

logger = logging.getLogger("prompt_shield.pydantic_ai")

_MISSING_MSG = (
    "pydantic-ai is required for the Pydantic AI integration. "
    "Install with: pip install prompt-shield-ai[pydantic-ai]"
)


def _require_pydantic_ai() -> None:
    if not _PYDANTIC_AI_AVAILABLE:
        raise ImportError(_MISSING_MSG)


def _require_toolset_api() -> None:
    _require_pydantic_ai()
    if not _PYDANTIC_AI_TOOLSET_AVAILABLE:
        raise ImportError(
            "PromptShieldToolset requires a pydantic-ai version that provides "
            'WrapperToolset. Upgrade with: pip install -U "pydantic-ai>=1.0.12"'
        )


def _serialize_payload(payload: Any, tool_name: str | None) -> str:
    """Serialize one payload the way pydantic-ai will send it to the model."""
    if _PydanticAIToolReturnPart is not None:
        return _PydanticAIToolReturnPart(
            tool_name=tool_name or "",
            content=payload,
            tool_call_id="",
        ).model_response_str()
    return payload if isinstance(payload, str) else str(payload)


def _tool_result_payloads(
    content: Any,
    tool_name: str | None,
) -> list[tuple[str, str]]:
    """Return the ordered list of (field_name, serialized_text) pairs to scan.

    - Plain return (string/dict/anything non-ToolReturn): one entry
      ``("payload", serialized)``.
    - ``ToolReturn``: up to TWO entries - one for ``return_value`` (what
      becomes the ``ToolReturnPart.content``) and one for ``content`` (what
      becomes the separate ``UserPromptPart``). ``None``/empty fields are
      skipped. Both fields are scanned independently so an injection in
      either path is caught.
    """
    if _PydanticAIToolReturn is not None and isinstance(content, _PydanticAIToolReturn):
        pairs: list[tuple[str, str]] = []
        if content.return_value is not None:
            pairs.append(("return_value", _serialize_payload(content.return_value, tool_name)))
        if content.content:  # str or non-empty Sequence[UserContent]
            pairs.append(("content", _serialize_payload(content.content, tool_name)))
        return pairs
    return [("payload", _serialize_payload(content, tool_name))]


def _tool_result_text(content: Any, tool_name: str | None) -> str:
    """Return the first serialized model-facing payload (single-string contract)."""
    pairs = _tool_result_payloads(content, tool_name)
    return pairs[0][1] if pairs else ""


def _sanitized_tool_result(
    result: Any,
    sanitized_by_field: dict[str, str],
) -> Any:
    """Preserve a structured ToolReturn while replacing per-field model-facing text.

    ``sanitized_by_field`` maps field name (``"return_value"`` or ``"content"``)
    to its sanitized string. Fields not in the dict are left unchanged. For
    non-``ToolReturn`` results, falls back to the single sanitized string
    (keyed as ``"payload"``).

    Known gap: a non-string ``content`` (a sequence of ``UserContent``) is
    replaced by the sanitized serialized string and does not round-trip back
    into ``UserContent`` parts.
    """
    if _PydanticAIToolReturn is not None and isinstance(result, _PydanticAIToolReturn):
        kwargs: dict[str, Any] = {}
        if "return_value" in sanitized_by_field:
            kwargs["return_value"] = sanitized_by_field["return_value"]
        if "content" in sanitized_by_field:
            kwargs["content"] = sanitized_by_field["content"]
        if not kwargs:
            return result
        return replace(result, **kwargs)
    return sanitized_by_field.get("payload", result)


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


def scan_tool_result(
    content: Any,
    *,
    tool_name: str | None = None,
    engine: PromptShieldEngine | None = None,
    mode: str = "block",
) -> ScanReport:
    """Scan one Pydantic AI tool result before it returns to the model.

    When ``content`` is a ``ToolReturn``, BOTH ``return_value`` and
    ``content`` are scanned independently - pydantic-ai emits them to the
    model via separate parts, so a single scan of either field alone is
    unsound. In ``block`` mode the first flagged field raises
    ``ValueError``. In ``sanitize`` mode the returned report is the last
    *flagged* field's report (``content`` if both were dirty); its
    ``sanitized_text`` applies to that field only - use
    :class:`PromptShieldToolset` for per-field redaction.
    ``flag`` warns and ``log`` returns silently.

    Use :class:`PromptShieldToolset` when automatic interception is
    preferable to calling this helper manually.
    """
    guard = ToolResultGuard(engine=engine, mode=mode, cache_size=0)
    payloads = _tool_result_payloads(content, tool_name)
    if not payloads:
        return guard.scan("", tool_name=tool_name)
    reports = [guard.scan(text, tool_name=tool_name) for _field_name, text in payloads]
    flagged = [r for r in reports if r.detections]
    return flagged[-1] if flagged else reports[-1]


class PromptShieldToolset(_WrapperToolset):
    """Pydantic AI toolset wrapper that guards wrapped tool return values.

    Pydantic AI funnels both synchronous and asynchronous function tools
    through the asynchronous ``WrapperToolset.call_tool`` extension point.
    The wrapped result is therefore scanned exactly once, immediately before
    Pydantic AI places it back into model context.

    Tools registered directly through ``@agent.tool`` or ``@agent.tool_plain``
    live in the agent's separate function toolset and are not intercepted.
    Move those tools into a ``FunctionToolset`` (or similar) and wrap that
    toolset to guard their results.

    ``block`` raises ``ValueError`` and prevents the result from reaching the
    model. ``sanitize`` preserves ``ToolReturn`` metadata and structure while
    replacing its model-facing text; other non-string results become strings.
    ``flag`` and ``log`` preserve the original result (and its type).
    """

    def __init__(
        self,
        wrapped: AbstractToolset[Any],
        *,
        engine: PromptShieldEngine | None = None,
        mode: str = "block",
        cache_size: int = 128,
        sanitize_replacement: str = "[REDACTED by prompt-shield]",
    ) -> None:
        _require_toolset_api()
        super().__init__(wrapped)
        self.guard = ToolResultGuard(
            engine=engine,
            mode=mode,
            cache_size=cache_size,
            sanitize_replacement=sanitize_replacement,
        )

    async def call_tool(
        self,
        name: str,
        tool_args: dict[str, Any],
        ctx: RunContext[Any],
        tool: ToolsetTool[Any],
    ) -> Any:
        """Run the wrapped tool, scan every model-facing payload, enforce mode."""
        result = await super().call_tool(name, tool_args, ctx, tool)
        payloads = _tool_result_payloads(result, name)

        sanitized_by_field: dict[str, str] = {}
        for field_name, text in payloads:
            report = await self.guard.ascan(text, tool_name=name)
            if (
                self.guard.mode == "sanitize"
                and report.scan_context is not None
                and report.scan_context.sanitized_text is not None
            ):
                sanitized_by_field[field_name] = report.scan_context.sanitized_text

        if self.guard.mode == "sanitize" and sanitized_by_field:
            return _sanitized_tool_result(result, sanitized_by_field)
        return result


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
    "PromptShieldToolset",
    "attach",
    "scan_input",
    "scan_tool_result",
]
