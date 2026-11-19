"""OpenAI client wrapper for automatic prompt-shield scanning.

Stream scan coverage
--------------------

Streamed chat / Responses text is scanned by :class:`StreamGuard`'s
internal :class:`OutputScanEngine`, which is distinct from the
:class:`PromptShieldEngine` used for non-stream input/output scans.
The engines carry different detector families, so the stream-safe
default scanner set excludes ``sentiment``, ``relevance``,
``hallucination`` and ``schema_validation`` (whole-response readers
that misfire on sub-complete fragments). The wrapper runs a
belt-and-suspenders full-text re-scan through the wrapper's own
``PromptShieldEngine`` after the stream terminates so injection
detectors that only live on the input-side engine still see the
complete response text.

Streamed tool-call arguments ARE scanned through the wrapper's
``PromptShieldEngine`` (via :class:`AgentGuard.scan_tool_call`) — the
full detector set applies, including the d034 honeypot.

Customise stream text scanning with the constructor kwargs
``stream_scanners`` (names forwarded to the guard), ``stream_canary_tokens``
(canary leak tokens checked on each window), ``stream_hold_back`` and
``stream_overlap`` (override the guard's default buffer sizes).

Scope of ``scan_responses``
---------------------------

``scan_responses=False`` (the default) preserves pre-T7 behaviour for
streams: text passes through un-scanned, and only tool-call arguments
are scanned (since that is a safety primitive, not an opt-in). Setting
``scan_responses=True`` turns on StreamGuard-based text scanning AND the
post-stream full-text re-scan.

Enforcement model
-----------------

Streamed scanning is enforced by the wrapper ``mode``:

* ``mode="block"`` raises :class:`PromptShieldStreamBlocked` as soon as
  any stream detector would block — StreamGuard window, tool-call
  argument scan, nameless-tool guard, or the belt-and-suspenders
  full-text re-scan. For a short reply (under
  ``hold_back + overlap``) the entire tail is withheld: the caller
  sees no text and then the exception.
* ``mode="flag"``, ``"log"``, ``"monitor"`` log findings and pass text
  through unchanged.

The non-stream ``scan_responses=True`` path is deliberately
log-only by default: it logs suspicious response content but does NOT
raise. Streaming is more aggressive because held-back text is the only
chance to withhold a leak before the caller has already seen it.
"""

from __future__ import annotations

import inspect
import logging
import warnings
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.integrations.agent_guard import AgentGuard
from prompt_shield.models import Action
from prompt_shield.streaming import (
    PromptShieldStreamBlocked,
    StreamFinding,
    StreamGuard,
)
from prompt_shield.streaming.tool_call_accumulator import ToolCallAccumulator
from prompt_shield.tool_guard.guard import ToolResultGuard

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator, Sequence

    from prompt_shield.models import GateResult, ScanReport

logger = logging.getLogger("prompt_shield.openai")


# ----------------------------------------------------------------------
# Small shaping helpers
# ----------------------------------------------------------------------


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


def _text_chunk(
    text: str | None,
    finish_reason: str | None = None,
    *,
    source_chunk: Any = None,
    choice_index: int = 0,
) -> SimpleNamespace:
    """Build a ``ChatCompletionChunk``-shaped shim with ``text`` in ``delta.content``.

    Preserves ``id``/``model``/``created``/``system_fingerprint``/``usage``
    by copying them from ``source_chunk`` when supplied — H2 fix: text
    shims must not strip chunk metadata. Passing ``text=None`` produces a
    terminator-only shim (``delta.content=None``) for use when the source
    chunk's content has already been shimmed out upstream.
    """
    shim = SimpleNamespace(
        id=getattr(source_chunk, "id", None),
        model=getattr(source_chunk, "model", None),
        created=getattr(source_chunk, "created", None),
        object=getattr(source_chunk, "object", "chat.completion.chunk"),
        system_fingerprint=getattr(source_chunk, "system_fingerprint", None),
        choices=[
            SimpleNamespace(
                index=choice_index,
                delta=SimpleNamespace(content=text, tool_calls=None, role=None),
                finish_reason=finish_reason,
            )
        ],
        usage=getattr(source_chunk, "usage", None),
    )
    return shim


def _tool_only_chunk(
    tool_calls: Any,
    *,
    source_chunk: Any = None,
    choice_index: int = 0,
    function_call: Any = None,
) -> SimpleNamespace:
    """Build a per-choice ChatCompletionChunk shim carrying only tool deltas.

    N3 fix: when a single delta carries BOTH ``content`` and ``tool_calls``
    we shim the content out via :func:`_text_chunk` and buffer a
    synthetic tool-only chunk here so the flush path cannot re-emit the
    content. Used for modern ``tool_calls`` and for L3's legacy
    ``function_call`` deltas (via the ``function_call`` kwarg).
    """
    return SimpleNamespace(
        id=getattr(source_chunk, "id", None),
        model=getattr(source_chunk, "model", None),
        created=getattr(source_chunk, "created", None),
        object=getattr(source_chunk, "object", "chat.completion.chunk"),
        system_fingerprint=getattr(source_chunk, "system_fingerprint", None),
        choices=[
            SimpleNamespace(
                index=choice_index,
                delta=SimpleNamespace(
                    content=None,
                    tool_calls=tool_calls,
                    role=None,
                    function_call=function_call,
                ),
                finish_reason=None,
            )
        ],
        usage=None,
    )


def _responses_text_event(delta: str) -> SimpleNamespace:
    """Build a Responses-style ``response.output_text.delta`` shim."""
    return SimpleNamespace(type="response.output_text.delta", delta=delta)


def _finding_from_gate_result(result: GateResult) -> StreamFinding:
    """Translate a blocking :class:`GateResult` from ``scan_tool_call`` to a finding.

    L1 fix: ``scanner_id`` carries the top detector name, not the scan UUID,
    so the raised exception message reads naturally
    ("blocked by prompt_injection_v2", not "blocked by <uuid>").
    """
    sr = result.scan_report
    scanner_id = "tool_call"
    categories: tuple[str, ...] = ()
    confidence = 1.0
    if sr is not None:
        categories = tuple(d.detector_id for d in sr.detections)
        if sr.detections:
            top = max(sr.detections, key=lambda d: d.confidence)
            scanner_id = top.detector_id
        confidence = float(sr.overall_risk_score)
    return StreamFinding(
        source="tool_call",
        scanner_id=scanner_id,
        confidence=confidence,
        categories=categories,
        explanation=result.explanation,
        window_offset=0,
    )


def _finding_from_scan_report(report: ScanReport, *, source: str) -> StreamFinding:
    """Translate an engine-level :class:`ScanReport` (from the full-text re-scan) to a finding."""
    scanner_id = "output"
    if report.detections:
        top = max(report.detections, key=lambda d: d.confidence)
        scanner_id = top.detector_id
    categories = tuple(d.detector_id for d in report.detections)
    return StreamFinding(
        source=source,
        scanner_id=scanner_id,
        confidence=float(report.overall_risk_score),
        categories=categories,
        explanation=f"full-text output scan blocked (scan_id={report.scan_id})",
        window_offset=0,
    )


# Modes forwarded to :class:`StreamGuard`. The wrapper also accepts
# ``"monitor"`` (observe-only, pass-through); map it to ``"log"`` for
# the guard so detections surface in logs without raising.
_STREAM_MODE_MAP: dict[str, str] = {
    "block": "block",
    "flag": "flag",
    "log": "log",
    "monitor": "log",
}


# ----------------------------------------------------------------------
# Public wrapper
# ----------------------------------------------------------------------


class PromptShieldOpenAI:
    """Wraps an OpenAI client to auto-scan inputs, outputs, and tool results.

    v0.8.0 added ``role="tool"`` and ``role="function"`` message scanning:
    when the ``messages`` list contains messages with ``role="tool"`` or
    ``role="function"`` (OpenAI's tool/function result message format),
    each message's text is scanned through ``ToolResultGuard`` before the
    request is forwarded. ``tool_result_mode`` controls tool result enforcement:
    ``'block'`` raises on detection, non-block modes (``'flag'``, ``'log'``,
    ``'monitor'``) log and pass through. ``'sanitize'`` is not supported by
    this wrapper.

    v0.10.0 adds streaming (``create(stream=True)``), async (``acreate()``)
    and Responses API (``shield.responses.create`` / ``.acreate``) coverage.
    Streamed text is routed through :class:`StreamGuard` when
    ``scan_responses=True`` and raw passthrough otherwise; tool-call argument
    deltas always flow through :class:`ToolCallAccumulator` and are scanned
    before any tool-call chunk reaches the caller. ``create()`` requires a
    synchronous ``openai.OpenAI`` client; ``acreate()`` requires an
    ``openai.AsyncOpenAI`` client — mismatches raise :class:`TypeError`.

    Stream scan coverage
    --------------------
    See the module-level docstring. In short: StreamGuard owns its own
    :class:`OutputScanEngine` (different detector family from the wrapper's
    :class:`PromptShieldEngine`); after the stream terminates the wrapper
    runs a belt-and-suspenders full-text re-scan with its own engine so
    injection detectors still see the whole response.

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
        *,
        stream_scanners: Sequence[str] | None = None,
        stream_canary_tokens: Sequence[str] | None = None,
        stream_hold_back: int | None = None,
        stream_overlap: int | None = None,
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
            if tool_result_mode is None:
                raise ValueError(
                    f"mode={mode!r} cannot be inherited as tool_result_mode "
                    "('sanitize' is not supported by PromptShieldOpenAI); "
                    "pass tool_result_mode explicitly"
                )
            raise ValueError("tool_result_mode='sanitize' is not supported by PromptShieldOpenAI")
        valid_modes = ("block", "flag", "log", "monitor")
        if effective_tool_mode not in valid_modes:
            raise ValueError(
                f"tool_result_mode must be one of {valid_modes}, got {effective_tool_mode!r}"
            )
        self.tool_result_mode = effective_tool_mode
        # mode="log" so this wrapper controls block/flag via tool_result_mode.
        self._tool_guard = ToolResultGuard(engine=self._engine, mode="log")
        # Reused by streaming paths for tool-call argument scans. ``data_mode="log"``
        # keeps scan_tool_result out of this agent_guard's path; the wrapper runs
        # tool_result scanning through ``self._tool_guard`` exclusively.
        self._agent_guard = AgentGuard(
            engine=self._engine,
            input_mode=mode if mode in valid_modes else "block",
            data_mode="log",
            output_mode=mode if mode in valid_modes else "block",
        )

        # Stream-scan configuration (H1): preserve guard defaults when unset.
        self._stream_scanners: list[str] | None = (
            list(stream_scanners) if stream_scanners is not None else None
        )
        self._stream_canary_tokens: tuple[str, ...] = (
            tuple(stream_canary_tokens) if stream_canary_tokens is not None else ()
        )
        self._stream_hold_back = stream_hold_back
        self._stream_overlap = stream_overlap

        # Autodetect sync-vs-async client. Mismatched dispatch raises TypeError
        # in create() / acreate() for a clear failure, not a silent one.
        create_fn = getattr(
            getattr(getattr(client, "chat", None), "completions", None),
            "create",
            None,
        )
        self._is_async = inspect.iscoroutinefunction(create_fn)

        # Responses API namespace. Entry points check for ``client.responses``
        # at call time, so an older client simply surfaces ``NotImplementedError``
        # on first use rather than at construction.
        self.responses = _ResponsesNamespace(self)

    # ------------------------------------------------------------------
    # Public API — chat.completions
    # ------------------------------------------------------------------

    def create(self, **kwargs: Any) -> Any:
        """Scan messages, call ``chat.completions.create``, optionally scan response."""
        if self._is_async:
            raise TypeError(
                "PromptShieldOpenAI.create() requires a synchronous openai.OpenAI client; "
                "pass an AsyncOpenAI instance and use acreate() instead"
            )
        if kwargs.get("stream", False):
            self._reject_sanitize_for_stream()
        messages = kwargs.get("messages", [])
        self._scan_input_messages(messages)

        if kwargs.get("stream", False):
            raw_stream = self._client.chat.completions.create(**kwargs)
            return self._wrap_chat_stream(raw_stream)

        response = self._client.chat.completions.create(**kwargs)
        self._scan_chat_response(response)
        return response

    async def acreate(self, **kwargs: Any) -> Any:
        """Async mirror of :meth:`create` — requires an ``openai.AsyncOpenAI`` client."""
        if not self._is_async:
            raise TypeError(
                "PromptShieldOpenAI.acreate() requires an openai.AsyncOpenAI client; "
                "pass a sync OpenAI instance and use create() instead"
            )
        if kwargs.get("stream", False):
            self._reject_sanitize_for_stream()
        messages = kwargs.get("messages", [])
        self._scan_input_messages(messages)

        if kwargs.get("stream", False):
            raw_stream = await self._client.chat.completions.create(**kwargs)
            return self._wrap_async_chat_stream(raw_stream)

        response = await self._client.chat.completions.create(**kwargs)
        self._scan_chat_response(response)
        return response

    @property
    def engine(self) -> PromptShieldEngine:
        """Access the underlying scanning engine."""
        return self._engine

    # ------------------------------------------------------------------
    # Internal — input scanning (shared by sync / async / streaming)
    # ------------------------------------------------------------------

    def _scan_input_messages(self, messages: list[dict[str, Any]] | Any) -> None:
        """Scan every input message. Shared by sync, async and streaming paths."""
        if not messages:
            return
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

    # ------------------------------------------------------------------
    # Internal — non-stream response scanning
    # ------------------------------------------------------------------

    def _scan_chat_response(self, response: Any) -> None:
        """Scan a non-stream ``chat.completions`` response when ``scan_responses`` is set."""
        if not self.scan_responses:
            return
        choices = getattr(response, "choices", None)
        if choices is None:
            warnings.warn(
                "prompt-shield: scan_responses=True but the response is not a "
                "scannable chat.completions object (unrecognised response shape); "
                "output scanning was skipped for this call.",
                UserWarning,
                stacklevel=3,
            )
            return
        if not choices:
            return
        for choice in choices:
            text = getattr(getattr(choice, "message", None), "content", None)
            if not text:
                continue
            resp_report = self._engine.scan(
                text,
                context={"gate": "output", "source": "openai"},
            )
            if resp_report.detections:
                logger.warning(
                    "Suspicious content in response: %s",
                    resp_report.scan_id,
                )

    # ------------------------------------------------------------------
    # Internal — streaming plumbing
    # ------------------------------------------------------------------

    def _reject_sanitize_for_stream(self) -> None:
        """Raise ``ValueError`` if ``mode='sanitize'`` is combined with any
        streaming entry point. Released stream text cannot be recalled, so
        ``sanitize`` is never meaningful on a stream. This runs at the call
        site (``create``/``acreate`` with ``stream=True``, or ``responses``
        streaming paths) so the raise fires before the upstream SDK is
        touched, matching the Anthropic wrapper's behaviour.
        """
        if self.mode == "sanitize":
            raise ValueError(
                "mode='sanitize' is not supported on streaming responses; "
                "released text cannot be recalled. Use 'block', 'flag', or 'log' for streams."
            )

    def _make_stream_guard(self) -> StreamGuard:
        """Construct a fresh :class:`StreamGuard` honouring user overrides."""
        self._reject_sanitize_for_stream()
        guard_mode = _STREAM_MODE_MAP.get(self.mode, "log")
        kwargs: dict[str, Any] = {"mode": guard_mode}
        if self._stream_scanners is not None:
            kwargs["scanners"] = self._stream_scanners
        if self._stream_canary_tokens:
            kwargs["canary_tokens"] = self._stream_canary_tokens
        if self._stream_hold_back is not None:
            kwargs["hold_back"] = self._stream_hold_back
        if self._stream_overlap is not None:
            kwargs["overlap"] = self._stream_overlap
        return StreamGuard(**kwargs)

    def _wrap_chat_stream(self, raw_stream: Any) -> _GuardedChatStream:
        return _GuardedChatStream(raw_iter=raw_stream, wrapper=self)

    def _wrap_async_chat_stream(self, raw_stream: Any) -> _AsyncGuardedChatStream:
        return _AsyncGuardedChatStream(raw_iter=raw_stream, wrapper=self)

    def _scan_completed_tool_calls(
        self,
        accumulator: ToolCallAccumulator,
        released_chars: int,
    ) -> None:
        """Drain ``accumulator`` and scan every completed call; raise on first block."""
        self._scan_tool_call_list(accumulator.completed(), released_chars)

    def _scan_tool_call_list(
        self,
        calls: list[Any],
        released_chars: int,
    ) -> None:
        """Scan a pre-drained list of :class:`CompletedToolCall` records.

        Shared by chat-completions and Responses finish paths — the
        Responses path must pre-drain so it can tell ``.done`` apart
        from an accumulator shutdown and compute unannounced-item ids.
        Raises :class:`PromptShieldStreamBlocked` on the first block.
        """
        for call in calls:
            raw_args: dict[str, Any] = {"_raw": call.arguments_raw}
            raw_result = self._agent_guard.scan_tool_call(
                call.name,
                raw_args,
                context={"tool_calls": [{"name": call.name}], "stream": True},
            )
            parsed_result: GateResult | None = None
            if call.arguments_parsed is not None:
                parsed_result = self._agent_guard.scan_tool_call(
                    call.name,
                    call.arguments_parsed,
                    context={"tool_calls": [{"name": call.name}], "stream": True},
                )
            for r in (raw_result, parsed_result):
                if r is None:
                    continue
                if r.blocked and self.mode == "block":
                    raise PromptShieldStreamBlocked(
                        finding=_finding_from_gate_result(r),
                        released_chars=released_chars,
                    )
                if r.scan_report is not None and r.scan_report.detections:
                    logger.warning(
                        "stream tool-call finding: tool=%s scan_id=%s",
                        call.name,
                        r.scan_report.scan_id,
                    )

    def _full_text_rescan(self, text: str, *, source: str) -> StreamFinding | None:
        """Belt-and-suspenders full-text re-scan with the wrapper's engine.

        Runs on the full accumulated stream text after the stream terminates,
        but only when ``scan_responses=True`` — the explicit opt-in that also
        turns on StreamGuard. B2: with ``scan_responses=False`` the wrapper
        preserves the pre-T7 raw-passthrough contract for stream text.

        Returns a :class:`StreamFinding` when ``mode == "block"`` and the engine
        would block; ``None`` otherwise. Non-block findings are logged.
        """
        if not self.scan_responses:
            return None
        if not text:
            return None
        report = self._engine.scan(
            text,
            context={"gate": "output", "source": source, "stream": True},
        )
        if report.action == Action.BLOCK and self.mode == "block":
            return _finding_from_scan_report(report, source=source)
        if report.detections:
            logger.warning(
                "stream full-text re-scan finding: scan_id=%s detections=%d",
                report.scan_id,
                len(report.detections),
            )
        return None

    # ------------------------------------------------------------------
    # Internal — Responses API support (shared with _ResponsesNamespace)
    # ------------------------------------------------------------------

    def _responses_scan_input(self, input_value: Any) -> None:
        """Run the input-side scan on a Responses payload.

        H4 fix: route chat-style ``{"role":..., "content":...}`` items
        through :meth:`_scan_input_messages`; route ``function_call_output``
        items through :class:`ToolResultGuard`; scan plain strings and
        content-part lists through the engine.
        """
        if input_value is None:
            return
        if isinstance(input_value, str):
            self._scan_plain_input_text(input_value)
            return
        if isinstance(input_value, list):
            chat_msgs: list[dict[str, Any]] = []
            for part in input_value:
                if isinstance(part, dict) and "role" in part and "content" in part:
                    content_val = part["content"]
                    chat_msgs.append(
                        {
                            "role": part.get("role", "user"),
                            "content": content_val,
                            "name": part.get("name"),
                            "tool_call_id": part.get("tool_call_id"),
                        }
                    )
                    continue
                if isinstance(part, dict) and part.get("type") == "function_call_output":
                    self._responses_scan_function_call_output(part)
                    continue
                for text in self._responses_input_text_part(part):
                    self._scan_plain_input_text(text)
            if chat_msgs:
                self._scan_input_messages(chat_msgs)
            return
        self._scan_plain_input_text(str(input_value))

    def _responses_input_text_part(self, part: Any) -> list[str]:
        """Extract scannable text snippets from one Responses input-list item."""
        if isinstance(part, str):
            return [part] if part else []
        if not isinstance(part, dict):
            return []
        texts: list[str] = []
        text = part.get("text")
        if isinstance(text, str) and text:
            texts.append(text)
        content = part.get("content")
        if isinstance(content, str) and content:
            texts.append(content)
        elif isinstance(content, list):
            for sub in content:
                if isinstance(sub, dict):
                    sub_text = sub.get("text")
                    if isinstance(sub_text, str) and sub_text:
                        texts.append(sub_text)
                elif isinstance(sub, str) and sub:
                    texts.append(sub)
        return texts

    def _scan_plain_input_text(self, text: str) -> None:
        if not text:
            return
        report = self._engine.scan(
            text,
            context={"gate": "input", "source": "openai_responses", "role": "user"},
        )
        if report.action == Action.BLOCK and self.mode == "block":
            raise ValueError(
                f"Prompt injection detected by prompt-shield: "
                f"{report.scan_id} (risk={report.overall_risk_score:.2f})"
            )
        if report.detections:
            logger.warning(
                "Suspicious content in responses input: %s",
                report.scan_id,
            )

    def _responses_scan_function_call_output(self, part: dict[str, Any]) -> None:
        """Scan a Responses ``function_call_output`` item like a tool-result message."""
        if not self.scan_tool_results:
            return
        output_val = part.get("output")
        text = _extract_openai_message_text(output_val)
        if not text:
            return
        tool_name = part.get("name") or part.get("call_id")
        if not isinstance(tool_name, str):
            tool_name = None
        report = self._tool_guard.scan(
            text,
            tool_name=tool_name,
            tool_type="openai_function_call_output",
        )
        if report.action == Action.BLOCK and self.tool_result_mode == "block":
            raise ValueError(
                f"prompt-shield BLOCKED function_call_output "
                f"(scan_id={report.scan_id}, tool_name={tool_name})"
            )
        if report.detections:
            logger.warning(
                "Suspicious content in function_call_output (tool_name=%s): %s",
                tool_name,
                report.scan_id,
            )

    def _scan_responses_response(self, response: Any) -> None:
        """Scan a non-stream Responses output."""
        if not self.scan_responses:
            return
        output_text = getattr(response, "output_text", None)
        if output_text is None:
            warnings.warn(
                "prompt-shield: scan_responses=True but the Responses object has no "
                "`output_text` attribute (unrecognised response shape); output "
                "scanning was skipped for this call.",
                UserWarning,
                stacklevel=3,
            )
            return
        if not isinstance(output_text, str) or not output_text:
            return
        resp_report = self._engine.scan(
            output_text,
            context={"gate": "output", "source": "openai_responses"},
        )
        if resp_report.detections:
            logger.warning(
                "Suspicious content in responses output: %s",
                resp_report.scan_id,
            )

    def _require_responses_api(self) -> None:
        """Raise :class:`NotImplementedError` with version hint if Responses is unavailable."""
        if not hasattr(self._client, "responses"):
            try:
                import openai as _openai

                ver = getattr(_openai, "__version__", "unknown")
            except ImportError:
                ver = "unknown"
            raise NotImplementedError(f"Responses API requires openai>=1.33; installed: {ver}")

    def _wrap_responses_stream(self, raw_stream: Any) -> _GuardedResponsesStream:
        return _GuardedResponsesStream(raw_iter=raw_stream, wrapper=self)

    def _wrap_async_responses_stream(self, raw_stream: Any) -> _AsyncGuardedResponsesStream:
        return _AsyncGuardedResponsesStream(raw_iter=raw_stream, wrapper=self)


# ----------------------------------------------------------------------
# Responses API namespace
# ----------------------------------------------------------------------


class _ResponsesNamespace:
    """``shield.responses`` accessor exposing Responses-API ``create``/``acreate``."""

    __slots__ = ("_p",)

    def __init__(self, parent: PromptShieldOpenAI) -> None:
        self._p = parent

    def create(self, **kwargs: Any) -> Any:
        """Sync Responses ``create``; ``stream=True`` returns a guarded iterator."""
        if self._p._is_async:
            raise TypeError(
                "PromptShieldOpenAI.responses.create() requires a synchronous "
                "openai.OpenAI client; use acreate() with AsyncOpenAI instead"
            )
        self._p._require_responses_api()
        if kwargs.get("stream", False):
            self._p._reject_sanitize_for_stream()
        self._p._responses_scan_input(kwargs.get("input"))

        if kwargs.get("stream", False):
            raw_stream = self._p._client.responses.create(**kwargs)
            return self._p._wrap_responses_stream(raw_stream)

        response = self._p._client.responses.create(**kwargs)
        self._p._scan_responses_response(response)
        return response

    async def acreate(self, **kwargs: Any) -> Any:
        """Async Responses ``create`` — mirrors :meth:`create` on ``AsyncOpenAI``."""
        if not self._p._is_async:
            raise TypeError(
                "PromptShieldOpenAI.responses.acreate() requires an openai.AsyncOpenAI "
                "client; use create() with a sync OpenAI instance instead"
            )
        self._p._require_responses_api()
        if kwargs.get("stream", False):
            self._p._reject_sanitize_for_stream()
        self._p._responses_scan_input(kwargs.get("input"))

        if kwargs.get("stream", False):
            raw_stream = await self._p._client.responses.create(**kwargs)
            return self._p._wrap_async_responses_stream(raw_stream)

        response = await self._p._client.responses.create(**kwargs)
        self._p._scan_responses_response(response)
        return response


# ----------------------------------------------------------------------
# Per-choice state for chat streams
# ----------------------------------------------------------------------


@dataclass
class _ChatChoiceState:
    """Per-``choices[].index`` state for a guarded chat stream.

    Separated out so H5 (multi-choice n>1) works: one guard, one
    accumulator, one pending-chunk buffer per choice index. Also holds
    the accumulated text for the H1 belt-and-suspenders full-text
    re-scan after the choice's ``finish_reason`` arrives.

    ``seen_tool_indices`` and ``had_bad_tool_delta`` implement the N1
    nameless-tool-call guard: the accumulator drops a tool-call entry
    whose name was never provided, so the only way to notice is to
    compare the indices we fed in against the indices that came back
    from :meth:`ToolCallAccumulator.completed`.
    """

    guard: StreamGuard | None = None
    accumulator: ToolCallAccumulator = field(default_factory=ToolCallAccumulator)
    pending_tool_chunks: list[Any] = field(default_factory=list)
    accumulated_text: list[str] = field(default_factory=list)
    finish_called: bool = False
    seen_tool_indices: set[int] = field(default_factory=set)
    had_bad_tool_delta: bool = False


def _choice_state_for(
    index: int,
    state_map: dict[int, _ChatChoiceState],
    wrapper: PromptShieldOpenAI,
) -> _ChatChoiceState:
    st = state_map.get(index)
    if st is None:
        st = _ChatChoiceState()
        if wrapper.scan_responses:
            st.guard = wrapper._make_stream_guard()
        state_map[index] = st
    return st


def _handle_chat_chunk(
    chunk: Any,
    state_map: dict[int, _ChatChoiceState],
    wrapper: PromptShieldOpenAI,
) -> tuple[list[Any], PromptShieldStreamBlocked | None]:
    """Process one chat-completion chunk; return ``(items_to_yield, deferred_error)``.

    Shared by sync and async guarded iterators (M1 — factors the
    sync/async duplication). May raise :class:`PromptShieldStreamBlocked`
    synchronously on tool-call scan failure or on an N1 nameless/bad
    tool-call delta. The N4 full-text rescan raises via the
    ``deferred_error`` slot and is sent BEFORE the remaining-text tail,
    not after: a short-reply injection delivers zero text to the caller
    before the exception lands.

    Yield-order contract on a chunk that carries ``finish_reason`` (B1):

    1. Text released during ``feed`` (emitted as shims above).
    2. ``StreamGuard.finish().remaining_text`` as a text shim with
       ``finish_reason=None`` (SUPPRESSED if N4 rescan blocks).
    3. Pending tool-call chunks (already scanned and cleared).
    4. A synthetic per-choice terminator shim carrying ``finish_reason``.
    """
    out: list[Any] = []
    deferred_error: PromptShieldStreamBlocked | None = None
    choices = getattr(chunk, "choices", None)
    # H2: usage-only chunks (choices=[] with .usage set) must be yielded verbatim,
    # not dropped. Chunks without a choices attribute at all also pass through.
    if choices is None or len(choices) == 0:
        out.append(chunk)
        return out, deferred_error

    any_choice_consumed = False

    for choice in choices:
        index = getattr(choice, "index", 0) or 0
        state = _choice_state_for(index, state_map, wrapper)
        delta = getattr(choice, "delta", None)
        finish_reason = getattr(choice, "finish_reason", None)

        content = getattr(delta, "content", None) if delta is not None else None
        tool_calls = getattr(delta, "tool_calls", None) if delta is not None else None
        # L3: legacy delta.function_call (pre-tools format) — route to accumulator too.
        legacy_fn = getattr(delta, "function_call", None) if delta is not None else None

        choice_consumed = False

        # --- text path ---
        if isinstance(content, str) and content:
            choice_consumed = True
            state.accumulated_text.append(content)
            if state.guard is not None:
                released = state.guard.feed(content)
                if released:
                    out.append(
                        _text_chunk(
                            released,
                            source_chunk=chunk,
                            choice_index=index,
                        )
                    )
            else:
                # B2: scan_responses=False — raw passthrough semantics. Yield a
                # per-choice shim carrying just this delta's content so the
                # wrapper never swallows text and chunk id/model survive (H2).
                out.append(
                    _text_chunk(
                        content,
                        source_chunk=chunk,
                        choice_index=index,
                    )
                )

        # --- tool-call path (buffered until scan completes) ---
        yielded_tool_this_chunk = False
        if tool_calls:
            choice_consumed = True
            for item in tool_calls:
                idx = getattr(item, "index", None)
                if isinstance(idx, int):
                    state.seen_tool_indices.add(idx)
                else:
                    # N1: non-integer index — accumulator will drop the fragment.
                    state.had_bad_tool_delta = True
                state.accumulator.accumulate_openai_delta(item)
            # N3: ALWAYS buffer a per-choice tool-only shim (content=None).
            # The source chunk could also carry content or finish_reason that
            # must not re-emit from the flush path.
            state.pending_tool_chunks.append(
                _tool_only_chunk(tool_calls=tool_calls, source_chunk=chunk, choice_index=index)
            )
            yielded_tool_this_chunk = True

        # L3: legacy function_call shape — adapt to the openai-delta shape
        # the accumulator understands (index=0 is a safe default because
        # legacy function_call predates multi-tool-call and never carries
        # a positional index of its own).
        if legacy_fn is not None:
            choice_consumed = True
            shim = SimpleNamespace(
                index=0,
                id=None,
                function=SimpleNamespace(
                    name=getattr(legacy_fn, "name", None),
                    arguments=getattr(legacy_fn, "arguments", None),
                ),
            )
            state.accumulator.accumulate_openai_delta(shim)
            state.seen_tool_indices.add(0)
            if not yielded_tool_this_chunk:
                state.pending_tool_chunks.append(
                    _tool_only_chunk(
                        tool_calls=None,
                        source_chunk=chunk,
                        choice_index=index,
                        function_call=legacy_fn,
                    )
                )
                yielded_tool_this_chunk = True

        # --- finish path ---
        if finish_reason:
            choice_consumed = True
            # H3: drain on ANY non-None finish_reason. ``accumulate_openai_finish``
            # itself only drains on ("tool_calls","stop","length"); force a drain by
            # passing "tool_calls" so content_filter / function_call etc. do not
            # leak unreleased pending entries.
            state.accumulator.accumulate_openai_finish("tool_calls")
            completed = state.accumulator.completed()
            released_chars = state.guard.released_chars if state.guard is not None else 0

            # N1 + H3 (combined): a tool-call delta whose entry the accumulator
            # dropped (nameless) is gone — pending_indices() cannot see it,
            # because _finalize pops before dropping. Compare the indices we
            # fed in against the indices that came back from ``completed``.
            scanned_indices = {c.index for c in completed}
            unscanned = state.seen_tool_indices - scanned_indices
            if unscanned or state.had_bad_tool_delta:
                logger.warning(
                    "stream tool-call deltas dropped unscanned "
                    "(nameless or non-integer index): unscanned=%r bad_delta=%s "
                    "finish_reason=%s",
                    sorted(unscanned),
                    state.had_bad_tool_delta,
                    finish_reason,
                )
                if wrapper.mode == "block":
                    raise PromptShieldStreamBlocked(
                        finding=StreamFinding(
                            source="tool_call",
                            scanner_id="wrapper",
                            confidence=1.0,
                            categories=("nameless_tool_call",),
                            explanation=(
                                f"tool-call deltas dropped unscanned "
                                f"(unscanned_indices={sorted(unscanned)}, "
                                f"bad_delta={state.had_bad_tool_delta}, "
                                f"finish_reason={finish_reason!r})"
                            ),
                            window_offset=0,
                        ),
                        released_chars=released_chars,
                    )

            # Scan the pre-drained completed calls.
            wrapper._scan_tool_call_list(completed, released_chars)

            # B1: finish the guard (do NOT yield remaining_text yet — N4
            # requires the rescan to run first so a block withholds the tail).
            report = None
            if state.guard is not None and not state.finish_called:
                report = state.guard.finish()
                state.finish_called = True

            # N4: full-text re-scan with the wrapper's own engine
            # (different detector family from StreamGuard) BEFORE the tail
            # ships. A short-reply injection that StreamGuard's hold-back
            # buffered will be withheld in full: caller sees zero text and
            # then the raised block.
            full_text = "".join(state.accumulated_text)
            finding = wrapper._full_text_rescan(full_text, source="openai")
            if finding is not None:
                deferred_error = PromptShieldStreamBlocked(
                    finding=finding,
                    released_chars=(
                        state.guard.released_chars if state.guard is not None else len(full_text)
                    ),
                )
                # Suppress the remaining-text tail, any pending tool chunks,
                # and the finish-reason chunk. Short-reply injection: nothing
                # more reaches the caller before the exception.
                state.pending_tool_chunks = []
                if any_choice_consumed or choice_consumed:
                    any_choice_consumed = True
                return out, deferred_error

            # Not blocked — now emit the tail, pending tool chunks, and a
            # synthetic per-choice terminator shim. The terminator is always
            # synthetic (never the raw chunk) so n>1 with content on choice A
            # and finish_reason on choice B does not re-emit A's content.
            if report is not None and report.remaining_text:
                out.append(
                    _text_chunk(
                        report.remaining_text,
                        finish_reason=None,
                        source_chunk=chunk,
                        choice_index=index,
                    )
                )
            out.extend(state.pending_tool_chunks)
            state.pending_tool_chunks = []
            out.append(
                _text_chunk(
                    None,
                    finish_reason=finish_reason,
                    source_chunk=chunk,
                    choice_index=index,
                )
            )

        if choice_consumed:
            any_choice_consumed = True

    # N2: a chunk whose choices carried no content, no tool_calls, no
    # legacy function_call and no finish_reason (an opening role chunk,
    # a refusal delta, a reasoning-content / audio / logprobs-only chunk)
    # must still reach the caller — pre-T7 behaviour was raw passthrough.
    if not any_choice_consumed:
        out.append(chunk)

    return out, deferred_error


def _finalize_chat_streams(
    state_map: dict[int, _ChatChoiceState],
    wrapper: PromptShieldOpenAI,
) -> tuple[list[Any], PromptShieldStreamBlocked | None]:
    """Post-loop flush for choices that ended without a ``finish_reason``.

    N5 fix: the stream ended abnormally (no ``finish_reason`` chunk).
    Run the full-text re-scan on whatever accumulated text we have and,
    if the engine would block in ``block`` mode, return a
    :class:`PromptShieldStreamBlocked` via the deferred-error slot so
    the driver raises instead of silently discarding the finding.
    A warning is logged in every case where the stream terminated
    without a terminator, since the belt-and-suspenders path is now the
    only safety net.
    """
    out: list[Any] = []
    deferred_error: PromptShieldStreamBlocked | None = None
    for index, state in state_map.items():
        if state.guard is None and not state.accumulated_text:
            continue
        if state.finish_called:
            continue

        report = None
        if state.guard is not None:
            report = state.guard.finish()
            state.finish_called = True

        logger.warning(
            "stream ended without finish_reason for choice index %d; "
            "running belt-and-suspenders rescan on %d accumulated chars",
            index,
            sum(len(s) for s in state.accumulated_text),
        )

        full_text = "".join(state.accumulated_text)
        if full_text:
            finding = wrapper._full_text_rescan(full_text, source="openai")
            if finding is not None:
                deferred_error = PromptShieldStreamBlocked(
                    finding=finding,
                    released_chars=(
                        state.guard.released_chars if state.guard is not None else len(full_text)
                    ),
                )
                # Suppress any tail we might otherwise ship — block means
                # no further output reaches the caller.
                continue

        if report is not None and report.remaining_text:
            out.append(
                _text_chunk(
                    report.remaining_text,
                    finish_reason=None,
                    choice_index=index,
                )
            )
    return out, deferred_error


# ----------------------------------------------------------------------
# Guarded chat stream iterators
# ----------------------------------------------------------------------


class _GuardedChatStream:
    """Synchronous guarded iterator over an ``openai`` chat-completion stream.

    Supports the ``with`` protocol (M2): ``with shield.create(stream=True) as s:``
    closes the underlying raw stream on exit.
    """

    def __init__(self, raw_iter: Iterator[Any], wrapper: PromptShieldOpenAI) -> None:
        self._raw_iter = raw_iter
        self._wrapper = wrapper
        self._state_map: dict[int, _ChatChoiceState] = {}
        self._gen = self._generate()

    def __iter__(self) -> _GuardedChatStream:
        return self

    def __next__(self) -> Any:
        return next(self._gen)

    def __enter__(self) -> _GuardedChatStream:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        close_fn = getattr(self._raw_iter, "close", None)
        if close_fn is not None:
            close_fn()
        gen_close = getattr(self._gen, "close", None)
        if gen_close is not None:
            gen_close()

    def _generate(self) -> Iterator[Any]:
        for chunk in self._raw_iter:
            items, deferred = _handle_chat_chunk(chunk, self._state_map, self._wrapper)
            for item in items:
                yield item
            if deferred is not None:
                raise deferred
        items, deferred = _finalize_chat_streams(self._state_map, self._wrapper)
        for item in items:
            yield item
        if deferred is not None:
            raise deferred


class _AsyncGuardedChatStream:
    """Async mirror of :class:`_GuardedChatStream`."""

    def __init__(self, raw_iter: AsyncIterator[Any], wrapper: PromptShieldOpenAI) -> None:
        self._raw_iter = raw_iter
        self._wrapper = wrapper
        self._state_map: dict[int, _ChatChoiceState] = {}
        self._gen = self._generate()

    def __aiter__(self) -> _AsyncGuardedChatStream:
        return self

    async def __anext__(self) -> Any:
        return await self._gen.__anext__()

    async def __aenter__(self) -> _AsyncGuardedChatStream:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        close_fn = getattr(self._raw_iter, "aclose", None)
        if close_fn is not None:
            await close_fn()
        gen_close = getattr(self._gen, "aclose", None)
        if gen_close is not None:
            await gen_close()

    async def _generate(self) -> AsyncIterator[Any]:
        async for chunk in self._raw_iter:
            items, deferred = _handle_chat_chunk(chunk, self._state_map, self._wrapper)
            for item in items:
                yield item
            if deferred is not None:
                raise deferred
        items, deferred = _finalize_chat_streams(self._state_map, self._wrapper)
        for item in items:
            yield item
        if deferred is not None:
            raise deferred


# ----------------------------------------------------------------------
# Per-item state for Responses streams
# ----------------------------------------------------------------------


@dataclass
class _ResponsesState:
    """State for a guarded Responses stream — single-choice; multiple function items.

    ``pending_fn_arg_deltas`` holds ``response.function_call_arguments.delta``
    events until their matching ``.done`` has scanned clean — M4 fix.
    ``unannounced_item_ids`` holds item ids seen on a delta event before
    (or without) a matching ``response.output_item.added`` — N1 fix for
    the Responses path: a function call for which no name was ever
    declared is fail-closed in block mode.
    """

    guard: StreamGuard | None = None
    accumulator: ToolCallAccumulator = field(default_factory=ToolCallAccumulator)
    accumulated_text: list[str] = field(default_factory=list)
    item_names: dict[str, str] = field(default_factory=dict)
    item_indices: dict[str, int] = field(default_factory=dict)
    next_index: int = 0
    finish_called: bool = False
    pending_fn_arg_deltas: dict[str, list[Any]] = field(default_factory=dict)
    unannounced_item_ids: set[str] = field(default_factory=set)


def _handle_responses_event(
    event: Any,
    state: _ResponsesState,
    wrapper: PromptShieldOpenAI,
) -> tuple[list[Any], PromptShieldStreamBlocked | None]:
    """Process one Responses stream event; return ``(items, deferred_error)``."""
    out: list[Any] = []
    deferred_error: PromptShieldStreamBlocked | None = None
    et = getattr(event, "type", None)

    if et == "response.output_item.added":
        item = getattr(event, "item", None)
        if item is not None and getattr(item, "type", None) == "function_call":
            item_id = getattr(item, "id", None)
            name = getattr(item, "name", None)
            if isinstance(item_id, str) and isinstance(name, str):
                state.item_names[item_id] = name
                state.item_indices[item_id] = state.next_index
                state.next_index += 1
                # An announced name invalidates any prior "unannounced" mark.
                state.unannounced_item_ids.discard(item_id)
        out.append(event)
        return out, deferred_error

    if et == "response.output_text.delta":
        delta_text = getattr(event, "delta", None)
        if isinstance(delta_text, str) and delta_text:
            state.accumulated_text.append(delta_text)
            if state.guard is not None:
                released = state.guard.feed(delta_text)
                if released:
                    out.append(_responses_text_event(released))
            else:
                # B2: scan_responses=False — pass text events through unchanged.
                out.append(event)
        return out, deferred_error

    if et == "response.function_call_arguments.delta":
        item_id = getattr(event, "item_id", None)
        delta_text = getattr(event, "delta", None)
        if isinstance(item_id, str) and isinstance(delta_text, str):
            idx = state.item_indices.get(item_id)
            if idx is None:
                # N1 (Responses variant): a delta for an item that was never
                # announced via ``response.output_item.added`` means we don't
                # know the function name. Track it so the matching ``.done``
                # can fail-closed in block mode.
                idx = state.next_index
                state.item_indices[item_id] = idx
                state.next_index += 1
                state.unannounced_item_ids.add(item_id)
            shim = SimpleNamespace(
                index=idx,
                id=item_id,
                function=SimpleNamespace(
                    name=state.item_names.get(item_id),
                    arguments=delta_text,
                ),
            )
            state.accumulator.accumulate_openai_delta(shim)
            # M4: buffer the delta event itself; it ships only after its
            # matching ``.done`` has been scanned clean. Previously this
            # event was silently dropped.
            state.pending_fn_arg_deltas.setdefault(item_id, []).append(event)
        return out, deferred_error

    if et == "response.function_call_arguments.done":
        item_id = getattr(event, "item_id", None)
        state.accumulator.accumulate_openai_finish("tool_calls")
        completed = state.accumulator.completed()
        released_chars = state.guard.released_chars if state.guard is not None else 0

        # N1 (Responses variant): a done event for an item that never had an
        # announced name is fail-closed in block mode. The accumulator
        # dropped the entry because it had no name; the buffered deltas are
        # discarded so the full payload never reaches the caller.
        if isinstance(item_id, str) and item_id in state.unannounced_item_ids:
            logger.warning(
                "Responses function_call.done for unannounced item_id=%r; "
                "dropping %d buffered delta events",
                item_id,
                len(state.pending_fn_arg_deltas.get(item_id, [])),
            )
            state.pending_fn_arg_deltas.pop(item_id, None)
            state.unannounced_item_ids.discard(item_id)
            if wrapper.mode == "block":
                raise PromptShieldStreamBlocked(
                    finding=StreamFinding(
                        source="tool_call",
                        scanner_id="wrapper",
                        confidence=1.0,
                        categories=("nameless_tool_call",),
                        explanation=(
                            f"Responses function_call_arguments.done for "
                            f"unannounced item_id={item_id!r}"
                        ),
                        window_offset=0,
                    ),
                    released_chars=released_chars,
                )
            # Non-block: still emit the ``.done`` event so the caller
            # observes completion; the actual argument deltas never ship.
            out.append(event)
            return out, deferred_error

        # Scan the pre-drained completed calls.
        wrapper._scan_tool_call_list(completed, released_chars)

        # M4: now emit the buffered deltas for THIS item in arrival order,
        # then the ``.done`` event itself.
        if isinstance(item_id, str):
            for buffered in state.pending_fn_arg_deltas.pop(item_id, []):
                out.append(buffered)
        out.append(event)
        return out, deferred_error

    if et == "response.completed":
        state.accumulator.accumulate_openai_finish("tool_calls")
        completed = state.accumulator.completed()
        released_chars = state.guard.released_chars if state.guard is not None else 0
        wrapper._scan_tool_call_list(completed, released_chars)

        # B1: finish the guard BEFORE the rescan (N4) so a block withholds
        # the tail — parallel to the chat-completion fix.
        report = None
        if state.guard is not None and not state.finish_called:
            report = state.guard.finish()
            state.finish_called = True

        full_text = "".join(state.accumulated_text)
        finding = wrapper._full_text_rescan(full_text, source="openai_responses")
        if finding is not None:
            deferred_error = PromptShieldStreamBlocked(
                finding=finding,
                released_chars=(
                    state.guard.released_chars if state.guard is not None else len(full_text)
                ),
            )
            return out, deferred_error

        if report is not None and report.remaining_text:
            out.append(_responses_text_event(report.remaining_text))

        out.append(event)
        return out, deferred_error

    # Unknown event type: pass through unchanged.
    out.append(event)
    return out, deferred_error


def _finalize_responses_state(
    state: _ResponsesState,
    wrapper: PromptShieldOpenAI,
) -> tuple[list[Any], PromptShieldStreamBlocked | None]:
    """Flush a Responses stream that ended without a ``response.completed`` event.

    N5 fix (parallel to :func:`_finalize_chat_streams`): the stream
    ended abnormally (no ``response.completed`` event). Run the
    full-text re-scan and, in ``block`` mode, raise via the deferred
    slot rather than silently discarding the finding. A warning is
    logged in every case.
    """
    out: list[Any] = []
    deferred_error: PromptShieldStreamBlocked | None = None
    if state.guard is None and not state.accumulated_text:
        return out, deferred_error
    if state.finish_called:
        return out, deferred_error

    report = None
    if state.guard is not None:
        report = state.guard.finish()
        state.finish_called = True

    logger.warning(
        "Responses stream ended without response.completed; "
        "running belt-and-suspenders rescan on %d accumulated chars",
        sum(len(s) for s in state.accumulated_text),
    )

    full_text = "".join(state.accumulated_text)
    if full_text:
        finding = wrapper._full_text_rescan(full_text, source="openai_responses")
        if finding is not None:
            deferred_error = PromptShieldStreamBlocked(
                finding=finding,
                released_chars=(
                    state.guard.released_chars if state.guard is not None else len(full_text)
                ),
            )
            return out, deferred_error

    if report is not None and report.remaining_text:
        out.append(_responses_text_event(report.remaining_text))
    return out, deferred_error


# ----------------------------------------------------------------------
# Guarded Responses stream iterators
# ----------------------------------------------------------------------


class _GuardedResponsesStream:
    """Synchronous guarded iterator over an ``openai`` Responses stream."""

    def __init__(self, raw_iter: Iterator[Any], wrapper: PromptShieldOpenAI) -> None:
        self._raw_iter = raw_iter
        self._wrapper = wrapper
        self._state = _ResponsesState(
            guard=wrapper._make_stream_guard() if wrapper.scan_responses else None,
        )
        self._gen = self._generate()

    def __iter__(self) -> _GuardedResponsesStream:
        return self

    def __next__(self) -> Any:
        return next(self._gen)

    def __enter__(self) -> _GuardedResponsesStream:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        close_fn = getattr(self._raw_iter, "close", None)
        if close_fn is not None:
            close_fn()
        gen_close = getattr(self._gen, "close", None)
        if gen_close is not None:
            gen_close()

    def _generate(self) -> Iterator[Any]:
        for event in self._raw_iter:
            items, deferred = _handle_responses_event(event, self._state, self._wrapper)
            for item in items:
                yield item
            if deferred is not None:
                raise deferred
        items, deferred = _finalize_responses_state(self._state, self._wrapper)
        for item in items:
            yield item
        if deferred is not None:
            raise deferred


class _AsyncGuardedResponsesStream:
    """Async mirror of :class:`_GuardedResponsesStream`."""

    def __init__(self, raw_iter: AsyncIterator[Any], wrapper: PromptShieldOpenAI) -> None:
        self._raw_iter = raw_iter
        self._wrapper = wrapper
        self._state = _ResponsesState(
            guard=wrapper._make_stream_guard() if wrapper.scan_responses else None,
        )
        self._gen = self._generate()

    def __aiter__(self) -> _AsyncGuardedResponsesStream:
        return self

    async def __anext__(self) -> Any:
        return await self._gen.__anext__()

    async def __aenter__(self) -> _AsyncGuardedResponsesStream:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        close_fn = getattr(self._raw_iter, "aclose", None)
        if close_fn is not None:
            await close_fn()
        gen_close = getattr(self._gen, "aclose", None)
        if gen_close is not None:
            await gen_close()

    async def _generate(self) -> AsyncIterator[Any]:
        async for event in self._raw_iter:
            items, deferred = _handle_responses_event(event, self._state, self._wrapper)
            for item in items:
                yield item
            if deferred is not None:
                raise deferred
        items, deferred = _finalize_responses_state(self._state, self._wrapper)
        for item in items:
            yield item
        if deferred is not None:
            raise deferred
