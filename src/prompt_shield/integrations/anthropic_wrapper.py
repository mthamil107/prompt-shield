"""Anthropic client wrapper for automatic prompt-shield scanning."""

from __future__ import annotations

import contextlib
import json
import logging
import warnings
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action
from prompt_shield.streaming.stream_guard import (
    PromptShieldStreamBlocked,
    StreamFinding,
    StreamGuard,
    StreamReport,
)
from prompt_shield.streaming.tool_call_accumulator import (
    CompletedToolCall,
    ToolCallAccumulator,
)
from prompt_shield.tool_guard.guard import ToolResultGuard

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator, Sequence

logger = logging.getLogger("prompt_shield.anthropic")


def _extract_tool_result_text(content: Any) -> str:
    """Anthropic's ``tool_result`` block content may be a string, a list of
    ``{"type": "text", "text": ...}`` (and ``"image"``) blocks, or omitted.
    Concatenate all text portions; ignore non-text blocks."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


# Wrapper-level mode strings map to StreamGuard modes. ``monitor`` has no
# StreamGuard analogue — the closest semantics are ``log`` (keep streaming,
# log every finding, never raise). ``sanitize`` is not listed: streams
# cannot recall released text, so the wrapper rejects it at the stream
# entry points rather than silently downgrading.
_STREAM_MODE_MAP: dict[str, str] = {
    "block": "block",
    "flag": "flag",
    "log": "log",
    "monitor": "log",
}


def _tool_use_block_to_call(block: Any, index: int) -> CompletedToolCall:
    """Translate a materialized ``tool_use`` content block into the shape
    ``_scan_streaming_tool_call`` understands. Non-dict ``input`` leaves
    ``arguments_parsed`` ``None`` so the raw payload still carries the
    scanner-visible bytes.
    """
    name_val = getattr(block, "name", None)
    name = name_val if isinstance(name_val, str) else ""
    id_val = getattr(block, "id", None)
    block_id = id_val if isinstance(id_val, str) else None
    inp = getattr(block, "input", None)
    if isinstance(inp, dict):
        raw = json.dumps(inp, default=str)
        parsed: dict[str, Any] | None = inp
    elif inp is None:
        raw = ""
        parsed = None
    else:
        raw = json.dumps(inp, default=str)
        parsed = None
    return CompletedToolCall(
        index=index,
        id=block_id,
        name=name,
        arguments_raw=raw,
        arguments_parsed=parsed,
        provider="anthropic",
        parse_error=None,
    )


class PromptShieldAnthropic:
    """Wraps an Anthropic client to auto-scan inputs, outputs, and tool results.

    v0.7.0 adds ``tool_result`` block scanning: when the ``messages`` list
    contains a user message whose content includes one or more
    ``{"type": "tool_result", "content": ...}`` blocks (Anthropic's native
    shape for agent tool outputs), each block's text is scanned through
    ``ToolResultGuard`` before the request is forwarded. Blocks are
    classified into ``ToolResultAttackFamily`` values available via
    ``report.scan_context.attack_families``.

    ``tool_result_mode`` controls tool result enforcement: ``'block'``
    raises on detection, non-block modes (``'flag'``, ``'log'``,
    ``'monitor'``) log and pass through. ``'sanitize'`` is not supported
    by this wrapper. When omitted, ``tool_result_mode`` inherits from
    ``mode``.

    v0.10.0 adds streaming + async + ``messages.stream`` coverage:
    :meth:`create` with ``stream=True`` returns a guarded event iterator;
    :meth:`acreate` is the ``async def`` twin, driving an
    ``AsyncAnthropic`` client (constructed lazily when ``async_client``
    was not supplied); :meth:`stream_messages` wraps the ergonomic
    ``messages.stream`` helper. Streamed ``tool_use`` input is scanned at
    the content-block boundary before the caller sees the completed call
    (gated by ``scan_responses``, mirroring the non-stream path).
    ``mode='sanitize'`` is rejected on every stream entry point because
    released text cannot be recalled.

    Scan engine coverage
    --------------------
    Two engines run under this wrapper and they cover different inputs:

    - **Stream output text** (``create(stream=True)`` events, ``text_stream``
      chunks, raw ``for event in stream`` iteration): scanned by a
      :class:`StreamGuard` using its own internal
      :class:`~prompt_shield.output_scanners.OutputScanEngine` — distinct
      from this wrapper's :class:`PromptShieldEngine`. Configurable via
      the ``stream_scanners``, ``stream_canary_tokens``,
      ``stream_hold_back`` and ``stream_overlap`` constructor kwargs,
      which mirror :class:`PromptShieldOpenAI`.
    - **Final-message text** (``get_final_message`` /
      ``get_final_text``): scanned by this wrapper's
      :class:`PromptShieldEngine` through
      :meth:`_scan_output_text_enforced`. Runs only when the live guard
      did not already process the text (i.e., the caller skipped
      ``text_stream`` or iterated it only partially).
    - **Tool calls** (streamed ``tool_use`` input and tool_use blocks in
      the final/non-stream response): scanned by this wrapper's
      :class:`PromptShieldEngine` through
      :meth:`_scan_streaming_tool_call`. Only the raw argument JSON is
      scanned — one pass per call — because the parsed re-serialization
      only differs by whitespace from the raw payload and would
      silently drop duplicate keys (last-key-wins), giving the same
      verdict without covering more surface. ``d034_honeypot_tool``
      fires via the shared ``tool_calls`` context regardless.
    - **Input messages and ``tool_result`` blocks**: scanned by this
      wrapper's :class:`PromptShieldEngine` and
      :class:`ToolResultGuard` as before.

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
        scan_tool_results: bool = True,
        tool_result_mode: str | None = None,
        async_client: Any = None,
        *,
        stream_scanners: Sequence[str] | None = None,
        stream_canary_tokens: Sequence[str] | None = None,
        stream_hold_back: int | None = None,
        stream_overlap: int | None = None,
    ) -> None:
        if client is None:
            try:
                from anthropic import Anthropic

                client = Anthropic()
            except ImportError as exc:
                raise ImportError(
                    "Install anthropic extras: pip install prompt-shield[anthropic]"
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
                    "('sanitize' is not supported by PromptShieldAnthropic); "
                    "pass tool_result_mode explicitly"
                )
            raise ValueError(
                "tool_result_mode='sanitize' is not supported by PromptShieldAnthropic"
            )
        valid_modes = ("block", "flag", "log", "monitor")
        if effective_tool_mode not in valid_modes:
            raise ValueError(
                f"tool_result_mode must be one of {valid_modes}, got {effective_tool_mode!r}"
            )
        self.tool_result_mode = effective_tool_mode
        # mode="log" so this wrapper controls block/flag via tool_result_mode.
        self._tool_guard = ToolResultGuard(engine=self._engine, mode="log")
        self._async_client = async_client

        # Stream-scan configuration — mirrors PromptShieldOpenAI so the
        # two wrappers share a surface. Unset values leave the guard
        # defaults alone (see ``_build_stream_guard``).
        self._stream_scanners: list[str] | None = (
            list(stream_scanners) if stream_scanners is not None else None
        )
        self._stream_canary_tokens: tuple[str, ...] = (
            tuple(stream_canary_tokens) if stream_canary_tokens is not None else ()
        )
        self._stream_hold_back = stream_hold_back
        self._stream_overlap = stream_overlap

    # ------------------------------------------------------------------
    # Public API — sync
    # ------------------------------------------------------------------
    def create(self, **kwargs: Any) -> Any:
        """Scan messages, call ``messages.create``, optionally scan response.

        v0.7.0: also scans ``tool_result`` blocks inside a message's
        content list (Anthropic's native shape for agent tool outputs).

        v0.10.0: when ``stream=True``, returns a guarded iterator that
        feeds text deltas through a :class:`StreamGuard` and routes
        ``tool_use`` input deltas through a :class:`ToolCallAccumulator`.
        Each yielded ``content_block_delta`` carries the releasable text
        slice from the guard; a synthesized trailing delta before
        ``message_stop`` carries the held tail so raw-event consumers see
        the complete text. Tool-use scanning is gated by
        ``scan_responses`` (same rule as the non-stream path).
        ``mode='sanitize'`` is rejected here because released text can
        no longer be recalled.
        """
        messages = kwargs.get("messages", [])
        self._scan_input_messages(messages)

        stream_requested = bool(kwargs.get("stream"))
        if stream_requested:
            self._reject_sanitize_for_stream()
        response = self._client.messages.create(**kwargs)

        if stream_requested:
            return _GuardedAnthropicStream(
                source=response,
                guard=self._build_stream_guard() if self.scan_responses else None,
                accumulator=ToolCallAccumulator(),
                on_tool_call=(self._scan_streaming_tool_call if self.scan_responses else None),
            )

        if self.scan_responses:
            if hasattr(response, "content"):
                self._scan_response_content(response)
            else:
                warnings.warn(
                    "prompt-shield: response scanning is enabled but the response shape "
                    "is not scannable (stream=True returns an event iterator with no "
                    ".content attribute; use shield.create(stream=True) for guarded "
                    "streaming). This call's output was not scanned. Set "
                    "scan_responses=False or use a non-streaming call to suppress "
                    "this warning.",
                    UserWarning,
                    stacklevel=2,
                )

        return response

    def stream_messages(self, **kwargs: Any) -> GuardedMessageStreamManager:
        """Guard-wrap the ergonomic ``client.messages.stream`` helper.

        Returns a context manager; ``__enter__`` yields a
        :class:`GuardedMessageStream` whose ``.text_stream`` filters
        through a :class:`StreamGuard` (releases the held tail at the
        end) and whose ``.get_final_message()`` / ``.get_final_text()``
        scan every text block and ``tool_use`` block in the final
        message before returning it. Raw iteration (``for event in
        stream: ...``) is routed through the same event-dispatch
        pipeline as ``create(stream=True)`` so no event bypasses the
        guard. ``stream_messages()`` and ``create(stream=True)`` share
        the same guard pipeline: use ``stream_messages()`` for the
        ergonomic ``.text_stream`` / ``.get_final_message()`` API, and
        ``create(stream=True)`` when the raw event iterator is enough.
        """
        self._reject_sanitize_for_stream()
        underlying = self._client.messages.stream(**kwargs)
        return GuardedMessageStreamManager(
            manager=underlying,
            shield=self,
        )

    # ------------------------------------------------------------------
    # Public API — async
    # ------------------------------------------------------------------
    async def acreate(self, **kwargs: Any) -> Any:
        """Async twin of :meth:`create`.

        Drives an ``AsyncAnthropic`` client — either the one supplied
        via ``async_client=`` in ``__init__`` or one constructed lazily
        on first access (requires ``anthropic`` to be installed). With
        ``stream=True`` returns a :class:`_GuardedAnthropicAsyncStream`;
        otherwise returns the awaited response after the same output
        scan as :meth:`create`.
        """
        messages = kwargs.get("messages", [])
        self._scan_input_messages(messages)

        stream_requested = bool(kwargs.get("stream"))
        if stream_requested:
            self._reject_sanitize_for_stream()
        client = self._get_async_client()
        response = await client.messages.create(**kwargs)

        if stream_requested:
            return _GuardedAnthropicAsyncStream(
                source=response,
                guard=self._build_stream_guard() if self.scan_responses else None,
                accumulator=ToolCallAccumulator(),
                on_tool_call=(self._scan_streaming_tool_call if self.scan_responses else None),
            )

        if self.scan_responses:
            if hasattr(response, "content"):
                self._scan_response_content(response)
            else:
                warnings.warn(
                    "prompt-shield: response scanning is enabled but the response shape "
                    "is not scannable (stream=True returns an event iterator with no "
                    ".content attribute; use shield.acreate(stream=True) for guarded "
                    "streaming). This call's output was not scanned. Set "
                    "scan_responses=False or use a non-streaming call to suppress "
                    "this warning.",
                    UserWarning,
                    stacklevel=2,
                )

        return response

    def astream_messages(self, **kwargs: Any) -> GuardedAsyncMessageStreamManager:
        """Async variant of :meth:`stream_messages`.

        Returns an object usable as an ``async with`` context manager;
        ``__aenter__`` yields a :class:`GuardedAsyncMessageStream` with
        a filtered async ``.text_stream`` and an async
        ``.get_final_message()`` / ``.get_final_text()`` that scan every
        text block and ``tool_use`` block in the final message before
        returning it.
        """
        self._reject_sanitize_for_stream()
        client = self._get_async_client()
        underlying = client.messages.stream(**kwargs)
        return GuardedAsyncMessageStreamManager(
            manager=underlying,
            shield=self,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _get_async_client(self) -> Any:
        if self._async_client is not None:
            return self._async_client
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:
            raise ImportError(
                "Install anthropic extras: pip install prompt-shield[anthropic]"
            ) from exc
        self._async_client = AsyncAnthropic()
        return self._async_client

    def _reject_sanitize_for_stream(self) -> None:
        """Streams cannot sanitize: once bytes are released to the caller
        they cannot be recalled, so the semantics ``sanitize`` promises
        are impossible to deliver mid-stream."""
        if self.mode == "sanitize":
            raise ValueError(
                "sanitize mode is not supported on streaming responses; "
                "released text cannot be recalled. Use mode='block', 'flag', "
                "'log', or 'monitor' for streams."
            )

    def _build_stream_guard(self) -> StreamGuard:
        stream_mode = _STREAM_MODE_MAP.get(self.mode, "flag")
        kwargs: dict[str, Any] = {"mode": stream_mode}
        if self._stream_scanners is not None:
            kwargs["scanners"] = self._stream_scanners
        if self._stream_canary_tokens:
            kwargs["canary_tokens"] = self._stream_canary_tokens
        if self._stream_hold_back is not None:
            kwargs["hold_back"] = self._stream_hold_back
        if self._stream_overlap is not None:
            kwargs["overlap"] = self._stream_overlap
        return StreamGuard(**kwargs)

    def _scan_input_messages(self, messages: list[Any]) -> None:
        """Scan every user-visible message text and every ``tool_result``
        block. Factored out of :meth:`create` so sync and async paths
        share identical input-scan behaviour; raises on ``mode='block'``
        the way the original :meth:`create` did.
        """
        for msg in messages:
            content = msg.get("content")

            if isinstance(content, list):
                self._scan_tool_result_blocks(content, role=msg.get("role", "unknown"))

            if isinstance(content, str):
                texts: list[str] = [content]
            elif isinstance(content, list):
                texts = [
                    block.get("text", "")
                    if isinstance(block, dict) and block.get("type") != "tool_result"
                    else ""
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

    def _scan_response_content(self, response: Any) -> None:
        """Scan every content block in a non-stream response.

        Text blocks run through the output scan engine (previous
        behaviour). ``tool_use`` and ``server_tool_use`` blocks run
        through :meth:`_scan_streaming_tool_call` — ``BLOCK`` verdicts
        raise :class:`PromptShieldStreamBlocked` when
        ``self.mode == "block"``; other modes log. Closes the T8
        future_note gap where a response made entirely of ``tool_use``
        blocks reached neither the text-scan loop nor the
        unknown-shape warning.
        """
        for i, block in enumerate(response.content):
            block_type = getattr(block, "type", None)
            if block_type in ("tool_use", "server_tool_use"):
                call = _tool_use_block_to_call(block, i)
                self._scan_streaming_tool_call(call)
                continue
            text = getattr(block, "text", None)
            if text:
                # Non-stream text blocks preserve the pre-T8 log-only
                # behaviour — ``mode='block'`` on response text has
                # never raised on this path. Stream paths enforce via
                # ``_scan_output_text_enforced``.
                resp_report = self._engine.scan(
                    text,
                    context={"gate": "output", "source": "anthropic"},
                )
                if resp_report.detections:
                    logger.warning(
                        "Suspicious content in response: %s",
                        resp_report.scan_id,
                    )

    def _scan_output_text_enforced(self, text: str) -> None:
        """Scan a text fragment emitted on a stream path. Unlike the
        non-stream text-block scan, this raises
        :class:`PromptShieldStreamBlocked` when a ``BLOCK`` verdict
        fires in ``mode='block'`` — needed so an injected prompt that
        bypassed the live ``StreamGuard`` (e.g. because the caller
        went straight to ``get_final_message``) still fails closed.
        """
        resp_report = self._engine.scan(
            text,
            context={"gate": "output", "source": "anthropic"},
        )
        if resp_report.action == Action.BLOCK and self.mode == "block":
            raise PromptShieldStreamBlocked(
                finding=StreamFinding(
                    source="output_text",
                    scanner_id=resp_report.scan_id or "output_text",
                    confidence=1.0,
                    categories=("output_text",),
                    explanation=(f"blocked response text (scan_id={resp_report.scan_id})"),
                    window_offset=0,
                    metadata={},
                ),
                released_chars=0,
            )
        if resp_report.detections:
            logger.warning(
                "Suspicious content in response: %s",
                resp_report.scan_id,
            )

    def _scan_streaming_tool_call(self, call: CompletedToolCall) -> None:
        """Scan one completed ``tool_use`` call.

        Scans the raw concatenated JSON fragment as a single engine
        pass. A second pass over the parsed-then-re-serialized view was
        removed in v3: for every probed call the parsed re-serialization
        differs from ``arguments_raw`` only by whitespace while silently
        dropping duplicate keys (last-key-wins) — the raw scan already
        covers the duplicate-key attack surface and the parsed scan was
        redundant. ``d034_honeypot_tool`` still fires via the shared
        ``tool_calls`` context on every call. ``mode='block'`` raises
        :class:`PromptShieldStreamBlocked`; other modes log.
        """
        name = call.name
        context: dict[str, Any] = {
            "gate": "tool_call",
            "tool": name,
            "tool_calls": [{"name": name, "arguments": call.arguments_raw}],
            "source": "anthropic",
            "stream": True,
        }

        # The context above carries d034's invocation signal even if the
        # raw payload is empty, so run the scan even when arguments_raw
        # is "" (e.g. a tool_use with no input): the honeypot name alone
        # must still raise.
        rep = self._engine.scan(call.arguments_raw or "", context=context)
        if rep.action == Action.BLOCK and self.mode == "block":
            raise PromptShieldStreamBlocked(
                finding=StreamFinding(
                    source="tool_call",
                    scanner_id=rep.scan_id or "tool_call",
                    confidence=1.0,
                    categories=("tool_call", "raw"),
                    explanation=(f"blocked streamed tool_use {name!r} scan_id={rep.scan_id}"),
                    window_offset=0,
                    metadata={
                        "tool_name": name,
                        "tool_id": call.id or "",
                        "parse_error": call.parse_error or "",
                        "scanned_view": "raw",
                        "detectors": [d.detector_id for d in rep.detections],
                    },
                ),
                released_chars=0,
            )
        if rep.detections:
            logger.warning(
                "Suspicious content in streamed tool_use (name=%s, id=%s): %s",
                name,
                call.id,
                rep.scan_id,
            )

    def _scan_tool_result_blocks(self, content: list[Any], role: str) -> None:
        """Scan every ``{"type": "tool_result", ...}`` block in a message's content list."""
        if not self.scan_tool_results:
            return
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            text = _extract_tool_result_text(block.get("content"))
            if not text:
                continue
            tool_use_id = block.get("tool_use_id")
            report = self._tool_guard.scan(
                text,
                tool_name=tool_use_id if isinstance(tool_use_id, str) else None,
                tool_type="anthropic_tool",
            )
            if report.action == Action.BLOCK and self.tool_result_mode == "block":
                families = (
                    [f.value for f in report.scan_context.attack_families]
                    if report.scan_context
                    else []
                )
                raise ValueError(
                    f"prompt-shield BLOCKED tool_result block "
                    f"(scan_id={report.scan_id}, tool_use_id={tool_use_id}, "
                    f"families={families})"
                )
            if report.detections:
                families = (
                    [f.value for f in report.scan_context.attack_families]
                    if report.scan_context
                    else []
                )
                logger.warning(
                    "Suspicious content in tool_result block (role=%s, tool_use_id=%s): "
                    "%s (families=%s)",
                    role,
                    tool_use_id,
                    report.scan_id,
                    families,
                )

    @property
    def engine(self) -> PromptShieldEngine:
        """Access the underlying scanning engine."""
        return self._engine


# ----------------------------------------------------------------------
# Stream wrappers
# ----------------------------------------------------------------------


class _GuardedAnthropicStream:
    """Sync wrapper over an Anthropic event stream.

    Routes ``text_delta`` events through a single :class:`StreamGuard`
    (shared across every text content block in the response), routes
    ``tool_use`` input deltas through a single
    :class:`ToolCallAccumulator`, and synthesizes a trailing
    ``content_block_delta`` carrying ``StreamReport.remaining_text`` at
    ``message_stop`` so raw-event consumers still receive the complete
    text. After exhaustion, :attr:`stream_report` and :attr:`tool_calls`
    report what the guard observed. If the underlying stream ends
    without a ``message_stop`` event (truncation), the held tail is
    still emitted and any pending ``tool_use`` indices are drained
    best-effort so no scan is silently skipped.
    """

    def __init__(
        self,
        source: Any,
        guard: StreamGuard | None,
        accumulator: ToolCallAccumulator,
        on_tool_call: Any,
    ) -> None:
        self._source = source
        self._guard = guard
        self._accumulator = accumulator
        self._on_tool_call = on_tool_call
        self.stream_report: StreamReport | None = None
        self.tool_calls: list[CompletedToolCall] = []
        self._finish_called = False
        self._gen = self._run()

    def __iter__(self) -> Iterator[Any]:
        return self._gen

    def __next__(self) -> Any:
        return next(self._gen)

    def _run(self) -> Iterator[Any]:
        text_indices: set[int] = set()
        tool_indices: set[int] = set()
        last_text_index: int | None = None
        message_stopped = False

        try:
            for event in self._source:
                et = getattr(event, "type", None)

                if et == "content_block_start":
                    idx = getattr(event, "index", None)
                    block = getattr(event, "content_block", None)
                    bt = getattr(block, "type", None) if block is not None else None
                    if bt == "text" and isinstance(idx, int):
                        text_indices.add(idx)
                        last_text_index = idx
                    elif bt in ("tool_use", "server_tool_use") and isinstance(idx, int):
                        tool_indices.add(idx)
                        self._accumulator.accumulate_anthropic_event(event)
                    yield event
                    continue

                if et == "content_block_delta":
                    delta = getattr(event, "delta", None)
                    dt = getattr(delta, "type", None) if delta is not None else None
                    if dt == "text_delta":
                        didx = getattr(event, "index", None)
                        if isinstance(didx, int):
                            if didx not in text_indices:
                                logger.debug(
                                    "prompt_shield.anthropic: text_delta for index %d "
                                    "with no preceding content_block_start; treating "
                                    "as text",
                                    didx,
                                )
                                text_indices.add(didx)
                            last_text_index = didx
                        yield from self._handle_text_delta(event, delta)
                    elif dt == "input_json_delta":
                        self._accumulator.accumulate_anthropic_event(event)
                        yield event
                    else:
                        yield event
                    continue

                if et == "content_block_stop":
                    idx = getattr(event, "index", None)
                    if isinstance(idx, int) and idx in tool_indices:
                        self._accumulator.accumulate_anthropic_event(event)
                        for call in self._accumulator.completed():
                            self.tool_calls.append(call)
                            if self._on_tool_call is not None:
                                self._on_tool_call(call)
                    yield event
                    continue

                if et == "message_stop":
                    message_stopped = True
                    yield from self._finalize(last_text_index)
                    # N3: drain any tool_use that never saw a
                    # ``content_block_stop``. Any ``PromptShieldStreamBlocked``
                    # raised here propagates to the consumer.
                    self._drain_pending_tool_indices()
                    yield event
                    continue

                if et == "text":
                    # N1: the real SDK's ``MessageStream`` emits a derived
                    # ``text`` event (``.text`` fragment, ``.snapshot``
                    # accumulated) BEFORE the ``content_block_delta`` that
                    # carries the same fragment. Passing it through would
                    # release the unguarded text ahead of the guard. When a
                    # guard is active, drop the SDK's derived ``text`` event
                    # — guard-filtered text still reaches the consumer via
                    # the ``content_block_delta`` path below.
                    if self._guard is not None:
                        continue
                    yield event
                    continue

                # message_start / message_delta / ping / unknown — pass through.
                yield event

            if not message_stopped:
                # Source ended without ``message_stop`` — best-effort flush
                # so no held text or pending tool_use scan is silently lost.
                yield from self._finalize(last_text_index)
                self._drain_pending_tool_indices()
        finally:
            # Last-resort: ensure finish() ran even on early abandon.
            # No yields allowed here (generator may be mid-close).
            if self._guard is not None and not self._finish_called:
                with contextlib.suppress(Exception):
                    self.stream_report = self._guard.finish()
                    self._finish_called = True

    def _finalize(self, last_text_index: int | None) -> Iterator[Any]:
        if self._guard is not None and not self._finish_called:
            report = self._guard.finish()
            self._finish_called = True
            self.stream_report = report
            if report.remaining_text and last_text_index is not None:
                yield SimpleNamespace(
                    type="content_block_delta",
                    index=last_text_index,
                    delta=SimpleNamespace(type="text_delta", text=report.remaining_text),
                )

    def _drain_pending_tool_indices(self) -> None:
        """Flush any tool_use index the accumulator still holds open.

        N3: when the stream ends (``message_stop`` or source exhaustion)
        with a tool_use index that never saw ``content_block_stop``, we
        synthesize the missing stop so the accumulator can finalize the
        call, then invoke ``on_tool_call``. A ``PromptShieldStreamBlocked``
        raised by the scan **propagates** — a truncated honeypot call
        must not be silently fail-open in ``mode='block'``. The call
        still appears in ``self.tool_calls`` for post-hoc audit.
        """
        pending = list(self._accumulator.pending_indices())
        if not pending:
            return
        for idx in pending:
            # Synthesize a content_block_stop so the accumulator can
            # finalize the call. Accumulator-internal errors are
            # swallowed (best-effort); the scan runs below.
            with contextlib.suppress(Exception):
                self._accumulator.accumulate_anthropic_event(
                    SimpleNamespace(type="content_block_stop", index=idx)
                )
        for call in self._accumulator.completed():
            self.tool_calls.append(call)
            if self._on_tool_call is not None:
                # No suppress: let PromptShieldStreamBlocked propagate so
                # ``mode='block'`` still fails closed on a truncated
                # tool_use. The call is already in ``self.tool_calls``.
                self._on_tool_call(call)

    def _handle_text_delta(self, event: Any, delta: Any) -> Iterator[Any]:
        """Common text-delta dispatch for the sync and async streams.

        A non-str ``delta.text`` under current SDK shapes is an SDK bug
        — passed through unchanged rather than crashing the stream. A
        non-scanning path (no guard) also passes through unchanged.
        """
        text = getattr(delta, "text", None)
        if self._guard is None:
            yield event
            return
        if not isinstance(text, str):
            yield event
            return
        if not text:
            # An empty text_delta carries nothing to scan; drop it.
            return
        released = self._guard.feed(text)
        if released:
            yield SimpleNamespace(
                type="content_block_delta",
                index=getattr(event, "index", None),
                delta=SimpleNamespace(type="text_delta", text=released),
            )


class _GuardedAnthropicAsyncStream:
    """Async wrapper over an Anthropic async event stream.

    Mirrors :class:`_GuardedAnthropicStream` with ``async for`` semantics.
    """

    def __init__(
        self,
        source: Any,
        guard: StreamGuard | None,
        accumulator: ToolCallAccumulator,
        on_tool_call: Any,
    ) -> None:
        self._source = source
        self._guard = guard
        self._accumulator = accumulator
        self._on_tool_call = on_tool_call
        self.stream_report: StreamReport | None = None
        self.tool_calls: list[CompletedToolCall] = []
        self._finish_called = False
        self._agen = self._run()

    def __aiter__(self) -> AsyncIterator[Any]:
        return self._agen

    async def _run(self) -> AsyncIterator[Any]:
        text_indices: set[int] = set()
        tool_indices: set[int] = set()
        last_text_index: int | None = None
        message_stopped = False

        try:
            async for event in self._source:
                et = getattr(event, "type", None)

                if et == "content_block_start":
                    idx = getattr(event, "index", None)
                    block = getattr(event, "content_block", None)
                    bt = getattr(block, "type", None) if block is not None else None
                    if bt == "text" and isinstance(idx, int):
                        text_indices.add(idx)
                        last_text_index = idx
                    elif bt in ("tool_use", "server_tool_use") and isinstance(idx, int):
                        tool_indices.add(idx)
                        self._accumulator.accumulate_anthropic_event(event)
                    yield event
                    continue

                if et == "content_block_delta":
                    delta = getattr(event, "delta", None)
                    dt = getattr(delta, "type", None) if delta is not None else None
                    if dt == "text_delta":
                        didx = getattr(event, "index", None)
                        if isinstance(didx, int):
                            if didx not in text_indices:
                                logger.debug(
                                    "prompt_shield.anthropic: text_delta for index %d "
                                    "with no preceding content_block_start; treating "
                                    "as text",
                                    didx,
                                )
                                text_indices.add(didx)
                            last_text_index = didx
                        text = getattr(delta, "text", None)
                        if self._guard is None or not isinstance(text, str):
                            yield event
                        elif not text:
                            pass
                        else:
                            released = self._guard.feed(text)
                            if released:
                                yield SimpleNamespace(
                                    type="content_block_delta",
                                    index=getattr(event, "index", None),
                                    delta=SimpleNamespace(type="text_delta", text=released),
                                )
                    elif dt == "input_json_delta":
                        self._accumulator.accumulate_anthropic_event(event)
                        yield event
                    else:
                        yield event
                    continue

                if et == "content_block_stop":
                    idx = getattr(event, "index", None)
                    if isinstance(idx, int) and idx in tool_indices:
                        self._accumulator.accumulate_anthropic_event(event)
                        for call in self._accumulator.completed():
                            self.tool_calls.append(call)
                            if self._on_tool_call is not None:
                                self._on_tool_call(call)
                    yield event
                    continue

                if et == "message_stop":
                    message_stopped = True
                    async for ev in self._afinalize(last_text_index):
                        yield ev
                    # N3: drain any tool_use that never saw a
                    # ``content_block_stop``. Any ``PromptShieldStreamBlocked``
                    # raised here propagates to the consumer.
                    self._drain_pending_tool_indices()
                    yield event
                    continue

                if et == "text":
                    # N1: see sync equivalent — drop the SDK's derived
                    # ``text`` event when a guard is active so the
                    # unguarded fragment does not reach the consumer
                    # ahead of the guard-filtered ``content_block_delta``.
                    if self._guard is not None:
                        continue
                    yield event
                    continue

                yield event

            if not message_stopped:
                async for ev in self._afinalize(last_text_index):
                    yield ev
                self._drain_pending_tool_indices()
        finally:
            if self._guard is not None and not self._finish_called:
                with contextlib.suppress(Exception):
                    self.stream_report = self._guard.finish()
                    self._finish_called = True

    async def _afinalize(self, last_text_index: int | None) -> AsyncIterator[Any]:
        if self._guard is not None and not self._finish_called:
            report = self._guard.finish()
            self._finish_called = True
            self.stream_report = report
            if report.remaining_text and last_text_index is not None:
                yield SimpleNamespace(
                    type="content_block_delta",
                    index=last_text_index,
                    delta=SimpleNamespace(type="text_delta", text=report.remaining_text),
                )

    def _drain_pending_tool_indices(self) -> None:
        """Async twin of :meth:`_GuardedAnthropicStream._drain_pending_tool_indices`.

        N3: ``PromptShieldStreamBlocked`` propagates so a truncated
        honeypot invocation still fails closed in ``mode='block'``.
        """
        pending = list(self._accumulator.pending_indices())
        if not pending:
            return
        for idx in pending:
            with contextlib.suppress(Exception):
                self._accumulator.accumulate_anthropic_event(
                    SimpleNamespace(type="content_block_stop", index=idx)
                )
        for call in self._accumulator.completed():
            self.tool_calls.append(call)
            if self._on_tool_call is not None:
                # N3: no suppress — let the block raise.
                self._on_tool_call(call)


class GuardedMessageStream:
    """Guarded view of an Anthropic ``MessageStream``.

    Exposes a filtered :attr:`text_stream` (yields what the guard
    releases, plus the held tail at exhaustion) and
    :meth:`get_final_message` / :meth:`get_final_text` that scan every
    text block AND every ``tool_use`` block in the final message before
    returning it. Raw iteration (``for event in stream: ...``) is routed
    through the same event-dispatch pipeline as
    :meth:`PromptShieldAnthropic.create` with ``stream=True`` so no
    event bypasses the guard. The Anthropic SDK's ``MessageStream`` does
    not expose an ``accumulate()`` method in 2.x, so this wrapper does
    not either — use ``get_final_message()`` instead.
    """

    def __init__(
        self,
        underlying: Any,
        shield: PromptShieldAnthropic,
    ) -> None:
        self._underlying = underlying
        self._shield = shield
        self._guard = shield._build_stream_guard() if shield.scan_responses else None
        self._accumulator = ToolCallAccumulator()
        self.stream_report: StreamReport | None = None
        self.tool_calls: list[CompletedToolCall] = []

    @property
    def text_stream(self) -> Iterator[str]:
        return self._iter_text_stream()

    def _iter_text_stream(self) -> Iterator[str]:
        # N2: do NOT mark the text as "guard-covered" when iteration
        # starts. The guard only covers the text it has actually
        # processed; a caller that abandons the loop early leaves later
        # text unguarded. ``stream_report is not None`` after
        # ``StreamGuard.finish()`` ran is the authoritative "guard
        # finished" marker used by :meth:`_scan_final_message`.
        source = getattr(self._underlying, "text_stream", None)
        if source is None:
            return
        if self._guard is None:
            for chunk in source:
                if isinstance(chunk, str) and chunk:
                    yield chunk
            return
        for chunk in source:
            if not isinstance(chunk, str) or not chunk:
                continue
            released = self._guard.feed(chunk)
            if released:
                yield released
        if self.stream_report is None:
            self.stream_report = self._guard.finish()
        if self.stream_report.remaining_text:
            yield self.stream_report.remaining_text

    def __iter__(self) -> Iterator[Any]:
        """Iterate underlying events through the same guard pipeline
        used by :meth:`PromptShieldAnthropic.create` with ``stream=True``.
        """
        return self._iter_events()

    def _iter_events(self) -> Iterator[Any]:
        on_tool_call = (
            self._shield._scan_streaming_tool_call if self._shield.scan_responses else None
        )
        inner = _GuardedAnthropicStream(
            source=iter(self._underlying),
            guard=self._guard,
            accumulator=self._accumulator,
            on_tool_call=on_tool_call,
        )
        try:
            yield from inner
        finally:
            if inner.stream_report is not None:
                self.stream_report = inner.stream_report
            self.tool_calls.extend(inner.tool_calls)

    def get_final_message(self) -> Any:
        """Return the materialized final :class:`Message`, after
        scanning every text block and every ``tool_use`` block.
        ``BLOCK`` verdicts raise :class:`PromptShieldStreamBlocked`
        when ``self.mode == 'block'``."""
        message = self._underlying.get_final_message()
        self._scan_final_message(message)
        return message

    def get_final_text(self) -> Any:
        """Return the materialized final text, after scanning it as an
        output. Mirrors ``get_final_message`` but for the SDK's text
        shortcut."""
        text = self._underlying.get_final_text()
        if self._shield.scan_responses and isinstance(text, str) and text:
            self._scan_output_text_once(text)
        return text

    def until_done(self) -> None:
        """Drain the stream to completion. The guard's finish() runs via
        the usual ``text_stream`` / event path; this method simply
        delegates to the underlying stream."""
        self._underlying.until_done()

    def close(self) -> None:
        """Close the underlying SDK stream."""
        self._underlying.close()

    def _scan_final_message(self, message: Any) -> None:
        if not self._shield.scan_responses:
            # Mirror the non-stream rule: tool-use scanning is gated on
            # scan_responses.
            return
        content = getattr(message, "content", None)
        if content is None:
            return
        # N2: scan text blocks when the live guard did not finish — that
        # is the only authoritative proof the stream's text was fully
        # covered. A caller that iterated ``text_stream`` or events
        # partially (reads some chunks, then calls ``get_final_message``)
        # does NOT have a populated ``stream_report`` until ``finish()``
        # ran, so the text was not fully guarded and must be rescanned.
        guard_finished = self.stream_report is not None
        for i, block in enumerate(content):
            bt = getattr(block, "type", None)
            if bt in ("tool_use", "server_tool_use"):
                call = _tool_use_block_to_call(block, i)
                self._shield._scan_streaming_tool_call(call)
                continue
            text = getattr(block, "text", None)
            if isinstance(text, str) and text and not guard_finished:
                self._scan_output_text_once(text)

    def _scan_output_text_once(self, text: str) -> None:
        self._shield._scan_output_text_enforced(text)


class GuardedMessageStreamManager:
    """Context manager wrapping ``client.messages.stream(...)``."""

    def __init__(
        self,
        manager: Any,
        shield: PromptShieldAnthropic,
    ) -> None:
        self._manager = manager
        self._shield = shield
        self._stream: GuardedMessageStream | None = None

    def __enter__(self) -> GuardedMessageStream:
        underlying = self._manager.__enter__()
        self._stream = GuardedMessageStream(
            underlying=underlying,
            shield=self._shield,
        )
        return self._stream

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        self._ensure_finish()
        return self._manager.__exit__(exc_type, exc_val, exc_tb)

    def _ensure_finish(self) -> None:
        """Flush ``StreamGuard.finish`` so ``stream_report`` is populated
        even when the caller never consumed ``text_stream`` or iterated
        events. Covers the truncation case where ``message_stop`` never
        arrived.
        """
        if (
            self._stream is not None
            and self._stream._guard is not None
            and self._stream.stream_report is None
        ):
            with contextlib.suppress(PromptShieldStreamBlocked):
                self._stream.stream_report = self._stream._guard.finish()


class GuardedAsyncMessageStream:
    """Async twin of :class:`GuardedMessageStream`."""

    def __init__(
        self,
        underlying: Any,
        shield: PromptShieldAnthropic,
    ) -> None:
        self._underlying = underlying
        self._shield = shield
        self._guard = shield._build_stream_guard() if shield.scan_responses else None
        self._accumulator = ToolCallAccumulator()
        self.stream_report: StreamReport | None = None
        self.tool_calls: list[CompletedToolCall] = []

    @property
    def text_stream(self) -> AsyncIterator[str]:
        return self._aiter_text_stream()

    async def _aiter_text_stream(self) -> AsyncIterator[str]:
        # N2: see sync twin — don't claim the text was guard-covered
        # just because iteration started. ``stream_report is not None``
        # after finish() is the real marker.
        source = getattr(self._underlying, "text_stream", None)
        if source is None:
            return
        if self._guard is None:
            async for chunk in source:
                if isinstance(chunk, str) and chunk:
                    yield chunk
            return
        async for chunk in source:
            if not isinstance(chunk, str) or not chunk:
                continue
            released = self._guard.feed(chunk)
            if released:
                yield released
        if self.stream_report is None:
            self.stream_report = self._guard.finish()
        if self.stream_report.remaining_text:
            yield self.stream_report.remaining_text

    def __aiter__(self) -> AsyncIterator[Any]:
        return self._aiter_events()

    async def _aiter_events(self) -> AsyncIterator[Any]:
        on_tool_call = (
            self._shield._scan_streaming_tool_call if self._shield.scan_responses else None
        )
        inner = _GuardedAnthropicAsyncStream(
            source=self._underlying.__aiter__(),
            guard=self._guard,
            accumulator=self._accumulator,
            on_tool_call=on_tool_call,
        )
        try:
            async for event in inner:
                yield event
        finally:
            if inner.stream_report is not None:
                self.stream_report = inner.stream_report
            self.tool_calls.extend(inner.tool_calls)

    async def get_final_message(self) -> Any:
        message = await self._underlying.get_final_message()
        self._scan_final_message(message)
        return message

    async def get_final_text(self) -> Any:
        text = await self._underlying.get_final_text()
        if self._shield.scan_responses and isinstance(text, str) and text:
            self._shield._scan_output_text_enforced(text)
        return text

    async def until_done(self) -> None:
        await self._underlying.until_done()

    async def close(self) -> None:
        await self._underlying.close()

    def _scan_final_message(self, message: Any) -> None:
        if not self._shield.scan_responses:
            return
        content = getattr(message, "content", None)
        if content is None:
            return
        # N2: see sync twin — only skip the rescan when the live guard
        # actually finished (``stream_report`` populated).
        guard_finished = self.stream_report is not None
        for i, block in enumerate(content):
            bt = getattr(block, "type", None)
            if bt in ("tool_use", "server_tool_use"):
                call = _tool_use_block_to_call(block, i)
                self._shield._scan_streaming_tool_call(call)
                continue
            text = getattr(block, "text", None)
            if isinstance(text, str) and text and not guard_finished:
                self._shield._scan_output_text_enforced(text)


class GuardedAsyncMessageStreamManager:
    """Async context manager wrapping ``AsyncAnthropic.messages.stream(...)``."""

    def __init__(
        self,
        manager: Any,
        shield: PromptShieldAnthropic,
    ) -> None:
        self._manager = manager
        self._shield = shield
        self._stream: GuardedAsyncMessageStream | None = None

    async def __aenter__(self) -> GuardedAsyncMessageStream:
        underlying = await self._manager.__aenter__()
        self._stream = GuardedAsyncMessageStream(
            underlying=underlying,
            shield=self._shield,
        )
        return self._stream

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        self._ensure_finish()
        return await self._manager.__aexit__(exc_type, exc_val, exc_tb)

    def _ensure_finish(self) -> None:
        if (
            self._stream is not None
            and self._stream._guard is not None
            and self._stream.stream_report is None
        ):
            with contextlib.suppress(PromptShieldStreamBlocked):
                self._stream.stream_report = self._stream._guard.finish()
