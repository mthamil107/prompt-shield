"""Accumulate streamed tool-call argument fragments.

Accumulate streamed tool-call argument fragments from OpenAI and
Anthropic SDK shapes into complete ``CompletedToolCall`` records. The
module is pure state; scanning is the caller's responsibility. This
exists so the integration wrappers can scan a tool call *before*
surfacing it to the caller, closing the coverage gap where a streamed
``tool_calls`` payload was previously only visible after the stream
ended.

Scan delegation contract (implemented by the wrappers, not here)
----------------------------------------------------------------
After a ``CompletedToolCall`` has been drained from :meth:`completed`,
the wrapper calls ``AgentGuard.scan_tool_call`` (see
``src/prompt_shield/integrations/agent_guard.py``). Recommended usage::

    args_for_scan = {"_raw": call.arguments_raw}
    if call.arguments_parsed is not None:
        args_for_scan["_parsed"] = call.arguments_parsed
    result = agent_guard.scan_tool_call(
        call.name,
        args_for_scan,
        context={"tool_calls": [{"name": call.name}]},
    )

Notes for wrapper authors:

* Scan BOTH ``arguments_parsed`` (if present) AND ``arguments_raw``.
  ``json.loads`` is last-key-wins, so ``{"cmd":"evil","cmd":"benign"}``
  loses ``evil`` after parsing. The raw string preserves the full
  payload.
* ``AgentGuard.scan_tool_call`` serializes ``args`` via
  ``json.dumps(args, default=str)`` and runs the scan engine on the
  resulting text. The honeypot detector (d034) is one of the
  detectors; passing ``{"tool_calls": [{"name": call.name}]}`` in the
  context makes its invocation path fire at confidence 1.0, but only
  when the tool name is a registered honeypot, not for every call.
* When ``arguments_parsed`` is ``None`` (malformed JSON), the raw
  fragment must still be scanned; it is the only copy of the payload.

This module itself performs no scanning, imports no SDKs, and does not
raise on malformed argument payloads (including pathologically nested
JSON).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = ["CompletedToolCall", "ToolCallAccumulator"]

_LOG = logging.getLogger("prompt_shield.streaming")


Provider = Literal["openai", "anthropic"]


@dataclass(frozen=True)
class CompletedToolCall:
    """A finalized tool call drained from the stream accumulator.

    ``arguments_raw`` is always the exact concatenated fragment string
    the stream delivered. ``arguments_parsed`` is the decoded JSON
    object when parsing succeeded and the top-level value is a dict;
    otherwise it is ``None`` and ``parse_error`` carries a descriptive
    message. The wrapper is expected to scan the call in either case.
    """

    index: int
    id: str | None
    name: str
    arguments_raw: str
    arguments_parsed: dict[str, Any] | None
    provider: Provider
    parse_error: str | None = None


@dataclass
class _Pending:
    """In-flight tool call being accumulated from stream fragments."""

    provider: Provider
    id: str | None = None
    name: str | None = None
    fragments: list[str] = field(default_factory=list)


class ToolCallAccumulator:
    """Collect tool-call argument deltas from streamed chunks.

    The accumulator is provider-agnostic from the caller's point of
    view: the wrapper calls the appropriate ``accumulate_*`` method per
    chunk, then drains finalized entries via :meth:`completed`. The
    accumulator holds no network or SDK state and is safe to construct
    per-request.

    Contract: one accumulator instance per ``choice``. With ``n>1`` on
    ``chat.completions.create``, create a separate
    ``ToolCallAccumulator`` per choice; tool-call indices are only
    unique within a single choice.

    Known fail-open paths. An empty :meth:`completed` drain does NOT
    mean no tool call was streamed. Callers should also check
    :meth:`pending_indices` at stream end. Cases where argument bytes
    are received but nothing is emitted:

    * An OpenAI entry with no name is dropped together with its
      payload (callers should name tools).
    * ``finish_reason`` values other than ``tool_calls``, ``stop`` or
      ``length`` (e.g. ``content_filter``, ``function_call``) leave
      entries pending.
    * Dict-shaped chunks rather than SDK objects are ignored on the
      Anthropic path (accepted as-is; the OpenAI path is unchanged).
    """

    def __init__(self) -> None:
        self._pending: dict[int, _Pending] = {}
        self._done: list[CompletedToolCall] = []

    # ------------------------------------------------------------------
    # OpenAI shape
    # ------------------------------------------------------------------
    def accumulate_openai_delta(self, delta_item: Any) -> None:
        """Consume one OpenAI ``ToolCallDelta`` object.

        The delta is expected to carry ``.index`` (int), optional
        ``.id`` (set on the first delta for an index and ``None``
        thereafter), and ``.function`` with optional ``.name`` and
        ``.arguments`` strings. Missing attributes are tolerated — the
        accumulator uses ``getattr`` throughout so test doubles need
        not implement the full SDK shape.

        One accumulator instance per ``choice``. With ``n>1`` on
        ``chat.completions.create``, create a separate
        ``ToolCallAccumulator`` per choice; tool-call indices are only
        unique within a single choice.
        """
        idx = getattr(delta_item, "index", None)
        if idx is None or not isinstance(idx, int):
            _LOG.warning("openai tool-call delta without integer index; dropping fragment")
            return

        entry = self._pending.get(idx)
        if entry is None:
            entry = _Pending(provider="openai")
            self._pending[idx] = entry
        elif entry.provider != "openai":
            _LOG.warning(
                "openai delta arrived for index %d previously used by provider %s; "
                "overwriting pending entry",
                idx,
                entry.provider,
            )
            entry = _Pending(provider="openai")
            self._pending[idx] = entry

        call_id = getattr(delta_item, "id", None)
        if call_id and entry.id is None:
            entry.id = call_id

        fn = getattr(delta_item, "function", None)
        if fn is not None:
            name = getattr(fn, "name", None)
            if isinstance(name, str) and name and entry.name is None:
                entry.name = name
            arguments = getattr(fn, "arguments", None)
            if isinstance(arguments, str):
                entry.fragments.append(arguments)

    def accumulate_openai_finish(self, finish_reason: str | None = None) -> None:
        """Mark all pending OpenAI entries as complete.

        OpenAI has no per-tool-call "done" event: completion is
        signalled by the choice's ``finish_reason``. The wrapper calls
        this method whenever a chunk carries a terminal
        ``finish_reason`` (typically ``"tool_calls"``, but ``"stop"``
        and ``"length"`` also close any pending tool-call deltas the
        model emitted before stopping). Other values are ignored.

        Edge case: if the stream aborts before any ``finish_reason``
        arrives, the pending entries are never finalized and
        :meth:`completed` returns nothing for them. This is deliberate
        — partial tool calls are unsafe to surface to the caller.
        """
        if finish_reason not in ("tool_calls", "stop", "length"):
            return
        for idx in list(self._pending):
            if self._pending[idx].provider == "openai":
                self._finalize(idx)

    # ------------------------------------------------------------------
    # Anthropic shape
    # ------------------------------------------------------------------
    def accumulate_anthropic_event(self, event: Any) -> None:
        """Consume one Anthropic SSE event object.

        Events are duck-typed on ``.type``. Only ``tool_use`` content
        blocks are tracked; text-block events are ignored (the wrapper
        routes text to the StreamGuard, not here). Unknown event
        types are silently ignored so new SDK event variants do not
        break accumulation.
        """
        event_type = getattr(event, "type", None)

        if event_type == "content_block_start":
            idx = getattr(event, "index", None)
            block = getattr(event, "content_block", None)
            if idx is None or not isinstance(idx, int) or block is None:
                return
            if getattr(block, "type", None) != "tool_use":
                # text or other non-tool block — not our concern
                return
            block_name = getattr(block, "name", None)
            if not isinstance(block_name, str) or not block_name:
                _LOG.debug("anthropic tool_use block without a valid name; dropping")
                return
            if idx in self._pending:
                _LOG.warning(
                    "anthropic content_block_start reused index %d; overwriting pending entry",
                    idx,
                )
            self._pending[idx] = _Pending(
                provider="anthropic",
                id=getattr(block, "id", None),
                name=block_name,
            )
            return

        if event_type == "content_block_delta":
            idx = getattr(event, "index", None)
            if not isinstance(idx, int):
                return
            if idx not in self._pending:
                # text-block delta or unknown index — ignore
                return
            delta = getattr(event, "delta", None)
            if delta is None:
                return
            if getattr(delta, "type", None) != "input_json_delta":
                return
            partial = getattr(delta, "partial_json", None)
            if isinstance(partial, str):
                self._pending[idx].fragments.append(partial)
            return

        if event_type == "content_block_stop":
            idx = getattr(event, "index", None)
            if not isinstance(idx, int):
                return
            if idx not in self._pending:
                return
            self._finalize(idx)
            return

        # message_start, message_delta, message_stop, ping, etc. — the
        # accumulator has nothing to do. Per-block completion already
        # happened via content_block_stop.

    # ------------------------------------------------------------------
    # Draining
    # ------------------------------------------------------------------
    def completed(self) -> list[CompletedToolCall]:
        """Return and clear finalized tool calls since the last drain."""
        drained = self._done
        self._done = []
        return drained

    def pending_indices(self) -> set[int]:
        """Return the stream indices still being accumulated.

        Intended for diagnostics (e.g. logging what was dropped when a
        stream aborts). Does not mutate state.
        """
        return set(self._pending)

    def reset(self) -> None:
        """Discard all pending and drained state. Intended for tests."""
        self._pending.clear()
        self._done.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _finalize(self, idx: int) -> None:
        pending = self._pending.pop(idx, None)
        if pending is None:
            return
        if pending.name is None:
            # Defensive: never promote a nameless entry; the model never
            # declared which tool it meant to call.
            _LOG.warning("dropping tool-call index %d finalized without a name", idx)
            return

        raw = "".join(pending.fragments)
        parsed: dict[str, Any] | None
        err: str | None = None

        if raw == "":
            # Void tool — the model invoked a zero-argument function.
            parsed = {}
        else:
            try:
                loaded = json.loads(raw)
            except (ValueError, RecursionError) as exc:
                parsed = None
                err = f"{type(exc).__name__}: {exc}"
            else:
                if isinstance(loaded, dict):
                    parsed = loaded
                else:
                    parsed = None
                    err = f"tool arguments decoded to non-object: {type(loaded).__name__}"

        self._done.append(
            CompletedToolCall(
                index=idx,
                id=pending.id,
                name=pending.name,
                arguments_raw=raw,
                arguments_parsed=parsed,
                provider=pending.provider,
                parse_error=err,
            )
        )
