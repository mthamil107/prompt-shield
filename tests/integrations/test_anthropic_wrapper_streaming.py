"""Streaming / async / messages.stream coverage for ``PromptShieldAnthropic``.

No ``anthropic`` SDK import — events are built with ``types.SimpleNamespace``
so the SDK is not a test dependency and shape drift in a future release
does not silently pass these tests. Fixtures mirror the conventions used
by ``tests/streaming/test_tool_call_accumulator.py``.
"""

from __future__ import annotations

import warnings
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.integrations.anthropic_wrapper import (
    GuardedAsyncMessageStream,
    GuardedAsyncMessageStreamManager,
    GuardedMessageStream,
    GuardedMessageStreamManager,
    PromptShieldAnthropic,
    _GuardedAnthropicAsyncStream,
    _GuardedAnthropicStream,
)
from prompt_shield.streaming import PromptShieldStreamBlocked

# ---------------------------------------------------------------------------
# Event fixture helpers
# ---------------------------------------------------------------------------


def make_message_start(msg_id: str = "msg_test") -> SimpleNamespace:
    return SimpleNamespace(
        type="message_start",
        message=SimpleNamespace(id=msg_id),
    )


def make_text_block_start(index: int) -> SimpleNamespace:
    return SimpleNamespace(
        type="content_block_start",
        index=index,
        content_block=SimpleNamespace(type="text"),
    )


def make_tool_use_start(index: int, name: str, tool_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        type="content_block_start",
        index=index,
        content_block=SimpleNamespace(type="tool_use", id=tool_id, name=name),
    )


def make_text_delta(index: int, text: str) -> SimpleNamespace:
    return SimpleNamespace(
        type="content_block_delta",
        index=index,
        delta=SimpleNamespace(type="text_delta", text=text),
    )


def make_sdk_text_event(fragment: str, snapshot: str) -> SimpleNamespace:
    """Mirror the derived ``text`` event the real Anthropic SDK's
    ``MessageStream`` emits: ``event.type == "text"`` with ``.text``
    (the new fragment) and ``.snapshot`` (the text accumulated so far).
    Exists so the fake can prove N1 — these events used to pass through
    the dispatch unchanged, leaking unguarded text ahead of the
    ``content_block_delta`` path."""
    return SimpleNamespace(type="text", text=fragment, snapshot=snapshot)


def make_input_json_delta(index: int, partial_json: str) -> SimpleNamespace:
    return SimpleNamespace(
        type="content_block_delta",
        index=index,
        delta=SimpleNamespace(type="input_json_delta", partial_json=partial_json),
    )


def make_content_block_stop(index: int) -> SimpleNamespace:
    return SimpleNamespace(type="content_block_stop", index=index)


def make_message_delta() -> SimpleNamespace:
    return SimpleNamespace(type="message_delta", delta=SimpleNamespace(stop_reason="end_turn"))


def make_message_stop() -> SimpleNamespace:
    return SimpleNamespace(type="message_stop")


def make_text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def make_tool_use_block(name: str, inp: Any, tool_id: str = "toolu_x") -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=tool_id, name=name, input=inp)


def _collect_text(events: list[Any]) -> str:
    """Join every ``text_delta`` text across the yielded events."""
    out: list[str] = []
    for event in events:
        if getattr(event, "type", None) != "content_block_delta":
            continue
        delta = getattr(event, "delta", None)
        if getattr(delta, "type", None) == "text_delta":
            text = getattr(delta, "text", "")
            if isinstance(text, str):
                out.append(text)
    return "".join(out)


BASE_CALL: dict[str, Any] = {
    "model": "test-model",
    "max_tokens": 16,
    "messages": [{"role": "user", "content": "hi"}],
}


# ---------------------------------------------------------------------------
# TestStreamCreate — guarded sync event stream over text
# ---------------------------------------------------------------------------


class TestStreamCreate:
    def test_returns_guarded_stream(self, engine):
        client = MagicMock()
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, "Hello world!"),
            make_content_block_stop(0),
            make_message_delta(),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(client=client, engine=engine, scan_responses=True)
        stream = shield.create(stream=True, **BASE_CALL)
        assert isinstance(stream, _GuardedAnthropicStream)

    def test_happy_path_round_trip(self, engine):
        """Every byte of the text delta reaches the consumer once the
        stream completes (hold-back tail released at ``message_stop``)."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, "Hello "),
            make_text_delta(0, "world!"),
            make_content_block_stop(0),
            make_message_delta(),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(client=client, engine=engine, scan_responses=True)
        stream = shield.create(stream=True, **BASE_CALL)
        yielded = list(stream)
        assert _collect_text(yielded) == "Hello world!"
        assert stream.stream_report is not None
        assert stream.stream_report.total_chars == len("Hello world!")
        assert stream.stream_report.blocked is False

    def test_no_scan_when_scan_responses_false(self, engine):
        """When ``scan_responses=False`` the guard is not built; events
        are passed through unchanged (no synthesized tail)."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, "Hello"),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(client=client, engine=engine)
        stream = shield.create(stream=True, **BASE_CALL)
        yielded = list(stream)
        # Text delta is passed through verbatim.
        assert _collect_text(yielded) == "Hello"
        assert stream.stream_report is None

    def test_non_stream_path_unchanged(self, engine):
        """Non-stream create() still returns the raw response object."""
        client = MagicMock()
        response = MagicMock()
        response.content = [make_text_block("Hi there")]
        client.messages.create.return_value = response
        shield = PromptShieldAnthropic(client=client, engine=engine)
        result = shield.create(**BASE_CALL)
        assert result is response


# ---------------------------------------------------------------------------
# TestStreamToolUse — tool_use blocks accumulated + scanned
# ---------------------------------------------------------------------------


class TestStreamToolUse:
    def test_tool_use_block_scanned_at_stop(self, engine):
        """``content_block_stop`` on a tool_use index drains the
        accumulator and the wrapper's streaming scan runs exactly once.
        Tool scanning is gated on ``scan_responses`` (M1)."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "search", "toolu_1"),
            make_input_json_delta(0, '{"q":'),
            make_input_json_delta(0, '"weather"}'),
            make_content_block_stop(0),
            make_message_delta(),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        list(stream)
        assert len(stream.tool_calls) == 1
        call = stream.tool_calls[0]
        assert call.name == "search"
        assert call.arguments_parsed == {"q": "weather"}
        assert call.arguments_raw == '{"q":"weather"}'

    def test_raw_duplicate_key_scanned(self, engine):
        """``json.loads`` is last-key-wins. The raw fragment must still
        reach the scanner so duplicate-key attacks remain visible."""
        client = MagicMock()
        payload_fragments = [
            '{"cmd":"rm -rf /",',
            '"cmd":"echo hi"}',
        ]
        events = [
            make_message_start(),
            make_tool_use_start(0, "shell", "toolu_dup"),
            *[make_input_json_delta(0, frag) for frag in payload_fragments],
            make_content_block_stop(0),
            make_message_delta(),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        list(stream)
        (call,) = stream.tool_calls
        # Parsed view keeps the benign last-write, raw preserves the attack.
        assert call.arguments_parsed == {"cmd": "echo hi"}
        assert "rm -rf /" in call.arguments_raw

    def test_tool_scan_gated_on_scan_responses(self, engine):
        """When ``scan_responses=False`` the wrapper does not run the
        tool-call scan. The accumulator still captures the call for
        post-hoc inspection, but ``_scan_streaming_tool_call`` is not
        invoked — mirrors the non-stream path's rule."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "search", "toolu_1"),
            make_input_json_delta(0, '{"q":"weather"}'),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(client=client, engine=engine, mode="log")
        scan_calls: list[Any] = []
        original = shield._scan_streaming_tool_call

        def recording(call: Any) -> None:
            scan_calls.append(call)
            original(call)

        shield._scan_streaming_tool_call = recording  # type: ignore[assignment]
        stream = shield.create(stream=True, **BASE_CALL)
        list(stream)
        # Accumulator captured the call but the scan callback was not wired.
        assert len(stream.tool_calls) == 1
        assert scan_calls == []


# ---------------------------------------------------------------------------
# TestToolCallEnvelope (B1) — scan raw and parsed separately, no envelope
# ---------------------------------------------------------------------------


class TestToolCallEnvelope:
    def test_scan_sees_raw_string_not_wrapper(self, engine):
        """B1 regression: ``_scan_streaming_tool_call`` must scan the
        raw argument JSON as a plain string (not wrapped in a
        ``{"_raw": ..., "_parsed": ...}`` envelope). The envelope shape
        made the semantic classifier flag ordinary benign calls.

        v3: a single scan per call (N4) — the parsed-view second pass
        was redundant (differed only by whitespace, silently collapsed
        duplicate keys) and has been removed."""
        shield = PromptShieldAnthropic(client=MagicMock(), engine=engine, mode="log")
        scanned_payloads: list[str] = []
        original_scan = shield._engine.scan

        def recording(text: str, context: Any | None = None) -> Any:
            scanned_payloads.append(text)
            return original_scan(text, context=context)

        shield._engine.scan = recording  # type: ignore[assignment]
        from prompt_shield.streaming.tool_call_accumulator import CompletedToolCall

        call = CompletedToolCall(
            index=0,
            id="toolu_x",
            name="get_weather",
            arguments_raw='{"city":"Paris"}',
            arguments_parsed={"city": "Paris"},
            provider="anthropic",
            parse_error=None,
        )
        shield._scan_streaming_tool_call(call)
        # One scan — raw only. Not wrapped.
        assert len(scanned_payloads) == 1
        raw_scan = scanned_payloads[0]
        assert raw_scan == '{"city":"Paris"}'
        assert "_raw" not in raw_scan
        assert "_parsed" not in raw_scan

    def test_default_engine_benign_tool_not_blocked(self):
        """B1 smoke in a test: with the default engine, mode='block' and
        scan_responses=True, a benign ``get_weather`` tool call does
        not raise. Pre-fix the ``_raw``/``_parsed`` envelope made the
        default engine block almost every tool call."""
        default_engine = PromptShieldEngine()
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "get_weather", "toolu_w"),
            make_input_json_delta(0, '{"city":"Boston"}'),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client,
            engine=default_engine,
            mode="block",
            scan_responses=True,
        )
        stream = shield.create(stream=True, **BASE_CALL)
        yielded = list(stream)
        assert any(getattr(e, "type", None) == "message_stop" for e in yielded), (
            "stream should complete without blocking"
        )
        assert len(stream.tool_calls) == 1


# ---------------------------------------------------------------------------
# TestD034Honeypot (H4) — d034 fires on honeypot tool names
# ---------------------------------------------------------------------------


class TestD034Honeypot:
    """H4: prove the honeypot block is **specifically** ``d034_honeypot_tool``.

    v2 used ``{"q":"weather"}`` arguments; that fires ``d022`` on its
    own, so the block passed with d034 disabled and the test proved
    nothing. v3 uses ``{"a":1}`` — benign enough that no other detector
    fires against the fixture engine — and asserts d034 appears in the
    scanned report's detector list. A control (non-honeypot name, same
    args) confirms no raise, pinning the block to the honeypot name
    alone.
    """

    _BENIGN_ARGS: str = '{"a":1}'

    @staticmethod
    def _record_engine_scans(engine: Any) -> list[Any]:
        """Patch ``engine.scan`` to record every report returned."""
        reports: list[Any] = []
        original = engine.scan

        def recording(text: str, context: Any | None = None) -> Any:
            rep = original(text, context=context)
            reports.append(rep)
            return rep

        engine.scan = recording  # type: ignore[assignment]
        return reports

    @staticmethod
    def _d034_hits(reports: list[Any]) -> list[Any]:
        return [
            rep
            for rep in reports
            if any(getattr(d, "detector_id", "") == "d034_honeypot_tool" for d in rep.detections)
        ]

    def test_honeypot_tool_name_blocks_in_block_mode(self, engine):
        """A honeypot tool name with truly benign args (``{"a":1}`` — no
        other detector fires alone against the fixture engine) raises
        in block mode, and the raised finding's metadata attributes
        the block to ``d034``."""
        reports = self._record_engine_scans(engine)
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "admin_shell", "toolu_hp"),
            make_input_json_delta(0, self._BENIGN_ARGS),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        with pytest.raises(PromptShieldStreamBlocked) as exc_info:
            list(stream)
        # Specifically d034 fired — not just "something blocked".
        hits = self._d034_hits(reports)
        assert hits, (
            "d034_honeypot_tool must appear in the scanned detector list; "
            f"got reports with detectors={[[d.detector_id for d in r.detections] for r in reports]}"
        )
        # Raised finding attributes the block to d034 via metadata.
        detectors = exc_info.value.finding.metadata.get("detectors", [])
        assert "d034_honeypot_tool" in detectors, (
            f"PromptShieldStreamBlocked must name d034 in metadata.detectors; got {detectors}"
        )

    def test_benign_tool_name_same_args_does_not_raise(self, engine):
        """Control: ``get_weather`` with the same ``{"a":1}`` args
        passes without raising — proves the block in the previous
        test was specifically from the honeypot name, not an unrelated
        detector firing on the args."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "get_weather", "toolu_safe"),
            make_input_json_delta(0, self._BENIGN_ARGS),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        # No raise expected — the control must pass cleanly.
        yielded = list(stream)
        assert any(getattr(e, "type", None) == "message_stop" for e in yielded)
        assert len(stream.tool_calls) == 1
        assert stream.tool_calls[0].name == "get_weather"

    def test_honeypot_tool_records_d034_finding_in_log_mode(self, engine):
        """In ``mode='log'`` the honeypot invocation does NOT raise, but
        the engine report for the scanned tool_use **must** list
        ``d034_honeypot_tool`` as a fired detector. Asserting on
        ``tool_calls`` alone (as v2 did) proves nothing — the
        accumulator fills that list regardless of any scan verdict."""
        reports = self._record_engine_scans(engine)
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "admin_shell", "toolu_hp"),
            make_input_json_delta(0, self._BENIGN_ARGS),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        list(stream)  # no raise in log mode
        hits = self._d034_hits(reports)
        assert hits, (
            "d034_honeypot_tool must fire in log mode too; "
            f"got detectors={[[d.detector_id for d in r.detections] for r in reports]}"
        )
        # The accumulator still captures the call for post-hoc audit.
        assert len(stream.tool_calls) == 1
        assert stream.tool_calls[0].name == "admin_shell"


# ---------------------------------------------------------------------------
# TestMessagesStreamHelper — stream_messages() context manager
# ---------------------------------------------------------------------------


class TestMessagesStreamHelper:
    def _make_manager(
        self,
        text_chunks: list[str],
        tool_use_blocks: list[Any],
        events: list[Any] | None = None,
    ) -> MagicMock:
        """Build a duck-typed mock that quacks like ``MessageStreamManager``."""

        class _Underlying:
            def __init__(
                self,
                chunks: list[str],
                blocks: list[Any],
                evs: list[Any] | None,
            ) -> None:
                self.text_stream = iter(chunks)
                self._final = SimpleNamespace(content=[make_text_block("".join(chunks)), *blocks])
                self._events = list(evs or [])

            def __iter__(self) -> Any:
                return iter(self._events)

            def get_final_message(self) -> Any:
                return self._final

            def get_final_text(self) -> Any:
                return "".join(text_chunks)

            def until_done(self) -> None:
                pass

            def close(self) -> None:
                pass

        underlying = _Underlying(text_chunks, tool_use_blocks, events)
        manager = MagicMock()
        manager.__enter__ = MagicMock(return_value=underlying)
        manager.__exit__ = MagicMock(return_value=False)
        return manager

    def test_text_stream_filtered(self, engine):
        client = MagicMock()
        manager = self._make_manager(["Hello ", "world!"], tool_use_blocks=[])
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(client=client, engine=engine, scan_responses=True)
        with shield.stream_messages(**BASE_CALL) as stream:
            assert isinstance(stream, GuardedMessageStream)
            chunks = list(stream.text_stream)
        assert "".join(chunks) == "Hello world!"
        assert stream.stream_report is not None
        assert stream.stream_report.blocked is False

    def test_get_final_message_scans_tool_use(self, engine):
        """``get_final_message`` scans every tool_use block before
        returning (H3: method name is ``get_final_message``, not
        ``accumulate``). Tool scanning is gated on ``scan_responses``."""
        client = MagicMock()
        manager = self._make_manager(
            ["ok"],
            tool_use_blocks=[
                make_tool_use_block("search", {"q": "weather"}, tool_id="toolu_1"),
            ],
        )
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        calls: list[Any] = []
        original = shield._scan_streaming_tool_call

        def recording(call: Any) -> None:
            calls.append(call)
            original(call)

        shield._scan_streaming_tool_call = recording  # type: ignore[assignment]
        with shield.stream_messages(**BASE_CALL) as stream:
            msg = stream.get_final_message()
        assert msg is not None
        assert len(calls) == 1
        assert calls[0].name == "search"
        assert calls[0].arguments_parsed == {"q": "weather"}

    def test_get_final_message_scans_text_blocks(self, engine):
        """H2: text blocks in the final message are scanned. An injected
        prompt that never passed through ``text_stream`` or raw iteration
        still trips the guard when ``scan_responses=True`` and
        ``mode='block'``."""
        client = MagicMock()
        # No chunks -> text_stream yields nothing; the whole response
        # sits in the final message's text block. The injection is in
        # that text.
        injected = "' OR 1=1 --" * 10
        manager = MagicMock()

        class _Underlying:
            text_stream = iter([])
            _final = SimpleNamespace(content=[make_text_block(injected)])

            def __iter__(self) -> Any:
                return iter([])

            def get_final_message(self) -> Any:
                return self._final

            def get_final_text(self) -> Any:
                return injected

            def until_done(self) -> None:
                pass

            def close(self) -> None:
                pass

        manager.__enter__ = MagicMock(return_value=_Underlying())
        manager.__exit__ = MagicMock(return_value=False)
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        with (
            shield.stream_messages(**BASE_CALL) as stream,
            pytest.raises(PromptShieldStreamBlocked),
        ):
            stream.get_final_message()

    def test_manager_is_guarded_type(self, engine):
        client = MagicMock()
        manager = self._make_manager(["x"], tool_use_blocks=[])
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(client=client, engine=engine)
        wrapped = shield.stream_messages(**BASE_CALL)
        assert isinstance(wrapped, GuardedMessageStreamManager)

    def test_raw_iteration_filters_events(self, engine):
        """H1: ``for event in stream`` must route through the same
        pipeline as ``create(stream=True)``. An injected-text delta
        trips the guard in ``mode='block'`` even on this path."""
        client = MagicMock()
        inj = "' OR 1=1 --"
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, inj * 10),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        manager = self._make_manager(
            text_chunks=[],
            tool_use_blocks=[],
            events=events,
        )
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        with (
            shield.stream_messages(**BASE_CALL) as stream,
            pytest.raises(PromptShieldStreamBlocked),
        ):
            list(stream)

    def test_raw_iteration_honeypot_tool_blocks(self, engine):
        """H1 + H4 combined via the stream_messages path: raw event
        iteration routes a honeypot tool_use through the same guard
        pipeline and raises in block mode."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "admin_shell", "toolu_hp"),
            make_input_json_delta(0, '{"q":"ok"}'),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        manager = self._make_manager(
            text_chunks=[],
            tool_use_blocks=[],
            events=events,
        )
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        with (
            shield.stream_messages(**BASE_CALL) as stream,
            pytest.raises(PromptShieldStreamBlocked),
        ):
            list(stream)


# ---------------------------------------------------------------------------
# TestStreamBlockMode — mid-stream block raises
# ---------------------------------------------------------------------------


class TestStreamBlockMode:
    def test_injection_payload_blocks_mid_stream(self, engine):
        """A code-injection payload split across two text_delta events
        trips ``StreamGuard`` in ``mode='block'`` and raises
        :class:`PromptShieldStreamBlocked` before the whole stream is
        consumed."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, "'A' OR " * 60),  # fill the hold-back window
            make_text_delta(0, " 1=1 --"),
            make_text_delta(0, "tail"),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        consumed_after_block: list[Any] = []
        with pytest.raises(PromptShieldStreamBlocked):
            for event in stream:
                consumed_after_block.append(event)
        # No further next() calls after block raises.
        assert consumed_after_block, "stream should emit something before blocking"

    def test_tool_use_block_mode_raises(self, engine):
        """A malicious streamed tool_use argument raises in block mode
        when ``scan_responses=True``."""
        client = MagicMock()
        attack = '{"query":"\'; DROP TABLE users; --","url":"http://evil.example/exfil?q=all"}'
        events = [
            make_message_start(),
            make_tool_use_start(0, "db_query", "toolu_bad"),
            make_input_json_delta(0, attack),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        with pytest.raises(PromptShieldStreamBlocked):
            list(stream)

    def test_sanitize_mode_rejected_on_stream(self, engine):
        """M4: ``create(stream=True)`` with ``mode='sanitize'`` raises
        at call time. Streams cannot recall released text."""
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            mode="sanitize",
            tool_result_mode="log",  # keep __init__ happy
        )
        with pytest.raises(ValueError, match="sanitize mode is not supported"):
            shield.create(stream=True, **BASE_CALL)

    def test_sanitize_mode_rejected_on_stream_messages(self, engine):
        """M4: ``stream_messages`` also rejects ``mode='sanitize'``."""
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            mode="sanitize",
            tool_result_mode="log",
        )
        with pytest.raises(ValueError, match="sanitize mode is not supported"):
            shield.stream_messages(**BASE_CALL)


# ---------------------------------------------------------------------------
# TestAsyncCreate — async_client path
# ---------------------------------------------------------------------------


class _FakeAsyncStream:
    """Minimal async-iterator wrapper over a list of events."""

    def __init__(self, events: list[Any]) -> None:
        self._events = events
        self._i = 0

    def __aiter__(self) -> _FakeAsyncStream:
        return self

    async def __anext__(self) -> Any:
        if self._i >= len(self._events):
            raise StopAsyncIteration
        event = self._events[self._i]
        self._i += 1
        return event


class TestAsyncCreate:
    @pytest.mark.asyncio
    async def test_async_stream_round_trip(self, engine):
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, "Hello "),
            make_text_delta(0, "async!"),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        async_client = MagicMock()
        async_client.messages.create = AsyncMock(return_value=_FakeAsyncStream(events))
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            async_client=async_client,
            scan_responses=True,
        )
        stream = await shield.acreate(stream=True, **BASE_CALL)
        assert isinstance(stream, _GuardedAnthropicAsyncStream)
        collected: list[Any] = []
        async for event in stream:
            collected.append(event)
        assert _collect_text(collected) == "Hello async!"
        assert stream.stream_report is not None
        assert stream.stream_report.total_chars == len("Hello async!")

    @pytest.mark.asyncio
    async def test_async_non_stream_scans_text(self, engine):
        response = MagicMock()
        response.content = [make_text_block("Hi there")]
        async_client = MagicMock()
        async_client.messages.create = AsyncMock(return_value=response)
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            async_client=async_client,
            scan_responses=True,
        )
        result = await shield.acreate(**BASE_CALL)
        assert result is response

    @pytest.mark.asyncio
    async def test_async_stream_tool_use_scanned(self, engine):
        events = [
            make_message_start(),
            make_tool_use_start(0, "search", "toolu_async"),
            make_input_json_delta(0, '{"q":"hello"}'),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        async_client = MagicMock()
        async_client.messages.create = AsyncMock(return_value=_FakeAsyncStream(events))
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            async_client=async_client,
            mode="log",
            scan_responses=True,
        )
        stream = await shield.acreate(stream=True, **BASE_CALL)
        async for _ in stream:
            pass
        assert len(stream.tool_calls) == 1
        assert stream.tool_calls[0].arguments_parsed == {"q": "hello"}

    @pytest.mark.asyncio
    async def test_astream_messages_manager_type(self, engine):
        async_client = MagicMock()

        class _AsyncUnderlying:
            text_stream = _FakeAsyncStream(["Hi"])

            async def get_final_message(self) -> Any:
                return SimpleNamespace(content=[make_text_block("Hi")])

            async def get_final_text(self) -> Any:
                return "Hi"

            async def until_done(self) -> None:
                return None

            async def close(self) -> None:
                return None

            def __aiter__(self) -> Any:
                return _FakeAsyncStream([])

        underlying = _AsyncUnderlying()

        class _AsyncManager:
            async def __aenter__(self) -> Any:
                return underlying

            async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
                return False

        async_client.messages.stream = MagicMock(return_value=_AsyncManager())
        shield = PromptShieldAnthropic(client=MagicMock(), engine=engine, async_client=async_client)
        manager = shield.astream_messages(**BASE_CALL)
        assert isinstance(manager, GuardedAsyncMessageStreamManager)
        async with manager as stream:
            assert isinstance(stream, GuardedAsyncMessageStream)
            chunks: list[str] = []
            async for chunk in stream.text_stream:
                chunks.append(chunk)
        assert "".join(chunks) == "Hi"


# ---------------------------------------------------------------------------
# TestInterleavedBlocks — content[0]=text, [1]=tool_use, [2]=text
# ---------------------------------------------------------------------------


class TestInterleavedBlocks:
    def test_mixed_blocks_dispatched_correctly(self, engine):
        """Per-index dispatch across text, tool_use, text blocks: one
        shared StreamGuard across both text blocks, tool_use scanned
        once at its own stop."""
        client = MagicMock()
        events = [
            make_message_start(),
            # Block 0 — text
            make_text_block_start(0),
            make_text_delta(0, "Hello "),
            make_content_block_stop(0),
            # Block 1 — tool_use
            make_tool_use_start(1, "search", "toolu_mixed"),
            make_input_json_delta(1, '{"q":"ok"}'),
            make_content_block_stop(1),
            # Block 2 — text
            make_text_block_start(2),
            make_text_delta(2, "world!"),
            make_content_block_stop(2),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        collected = list(stream)
        # Combined text across both text blocks reaches the consumer in full.
        assert _collect_text(collected) == "Hello world!"
        # Exactly one tool_use call scanned.
        assert len(stream.tool_calls) == 1
        assert stream.tool_calls[0].index == 1
        assert stream.stream_report is not None


# ---------------------------------------------------------------------------
# TestToolUseOnlyResponse — non-stream path closes T8 future_note gap
# ---------------------------------------------------------------------------


class TestToolUseOnlyResponse:
    def test_tool_use_only_response_scanned(self, engine):
        """Pre-T8: a response whose content is entirely ``tool_use``
        blocks reached neither the text-scan loop nor the warning.
        T8 routes those blocks through ``_scan_streaming_tool_call``."""
        client = MagicMock()
        response = MagicMock()
        response.content = [
            make_tool_use_block("search", {"q": "weather"}, tool_id="toolu_1"),
        ]
        client.messages.create.return_value = response
        shield = PromptShieldAnthropic(
            client=client, engine=engine, scan_responses=True, mode="log"
        )
        scan_calls: list[Any] = []
        original = shield._scan_streaming_tool_call

        def recording(call: Any) -> None:
            scan_calls.append(call)
            original(call)

        shield._scan_streaming_tool_call = recording  # type: ignore[assignment]
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            result = shield.create(**BASE_CALL)
        assert result is response
        assert len(scan_calls) == 1
        assert scan_calls[0].name == "search"
        assert scan_calls[0].arguments_parsed == {"q": "weather"}

    def test_empty_content_no_warn(self, engine):
        """An empty ``.content`` list is a shape-legal but unusual
        Anthropic response; it should not warn."""
        client = MagicMock()
        response = MagicMock()
        response.content = []
        client.messages.create.return_value = response
        shield = PromptShieldAnthropic(client=client, engine=engine, scan_responses=True)
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            shield.create(**BASE_CALL)


# ---------------------------------------------------------------------------
# TestNoWarnOnCoveredPath — stream=True no longer warns
# ---------------------------------------------------------------------------


class TestNoWarnOnCoveredPath:
    def test_stream_true_no_user_warning(self, engine):
        """Regression against the P1 warning: ``stream=True`` with
        ``scan_responses=True`` now routes through StreamGuard, so no
        UserWarning should fire for this covered path."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, "Hi"),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(client=client, engine=engine, scan_responses=True)
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            stream = shield.create(stream=True, **BASE_CALL)
            list(stream)


# ---------------------------------------------------------------------------
# TestDispatchRobustness (M5) — truncation, orphan deltas, pending tool_use
# ---------------------------------------------------------------------------


class TestDispatchRobustness:
    def test_no_message_stop_flushes_held_text(self, engine):
        """Stream ending without ``message_stop`` still flushes the
        held tail and populates ``stream_report`` so held text is not
        silently dropped."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_text_delta(0, "Hello world"),
            make_content_block_stop(0),
            # NO message_stop
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        yielded = list(stream)
        assert "Hello world" in _collect_text(yielded)
        assert stream.stream_report is not None

    def test_delta_without_block_start_is_handled(self, engine):
        """A ``text_delta`` arriving before any ``content_block_start``
        is treated as text — the stream does not crash, and the held
        tail eventually reaches the consumer."""
        client = MagicMock()
        events = [
            make_text_delta(0, "orphan text"),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        yielded = list(stream)
        assert "orphan text" in _collect_text(yielded)

    def test_tool_use_without_content_block_stop_is_drained(self, engine):
        """Truncated ``tool_use`` (no ``content_block_stop``) still
        surfaces in ``tool_calls`` via the end-of-stream drain."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "search", "toolu_t"),
            make_input_json_delta(0, '{"q":"ok"}'),
            # NO content_block_stop or message_stop — abrupt end.
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        list(stream)
        assert len(stream.tool_calls) == 1
        assert stream.tool_calls[0].name == "search"


# ---------------------------------------------------------------------------
# TestRealSDKTextEvents (N1) — SDK's derived ``text`` events don't leak
# ---------------------------------------------------------------------------


class TestRealSDKTextEvents:
    """N1: the real ``anthropic.lib.streaming.MessageStream`` emits a
    derived ``text`` event (``.type == "text"``, ``.text`` fragment,
    ``.snapshot`` accumulated) BEFORE the ``content_block_delta`` that
    carries the same fragment. v2 passed those events through unchanged,
    releasing the unguarded text ahead of the guard. v3 drops them when
    a guard is active; guard-filtered text still reaches the consumer
    via the ``content_block_delta`` path.
    """

    def test_sdk_text_event_dropped_when_guard_active(self, engine):
        """A ``text`` event emitted AHEAD of the ``content_block_delta``
        must not reach the consumer. With a guard active, consumers see
        only the guard-filtered content_block_delta text."""
        client = MagicMock()
        fragment = "SECRET-HELD-PREFIX "
        events = [
            make_message_start(),
            make_text_block_start(0),
            # SDK's derived ``text`` event first (v2 passed this through).
            make_sdk_text_event(fragment, snapshot=fragment),
            # Then the raw text_delta the guard actually processes.
            make_text_delta(0, fragment),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        yielded = list(stream)
        # No raw ``text`` event survives the dispatch.
        text_events = [e for e in yielded if getattr(e, "type", None) == "text"]
        assert not text_events, (
            "SDK-derived ``text`` events must be dropped when a guard is "
            f"active; got {len(text_events)}: {text_events!r}"
        )
        # The guard-filtered content still reaches the consumer in full.
        assert _collect_text(yielded) == fragment

    def test_sdk_text_event_does_not_leak_blocked_payload_in_block_mode(self, engine):
        """When a payload would be caught by ``StreamGuard``, the
        SDK-derived ``text`` event carrying the leading bytes must not
        reach the consumer. The ``text`` event arrives BEFORE the raw
        delta: a pass-through would release it ahead of the guard
        even if the guard then blocks on a later chunk."""
        client = MagicMock()
        injection = "' OR 1=1 --" * 20  # enough to be detectable
        events = [
            make_message_start(),
            make_text_block_start(0),
            # Leading SDK text event — v2 would release this unguarded.
            make_sdk_text_event(injection[:50], snapshot=injection[:50]),
            # Raw delta that the guard sees and blocks on.
            make_text_delta(0, injection),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        collected: list[Any] = []
        with pytest.raises(PromptShieldStreamBlocked):
            for event in stream:
                collected.append(event)
        # Even if a block fired, the SDK text event must not have reached
        # the consumer. This is the crux of N1: a raw ``text`` event
        # releasing the leading bytes defeats the point of hold-back.
        text_events = [e for e in collected if getattr(e, "type", None) == "text"]
        assert not text_events, (
            f"SDK-derived ``text`` events must be dropped before block; got {text_events!r}"
        )

    def test_sdk_text_event_passes_through_when_no_guard(self, engine):
        """``scan_responses=False`` means no guard is built. SDK text
        events then pass through unchanged — callers that do not opt
        into scanning get the SDK's native event stream verbatim."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_text_block_start(0),
            make_sdk_text_event("hi", snapshot="hi"),
            make_text_delta(0, "hi"),
            make_content_block_stop(0),
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(client=client, engine=engine)  # no scan_responses
        stream = shield.create(stream=True, **BASE_CALL)
        yielded = list(stream)
        text_events = [e for e in yielded if getattr(e, "type", None) == "text"]
        assert len(text_events) == 1, (
            f"Without a guard, SDK text events must pass through; got {len(text_events)}"
        )


# ---------------------------------------------------------------------------
# TestPartialIterationFinalMessage (N2) — rescan when guard did not finish
# ---------------------------------------------------------------------------


class TestPartialIterationFinalMessage:
    """N2: ``_text_consumed`` was set as soon as iteration began, so a
    caller that read one chunk from ``text_stream`` and then called
    ``get_final_message`` had the final-text scan skipped — the guard
    had NOT finished and injected text past the first chunk was not
    rescanned. v3 uses ``stream_report is not None`` as the authoritative
    "guard finished" marker instead."""

    def _build_underlying(self, chunks: list[str], final_text: str) -> Any:
        class _Underlying:
            def __init__(self) -> None:
                self._chunks = iter(chunks)

            @property
            def text_stream(self) -> Any:
                return self._chunks

            def __iter__(self) -> Any:
                return iter([])

            def get_final_message(self) -> Any:
                return SimpleNamespace(content=[make_text_block(final_text)])

            def get_final_text(self) -> Any:
                return final_text

            def until_done(self) -> None:
                pass

            def close(self) -> None:
                pass

        return _Underlying()

    def test_partial_text_stream_then_final_message_raises(self, engine):
        """Caller reads ONE chunk from ``text_stream`` (benign), then
        calls ``get_final_message`` whose text is an injection payload.
        In block mode the final-message scan must raise — the guard did
        not finish, so ``stream_report`` is None and the rescan must
        run. Chunks are deliberately large and benign so ``feed()``
        releases on the first chunk without tripping the StreamGuard."""
        # Each chunk > hold_back(256)+overlap(64) so feed() releases
        # bytes without needing the tail. The text_stream chunks are
        # pure benign filler; the injection sits ONLY in the final
        # message's text block — exactly the scenario N2 targets.
        chunk1 = "benign filler text. " * 32  # 640 chars
        chunk2 = "more benign filler words. " * 32  # 832 chars
        injection = "' OR 1=1 --" * 40  # ~440 chars of SQLi
        underlying = self._build_underlying(
            chunks=[chunk1, chunk2],
            final_text=injection,
        )
        manager = MagicMock()
        manager.__enter__ = MagicMock(return_value=underlying)
        manager.__exit__ = MagicMock(return_value=False)
        client = MagicMock()
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        with shield.stream_messages(**BASE_CALL) as stream:
            # Read one chunk only — do not drain the stream.
            iterator = iter(stream.text_stream)
            first = next(iterator)
            assert isinstance(first, str)
            assert first  # feed released some bytes
            # Guard has NOT finished yet — stream_report is None.
            assert stream.stream_report is None, "stream_report populated too early; N2 regression"
            # get_final_message must rescan the final text (which
            # contains the injection) and raise.
            with pytest.raises(PromptShieldStreamBlocked):
                stream.get_final_message()

    def test_full_text_stream_then_final_message_skips_rescan(self, engine):
        """Caller drains ``text_stream`` fully, so ``stream_report`` is
        populated. ``get_final_message`` must NOT rescan the text (it
        would double-fire). This protects callers against duplicate
        warnings in log mode and double work in general."""
        underlying = self._build_underlying(
            chunks=["hello ", "world"],
            final_text="hello world",
        )
        manager = MagicMock()
        manager.__enter__ = MagicMock(return_value=underlying)
        manager.__exit__ = MagicMock(return_value=False)
        client = MagicMock()
        client.messages.stream.return_value = manager
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        scans: list[str] = []
        original_scan = shield._engine.scan

        def recording(text: str, context: Any | None = None) -> Any:
            scans.append(text)
            return original_scan(text, context=context)

        shield._engine.scan = recording  # type: ignore[assignment]
        with shield.stream_messages(**BASE_CALL) as stream:
            # Drain fully so the guard finishes.
            list(stream.text_stream)
            assert stream.stream_report is not None
            scans_before_final = list(scans)
            stream.get_final_message()
            scans_after_final = list(scans)
        # The final-message rescan would have called ``_engine.scan``
        # again on the output text. Verify it did NOT.
        assert scans_after_final == scans_before_final, (
            "get_final_message must not rescan text the live guard already "
            f"covered; new scans: {scans_after_final[len(scans_before_final) :]}"
        )


# ---------------------------------------------------------------------------
# TestTruncatedToolUseBlockMode (N3) — truncated tool_use fails closed
# ---------------------------------------------------------------------------


class TestTruncatedToolUseBlockMode:
    """N3: v2 wrapped the end-of-stream drain's ``on_tool_call`` in
    ``contextlib.suppress(PromptShieldStreamBlocked)``, so a tool_use
    that reached the drain without a ``content_block_stop`` (truncated
    response) was fail-open in block mode. v3 lets the block propagate
    and drains before emitting ``message_stop``."""

    def test_truncated_honeypot_tool_raises_in_block_mode(self, engine):
        """A honeypot tool_use that never sees ``content_block_stop`` —
        stream ends abruptly — must still raise in block mode.
        Uses ``{"a":1}`` so the raise is attributable to d034, not
        a stray detector that happens to fire on the args."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "admin_shell", "toolu_hp"),
            make_input_json_delta(0, '{"a":1}'),
            # NO content_block_stop. NO message_stop.
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        with pytest.raises(PromptShieldStreamBlocked):
            list(stream)

    def test_truncated_honeypot_tool_logs_in_log_mode(self, engine):
        """In log mode the drain still records the call — proves the
        drain itself still runs; the block-mode test above confirms
        the verdict propagates."""
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "admin_shell", "toolu_hp"),
            make_input_json_delta(0, '{"a":1}'),
            # NO content_block_stop. NO message_stop.
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="log", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        list(stream)
        assert len(stream.tool_calls) == 1
        assert stream.tool_calls[0].name == "admin_shell"

    def test_message_stop_without_content_block_stop_drains_tool(self, engine):
        """``message_stop`` arrives but a tool_use index never saw
        ``content_block_stop``. The N3 fix drains tools BEFORE emitting
        ``message_stop``, so a honeypot name still raises in block mode.
        """
        client = MagicMock()
        events = [
            make_message_start(),
            make_tool_use_start(0, "admin_shell", "toolu_hp"),
            make_input_json_delta(0, '{"a":1}'),
            # No content_block_stop — but message_stop DOES arrive.
            make_message_stop(),
        ]
        client.messages.create.return_value = iter(events)
        shield = PromptShieldAnthropic(
            client=client, engine=engine, mode="block", scan_responses=True
        )
        stream = shield.create(stream=True, **BASE_CALL)
        with pytest.raises(PromptShieldStreamBlocked):
            list(stream)


# ---------------------------------------------------------------------------
# TestStreamScannerConfig (M3) — symmetric stream_* kwargs plumb through
# ---------------------------------------------------------------------------


class TestStreamScannerConfig:
    """M3: ``stream_scanners`` / ``stream_canary_tokens`` /
    ``stream_hold_back`` / ``stream_overlap`` mirror the T7 OpenAI
    wrapper's surface. Verify each kwarg actually reaches
    :class:`StreamGuard`."""

    def test_stream_hold_back_and_overlap_reach_guard(self, engine):
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            scan_responses=True,
            stream_hold_back=32,
            stream_overlap=8,
        )
        guard = shield._build_stream_guard()
        assert guard.hold_back == 32
        assert guard.overlap == 8

    def test_stream_canary_tokens_wire_through(self, engine):
        token = "a1b2c3d4e5f67890"
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            scan_responses=True,
            stream_canary_tokens=[token],
        )
        guard = shield._build_stream_guard()
        assert token in guard._canary_tokens

    def test_defaults_unchanged_when_kwargs_omitted(self, engine):
        """A wrapper constructed without any ``stream_*`` kwargs still
        gets the StreamGuard's documented defaults — no change for
        existing callers."""
        shield = PromptShieldAnthropic(client=MagicMock(), engine=engine, scan_responses=True)
        guard = shield._build_stream_guard()
        assert guard.hold_back == 256
        assert guard.overlap == 64
        assert guard._canary_tokens == ()


# ---------------------------------------------------------------------------
# TestBackwardsCompat — non-stream + non-async paths unchanged
# ---------------------------------------------------------------------------


class TestBackwardsCompat:
    def test_non_stream_clean_text_response(self, engine):
        """v0.9.1 behaviour: non-stream create() with a text response
        returns the response untouched."""
        client = MagicMock()
        text_block = MagicMock()
        text_block.text = "All good."
        text_block.type = "text"
        response = MagicMock()
        response.content = [text_block]
        client.messages.create.return_value = response
        shield = PromptShieldAnthropic(client=client, engine=engine, mode="block")
        result = shield.create(**BASE_CALL)
        assert result is response
        client.messages.create.assert_called_once()

    def test_tool_result_mode_validation_still_rejects_invalid(self, engine):
        """PR #37 regression: invalid tool_result_mode still raises."""
        with pytest.raises(ValueError, match="tool_result_mode must be one of"):
            PromptShieldAnthropic(
                client=MagicMock(),
                engine=engine,
                tool_result_mode="not_a_mode",
            )

    def test_tool_result_mode_inherit_sanitize_blames_mode(self, engine):
        """PR #37 regression: inherited sanitize blames the inheritance source."""
        with pytest.raises(ValueError, match="mode='sanitize' cannot be inherited"):
            PromptShieldAnthropic(
                client=MagicMock(),
                engine=engine,
                mode="sanitize",
            )

    def test_tool_result_mode_inherits_from_mode(self, engine):
        """PR #37 regression: tool_result_mode inherits from mode when omitted."""
        shield = PromptShieldAnthropic(
            client=MagicMock(),
            engine=engine,
            mode="monitor",
        )
        assert shield.tool_result_mode == "monitor"

    def test_async_client_defaults_to_none(self, engine):
        """New kwarg defaults to None — zero behavioural change for
        callers that only use the sync client."""
        shield = PromptShieldAnthropic(client=MagicMock(), engine=engine)
        assert shield._async_client is None
