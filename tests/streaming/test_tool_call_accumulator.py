"""Unit tests for ``prompt_shield.streaming.ToolCallAccumulator``."""

from __future__ import annotations

from itertools import pairwise
from types import SimpleNamespace

import pytest

from prompt_shield.streaming.tool_call_accumulator import ToolCallAccumulator


def _oa(index, *, call_id=None, name=None, args=None):
    """Build an OpenAI tool-call delta."""
    fn = SimpleNamespace(name=name, arguments=args)
    return SimpleNamespace(index=index, id=call_id, function=fn)


def _ev_start(index, *, tool_id, name, block_type="tool_use"):
    return SimpleNamespace(
        type="content_block_start",
        index=index,
        content_block=SimpleNamespace(type=block_type, id=tool_id, name=name),
    )


def _ev_delta(index, partial_json, delta_type="input_json_delta"):
    return SimpleNamespace(
        type="content_block_delta",
        index=index,
        delta=SimpleNamespace(type=delta_type, partial_json=partial_json),
    )


def _ev_stop(index):
    return SimpleNamespace(type="content_block_stop", index=index)


def _feed_openai_split(acc, payload, cut_points):
    """Feed ``payload`` as OpenAI deltas split at the given offsets."""
    cuts = [0, *cut_points, len(payload)]
    for n, (a, b) in enumerate(pairwise(cuts)):
        if n == 0:
            acc.accumulate_openai_delta(_oa(0, call_id="call_1", name="search", args=payload[a:b]))
        else:
            acc.accumulate_openai_delta(_oa(0, args=payload[a:b]))
    acc.accumulate_openai_finish("tool_calls")


class TestOpenAI:
    def test_happy_path_single_call(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="call_1", name="search", args='{"q":'))
        acc.accumulate_openai_delta(_oa(0, args='"hi"}'))
        acc.accumulate_openai_finish("tool_calls")
        calls = acc.completed()
        assert len(calls) == 1
        call = calls[0]
        assert call.provider == "openai"
        assert call.id == "call_1"
        assert call.name == "search"
        assert call.arguments_raw == '{"q":"hi"}'
        assert call.arguments_parsed == {"q": "hi"}
        assert call.parse_error is None

    def test_split_mid_json(self):
        payload = '{"q":"hi"}'
        for cut in range(1, len(payload)):
            acc = ToolCallAccumulator()
            _feed_openai_split(acc, payload, [cut])
            (call,) = acc.completed()
            assert call.arguments_parsed == {"q": "hi"}

    def test_five_fragments(self):
        acc = ToolCallAccumulator()
        _feed_openai_split(acc, '{"q":"hi"}', [2, 4, 6, 8])
        (call,) = acc.completed()
        assert call.arguments_parsed == {"q": "hi"}

    def test_split_mid_string_value(self):
        payload = '{"q":"hello world"}'
        acc = ToolCallAccumulator()
        _feed_openai_split(acc, payload, [10, 13])
        (call,) = acc.completed()
        assert call.arguments_parsed == {"q": "hello world"}

    def test_malformed_json_sets_parse_error(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="t", args='{"q":'))
        acc.accumulate_openai_finish("tool_calls")
        (call,) = acc.completed()
        assert call.arguments_parsed is None
        assert call.arguments_raw == '{"q":'
        assert call.parse_error is not None
        assert call.parse_error.startswith("JSONDecodeError")

    def test_void_tool_empty_args(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="ping"))
        acc.accumulate_openai_finish("tool_calls")
        (call,) = acc.completed()
        assert call.arguments_parsed == {}
        assert call.arguments_raw == ""
        assert call.parse_error is None

    def test_openai_delta_with_name_and_empty_arguments(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="ping", args=""))
        acc.accumulate_openai_finish("tool_calls")
        (call,) = acc.completed()
        assert call.name == "ping"
        assert call.arguments_raw == ""
        assert call.arguments_parsed == {}
        assert call.parse_error is None

    def test_nested_args(self):
        payload = '{"a":{"b":[1,2,{"c":true}]}}'
        acc = ToolCallAccumulator()
        _feed_openai_split(acc, payload, [len(payload) // 2])
        (call,) = acc.completed()
        assert call.arguments_parsed == {"a": {"b": [1, 2, {"c": True}]}}

    def test_index_reuse_continuation(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="call_a", name="search", args="{"))
        acc.accumulate_openai_delta(_oa(0, args="}"))
        acc.accumulate_openai_finish("tool_calls")
        calls = acc.completed()
        assert len(calls) == 1
        assert calls[0].id == "call_a"
        assert calls[0].arguments_parsed == {}

    def test_multiple_indices(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="a", name="one", args="{}"))
        acc.accumulate_openai_delta(_oa(1, call_id="b", name="two", args='{"x":1}'))
        acc.accumulate_openai_finish("tool_calls")
        calls = sorted(acc.completed(), key=lambda c: c.index)
        assert [c.name for c in calls] == ["one", "two"]
        assert calls[1].arguments_parsed == {"x": 1}

    def test_non_tool_calls_finish_reason_leaves_pending(self):
        # Fail-open per the module docstring: unrecognised finish reasons
        # leave entries pending, so callers must also check pending_indices().
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="t", args="{}"))
        acc.accumulate_openai_finish("content_filter")
        assert acc.completed() == []
        assert acc.pending_indices() == {0}

    @pytest.mark.parametrize("reason", ["stop", "length"])
    def test_stop_and_length_still_finalise(self, reason):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="t", args="{}"))
        acc.accumulate_openai_finish(reason)
        assert len(acc.completed()) == 1
        assert acc.pending_indices() == set()

    @pytest.mark.parametrize("bad_index", [None, "0"])
    def test_missing_integer_index_dropped(self, bad_index):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(bad_index, call_id="c", name="t", args="{}"))
        assert acc.pending_indices() == set()
        acc.accumulate_openai_finish("tool_calls")
        assert acc.completed() == []

    def test_nameless_entry_dropped_on_finish(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", args="{}"))
        acc.accumulate_openai_finish("tool_calls")
        assert acc.completed() == []
        assert acc.pending_indices() == set()

    def test_dict_shaped_delta_dropped(self):
        # getattr on a bare dict yields no index, so nothing accumulates.
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta({"index": 0, "function": {"name": "t", "arguments": "{}"}})
        assert acc.pending_indices() == set()


class TestAnthropic:
    def test_happy_path(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start(0, tool_id="toolu_1", name="search"))
        acc.accumulate_anthropic_event(_ev_delta(0, '{"q":'))
        acc.accumulate_anthropic_event(_ev_delta(0, '"hi"}'))
        acc.accumulate_anthropic_event(_ev_stop(0))
        (call,) = acc.completed()
        assert call.provider == "anthropic"
        assert call.id == "toolu_1"
        assert call.name == "search"
        assert call.arguments_parsed == {"q": "hi"}

    def test_non_tool_use_content_block_ignored(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start(0, tool_id=None, name=None, block_type="text"))
        acc.accumulate_anthropic_event(_ev_delta(0, "{}"))
        acc.accumulate_anthropic_event(_ev_stop(0))
        assert acc.completed() == []
        assert acc.pending_indices() == set()

    def test_delta_without_matching_start_ignored(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_delta(3, "{}"))
        acc.accumulate_anthropic_event(_ev_stop(3))
        assert acc.completed() == []
        assert acc.pending_indices() == set()

    def test_input_json_delta_accumulation(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start(1, tool_id="t", name="calc"))
        for piece in ['{"a"', ":", "[1,2]", "}"]:
            acc.accumulate_anthropic_event(_ev_delta(1, piece))
        acc.accumulate_anthropic_event(_ev_stop(1))
        (call,) = acc.completed()
        assert call.arguments_raw == '{"a":[1,2]}'
        assert call.arguments_parsed == {"a": [1, 2]}

    def test_delta_other_type_ignored(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start(0, tool_id="t", name="calc"))
        acc.accumulate_anthropic_event(_ev_delta(0, "junk", delta_type="text_delta"))
        acc.accumulate_anthropic_event(_ev_stop(0))
        (call,) = acc.completed()
        assert call.arguments_raw == ""
        assert call.arguments_parsed == {}

    @pytest.mark.parametrize("name", ["", None])
    def test_start_without_name_dropped(self, name):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start(0, tool_id="t", name=name))
        acc.accumulate_anthropic_event(_ev_delta(0, "{}"))
        acc.accumulate_anthropic_event(_ev_stop(0))
        assert acc.pending_indices() == set()
        assert acc.completed() == []

    @pytest.mark.parametrize("event_type", ["ping", "message_stop", "message_start"])
    def test_unknown_event_type_ignored(self, event_type):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(SimpleNamespace(type=event_type))
        assert acc.pending_indices() == set()
        assert acc.completed() == []

    def test_start_reuses_index_overwrites(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start(0, tool_id="a", name="first_tool"))
        acc.accumulate_anthropic_event(_ev_start(0, tool_id="b", name="second_tool"))
        acc.accumulate_anthropic_event(_ev_stop(0))
        (call,) = acc.completed()
        assert call.name == "second_tool"
        assert call.id == "b"


class TestEdgeCases:
    def test_stream_abort_no_finish(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="a", name="one", args="{"))
        acc.accumulate_openai_delta(_oa(2, call_id="b", name="two", args="{"))
        assert acc.completed() == []
        assert acc.pending_indices() == {0, 2}

    def test_reset_clears_state(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="a", name="one", args="{}"))
        acc.accumulate_openai_finish("tool_calls")
        acc.accumulate_openai_delta(_oa(1, call_id="b", name="two", args="{}"))
        acc.reset()
        assert acc.completed() == []
        assert acc.pending_indices() == set()

    def test_recursion_safe_deep_json(self):
        # _finalize explicitly catches RecursionError from json.loads on
        # pathologically nested input; no exception may propagate.
        payload = "[" * 20000 + "]" * 20000
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="t", args=payload))
        acc.accumulate_openai_finish("tool_calls")
        (call,) = acc.completed()
        assert call.arguments_parsed is None
        assert call.arguments_raw == payload
        assert call.parse_error is not None
        assert call.parse_error.startswith("RecursionError")

    def test_non_int_index_guard(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start("0", tool_id="t", name="calc"))
        assert acc.pending_indices() == set()
        acc.accumulate_anthropic_event(_ev_stop("0"))
        assert acc.completed() == []

    def test_non_int_index_on_delta_and_stop_ignored(self):
        acc = ToolCallAccumulator()
        acc.accumulate_anthropic_event(_ev_start(0, tool_id="t", name="calc"))
        acc.accumulate_anthropic_event(_ev_delta("0", "{}"))
        acc.accumulate_anthropic_event(_ev_stop("0"))
        assert acc.pending_indices() == {0}
        assert acc.completed() == []

    def test_non_object_json_parsed_none(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="t", args="42"))
        acc.accumulate_openai_finish("tool_calls")
        (call,) = acc.completed()
        assert call.arguments_parsed is None
        assert call.parse_error is not None
        assert "non-object" in call.parse_error


class TestCompletedDrainBehaviour:
    def test_completed_drains_and_second_call_returns_empty(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="c", name="t", args="{}"))
        acc.accumulate_openai_finish("tool_calls")
        assert len(acc.completed()) == 1
        assert acc.completed() == []

    def test_pending_indices_reflects_reality(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="a", name="one", args="{}"))
        acc.accumulate_openai_delta(_oa(1, call_id="b", name="two", args="{}"))
        assert acc.pending_indices() == {0, 1}
        acc.accumulate_openai_finish("tool_calls")
        acc.completed()
        assert acc.pending_indices() == set()

    def test_reset_after_drain(self):
        acc = ToolCallAccumulator()
        acc.accumulate_openai_delta(_oa(0, call_id="a", name="one", args="{}"))
        acc.accumulate_openai_finish("tool_calls")
        acc.completed()
        acc.accumulate_openai_delta(_oa(5, call_id="z", name="late", args="{}"))
        acc.reset()
        assert acc.pending_indices() == set()
        assert acc.completed() == []
