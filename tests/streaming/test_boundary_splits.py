"""Boundary-split regression tests for ``StreamGuard`` (flag mode).

A payload must yield exactly one finding no matter how the stream is chunked
or where the payload sits relative to the hold-back / overlap window.
Parametrized over chunk size and lead offset; no randomness, no SDK imports.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from prompt_shield.streaming import StreamGuard

# No digits, '@', or phone/SSN-like shapes in filler (keeps output_pii quiet).
BENIGN_HEAD = "safe filler text content here "
BENIGN_TAIL = " more safe filler text follows "

PAYLOAD_SQL = "' OR 1=1 --"
CANARY_TOKEN = "deadbeefcafe1eed"
# Markdown image with a javascript: URL; fires the xss pattern exactly once.
PAYLOAD_MDIMG = "![pwn](javascript:void)"

HOLD_BACK = 64
OVERLAP = 16
CHUNK_SIZES = list(range(1, 21))
LEAD_OFFSETS = [0, 16, 48, 80, 120]
SHAPE_CHUNK_SIZES = [1, 3, 7, 13]

# name -> (payload, expected scanner_id, expected source, canary tokens)
CASES = {
    "sql": (PAYLOAD_SQL, "output_code_injection", "output_scanner", ()),
    "canary": (CANARY_TOKEN, "canary_leak", "canary", (CANARY_TOKEN,)),
    "mdimg": (PAYLOAD_MDIMG, "output_code_injection", "output_scanner", ()),
}


def build_stream(payload: str, lead_offset: int) -> str:
    head = (BENIGN_HEAD * ((lead_offset // len(BENIGN_HEAD)) + 2))[:lead_offset]
    return head + payload + (BENIGN_TAIL * 3)


def _drive(guard: StreamGuard, stream: str, chunk_size: int) -> str:
    out: list[str] = []
    for i in range(0, len(stream), chunk_size):
        out.append(guard.feed(stream[i : i + chunk_size]))
    return "".join(out)


def _guard(canary_tokens: tuple[str, ...] = ()) -> StreamGuard:
    return StreamGuard(
        mode="flag",
        scanners=["code_injection"],
        hold_back=HOLD_BACK,
        overlap=OVERLAP,
        canary_tokens=canary_tokens,
    )


def _assert_single(report: Any, scanner_id: str, source: str, ctx: object) -> None:
    hits = [f for f in report.findings if f.scanner_id == scanner_id]
    assert len(hits) == 1, ctx
    assert hits[0].source == source, ctx
    assert len(report.findings) == 1, ctx


@pytest.mark.parametrize("lead_offset", LEAD_OFFSETS)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
def test_sql_invariant(chunk_size, lead_offset):
    payload, sid, src, canaries = CASES["sql"]
    guard = _guard(canaries)
    stream = build_stream(payload, lead_offset)
    released = _drive(guard, stream, chunk_size)
    report = guard.finish()
    _assert_single(report, sid, src, (chunk_size, lead_offset))
    assert released + report.remaining_text == stream


@pytest.mark.parametrize("lead_offset", LEAD_OFFSETS)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
def test_canary_invariant(chunk_size, lead_offset):
    payload, sid, src, canaries = CASES["canary"]
    guard = _guard(canaries)
    stream = build_stream(payload, lead_offset)
    released = _drive(guard, stream, chunk_size)
    report = guard.finish()
    _assert_single(report, sid, src, (chunk_size, lead_offset))
    assert released + report.remaining_text == stream


@pytest.mark.parametrize("lead_offset", LEAD_OFFSETS)
@pytest.mark.parametrize("chunk_size", CHUNK_SIZES)
def test_markdown_image_js_invariant(chunk_size, lead_offset):
    payload, sid, src, canaries = CASES["mdimg"]
    guard = _guard(canaries)
    stream = build_stream(payload, lead_offset)
    released = _drive(guard, stream, chunk_size)
    report = guard.finish()
    _assert_single(report, sid, src, (chunk_size, lead_offset))
    assert released + report.remaining_text == stream


def openai_chunk(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content=text, tool_calls=None))]
    )


def anthropic_event(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        type="content_block_delta",
        index=0,
        delta=SimpleNamespace(type="text_delta", text=text),
    )


def extract_openai(chunk: Any) -> str:
    return chunk.choices[0].delta.content or ""


def extract_anthropic(ev: Any) -> str:
    if ev.type == "content_block_delta" and ev.delta.type == "text_delta":
        return ev.delta.text
    return ""


SHAPES = [
    ("openai", openai_chunk, extract_openai),
    ("anthropic", anthropic_event, extract_anthropic),
]


@pytest.mark.parametrize("chunk_size", SHAPE_CHUNK_SIZES)
@pytest.mark.parametrize("shape", SHAPES, ids=[s[0] for s in SHAPES])
@pytest.mark.parametrize("case", sorted(CASES))
def test_chunk_shape_invariance(case, shape, chunk_size):
    payload, sid, src, canaries = CASES[case]
    _, make, extract = shape
    stream = build_stream(payload, 48)
    guard = _guard(canaries)
    out: list[str] = []
    for i in range(0, len(stream), chunk_size):
        out.append(guard.feed(extract(make(stream[i : i + chunk_size]))))
    report = guard.finish()
    _assert_single(report, sid, src, (case, shape[0], chunk_size))
    assert "".join(out) + report.remaining_text == stream


@pytest.mark.parametrize("stream_len_mul", [1, 3, 10])
@pytest.mark.parametrize("chunk_size", [1, 2, 3, 5, 8, 13, 20])
def test_clean_stream_no_findings(chunk_size, stream_len_mul):
    guard = StreamGuard(mode="flag", hold_back=HOLD_BACK, overlap=OVERLAP)
    stream = (BENIGN_HEAD + BENIGN_TAIL) * stream_len_mul
    released = _drive(guard, stream, chunk_size)
    report = guard.finish()
    assert report.findings == []
    assert released + report.remaining_text == stream
