"""Unit tests for ``prompt_shield.streaming.StreamGuard``."""

from __future__ import annotations

import pytest

from prompt_shield.streaming import PromptShieldStreamBlocked, StreamGuard

PAYLOAD = "' OR 1=1 --"  # SQL injection tautology, fires code_injection
BENIGN = "safe filler text content here "
EMAIL = "alice@example.com"


def _drive(guard: StreamGuard, stream: str, chunk_size: int) -> str:
    """Feed ``stream`` in fixed-size chunks and return everything released."""
    out: list[str] = []
    for i in range(0, len(stream), chunk_size):
        out.append(guard.feed(stream[i : i + chunk_size]))
    return "".join(out)


class TestConstruction:
    def test_default_mode_is_flag(self):
        assert StreamGuard().mode == "flag"

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError, match=r"\('block', 'flag', 'log'\)"):
            StreamGuard(mode="nope")

    def test_sanitize_mode_rejected(self):
        with pytest.raises(ValueError, match="sanitize"):
            StreamGuard(mode="sanitize")

    def test_negative_hold_back_rejected(self):
        with pytest.raises(ValueError, match="hold_back"):
            StreamGuard(hold_back=-1)

    def test_negative_overlap_rejected(self):
        with pytest.raises(ValueError, match="overlap"):
            StreamGuard(overlap=-1)

    def test_empty_scanners_rejected(self):
        with pytest.raises(ValueError, match="empty scanners list"):
            StreamGuard(scanners=[])

    def test_unknown_scanner_rejected(self):
        with pytest.raises(ValueError, match="known short names"):
            StreamGuard(scanners=["does_not_exist"])

    def test_default_excludes_stream_unsafe_scanners(self):
        guard = StreamGuard()
        assert guard._scanners
        unsafe = {"sentiment", "relevance", "hallucination", "schema_validation"}
        assert unsafe.isdisjoint(guard._scanners)

    def test_scanner_id_accepted(self):
        guard = StreamGuard(scanners=["output_pii"])
        assert guard._scanners == ["pii"]

    def test_tuple_scanners_empty_rejected(self):
        with pytest.raises(ValueError, match="empty scanners list"):
            StreamGuard(scanners=())

    def test_single_scanner_runs_only_that_scanner(self):
        guard = StreamGuard(mode="flag", scanners=["prompt_leakage"])
        assert guard._scanners == ["prompt_leakage"]
        # A payload that code_injection would flag must be ignored here.
        guard.feed(PAYLOAD)
        report = guard.finish()
        assert report.findings == []


class TestFeedBasics:
    def test_empty_delta_noop(self):
        guard = StreamGuard()
        assert guard.feed("") == ""
        assert guard.total_chars == 0
        assert guard.released_chars == 0

    def test_non_str_delta_raises(self):
        guard = StreamGuard()
        with pytest.raises(TypeError, match="str"):
            guard.feed(123)  # type: ignore[arg-type]

    def test_byte_identical_passthrough_clean(self):
        text = BENIGN * 40
        guard = StreamGuard(hold_back=32, overlap=8)
        released = _drive(guard, text, 7)
        report = guard.finish()
        assert released + report.remaining_text == text
        assert report.findings == []

    def test_hold_back_withholds_until_threshold(self):
        guard = StreamGuard(scanners=["code_injection"], hold_back=16, overlap=0)
        assert guard.feed("a" * 10) == ""
        released = guard.feed("a" * 20)
        assert len(released) == 30 - 16
        assert released == "a" * 14

    def test_total_and_released_properties(self):
        guard = StreamGuard(scanners=["code_injection"], hold_back=16, overlap=0)
        guard.feed("a" * 10)
        assert guard.total_chars == 10
        assert guard.released_chars == 0
        guard.feed("a" * 20)
        assert guard.total_chars == 30
        assert guard.released_chars == 14


class TestHoldBackWindow:
    @pytest.mark.parametrize("chunk_size", [1, 2, 3, 5, 8, 16, 32])
    def test_split_attack_still_detected_with_sliding_window(self, chunk_size):
        # Tight hold_back/overlap so the window really slides in this stream.
        guard = StreamGuard(mode="flag", scanners=["code_injection"], hold_back=16, overlap=8)
        stream = BENIGN * 4 + PAYLOAD + " " + BENIGN * 4
        released = _drive(guard, stream, chunk_size)
        assert guard.released_chars > 0, "window never slid; test would pass on a regression"
        report = guard.finish()
        hits = [f for f in report.findings if f.scanner_id == "output_code_injection"]
        assert len(hits) == 1, f"chunk_size={chunk_size}: expected 1 finding, got {len(hits)}"
        assert released + report.remaining_text == stream

    def test_clean_stream_no_findings(self):
        guard = StreamGuard(mode="flag")
        _drive(guard, BENIGN * 30, 11)
        report = guard.finish()
        assert report.findings == []


class TestDedup:
    def test_positional_dedup_stationary_window(self):
        guard = StreamGuard(mode="flag", scanners=["code_injection"], hold_back=512, overlap=128)
        stream = BENIGN * 3 + PAYLOAD + " " + BENIGN * 10
        _drive(guard, stream, 8)
        report = guard.finish()
        hits = [f for f in report.findings if f.scanner_id == "output_code_injection"]
        assert len(hits) == 1
        assert report.scan_passes >= 40

    def test_positional_dedup_sliding_window(self):
        guard = StreamGuard(mode="flag", scanners=["code_injection"], hold_back=64, overlap=32)
        stream = ("safe filler text " * 30) + PAYLOAD + (" more safe filler text " * 30)
        _drive(guard, stream, 8)
        assert guard.released_chars > 0, "window never slid"
        report = guard.finish()
        assert report.scan_passes >= 40
        hits = [f for f in report.findings if f.scanner_id == "output_code_injection"]
        assert len(hits) == 1, f"expected 1 after dedup across sliding window, got {len(hits)}"

    def test_positionless_rising_edge_pii(self):
        guard = StreamGuard(mode="flag", scanners=["pii"], hold_back=64, overlap=16)
        stream = BENIGN * 2 + EMAIL + " " + BENIGN * 3
        _drive(guard, stream, 6)
        report = guard.finish()
        hits = [f for f in report.findings if f.scanner_id == "output_pii"]
        assert len(hits) == 1

    def test_positionless_rearms_after_clean_scan_pass(self):
        # After a scan pass with no positionless finding, the scanner is
        # re-armed and can fire again (the rising-edge dedup contract).
        guard = StreamGuard(mode="flag", scanners=["pii"], hold_back=16, overlap=8)
        guard.feed(EMAIL + " ")
        # Two benign feeds: the first rescan still contains the first email,
        # the second is a clean pass that resets the rising-edge state.
        guard.feed(BENIGN * 6)
        guard.feed(BENIGN * 6)
        guard.feed("bob@example.org ")
        guard.feed(BENIGN * 2)
        report = guard.finish()
        hits = [f for f in report.findings if f.scanner_id == "output_pii"]
        assert len(hits) == 2

    def test_positionless_underreports_on_continuous_coarse_chunks(self):
        # KNOWN LIMITATION: positionless dedup is per scan pass. With no clean
        # pass between two emails (coarse chunks), the second is suppressed.
        # Pins current behaviour; update if dedup becomes per-fire. Block mode
        # is unaffected because the first finding raises.
        guard = StreamGuard(mode="flag", scanners=["pii"], hold_back=64, overlap=32)
        stream = (
            "safe prefix text "
            + EMAIL
            + " more safe filler "
            + "bob@example.com"
            + " trailing safe filler to exceed hold-back"
        )
        _drive(guard, stream, 64)
        report = guard.finish()
        hits = [f for f in report.findings if f.scanner_id == "output_pii"]
        assert len(hits) == 1, f"expected 1 (current limitation), got {len(hits)}"


class TestBlockMode:
    def test_block_raises_in_feed(self):
        guard = StreamGuard(mode="block", scanners=["code_injection"])
        with pytest.raises(PromptShieldStreamBlocked) as excinfo:
            guard.feed(PAYLOAD)
        assert excinfo.value.finding.scanner_id == "output_code_injection"
        assert excinfo.value.released_chars == 0

    def test_feed_after_block_raises_runtime(self):
        guard = StreamGuard(mode="block", scanners=["code_injection"])
        with pytest.raises(PromptShieldStreamBlocked):
            guard.feed(PAYLOAD)
        with pytest.raises(RuntimeError, match="blocked"):
            guard.feed("x")

    def test_finish_after_block_is_idempotent(self):
        guard = StreamGuard(mode="block", scanners=["code_injection"])
        with pytest.raises(PromptShieldStreamBlocked):
            guard.feed(PAYLOAD)
        first = guard.finish()
        second = guard.finish()
        assert first is second
        assert first.blocked is True
        assert first.was_blocked is True

    def test_was_blocked_alias(self):
        clean = StreamGuard(mode="block", scanners=["code_injection"])
        clean.feed(BENIGN)
        assert clean.finish().was_blocked is False

        blocked = StreamGuard(mode="block", scanners=["code_injection"])
        with pytest.raises(PromptShieldStreamBlocked):
            blocked.feed(PAYLOAD)
        assert blocked.finish().was_blocked is True


class TestLogMode:
    def test_log_mode_does_not_raise_but_records_finding(self, caplog):
        guard = StreamGuard(mode="log", scanners=["code_injection"])
        with caplog.at_level("WARNING", logger="prompt_shield.streaming"):
            guard.feed(PAYLOAD)
            report = guard.finish()
        assert [f.scanner_id for f in report.findings] == ["output_code_injection"]
        assert report.blocked is False
        assert any("stream finding" in r.getMessage() for r in caplog.records)


class TestFinish:
    def test_remaining_text_delivers_held_tail(self):
        guard = StreamGuard(scanners=["code_injection"], hold_back=256, overlap=64)
        parts = ["safe filler ", "text content ", "here"]
        for part in parts:
            assert guard.feed(part) == ""
        report = guard.finish()
        assert report.remaining_text == "".join(parts)

    def test_finish_without_feed(self):
        report = StreamGuard().finish()
        assert report.total_chars == 0
        assert report.remaining_text == ""
        assert report.findings == []
        assert report.blocked is False

    def test_finish_is_idempotent_on_clean_stream(self):
        guard = StreamGuard()
        guard.feed(BENIGN)
        assert guard.finish() is guard.finish()

    def test_feed_after_clean_finish_raises(self):
        guard = StreamGuard()
        guard.finish()
        with pytest.raises(RuntimeError, match="finalized"):
            guard.feed("x")


class TestFinishBlockBranch:
    def test_finish_block_branch_via_private_state(self):
        # The block branch inside finish() is not reachable through the
        # public API: feed() scans the same window and raises first. We
        # force the branch by placing a payload into the held tail after
        # the last feed() scan, and rewinding _last_scan_end so finish()
        # believes the tail was never scanned. This simulates a future
        # change that breaks the feed-time scan invariant.
        guard = StreamGuard(mode="block", scanners=["code_injection"], hold_back=4, overlap=0)
        guard.feed(BENIGN)
        guard._held = PAYLOAD
        guard._total_chars = guard._window_start + len(guard._held)
        guard._last_scan_end = guard._window_start
        with pytest.raises(PromptShieldStreamBlocked):
            guard.finish()
        with pytest.raises(RuntimeError, match="already raised"):
            guard.finish()


class TestCanary:
    TOKEN = "deadbeefcafe1234"

    def test_canary_fires_once_per_token(self):
        guard = StreamGuard(
            scanners=["code_injection"],
            canary_tokens=(self.TOKEN,),
            hold_back=16,
            overlap=8,
        )
        guard.feed("leak: " + self.TOKEN + " ")
        guard.feed(BENIGN * 4)
        guard.feed("again " + self.TOKEN + " ")
        guard.feed(BENIGN)
        report = guard.finish()
        hits = [f for f in report.findings if f.scanner_id == "canary_leak"]
        assert len(hits) == 1
        assert hits[0].source == "canary"

    def test_canary_fragment_detected(self):
        guard = StreamGuard(scanners=["code_injection"], canary_tokens=(self.TOKEN,))
        guard.feed("prefix " + self.TOKEN[:12] + " suffix")
        report = guard.finish()
        hits = [f for f in report.findings if f.scanner_id == "canary_leak"]
        assert len(hits) == 1


class TestAsyncDriver:
    @pytest.mark.asyncio
    async def test_sync_guard_driven_from_async(self):
        guard = StreamGuard()

        async def gen():
            for chunk in ["safe ", "filler ", "text content here"]:
                yield chunk

        parts: list[str] = []
        async for chunk in gen():
            parts.append(guard.feed(chunk))
        report = guard.finish()
        assert "".join(parts) + report.remaining_text == "safe filler text content here"
        assert report.findings == []

    @pytest.mark.asyncio
    async def test_block_from_async_driver(self):
        guard = StreamGuard(mode="block", scanners=["code_injection"])

        async def gen():
            yield PAYLOAD

        with pytest.raises(PromptShieldStreamBlocked):
            async for chunk in gen():
                guard.feed(chunk)
