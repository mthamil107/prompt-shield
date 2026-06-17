"""Tests for the sliding-window rate limiter."""
from __future__ import annotations

import pytest

from prompt_shield.ratelimit import (
    RateLimitDecision,
    RateLimitExceeded,
    SlidingWindowLimiter,
)


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


class TestBasic:
    def test_rejects_invalid_config(self):
        with pytest.raises(ValueError):
            SlidingWindowLimiter(max_requests=0, window_seconds=60)
        with pytest.raises(ValueError):
            SlidingWindowLimiter(max_requests=10, window_seconds=0)

    def test_first_request_allowed(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=3, window_seconds=60, time_func=clock
        )
        decision = limiter.acquire("alice")
        assert decision.allowed is True
        assert decision.requests_in_window == 1
        assert decision.retry_after_seconds == 0.0

    def test_check_does_not_record(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=2, window_seconds=60, time_func=clock
        )
        # Several checks shouldn't consume any tokens
        for _ in range(5):
            d = limiter.check("alice")
            assert d.allowed is True
            assert d.requests_in_window == 0


class TestLimiting:
    def test_blocks_at_limit(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=2, window_seconds=60, time_func=clock
        )
        assert limiter.acquire("alice").allowed is True
        assert limiter.acquire("alice").allowed is True
        denied = limiter.acquire("alice")
        assert denied.allowed is False
        assert denied.retry_after_seconds > 0
        assert denied.requests_in_window == 2

    def test_recovers_after_window(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=2, window_seconds=10, time_func=clock
        )
        limiter.acquire("alice")
        limiter.acquire("alice")
        assert limiter.acquire("alice").allowed is False
        clock.advance(11)
        assert limiter.acquire("alice").allowed is True

    def test_per_key_independence(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=1, window_seconds=60, time_func=clock
        )
        assert limiter.acquire("alice").allowed is True
        assert limiter.acquire("bob").allowed is True
        # Alice is over her quota but Bob is not
        assert limiter.acquire("alice").allowed is False
        assert limiter.acquire("bob").allowed is False


class TestEnforce:
    def test_enforce_raises_on_deny(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=1, window_seconds=60, time_func=clock
        )
        limiter.enforce("alice")
        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.enforce("alice")
        assert exc_info.value.decision.key == "alice"
        assert exc_info.value.decision.allowed is False


class TestReset:
    def test_reset_specific_key(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=1, window_seconds=60, time_func=clock
        )
        limiter.acquire("alice")
        limiter.acquire("bob")
        limiter.reset("alice")
        # Alice should now be allowed again, Bob still throttled
        assert limiter.acquire("alice").allowed is True
        assert limiter.acquire("bob").allowed is False

    def test_reset_all(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=1, window_seconds=60, time_func=clock
        )
        limiter.acquire("alice")
        limiter.acquire("bob")
        limiter.reset()
        assert limiter.acquire("alice").allowed is True
        assert limiter.acquire("bob").allowed is True


class TestEviction:
    def test_max_tracked_keys_evicts(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=1,
            window_seconds=60,
            time_func=clock,
            max_tracked_keys=3,
        )
        for key in ["a", "b", "c", "d", "e"]:
            limiter.acquire(key)
            clock.advance(0.01)
        # We should never exceed 3 tracked keys after eviction
        assert limiter.tracked_key_count() <= 3


class TestSlidingBehavior:
    def test_partial_window_expiry(self, clock: FakeClock):
        limiter = SlidingWindowLimiter(
            max_requests=3, window_seconds=10, time_func=clock
        )
        # Three requests spread across the window
        limiter.acquire("alice")  # t=0
        clock.advance(3)
        limiter.acquire("alice")  # t=3
        clock.advance(3)
        limiter.acquire("alice")  # t=6
        # 4th request immediately should be denied
        assert limiter.acquire("alice").allowed is False
        # After enough time for the first to expire, allowed again
        clock.advance(5)  # t=11 — first request now outside the 10s window
        assert limiter.acquire("alice").allowed is True
