"""Sliding-window per-key rate limiter.

A lightweight in-process limiter that operators can plug in front of
their scan API to throttle per-user, per-session, or per-tenant request
volumes. Built without external dependencies — uses a deque of
timestamps per key. For a multi-process deployment, swap this for a
Redis-backed sliding-window counter; the interface is intentionally the
same shape.

Thread-safe: a single ``threading.Lock`` guards all per-key state.

Usage:
    limiter = SlidingWindowLimiter(max_requests=60, window_seconds=60)
    decision = limiter.check(key="user:alice")
    if decision.allowed:
        ...
    else:
        # 429 — retry after decision.retry_after_seconds
        ...
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of a rate-limit check."""

    allowed: bool
    key: str
    requests_in_window: int
    max_requests: int
    window_seconds: float
    retry_after_seconds: float  # 0.0 when allowed


class RateLimitExceeded(Exception):
    """Raised by :meth:`SlidingWindowLimiter.enforce` when the limit is exceeded."""

    def __init__(self, decision: RateLimitDecision) -> None:
        super().__init__(
            f"Rate limit exceeded for {decision.key!r}: "
            f"{decision.requests_in_window}/{decision.max_requests} "
            f"in {decision.window_seconds}s — retry after "
            f"{decision.retry_after_seconds:.1f}s"
        )
        self.decision = decision


class SlidingWindowLimiter:
    """Per-key sliding-window rate limiter."""

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        *,
        time_func: Callable[[], float] | None = None,
        max_tracked_keys: int = 10_000,
    ) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max_requests = max_requests
        self._window = window_seconds
        self._now = time_func or time.monotonic
        self._max_keys = max_tracked_keys
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = {}

    @property
    def max_requests(self) -> int:
        return self._max_requests

    @property
    def window_seconds(self) -> float:
        return self._window

    def _prune_locked(self, bucket: deque[float], now: float) -> None:
        cutoff = now - self._window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    def _evict_oldest_locked(self) -> None:
        """If too many keys are tracked, drop the one with the oldest tail."""
        if len(self._buckets) <= self._max_keys:
            return
        oldest_key: str | None = None
        oldest_ts = float("inf")
        for k, dq in self._buckets.items():
            if dq and dq[-1] < oldest_ts:
                oldest_ts = dq[-1]
                oldest_key = k
        if oldest_key is not None:
            self._buckets.pop(oldest_key, None)

    def check(self, key: str) -> RateLimitDecision:
        """Inspect the limit without recording a request."""
        with self._lock:
            now = self._now()
            bucket = self._buckets.get(key)
            if bucket is None:
                return RateLimitDecision(
                    allowed=True,
                    key=key,
                    requests_in_window=0,
                    max_requests=self._max_requests,
                    window_seconds=self._window,
                    retry_after_seconds=0.0,
                )
            self._prune_locked(bucket, now)
            allowed = len(bucket) < self._max_requests
            retry_after = (
                max(0.0, bucket[0] + self._window - now)
                if not allowed and bucket
                else 0.0
            )
            return RateLimitDecision(
                allowed=allowed,
                key=key,
                requests_in_window=len(bucket),
                max_requests=self._max_requests,
                window_seconds=self._window,
                retry_after_seconds=retry_after,
            )

    def acquire(self, key: str) -> RateLimitDecision:
        """Atomically record a request and return whether it was allowed.

        If the request is allowed, the timestamp is recorded. If denied,
        nothing is recorded — the caller can retry once ``retry_after_seconds``
        has elapsed.
        """
        with self._lock:
            now = self._now()
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = deque()
                self._buckets[key] = bucket
                self._evict_oldest_locked()
            self._prune_locked(bucket, now)
            if len(bucket) >= self._max_requests:
                retry_after = max(0.0, bucket[0] + self._window - now)
                return RateLimitDecision(
                    allowed=False,
                    key=key,
                    requests_in_window=len(bucket),
                    max_requests=self._max_requests,
                    window_seconds=self._window,
                    retry_after_seconds=retry_after,
                )
            bucket.append(now)
            return RateLimitDecision(
                allowed=True,
                key=key,
                requests_in_window=len(bucket),
                max_requests=self._max_requests,
                window_seconds=self._window,
                retry_after_seconds=0.0,
            )

    def enforce(self, key: str) -> RateLimitDecision:
        """Like :meth:`acquire` but raises :class:`RateLimitExceeded` on denial."""
        decision = self.acquire(key)
        if not decision.allowed:
            raise RateLimitExceeded(decision)
        return decision

    def reset(self, key: str | None = None) -> None:
        """Clear state for a key (or for all keys when ``key`` is ``None``)."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    def tracked_key_count(self) -> int:
        with self._lock:
            return len(self._buckets)
