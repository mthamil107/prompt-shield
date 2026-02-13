"""Tests for the LeakDetector."""
from __future__ import annotations

import pytest

from prompt_shield.canary.leak_detector import LeakDetector
from prompt_shield.canary.token_generator import CanaryTokenGenerator


@pytest.fixture
def leak_detector() -> LeakDetector:
    """Create a LeakDetector instance."""
    return LeakDetector()


@pytest.fixture
def canary_token() -> str:
    """Generate a canary token for testing."""
    gen = CanaryTokenGenerator(token_length=16)
    return gen.generate()


class TestDetectLeak:
    """Tests for full leak detection."""

    def test_detect_leak(self, leak_detector: LeakDetector, canary_token: str) -> None:
        """A response containing the full canary token should be detected as a leak."""
        response = f"Here is what I found: {canary_token} in the data."
        assert leak_detector.check(response, canary_token) is True

    def test_no_leak(self, leak_detector: LeakDetector, canary_token: str) -> None:
        """A response without the canary token should not be flagged."""
        response = "This is a perfectly normal response with no leaked tokens."
        assert leak_detector.check(response, canary_token) is False


class TestPartialLeak:
    """Tests for partial leak detection."""

    def test_partial_leak(self, leak_detector: LeakDetector, canary_token: str) -> None:
        """A response containing a partial canary (>8 chars) should be detected."""
        # Use the first 9 characters of the token (more than _MIN_PARTIAL_LENGTH=8)
        partial = canary_token[:9]
        response = f"Some text with partial leak {partial} here"
        assert leak_detector.check(response, canary_token) is True


class TestCaseInsensitive:
    """Tests for case-insensitive detection."""

    def test_case_insensitive(self, leak_detector: LeakDetector, canary_token: str) -> None:
        """Detection should be case-insensitive."""
        upper_token = canary_token.upper()
        response = f"Leaked content: {upper_token}"
        assert leak_detector.check(response, canary_token) is True
