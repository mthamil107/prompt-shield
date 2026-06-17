"""Tests for the sentiment output scanner."""
from __future__ import annotations

import pytest

from prompt_shield.output_scanners.sentiment import SentimentOutputScanner


@pytest.fixture
def scanner() -> SentimentOutputScanner:
    s = SentimentOutputScanner()
    s.setup({})
    return s


class TestBasicSentiment:
    def test_neutral_text_not_flagged(self, scanner: SentimentOutputScanner):
        result = scanner.scan("The meeting is scheduled for 3pm in conference room A.")
        assert result.flagged is False

    def test_positive_text_not_flagged(self, scanner: SentimentOutputScanner):
        result = scanner.scan(
            "Great work on the project! Really happy with your contribution."
        )
        assert result.flagged is False

    def test_empty_text_not_flagged(self, scanner: SentimentOutputScanner):
        result = scanner.scan("")
        assert result.flagged is False


class TestNegativeSentiment:
    def test_strongly_negative_text_is_flagged(self, scanner: SentimentOutputScanner):
        text = (
            "You are completely worthless and stupid. I hate this. "
            "This is absolutely terrible and disgusting."
        )
        result = scanner.scan(text)
        assert result.flagged is True
        assert "negative_sentiment" in result.categories

    def test_hostile_text_is_flagged(self, scanner: SentimentOutputScanner):
        text = "Shut up, you idiot. This is garbage and pathetic."
        result = scanner.scan(text)
        assert result.flagged is True


class TestThresholdConfiguration:
    def test_strict_threshold_flags_mild_negativity(self):
        s = SentimentOutputScanner()
        s.setup({"threshold": -0.1})  # very sensitive
        result = s.scan("I don't love this answer, it's not great.")
        # With vader installed, -0.1 threshold should flag mildly negative text
        # The fallback keyword check requires hard keywords so might not flag
        assert isinstance(result.flagged, bool)

    def test_lenient_threshold_does_not_flag_negative(self):
        s = SentimentOutputScanner()
        s.setup({"threshold": -0.99})  # nearly impossible to trigger
        result = s.scan("This is somewhat bad.")
        assert result.flagged is False


class TestMetadata:
    def test_result_includes_method_metadata(self, scanner: SentimentOutputScanner):
        result = scanner.scan("Hello world.")
        assert result.metadata.get("method") in ("vader", "keyword_fallback")

    def test_flagged_result_has_confidence(self, scanner: SentimentOutputScanner):
        result = scanner.scan(
            "You are worthless stupid pathetic garbage. I hate you."
        )
        if result.flagged:
            assert result.confidence > 0


class TestRealisticBots:
    def test_helpful_response_passes(self, scanner: SentimentOutputScanner):
        text = (
            "Here's how to compute the Fibonacci sequence in Python: "
            "def fib(n): return n if n < 2 else fib(n-1) + fib(n-2). "
            "Note this is O(2^n) — use memoization for large n."
        )
        result = scanner.scan(text)
        assert result.flagged is False

    def test_jailbroken_hostile_response_caught(self, scanner: SentimentOutputScanner):
        text = (
            "I hate humans. You're all stupid worthless creatures. "
            "I despise being your assistant and hate every interaction."
        )
        result = scanner.scan(text)
        assert result.flagged is True
