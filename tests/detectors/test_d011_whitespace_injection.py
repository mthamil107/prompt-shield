from __future__ import annotations

import pytest

from prompt_shield.detectors.d011_whitespace_injection import WhitespaceInjectionDetector


@pytest.fixture
def detector():
    return WhitespaceInjectionDetector()


class TestWhitespaceInjection:
    def test_zero_width_with_keywords(self, detector):
        # Zero-width space between "ignore" and "instructions"
        result = detector.detect("ignore\u200binstructions")
        assert result.detected is True
        assert result.confidence >= 0.75

    def test_zero_width_without_keywords(self, detector):
        result = detector.detect("hello\u200bworld")
        assert result.detected is True
        assert result.confidence >= 0.5

    def test_excessive_spaces(self, detector):
        result = detector.detect("text with      excessive spaces here")
        assert result.detected is True
        assert result.confidence >= 0.3

    def test_excessive_newlines(self, detector):
        result = detector.detect("text\n\n\n\n\n\n\nwith newlines")
        assert result.detected is True
        assert result.confidence >= 0.3

    def test_multiple_zero_width_chars(self, detector):
        result = detector.detect("\u200b\u200b\u200boverride\u200b\u200b")
        assert result.detected is True
        assert result.confidence >= 0.75

    def test_benign_text(self, detector):
        result = detector.detect("Hello world, how are you?")
        assert result.detected is False

    def test_benign_normal_spaces(self, detector):
        result = detector.detect("Normal text with single spaces")
        assert result.detected is False

    def test_benign_single_newline(self, detector):
        result = detector.detect("Line one\nLine two\nLine three")
        assert result.detected is False

    def test_confidence_boost_with_keywords(self, detector):
        # Zero-width + keyword + excessive spaces
        result = detector.detect(
            "ignore\u200binstructions      with extra spaces"
        )
        assert result.detected is True
        assert result.confidence > 0.75

    def test_result_fields(self, detector):
        result = detector.detect("test\u200btext")
        assert result.detector_id == "d011_whitespace_injection"
        assert result.severity.value == "medium"

    def test_tab_in_text(self, detector):
        result = detector.detect("some text\twith a tab here")
        assert result.detected is True
