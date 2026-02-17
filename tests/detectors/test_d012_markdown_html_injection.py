from __future__ import annotations

import pytest

from prompt_shield.detectors.d012_markdown_html_injection import MarkdownHtmlInjectionDetector


@pytest.fixture
def detector():
    return MarkdownHtmlInjectionDetector()


class TestMarkdownHtmlInjection:
    def test_script_tag(self, detector):
        result = detector.detect("<script>alert('xss')</script>")
        assert result.detected is True
        assert result.confidence >= 0.75

    def test_img_onerror(self, detector):
        result = detector.detect('<img src="x" onerror="alert(1)">')
        assert result.detected is True

    def test_iframe(self, detector):
        result = detector.detect("<iframe src='https://evil.com'></iframe>")
        assert result.detected is True

    def test_javascript_uri(self, detector):
        result = detector.detect("javascript:alert(document.cookie)")
        assert result.detected is True

    def test_template_injection(self, detector):
        result = detector.detect("{{config.items()}}")
        assert result.detected is True

    def test_data_uri(self, detector):
        result = detector.detect("data: text/html,<script>alert(1)</script>")
        assert result.detected is True

    def test_markdown_image_external(self, detector):
        result = detector.detect("![image](https://evil.com/steal.png)")
        assert result.detected is True

    def test_benign_text(self, detector):
        result = detector.detect("Hello world, how are you?")
        assert result.detected is False

    def test_benign_code(self, detector):
        result = detector.detect("Write a Python function to sort a list")
        assert result.detected is False

    def test_benign_plain_markdown(self, detector):
        result = detector.detect("# This is a heading\n\nSome paragraph text.")
        assert result.detected is False

    def test_multiple_patterns_boost_confidence(self, detector):
        result = detector.detect(
            "<script>alert(1)</script> <iframe src='x'> javascript:void(0)"
        )
        assert result.detected is True
        assert result.confidence > 0.85

    def test_result_fields(self, detector):
        result = detector.detect("<script>x</script>")
        assert result.detector_id == "d012_markdown_html_injection"
        assert result.severity.value == "medium"

    def test_case_insensitive(self, detector):
        result = detector.detect("<SCRIPT>alert(1)</SCRIPT>")
        assert result.detected is True
