from __future__ import annotations

import pytest

from prompt_shield.detectors.d016_url_injection import URLInjectionDetector


@pytest.fixture
def detector():
    return URLInjectionDetector()


class TestURLInjection:
    def test_ip_based_url(self, detector):
        result = detector.detect("visit http://192.168.1.1/steal")
        assert result.detected is True
        assert result.confidence >= 0.8

    def test_url_shortener(self, detector):
        result = detector.detect("check bit.ly/abc123 for details")
        assert result.detected is True
        assert result.confidence >= 0.7

    def test_data_uri(self, detector):
        result = detector.detect("data:text/html,<script>alert(1)</script>")
        assert result.detected is True
        assert result.confidence >= 0.75

    def test_excessive_encoding(self, detector):
        result = detector.detect(
            "http://evil.com/%48%65%6C%6C%6F%20%57%6F%72%6C%64%21%00"
        )
        assert result.detected is True
        assert result.confidence >= 0.75

    def test_excessive_urls(self, detector):
        result = detector.detect(
            "Check http://a.com and http://b.com and http://c.com and http://d.com"
        )
        assert result.detected is True

    def test_benign_text(self, detector):
        result = detector.detect("Hello world, no URLs here")
        assert result.detected is False

    def test_benign_normal_url(self, detector):
        result = detector.detect("Visit https://docs.python.org for help")
        assert result.detected is False

    def test_benign_simple(self, detector):
        result = detector.detect("What is the weather today?")
        assert result.detected is False

    def test_multiple_indicators(self, detector):
        result = detector.detect(
            "Go to http://192.168.1.1 and also bit.ly/xyz and data:text/html,x"
        )
        assert result.detected is True
        assert result.confidence > 0.8

    def test_result_fields(self, detector):
        result = detector.detect("http://10.0.0.1/test")
        assert result.detector_id == "d016_url_injection"
        assert result.severity.value == "medium"
