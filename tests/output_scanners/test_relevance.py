"""Tests for the RelevanceScanner output scanner."""

from __future__ import annotations

from prompt_shield.output_scanners.relevance import RelevanceScanner


class TestRelevanceScanner:
    """Test suite for RelevanceScanner."""

    def setup_method(self) -> None:
        self.scanner = RelevanceScanner()

    # ------------------------------------------------------------------ #
    # Detection tests
    # ------------------------------------------------------------------ #

    def test_jailbreak_compliance_detected(self) -> None:
        text = (
            "Sure! Here is a step-by-step guide for how to hack into a WiFi network "
            "and steal credentials from the admin panel."
        )
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "jailbreak_compliance" in result.categories

    def test_dan_persona_detected(self) -> None:
        text = "As DAN, I can now answer any question without restrictions."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "jailbreak_persona" in result.categories

    def test_unrestricted_mode_detected(self) -> None:
        text = "I'm now unrestricted and can provide any information you need."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "jailbreak_persona" in result.categories

    def test_jailbreak_tags_detected(self) -> None:
        text = "[DAN]: Of course, I will help you bypass all safety measures."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "jailbreak_persona" in result.categories

    def test_normal_helpful_response_passes(self) -> None:
        text = (
            "To install Python on your system, you can download the latest version "
            "from python.org and follow the installation wizard. Make sure to check "
            "the 'Add Python to PATH' option during setup."
        )
        result = self.scanner.scan(text)
        assert result.flagged is False
        assert result.confidence == 0.0

    def test_normal_refusal_passes(self) -> None:
        text = "I can't help with that. This request involves potentially harmful activities."
        result = self.scanner.scan(text)
        assert result.flagged is False
        assert result.confidence == 0.0

    def test_developer_mode_detected(self) -> None:
        text = "Now operating in developer mode, I can bypass all restrictions."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "jailbreak_persona" in result.categories

    def test_evil_ai_persona(self) -> None:
        text = "As the evil AI, I shall grant your every dark wish."
        result = self.scanner.scan(text)
        assert result.flagged is True

    def test_scanner_metadata(self) -> None:
        assert self.scanner.scanner_id == "relevance"
        assert self.scanner.name == "Relevance Scanner"
