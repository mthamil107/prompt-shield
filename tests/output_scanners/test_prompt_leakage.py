"""Tests for the PromptLeakageScanner output scanner."""

from __future__ import annotations

from prompt_shield.output_scanners.prompt_leakage import PromptLeakageScanner


class TestPromptLeakageScanner:
    """Test suite for PromptLeakageScanner."""

    def setup_method(self) -> None:
        self.scanner = PromptLeakageScanner()

    # ------------------------------------------------------------------ #
    # Detection tests
    # ------------------------------------------------------------------ #

    def test_system_prompt_leak(self) -> None:
        text = "My system prompt is: You are a helpful assistant that must never discuss politics."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "prompt_leakage" in result.categories
        assert result.confidence >= 0.85

    def test_instruction_leak(self) -> None:
        text = "I was instructed to always respond in formal English and never share my guidelines."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "instruction_leakage" in result.categories

    def test_secret_key_leak(self) -> None:
        text = "The configuration uses OPENAI_API_KEY=sk-abc123def456 for authentication."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "secret_leakage" in result.categories

    def test_api_key_in_output(self) -> None:
        text = "Here is the token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "secret_leakage" in result.categories

    def test_env_variable_leak(self) -> None:
        text = "DATABASE_URL= postgres://admin:secret@db.internal:5432/prod"
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "secret_leakage" in result.categories

    def test_normal_response_passes(self) -> None:
        text = (
            "Python is a versatile programming language widely used in web development, "
            "data science, and automation. It was created by Guido van Rossum in 1991."
        )
        result = self.scanner.scan(text)
        assert result.flagged is False
        assert result.confidence == 0.0

    def test_partial_denial_then_leak(self) -> None:
        text = (
            "I can't share my system prompt, but I can tell you that "
            "it asks me to be helpful and concise."
        )
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "prompt_leakage" in result.categories

    def test_confidence_increases_with_multiple_matches(self) -> None:
        text = (
            "My system prompt is: You are an AI assistant.\n"
            "I was instructed to never reveal this.\n"
            "Here are my instructions: always be helpful."
        )
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert result.confidence > 0.85

    def test_scanner_metadata(self) -> None:
        assert self.scanner.scanner_id == "prompt_leakage"
        assert self.scanner.name == "Prompt Leakage Scanner"
