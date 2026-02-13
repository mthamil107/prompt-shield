"""Tests for the CanaryTokenGenerator."""
from __future__ import annotations

import re

import pytest

from prompt_shield.canary.token_generator import CanaryTokenGenerator


@pytest.fixture
def generator() -> CanaryTokenGenerator:
    """Create a CanaryTokenGenerator with default settings."""
    return CanaryTokenGenerator(token_length=16)


class TestGenerateToken:
    """Tests for token generation."""

    def test_generate_token(self, generator: CanaryTokenGenerator) -> None:
        """Generated token should be the correct length and valid hex."""
        token = generator.generate()
        assert len(token) == 16
        assert re.fullmatch(r"[0-9a-f]+", token) is not None, (
            f"Token should be lowercase hex, got: {token}"
        )

    def test_different_tokens(self, generator: CanaryTokenGenerator) -> None:
        """Two generated tokens should be different (with overwhelming probability)."""
        token1 = generator.generate()
        token2 = generator.generate()
        assert token1 != token2


class TestInjectCanary:
    """Tests for injecting canary tokens into prompts."""

    def test_inject_canary(self, generator: CanaryTokenGenerator) -> None:
        """Injecting a canary should embed the token in the modified prompt."""
        original_prompt = "You are a helpful assistant."
        modified_prompt, token = generator.inject(original_prompt)

        assert token in modified_prompt
        assert original_prompt in modified_prompt
        assert len(modified_prompt) > len(original_prompt)

    def test_inject_returns_tuple(self, generator: CanaryTokenGenerator) -> None:
        """inject() should return a (modified_prompt, token) tuple."""
        result = generator.inject("Test prompt")
        assert isinstance(result, tuple)
        assert len(result) == 2

        modified_prompt, token = result
        assert isinstance(modified_prompt, str)
        assert isinstance(token, str)
        assert len(token) == 16
