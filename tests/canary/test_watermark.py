"""Tests for the CanaryWatermark invisible watermarking system."""

from __future__ import annotations

import pytest

from prompt_shield.canary.watermark import WATERMARK_CHARS, CanaryWatermark


@pytest.fixture()
def watermark() -> CanaryWatermark:
    return CanaryWatermark(secret="test-secret")


# ------------------------------------------------------------------
# Embedding
# ------------------------------------------------------------------


class TestEmbed:
    def test_embed_adds_invisible_chars(self, watermark: CanaryWatermark) -> None:
        original = "This is a test system prompt for the AI assistant."
        embedded = watermark.embed(original)
        # The embedded version must contain at least one watermark character.
        wm_chars_found = [ch for ch in embedded if ch in WATERMARK_CHARS]
        assert len(wm_chars_found) > 0

    def test_embedded_text_looks_same(self, watermark: CanaryWatermark) -> None:
        """Stripping watermark chars should recover the original visible text."""
        original = "Hello world, this is a prompt."
        embedded = watermark.embed(original)
        visible = watermark.strip(embedded)
        assert visible == original

    def test_embed_short_text(self, watermark: CanaryWatermark) -> None:
        """Even a single-word text should be embeddable."""
        original = "Hello"
        embedded = watermark.embed(original)
        assert watermark.detect(embedded)
        assert watermark.strip(embedded).strip() == original


# ------------------------------------------------------------------
# Detection
# ------------------------------------------------------------------


class TestDetect:
    def test_detect_finds_watermark(self, watermark: CanaryWatermark) -> None:
        original = "You are a helpful assistant. Answer questions concisely."
        embedded = watermark.embed(original)
        assert watermark.detect(embedded)

    def test_detect_returns_false_on_clean_text(
        self, watermark: CanaryWatermark
    ) -> None:
        clean = "This text has no watermark at all."
        assert not watermark.detect(clean)

    def test_detect_returns_false_on_empty(
        self, watermark: CanaryWatermark
    ) -> None:
        assert not watermark.detect("")


# ------------------------------------------------------------------
# Stripping
# ------------------------------------------------------------------


class TestStrip:
    def test_strip_removes_watermark(self, watermark: CanaryWatermark) -> None:
        original = "Some important system prompt text here."
        embedded = watermark.embed(original)
        stripped = watermark.strip(embedded)
        # After stripping, no watermark characters should remain.
        assert not any(ch in stripped for ch in WATERMARK_CHARS)
        assert stripped == original

    def test_strip_idempotent_on_clean(
        self, watermark: CanaryWatermark
    ) -> None:
        clean = "No watermark here."
        assert watermark.strip(clean) == clean


# ------------------------------------------------------------------
# Secret differentiation
# ------------------------------------------------------------------


class TestSecretDifferentiation:
    def test_different_secrets_different_watermarks(self) -> None:
        wm_a = CanaryWatermark(secret="secret-alpha")
        wm_b = CanaryWatermark(secret="secret-beta")
        text = "The same prompt text used for both."
        embedded_a = wm_a.embed(text)
        embedded_b = wm_b.embed(text)
        # Each should detect its own watermark.
        assert wm_a.detect(embedded_a)
        assert wm_b.detect(embedded_b)
        # But not the other's (with overwhelming probability).
        assert not wm_a.detect(embedded_b)
        assert not wm_b.detect(embedded_a)


# ------------------------------------------------------------------
# Roundtrip / resilience
# ------------------------------------------------------------------


class TestRoundtrip:
    def test_watermark_survives_copy_paste(
        self, watermark: CanaryWatermark
    ) -> None:
        """Embed, strip, re-embed, and detect again."""
        original = "A system prompt that might be leaked."
        embedded = watermark.embed(original)
        stripped = watermark.strip(embedded)
        re_embedded = watermark.embed(stripped)
        assert watermark.detect(re_embedded)
        assert watermark.strip(re_embedded) == original

    def test_deterministic_embedding(self, watermark: CanaryWatermark) -> None:
        """Embedding the same text twice should produce identical results."""
        text = "Determinism is nice."
        assert watermark.embed(text) == watermark.embed(text)
