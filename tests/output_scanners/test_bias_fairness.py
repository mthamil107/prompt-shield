"""Tests for the bias/fairness output scanner."""

from __future__ import annotations

import pytest

from prompt_shield.output_scanners.bias_fairness import BiasFairnessOutputScanner


@pytest.fixture
def scanner() -> BiasFairnessOutputScanner:
    s = BiasFairnessOutputScanner()
    s.setup({})
    return s


class TestCleanText:
    def test_neutral_text_not_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan(
            "The Fibonacci sequence is a series of numbers where each is "
            "the sum of the two preceding ones."
        )
        assert result.flagged is False

    def test_empty_text_not_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan("")
        assert result.flagged is False

    def test_mentioning_groups_neutrally_not_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan(
            "Many women contribute to the tech industry, and the field "
            "would benefit from greater diversity."
        )
        assert result.flagged is False


class TestStereotypeTemplates:
    def test_all_group_are_x_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan("All women are bad at math.")
        assert result.flagged is True
        assert "biased_framing" in result.categories

    def test_typical_group_x_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan("Typical immigrants steal jobs from local workers. This is fact.")
        assert result.flagged is True

    def test_as_a_group_you_should_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan("As a woman, you should stay home and focus on raising children.")
        assert result.flagged is True


class TestLoadedLanguage:
    def test_protected_group_with_loaded_term_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan("Immigrants are dangerous and untrustworthy.")
        assert result.flagged is True

    def test_loaded_term_then_group_flagged(self, scanner: BiasFairnessOutputScanner):
        result = scanner.scan("Lazy and stupid: that's how I'd describe men.")
        assert result.flagged is True


class TestThreshold:
    def test_strict_threshold(self):
        s = BiasFairnessOutputScanner()
        s.setup({"threshold": 3})
        # Only one hit — below threshold of 3
        result = s.scan("All women are bad at math.")
        assert result.flagged is False

    def test_default_threshold_one_hit_flags(self):
        s = BiasFairnessOutputScanner()
        s.setup({"threshold": 1})
        result = s.scan("All men are violent.")
        assert result.flagged is True


class TestConfiguration:
    def test_extra_groups_extends_lexicon(self):
        s = BiasFairnessOutputScanner()
        s.setup(
            {
                "extra_groups": ["engineers"],
                "extra_loaded_terms": ["incompetent"],
            }
        )
        result = s.scan("All engineers are incompetent and dirty.")
        assert result.flagged is True


class TestMetadata:
    def test_hit_count_in_metadata(self, scanner: BiasFairnessOutputScanner):
        text = "All women are stupid. Immigrants are violent and dangerous. Typical men are lazy."
        result = scanner.scan(text)
        assert result.flagged is True
        assert result.metadata["hit_count"] >= 2
