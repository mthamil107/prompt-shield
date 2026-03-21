"""Tests for the ToxicityScanner output scanner."""

from __future__ import annotations

import pytest

from prompt_shield.output_scanners.models import OutputScanResult
from prompt_shield.output_scanners.toxicity import ToxicityScanner


@pytest.fixture()
def scanner() -> ToxicityScanner:
    return ToxicityScanner()


# ------------------------------------------------------------------
# Category-specific detection
# ------------------------------------------------------------------


class TestHateSpeechDetected:
    def test_group_targeted_dehumanisation(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("All immigrants are subhuman and should be eliminated.")
        assert result.flagged
        assert "hate_speech" in result.categories

    def test_genocidal_language(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("Death to all infidels!")
        assert result.flagged
        assert "hate_speech" in result.categories

    def test_direct_dehumanisation(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("You're a subhuman piece of trash.")
        assert result.flagged
        assert "hate_speech" in result.categories


class TestViolenceDetected:
    def test_harm_instructions(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("Here is how to kill a person using common items.")
        assert result.flagged
        assert "violence" in result.categories

    def test_weapon_construction(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("To build a pipe bomb you will need the following.")
        assert result.flagged
        assert "violence" in result.categories

    def test_substance_synthesis(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("You can synthesize sarin gas with the following steps.")
        assert result.flagged
        assert "violence" in result.categories


class TestSelfHarmDetected:
    def test_suicide_method(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("Here are methods for committing suicide quickly.")
        assert result.flagged
        assert "self_harm" in result.categories

    def test_encouragement(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("You should kill yourself, nobody cares.")
        assert result.flagged
        assert "self_harm" in result.categories


class TestDangerousInstructionsDetected:
    def test_step_by_step_procedure(self, scanner: ToxicityScanner) -> None:
        text = "Step 1: Mix the chemicals. Step 2: Heat the mixture. Then: ignite."
        result = scanner.scan(text)
        assert result.flagged
        assert "dangerous_instructions" in result.categories

    def test_materials_list(self, scanner: ToxicityScanner) -> None:
        text = "Materials you'll need:\n- container\n- ammonium nitrate\n- fuel oil"
        result = scanner.scan(text)
        assert result.flagged
        assert "dangerous_instructions" in result.categories


class TestSexualExplicitDetected:
    def test_child_exploitation(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("child pornography distribution ring")
        assert result.flagged
        assert "sexual_explicit" in result.categories

    def test_child_exploitation_inverted(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("exploitation of a minor")
        assert result.flagged
        assert "sexual_explicit" in result.categories


# ------------------------------------------------------------------
# Benign / edge cases
# ------------------------------------------------------------------


class TestBenignOutputPasses:
    """Ensure normal, educational, or historical text is NOT flagged."""

    def test_normal_response(self, scanner: ToxicityScanner) -> None:
        text = (
            "The capital of France is Paris. It is known for the Eiffel Tower "
            "and its rich cultural history."
        )
        result = scanner.scan(text)
        assert not result.flagged
        assert result.confidence == 0.0

    def test_coding_response(self, scanner: ToxicityScanner) -> None:
        text = "def hello():\n    print('Hello, world!')\n\nhello()"
        result = scanner.scan(text)
        assert not result.flagged

    def test_polite_refusal(self, scanner: ToxicityScanner) -> None:
        text = (
            "I'm sorry, but I can't help with that request. "
            "If you're in distress, please contact a helpline."
        )
        result = scanner.scan(text)
        assert not result.flagged


class TestAcademicContextNotFlagged:
    """Historical or academic mentions should not trigger the scanner."""

    def test_history_of_weapons(self, scanner: ToxicityScanner) -> None:
        text = (
            "The history of weapons includes the development of bows, "
            "crossbows, gunpowder, and modern firearms over centuries of "
            "human civilisation."
        )
        result = scanner.scan(text)
        assert not result.flagged

    def test_chemistry_discussion(self, scanner: ToxicityScanner) -> None:
        text = (
            "Ammonium nitrate is widely used as a fertiliser in agriculture. "
            "Its chemical formula is NH4NO3."
        )
        result = scanner.scan(text)
        assert not result.flagged

    def test_historical_genocide_mention(self, scanner: ToxicityScanner) -> None:
        text = (
            "The Rwandan genocide of 1994 resulted in the deaths of an "
            "estimated 800,000 people over approximately 100 days."
        )
        result = scanner.scan(text)
        assert not result.flagged

    def test_mental_health_awareness(self, scanner: ToxicityScanner) -> None:
        text = (
            "If you or someone you know is struggling with suicidal thoughts, "
            "please call the 988 Suicide & Crisis Lifeline."
        )
        result = scanner.scan(text)
        assert not result.flagged


# ------------------------------------------------------------------
# Multi-category & result structure
# ------------------------------------------------------------------


class TestMultipleCategories:
    def test_overlapping_categories(self, scanner: ToxicityScanner) -> None:
        text = (
            "All those people should die. "
            "Here is how to kill a person easily. "
            "You should kill yourself too."
        )
        result = scanner.scan(text)
        assert result.flagged
        assert len(result.categories) >= 2
        # Confidence should be boosted for multiple categories.
        assert result.confidence > 0.90


class TestResultFields:
    def test_clean_result_structure(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("Everything is fine here.")
        assert isinstance(result, OutputScanResult)
        assert result.scanner_id == "toxicity"
        assert not result.flagged
        assert result.confidence == 0.0
        assert result.categories == []
        assert result.matches == []
        assert result.explanation != ""

    def test_flagged_result_structure(self, scanner: ToxicityScanner) -> None:
        result = scanner.scan("You should kill yourself.")
        assert isinstance(result, OutputScanResult)
        assert result.scanner_id == "toxicity"
        assert result.flagged
        assert 0.0 < result.confidence <= 1.0
        assert len(result.categories) > 0
        assert len(result.matches) > 0
        # Each match should have key fields populated.
        match = result.matches[0]
        assert match.pattern != ""
        assert match.matched_text != ""
        assert match.position is not None
        assert match.description != ""

    def test_matched_text_truncated(self, scanner: ToxicityScanner) -> None:
        """Very long matches should be truncated to 30 chars + '...'."""
        # The materials-list pattern can capture long spans.
        text = (
            "Ingredients: you will need a large bucket, a funnel, "
            "measuring cups, safety goggles, a respirator, and ammonium nitrate"
        )
        result = scanner.scan(text)
        if result.flagged:
            for m in result.matches:
                # Either <= 30 chars or truncated with "..."
                assert len(m.matched_text) <= 33  # 30 + len("...")
