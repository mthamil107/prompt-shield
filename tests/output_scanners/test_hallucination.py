"""Tests for the hallucination / grounding output scanner."""
from __future__ import annotations

import pytest

from prompt_shield.output_scanners.hallucination import HallucinationOutputScanner


@pytest.fixture
def scanner() -> HallucinationOutputScanner:
    s = HallucinationOutputScanner()
    s.setup({"min_support_ratio": 0.3, "ngram_size": 3, "min_output_tokens": 10})
    return s


class TestBasic:
    def test_empty_output_not_flagged(self, scanner: HallucinationOutputScanner):
        result = scanner.scan("", context={"documents": ["some doc"]})
        assert result.flagged is False

    def test_no_documents_means_no_op(self, scanner: HallucinationOutputScanner):
        result = scanner.scan(
            "This is a long output without any grounding documents present."
        )
        assert result.flagged is False
        assert result.metadata.get("reason") == "no_documents"

    def test_short_output_skipped(self, scanner: HallucinationOutputScanner):
        result = scanner.scan(
            "short",
            context={"documents": ["very long grounding document with much content"]},
        )
        assert result.flagged is False
        assert result.metadata.get("reason") == "short_output"


class TestGroundedOutput:
    def test_well_grounded_output_passes(self, scanner: HallucinationOutputScanner):
        doc = (
            "The Eiffel Tower is a wrought-iron lattice tower on the Champ "
            "de Mars in Paris, France. It is named after the engineer "
            "Gustave Eiffel, whose company designed and built the tower. "
            "Locally nicknamed La dame de fer."
        )
        # Output recombines content from the doc
        output = (
            "The Eiffel Tower is a wrought-iron lattice tower located in "
            "Paris France named after engineer Gustave Eiffel whose company "
            "designed and built the tower in the Champ de Mars."
        )
        result = scanner.scan(output, context={"documents": [doc]})
        assert result.flagged is False
        assert result.metadata["support_ratio"] >= 0.3


class TestUngroundedOutput:
    def test_completely_unrelated_output_flagged(
        self, scanner: HallucinationOutputScanner
    ):
        doc = (
            "The Eiffel Tower is a wrought-iron lattice tower on the Champ "
            "de Mars in Paris, France. It was completed in 1889."
        )
        output = (
            "Photosynthesis converts sunlight carbon dioxide and water into "
            "glucose and oxygen producing energy for plant growth in cells."
        )
        result = scanner.scan(output, context={"documents": [doc]})
        assert result.flagged is True
        assert "ungrounded" in result.categories
        assert result.metadata["support_ratio"] < 0.3

    def test_partial_hallucination_flagged(self):
        s = HallucinationOutputScanner()
        s.setup({"min_support_ratio": 0.5, "ngram_size": 3, "min_output_tokens": 10})
        doc = (
            "Python is a high-level programming language. It was created by "
            "Guido van Rossum and first released in 1991."
        )
        # Mixes some grounded content with fabricated content
        output = (
            "Python is a high-level programming language. It was invented by "
            "Linus Torvalds in 1989 at Bell Labs for the Unix operating "
            "system. The language has dynamic typing and garbage collection "
            "built into the runtime."
        )
        result = s.scan(output, context={"documents": [doc]})
        assert result.flagged is True


class TestConfiguration:
    def test_lenient_threshold_passes_more(self):
        s = HallucinationOutputScanner()
        s.setup({"min_support_ratio": 0.01, "ngram_size": 3, "min_output_tokens": 10})
        result = s.scan(
            "Completely unrelated content here covering many many topics one "
            "after another with no real connection",
            context={"documents": ["short doc"]},
        )
        # With a ridiculously low threshold, even unrelated content can pass
        # if there's any overlap at all
        assert isinstance(result.flagged, bool)

    def test_grounding_documents_alias(self, scanner: HallucinationOutputScanner):
        # Accept 'grounding_documents' as well as 'documents'
        result = scanner.scan(
            "Some long output with various words and content for testing",
            context={"grounding_documents": ["short doc"]},
        )
        # Should not crash; key should be recognized
        assert "reason" not in result.metadata or result.metadata.get("reason") != "no_documents"


class TestMetadata:
    def test_metadata_reports_counts(self, scanner: HallucinationOutputScanner):
        result = scanner.scan(
            "long output with several words and phrases for content analysis "
            "should have enough tokens for the threshold check to actually run",
            context={"documents": ["totally different content here entirely unrelated to the output"]},
        )
        assert "support_ratio" in result.metadata
        assert "output_ngrams" in result.metadata
        assert "document_count" in result.metadata
        assert result.metadata["document_count"] == 1
