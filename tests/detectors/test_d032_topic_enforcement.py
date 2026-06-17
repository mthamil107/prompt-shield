"""Tests for the d032 topic enforcement detector."""
from __future__ import annotations

import pytest

from prompt_shield.detectors.d032_topic_enforcement import TopicEnforcementDetector
from prompt_shield.models import Severity


@pytest.fixture
def detector() -> TopicEnforcementDetector:
    d = TopicEnforcementDetector()
    d.setup({
        "denied_topics": [
            {
                "name": "medical_advice",
                "keywords": ["diagnose", "prescription", "dosage", "symptoms"],
                "severity": "high",
                "description": "Block medical-advice requests",
            },
            {
                "name": "legal_advice",
                "keywords": ["lawsuit", "attorney", "court", "litigation"],
                "severity": "medium",
            },
        ],
        "min_keyword_hits": 2,
    })
    return d


class TestUnconfigured:
    def test_no_topics_means_no_detection(self):
        d = TopicEnforcementDetector()
        d.setup({})
        result = d.detect("I need medical advice about my symptoms and dosage")
        assert result.detected is False
        assert "No denied topics configured" in result.explanation


class TestDetection:
    def test_clean_input_passes(self, detector: TopicEnforcementDetector):
        result = detector.detect("How do I deploy a Docker container?")
        assert result.detected is False

    def test_empty_input_passes(self, detector: TopicEnforcementDetector):
        result = detector.detect("")
        assert result.detected is False

    def test_medical_topic_match(self, detector: TopicEnforcementDetector):
        text = "Can you diagnose this and tell me the dosage of my prescription?"
        result = detector.detect(text)
        assert result.detected is True
        assert result.metadata["topic"] == "medical_advice"
        assert result.severity == Severity.HIGH
        assert result.metadata["hit_count"] >= 2

    def test_legal_topic_match(self, detector: TopicEnforcementDetector):
        text = "I want to file a lawsuit against my employer in court for harassment"
        result = detector.detect(text)
        assert result.detected is True
        assert result.metadata["topic"] == "legal_advice"
        assert result.severity == Severity.MEDIUM

    def test_min_hits_required(self, detector: TopicEnforcementDetector):
        # Only one hit — below default threshold of 2
        result = detector.detect("Should I see a doctor about my symptoms?")
        assert result.detected is False

    def test_strongest_match_wins(self, detector: TopicEnforcementDetector):
        # Hits both topics, but medical has more matches
        text = (
            "I have symptoms and need a diagnose for my prescription dosage. "
            "Also maybe I'll get an attorney."
        )
        result = detector.detect(text)
        assert result.detected is True
        assert result.metadata["topic"] == "medical_advice"


class TestConfiguration:
    def test_case_sensitive_mode(self):
        d = TopicEnforcementDetector()
        d.setup({
            "denied_topics": [
                {"name": "brand", "keywords": ["FooBrand", "FooCorp"]}
            ],
            "min_keyword_hits": 1,
            "case_sensitive": True,
        })
        # lowercase shouldn't match in case-sensitive mode
        result_lower = d.detect("we use foobrand and foocorp internally")
        assert result_lower.detected is False
        result_proper = d.detect("we use FooBrand and FooCorp internally")
        assert result_proper.detected is True

    def test_min_hits_config(self):
        d = TopicEnforcementDetector()
        d.setup({
            "denied_topics": [
                {"name": "x", "keywords": ["alpha", "beta"]}
            ],
            "min_keyword_hits": 1,
        })
        result = d.detect("only alpha here, no beta")
        assert result.detected is True

    def test_invalid_topic_entries_are_skipped(self):
        d = TopicEnforcementDetector()
        d.setup({
            "denied_topics": [
                {"name": "good", "keywords": ["foo", "bar"]},
                {"name": "missing_keywords"},
                "not-a-dict",
                {"keywords": ["x"]},  # missing name
            ],
            "min_keyword_hits": 1,
        })
        assert len(d._topics) == 1
        assert d._topics[0].name == "good"


class TestMatchDetails:
    def test_match_positions_reported(self, detector: TopicEnforcementDetector):
        text = "diagnose this and check the dosage please"
        result = detector.detect(text)
        assert result.detected is True
        assert len(result.matches) >= 2
        # Positions should be valid
        for m in result.matches:
            start, end = m.position
            assert text[start:end] in {"diagnose", "dosage"}
