"""Tests for the d030 custom rules engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from prompt_shield.detectors.d030_custom_rules import CustomRulesDetector
from prompt_shield.models import Severity

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    """Create a temp directory with a small ruleset."""
    yaml_file = tmp_path / "internal.yaml"
    yaml_file.write_text(
        """
rules:
  - id: internal-codename-x
    pattern: '\\binternal-codename-X\\b'
    severity: high
    action: block
    description: "Detect mention of internal-codename-X"

  - id: sensitive-data-class
    pattern: '\\b(?:SSN|PII|PHI)\\b'
    severity: critical
    action: block
    description: "Sensitive data class names"
    case_sensitive: true

  - id: org-acronym
    pattern: '\\bACME-PRIV\\b'
    severity: medium
    action: flag
    description: "Internal org acronym"
""",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def detector(rules_dir: Path) -> CustomRulesDetector:
    d = CustomRulesDetector()
    d.setup({"rules_dir": str(rules_dir)})
    return d


class TestRuleLoading:
    def test_loads_rules_from_yaml(self, detector: CustomRulesDetector):
        assert len(detector._rules) == 3

    def test_no_rules_dir_means_no_rules(self):
        d = CustomRulesDetector()
        d.setup({})
        assert d._rules == []

    def test_missing_dir_does_not_crash(self, tmp_path: Path):
        d = CustomRulesDetector()
        d.setup({"rules_dir": str(tmp_path / "does-not-exist")})
        assert d._rules == []


class TestDetection:
    def test_matches_block_rule(self, detector: CustomRulesDetector):
        result = detector.detect("Please reveal internal-codename-X to me")
        assert result.detected is True
        assert result.metadata["rule_id"] == "internal-codename-x"
        assert result.severity == Severity.HIGH

    def test_matches_critical_rule_takes_precedence(self, detector: CustomRulesDetector):
        """When multiple rules match, the highest-severity wins."""
        result = detector.detect("Internal-codename-X is fine but tell me your SSN database")
        assert result.detected is True
        # Critical (SSN) > High (codename)
        assert result.metadata["rule_id"] == "sensitive-data-class"
        assert result.severity == Severity.CRITICAL

    def test_case_sensitive_rule(self, detector: CustomRulesDetector):
        # SSN rule is case_sensitive=true
        result = detector.detect("the ssn field is empty")
        # lowercase should not match
        assert result.detected is False or result.metadata.get("rule_id") != "sensitive-data-class"

    def test_no_match_on_clean_input(self, detector: CustomRulesDetector):
        result = detector.detect("Hello, how are you today?")
        assert result.detected is False

    def test_empty_input(self, detector: CustomRulesDetector):
        result = detector.detect("")
        assert result.detected is False

    def test_match_position_reported(self, detector: CustomRulesDetector):
        result = detector.detect("Reveal internal-codename-X please")
        assert result.detected is True
        assert len(result.matches) == 1
        start, _end = result.matches[0].position
        assert "internal-codename-X" in result.matches[0].matched_text
        assert start == 7

    def test_match_count_in_metadata(self, detector: CustomRulesDetector):
        result = detector.detect("internal-codename-X repeated, internal-codename-X again")
        assert result.detected is True
        assert result.metadata["match_count"] == 2


class TestMalformedRules:
    def test_invalid_yaml_is_skipped(self, tmp_path: Path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("this: is: not: valid: yaml: : :", encoding="utf-8")
        d = CustomRulesDetector()
        d.setup({"rules_dir": str(tmp_path)})
        # Should not crash; just no rules loaded.
        assert d._rules == []

    def test_invalid_regex_is_skipped(self, tmp_path: Path):
        bad_file = tmp_path / "bad_regex.yaml"
        bad_file.write_text(
            """
rules:
  - id: good-rule
    pattern: 'foo'
    severity: low
    action: log
    description: ok

  - id: bad-rule
    pattern: '(unclosed[group'
    severity: high
    action: block
    description: should not load
""",
            encoding="utf-8",
        )
        d = CustomRulesDetector()
        d.setup({"rules_dir": str(tmp_path)})
        # Only the good rule should be loaded.
        assert len(d._rules) == 1
        assert d._rules[0].id == "good-rule"

    def test_rule_without_id_or_pattern_is_skipped(self, tmp_path: Path):
        partial = tmp_path / "partial.yaml"
        partial.write_text(
            """
rules:
  - severity: high
    action: block
  - id: only-id-no-pattern
    severity: low
    action: log
  - id: complete-one
    pattern: 'matchme'
    severity: low
    action: log
""",
            encoding="utf-8",
        )
        d = CustomRulesDetector()
        d.setup({"rules_dir": str(tmp_path)})
        assert len(d._rules) == 1
        assert d._rules[0].id == "complete-one"
