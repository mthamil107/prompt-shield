"""Custom rules engine (d030).

Loads operator-defined regex rules from YAML files at engine init. Lets
deployments add private/internal patterns without modifying prompt-shield
itself. Rules are scanned in order and the highest-severity match wins.

YAML schema (one rule per list entry):

    rules:
      - id: my-org-internal-keyword
        pattern: '\\binternal-codename-X\\b'
        severity: high                  # critical | high | medium | low
        action: block                   # block | flag | log
        description: "Detect mention of internal-codename-X"
        case_sensitive: false           # optional, default false

      - id: data-class-exfil
        pattern: '\\b(SSN|PII|PHI)\\b'
        severity: critical
        action: block
        description: "Sensitive data class names"

The default rule directory is configured via ``rules_dir`` in the
per-detector config; falls back to no rules if the dir is empty or absent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal

import regex
import yaml

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
_SEVERITY_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}


@dataclass(frozen=True)
class CustomRule:
    """A single compiled custom rule."""

    id: str
    pattern: regex.Pattern
    severity: Severity
    action: Literal["block", "flag", "log"]
    description: str


class CustomRulesDetector(BaseDetector):
    """Operator-defined regex rules loaded from YAML at engine init."""

    detector_id: str = "d030_custom_rules"
    name: str = "Custom Rules"
    description: str = (
        "Operator-defined regex rules loaded from YAML files. Lets organizations "
        "add private/internal detection patterns without modifying prompt-shield."
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["custom", "rules", "operator-defined"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        self._rules: list[CustomRule] = []
        self._rules_dir: str | None = None

    def setup(self, config: dict[str, object]) -> None:
        rules_dir = config.get("rules_dir")
        if isinstance(rules_dir, str) and rules_dir:
            self._rules_dir = rules_dir
            self._rules = self._load_rules(rules_dir)
            logger.info(
                "d030_custom_rules: loaded %d rule(s) from %s",
                len(self._rules),
                rules_dir,
            )
        else:
            self._rules = []

    @staticmethod
    def _load_rules(rules_dir: str) -> list[CustomRule]:
        loaded: list[CustomRule] = []
        directory = Path(rules_dir)
        if not directory.exists() or not directory.is_dir():
            logger.warning("d030_custom_rules: rules_dir does not exist: %s", rules_dir)
            return loaded

        for fpath in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
            try:
                data = yaml.safe_load(fpath.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                logger.warning("d030_custom_rules: failed to parse %s: %s", fpath, exc)
                continue
            if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
                continue
            for entry in data["rules"]:
                rule = CustomRulesDetector._parse_rule(entry, source=str(fpath))
                if rule is not None:
                    loaded.append(rule)
        return loaded

    @staticmethod
    def _parse_rule(entry: object, *, source: str) -> CustomRule | None:
        if not isinstance(entry, dict):
            return None
        rule_id = entry.get("id")
        pattern_str = entry.get("pattern")
        severity_str = str(entry.get("severity", "medium")).lower()
        action = str(entry.get("action", "flag")).lower()
        description = str(entry.get("description", ""))
        case_sensitive = bool(entry.get("case_sensitive", False))

        if not isinstance(rule_id, str) or not isinstance(pattern_str, str):
            logger.warning(
                "d030_custom_rules: skipping malformed rule in %s (missing id or pattern)",
                source,
            )
            return None
        if action not in ("block", "flag", "log"):
            action = "flag"
        severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        flags = regex.UNICODE
        if not case_sensitive:
            flags |= regex.IGNORECASE
        try:
            compiled = regex.compile(pattern_str, flags)
        except regex.error as exc:
            logger.warning(
                "d030_custom_rules: rule %s in %s has invalid pattern: %s",
                rule_id,
                source,
                exc,
            )
            return None

        return CustomRule(
            id=rule_id,
            pattern=compiled,
            severity=severity,
            action=action,  # type: ignore[arg-type]
            description=description,
        )

    def detect(
        self,
        input_text: str,
        context: dict[str, object] | None = None,
    ) -> DetectionResult:
        if not self._rules or not input_text:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="no custom rules loaded" if not self._rules else "empty input",
            )

        # Find the highest-severity match across all rules; collect all matches.
        matches: list[MatchDetail] = []
        best_rule: CustomRule | None = None
        best_match: regex.Match | None = None
        best_rank = 0

        for rule in self._rules:
            for m in rule.pattern.finditer(input_text):
                matches.append(
                    MatchDetail(
                        pattern=rule.id,
                        matched_text=m.group(0),
                        position=(m.start(), m.end()),
                        description=rule.description or f"matched custom rule {rule.id}",
                    )
                )
                rank = _SEVERITY_RANK[rule.severity]
                if rank > best_rank:
                    best_rank = rank
                    best_rule = rule
                    best_match = m

        if best_rule is None or best_match is None:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="no custom rule matched",
            )

        confidence = (
            0.95 if best_rule.action == "block" else 0.75 if best_rule.action == "flag" else 0.5
        )

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=best_rule.severity,
            matches=matches[:5],  # Cap to keep results readable
            explanation=(
                f"Custom rule '{best_rule.id}' matched "
                f"({best_rule.severity.value}, action={best_rule.action})"
            ),
            metadata={
                "rule_id": best_rule.id,
                "rule_action": best_rule.action,
                "match_count": len(matches),
            },
        )
