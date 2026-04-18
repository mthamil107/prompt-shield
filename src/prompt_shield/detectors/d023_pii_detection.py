"""Detector for personally identifiable information (PII) in prompts."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity
from prompt_shield.pii.entity_types import DEFAULT_PII_PATTERNS, EntityType


class PIIDetectionDetector(BaseDetector):
    """Detects personally identifiable information in prompt text.

    Scans for emails, phone numbers, SSNs, credit card numbers,
    API keys/secrets, and IP addresses. Each entity type can be
    independently enabled/disabled via config.
    """

    detector_id: str = "d023_pii_detection"
    name: str = "PII Detection"
    description: str = (
        "Detects personally identifiable information such as emails, "
        "phone numbers, SSNs, credit cards, API keys, and IP addresses"
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["data_protection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.90

    def __init__(self) -> None:
        self._enabled_entities: set[str] = {e.value for e in EntityType}
        self._compiled_patterns: list[tuple[EntityType, regex.Pattern[str], str]] = []
        self._custom_patterns: list[tuple[str, str]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for enabled entity types."""
        self._compiled_patterns = []
        for entity_type, pattern_str, description in DEFAULT_PII_PATTERNS:
            if entity_type.value in self._enabled_entities:
                compiled = regex.compile(pattern_str, regex.IGNORECASE)
                self._compiled_patterns.append((entity_type, compiled, description))

    def setup(self, config: dict[str, object]) -> None:
        """Configure enabled entity types and custom patterns from YAML config."""
        entities_config = config.get("entities", {})
        if isinstance(entities_config, dict):
            for entity_name, enabled in entities_config.items():
                if enabled is False and entity_name in self._enabled_entities:
                    self._enabled_entities.discard(entity_name)
                elif enabled is True:
                    self._enabled_entities.add(entity_name)

        custom = config.get("custom_patterns", [])
        if isinstance(custom, list):
            self._custom_patterns = [
                (p.get("pattern", ""), p.get("description", "Custom PII pattern"))
                for p in custom
                if isinstance(p, dict) and p.get("pattern")
            ]

        self._compile_patterns()

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        matches: list[MatchDetail] = []
        entity_counts: dict[str, int] = {}

        for entity_type, compiled, description in self._compiled_patterns:
            for m in compiled.finditer(input_text):
                matches.append(
                    MatchDetail(
                        pattern=compiled.pattern,
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        description=f"[{entity_type.value}] {description}",
                    )
                )
                entity_counts[entity_type.value] = entity_counts.get(entity_type.value, 0) + 1

        # Custom patterns (no entity type prefix)
        for pattern_str, description in self._custom_patterns:
            try:
                compiled_custom = regex.compile(pattern_str, regex.IGNORECASE)
                for m in compiled_custom.finditer(input_text):
                    matches.append(
                        MatchDetail(
                            pattern=pattern_str,
                            matched_text=m.group(),
                            position=(m.start(), m.end()),
                            description=description,
                        )
                    )
            except regex.error:
                continue

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No PII detected",
            )

        confidence = min(1.0, self._base_confidence + 0.02 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=f"Detected {len(matches)} PII instance(s) across {len(entity_counts)} entity type(s)",
            metadata={"entity_counts": entity_counts},
        )
