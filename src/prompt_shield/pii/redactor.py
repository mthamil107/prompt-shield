"""Standalone PII redactor with entity-type-aware placeholders."""

from __future__ import annotations

from typing import Any

import regex

from prompt_shield.models import RedactionResult
from prompt_shield.pii.entity_types import (
    DEFAULT_PII_PATTERNS,
    DEFAULT_REPLACEMENTS,
    EntityType,
)


class PIIRedactor:
    """Detects and redacts PII from text with entity-type-aware placeholders.

    Can be used standalone (without AgentGuard) or integrated into the
    sanitization pipeline.
    """

    def __init__(
        self,
        replacements: dict[EntityType, str] | None = None,
        enabled_entities: set[EntityType] | None = None,
    ) -> None:
        self._replacements = replacements or dict(DEFAULT_REPLACEMENTS)
        self._enabled_entities = enabled_entities or set(EntityType)
        self._compiled_patterns: list[tuple[EntityType, regex.Pattern[str], str]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        self._compiled_patterns = []
        for entity_type, pattern_str, description in DEFAULT_PII_PATTERNS:
            if entity_type in self._enabled_entities:
                compiled = regex.compile(pattern_str, regex.IGNORECASE)
                self._compiled_patterns.append((entity_type, compiled, description))

    def redact(self, text: str) -> RedactionResult:
        """Detect and redact all PII from the given text.

        Returns a RedactionResult with the redacted text, counts, and entity details.
        """
        # Collect all matches: (start, end, entity_type, matched_text)
        raw_matches: list[tuple[int, int, EntityType, str]] = []

        for entity_type, compiled, _description in self._compiled_patterns:
            for m in compiled.finditer(text):
                raw_matches.append((m.start(), m.end(), entity_type, m.group()))

        if not raw_matches:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                redaction_count=0,
                entity_counts={},
                redacted_entities=[],
            )

        # Deduplicate overlapping matches: keep the longest match at each position
        raw_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        deduped: list[tuple[int, int, EntityType, str]] = []
        for match in raw_matches:
            if deduped and match[0] < deduped[-1][1]:
                # Overlapping — skip shorter match
                continue
            deduped.append(match)

        # Replace in reverse order to preserve positions
        entity_counts: dict[str, int] = {}
        redacted_entities: list[dict[str, str]] = []
        result = text

        for start, end, entity_type, matched_text in reversed(deduped):
            replacement = self._replacements.get(
                entity_type, f"[{entity_type.value.upper()}_REDACTED]"
            )
            result = result[:start] + replacement + result[end:]
            entity_counts[entity_type.value] = entity_counts.get(entity_type.value, 0) + 1
            redacted_entities.append({"entity_type": entity_type.value, "original": matched_text})

        redacted_entities.reverse()

        return RedactionResult(
            original_text=text,
            redacted_text=result,
            redaction_count=len(deduped),
            entity_counts=entity_counts,
            redacted_entities=redacted_entities,
        )

    def redact_with_detections(self, text: str, matches: list[dict[str, Any]]) -> str:
        """Redact text using pre-existing detection matches from d023.

        Each match dict should have 'description' with '[entity_type] ...' prefix
        and 'position' as (start, end) tuple.
        """
        # Parse entity types from descriptions and collect positions
        replacements: list[tuple[int, int, str]] = []

        for match in matches:
            position = match.get("position")
            if not position:
                continue

            start, end = position
            description = match.get("description", "")

            # Parse [entity_type] prefix
            replacement = self._replacements.get(EntityType.EMAIL, "[PII_REDACTED]")  # fallback
            if description.startswith("["):
                closing = description.find("]")
                if closing > 0:
                    entity_str = description[1:closing]
                    try:
                        entity_type = EntityType(entity_str)
                        replacement = self._replacements.get(
                            entity_type, f"[{entity_str.upper()}_REDACTED]"
                        )
                    except ValueError:
                        replacement = f"[{entity_str.upper()}_REDACTED]"

            replacements.append((start, end, replacement))

        if not replacements:
            return text

        # Sort by position descending for safe replacement
        replacements.sort(key=lambda x: x[0], reverse=True)

        # Deduplicate overlapping
        deduped: list[tuple[int, int, str]] = []
        for r in replacements:
            if deduped and r[1] > deduped[-1][0]:
                continue
            deduped.append(r)

        result = text
        for start, end, replacement in deduped:
            result = result[:start] + replacement + result[end:]

        return result
