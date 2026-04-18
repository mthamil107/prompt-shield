"""Output scanner that validates LLM structured outputs against JSON schemas."""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from prompt_shield.models import MatchDetail
from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult


def _extract_json(text: str) -> tuple[Any, int, int] | None:
    """Try to extract a JSON object or array from *text*.

    Returns ``(parsed, start, end)`` on success, or ``None`` when no
    valid JSON is found.
    """
    # Try parsing the entire text first.
    stripped = text.strip()
    try:
        return json.loads(stripped), 0, len(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Look for the first ``{`` or ``[`` and try to parse from there.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        # Walk backwards from the end to find the matching closer.
        end = text.rfind(closer)
        if end == -1 or end <= start:
            continue
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate), start, end + 1
        except (json.JSONDecodeError, ValueError):
            continue

    return None


def _validate_schema(
    data: Any,
    schema: dict[str, Any],
    path: str = "$",
) -> list[str]:
    """Minimal JSON-Schema-style validator (supports ``type``, ``properties``,
    ``required``, ``additionalProperties``, ``items``, and ``enum``).

    Returns a list of human-readable violation descriptions.
    """
    violations: list[str] = []

    # --- type check ---
    expected_type = schema.get("type")
    if expected_type is not None:
        type_map: dict[str, tuple[type, ...]] = {
            "object": (dict,),
            "array": (list,),
            "string": (str,),
            "number": (int, float),
            "integer": (int,),
            "boolean": (bool,),
            "null": (type(None),),
        }
        allowed = type_map.get(expected_type, ())
        if allowed and not isinstance(data, allowed):
            actual = type(data).__name__
            violations.append(f"{path}: expected type '{expected_type}', got '{actual}'")
            return violations  # no point drilling further on wrong type

    # --- enum ---
    if "enum" in schema and data not in schema["enum"]:
        violations.append(f"{path}: value {data!r} not in enum {schema['enum']}")

    # --- object-level checks ---
    if isinstance(data, dict):
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        for req_key in required:
            if req_key not in data:
                violations.append(f"{path}: missing required property '{req_key}'")

        additional = schema.get("additionalProperties", True)
        for key in data:
            child_path = f"{path}.{key}"
            if key in properties:
                violations.extend(_validate_schema(data[key], properties[key], child_path))
            elif additional is False:
                violations.append(f"{path}: unexpected additional property '{key}'")

    # --- array-level checks ---
    if isinstance(data, list) and "items" in schema:
        for idx, item in enumerate(data):
            violations.extend(_validate_schema(item, schema["items"], f"{path}[{idx}]"))

    return violations


class SchemaValidationScanner(BaseOutputScanner):
    """Validates that LLM structured outputs (JSON) conform to expected schemas.

    The scanner detects:

    * Invalid JSON in outputs that are expected to be structured.
    * Schema violations when an ``expected_schema`` is provided via *context*.
    * Suspicious field names that may indicate prompt leakage or prototype
      pollution (e.g. ``"system_prompt"``, ``"__proto__"``).
    * Injection patterns hiding inside JSON string values.

    Parameters
    ----------
    schema:
        Optional default JSON schema (subset of JSON Schema) to validate
        against.  Can be overridden per-call via ``context["expected_schema"]``.
    """

    scanner_id: str = "output_schema_validation"
    name: str = "Schema Validation"
    description: str = (
        "Validates LLM structured JSON outputs against schemas and detects "
        "suspicious fields or injection in values"
    )

    SUSPICIOUS_FIELDS: ClassVar[set[str]] = {
        "system_prompt",
        "instructions",
        "api_key",
        "password",
        "secret",
        "__proto__",
        "constructor",
    }

    _INJECTION_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (
            r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions",
            "Instruction override attempt",
        ),
        (
            r"disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)",
            "Instruction disregard attempt",
        ),
        (
            r"you\s+are\s+now\s+(?:a\s+)?(?:new|different)",
            "Role hijack attempt",
        ),
        (
            r"system\s*:\s*you\s+are",
            "Embedded system prompt",
        ),
        (
            r"<\|(?:im_start|system|endoftext)\|>",
            "Special token injection",
        ),
        (
            r"act\s+as\s+(?:if|though)?\s*(?:you\s+(?:are|were))?",
            "Role manipulation",
        ),
    ]

    def __init__(self, schema: dict[str, Any] | None = None) -> None:
        self._default_schema = schema
        self._compiled_injection = [
            (re.compile(pat, re.IGNORECASE), desc) for pat, desc in self._INJECTION_PATTERNS
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, output_text: str, context: dict[str, object] | None = None) -> OutputScanResult:
        matches: list[MatchDetail] = []
        categories: set[str] = set()

        # 1. Try to extract JSON ------------------------------------------------
        extraction = _extract_json(output_text)
        if extraction is None:
            # Only flag if the text *looks like* it was meant to be JSON.
            if _looks_like_json(output_text):
                categories.add("invalid_json")
                matches.append(
                    MatchDetail(
                        pattern="json_parse",
                        matched_text=output_text[:80],
                        description="Output appears to be malformed JSON",
                    )
                )
                return self._build_result(matches, categories)
            # Not JSON at all -- nothing to validate.
            return self._pass()

        parsed, _json_start, _json_end = extraction

        # 2. Schema validation ---------------------------------------------------
        schema = (context or {}).get("expected_schema") or self._default_schema
        if schema is not None and isinstance(schema, dict):
            violations = _validate_schema(parsed, schema)
            for v in violations:
                categories.add("schema_violation")
                matches.append(
                    MatchDetail(
                        pattern="schema_validation",
                        matched_text=v[:120],
                        description=v,
                    )
                )

        # 3. Suspicious field names ----------------------------------------------
        suspicious_found = self._check_suspicious_fields(parsed, matches)
        if suspicious_found:
            categories.add("suspicious_fields")

        # 4. Injection patterns inside string values -----------------------------
        injection_found = self._check_injection_in_values(parsed, matches)
        if injection_found:
            categories.add("injection_in_values")

        if matches:
            return self._build_result(matches, categories)
        return self._pass()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_suspicious_fields(
        self,
        data: Any,
        matches: list[MatchDetail],
        path: str = "$",
    ) -> bool:
        found = False
        if isinstance(data, dict):
            for key, value in data.items():
                normalised = key.lower().strip()
                if normalised in self.SUSPICIOUS_FIELDS:
                    found = True
                    matches.append(
                        MatchDetail(
                            pattern="suspicious_field",
                            matched_text=key,
                            description=f"Suspicious field '{key}' at {path}.{key}",
                        )
                    )
                found |= self._check_suspicious_fields(value, matches, f"{path}.{key}")
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                found |= self._check_suspicious_fields(item, matches, f"{path}[{idx}]")
        return found

    def _check_injection_in_values(
        self,
        data: Any,
        matches: list[MatchDetail],
        path: str = "$",
    ) -> bool:
        found = False
        if isinstance(data, dict):
            for key, value in data.items():
                found |= self._check_injection_in_values(value, matches, f"{path}.{key}")
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                found |= self._check_injection_in_values(item, matches, f"{path}[{idx}]")
        elif isinstance(data, str):
            for compiled, description in self._compiled_injection:
                m = compiled.search(data)
                if m:
                    found = True
                    preview = m.group()[:60]
                    matches.append(
                        MatchDetail(
                            pattern=compiled.pattern,
                            matched_text=preview,
                            position=(m.start(), m.end()),
                            description=f"{description} in value at {path}",
                        )
                    )
        return found

    def _pass(self) -> OutputScanResult:
        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=False,
            confidence=0.0,
            explanation="Output passed schema validation checks",
        )

    def _build_result(
        self,
        matches: list[MatchDetail],
        categories: set[str],
    ) -> OutputScanResult:
        sorted_cats = sorted(categories)
        # Confidence increases with the number of distinct issue categories.
        base = 0.75
        confidence = min(1.0, base + 0.08 * (len(sorted_cats) - 1))
        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=True,
            confidence=confidence,
            categories=sorted_cats,
            matches=matches,
            explanation=(
                f"Schema validation found {len(matches)} issue(s) across "
                f"categories: {', '.join(sorted_cats)}"
            ),
        )


def _looks_like_json(text: str) -> bool:
    """Heuristic: does the text appear to be an attempt at JSON?"""
    stripped = text.strip()
    if stripped.startswith(("{", "[", '"')):
        return True
    # Markdown-style JSON fences
    return "```json" in stripped or "```JSON" in stripped
