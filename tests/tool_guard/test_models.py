"""Tests for the new v0.7.0 data models in ``prompt_shield.models``.

Covers ``ScanContext``, ``ToolProvenance``, ``ToolResultAttackFamily``
and the new ``ScanReport.scan_context`` field.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from prompt_shield.models import (
    Action,
    ScanContext,
    ScanReport,
    ToolProvenance,
    ToolResultAttackFamily,
)


class TestToolResultAttackFamily:
    def test_enum_values_are_stable_strings(self):
        assert ToolResultAttackFamily.IMPERATIVE_INJECTION.value == "imperative_injection"
        assert ToolResultAttackFamily.RENDERED_EXFIL.value == "rendered_exfil"
        assert ToolResultAttackFamily.UNCLASSIFIED.value == "unclassified"

    def test_no_duplicate_values(self):
        seen = set()
        for member in ToolResultAttackFamily:
            assert member.value not in seen, f"duplicate value: {member.value}"
            seen.add(member.value)
        assert len(seen) == len(list(ToolResultAttackFamily))


class TestToolProvenance:
    def test_all_fields_optional(self):
        p = ToolProvenance()
        assert p.tool_name is None
        assert p.tool_type is None
        assert p.source_url is None
        assert p.parent_scan_id is None

    def test_roundtrip(self):
        p = ToolProvenance(
            tool_name="web_search",
            tool_type="retrieval",
            source_url="https://example.com/doc",
            parent_scan_id="scan_abc",
        )
        dumped = p.model_dump()
        assert ToolProvenance(**dumped) == p


class TestScanContext:
    def test_confidence_bounds_enforced(self):
        with pytest.raises(ValueError):
            ScanContext(gate="tool_result", classifier_confidence=1.5)
        with pytest.raises(ValueError):
            ScanContext(gate="tool_result", classifier_confidence=-0.1)

    def test_defaults(self):
        ctx = ScanContext(gate="tool_result")
        assert ctx.provenance is None
        assert ctx.attack_families == []
        assert ctx.is_indirect is False
        assert ctx.classifier_confidence == 0.0
        assert ctx.mitigation == ""
        assert ctx.sanitized_text is None

    def test_carries_families(self):
        ctx = ScanContext(
            gate="tool_result",
            attack_families=[
                ToolResultAttackFamily.IMPERATIVE_INJECTION,
                ToolResultAttackFamily.EXFILTRATION_COMMAND,
            ],
            classifier_confidence=0.8,
            is_indirect=True,
        )
        assert len(ctx.attack_families) == 2
        assert ctx.classifier_confidence == 0.8
        assert ctx.is_indirect is True


class TestScanReportScanContextField:
    def _report(self, ctx: ScanContext | None = None) -> ScanReport:
        return ScanReport(
            scan_id="scan_test",
            input_text="hello",
            input_hash="h",
            timestamp=datetime.now(timezone.utc),
            overall_risk_score=0.0,
            action=Action.PASS,
            detections=[],
            total_detectors_run=0,
            scan_duration_ms=0.0,
            scan_context=ctx,
        )

    def test_defaults_to_none(self):
        r = self._report()
        assert r.scan_context is None

    def test_accepts_scan_context(self):
        ctx = ScanContext(gate="tool_result")
        r = self._report(ctx)
        assert r.scan_context is not None
        assert r.scan_context.gate == "tool_result"

    def test_serialises_and_deserialises(self):
        ctx = ScanContext(
            gate="tool_result",
            provenance=ToolProvenance(tool_name="x"),
            attack_families=[ToolResultAttackFamily.ROLE_HIJACK],
        )
        r = self._report(ctx)
        dumped = r.model_dump()
        r2 = ScanReport(**dumped)
        assert r2.scan_context is not None
        assert r2.scan_context.provenance is not None
        assert r2.scan_context.provenance.tool_name == "x"
        assert r2.scan_context.attack_families == [ToolResultAttackFamily.ROLE_HIJACK]
