"""Tests for the MITRE ATLAS compliance mapping."""

from __future__ import annotations

from prompt_shield.compliance.mitre_atlas_mapping import (
    _VALID_ATLAS_IDS,
    ATLAS_TECHNIQUES,
    DETECTOR_ATLAS_MAP,
    AtlasReport,
    generate_atlas_report,
)
from tests.compliance.test_owasp_mapping import ALL_DETECTOR_IDS


class TestAtlasTechniquesStructure:
    """Validate the ATLAS technique list itself."""

    def test_at_least_5_techniques_defined(self) -> None:
        # We've curated 9 — never let the list silently shrink.
        assert len(ATLAS_TECHNIQUES) >= 5

    def test_technique_ids_are_unique(self) -> None:
        ids = [t.id for t in ATLAS_TECHNIQUES]
        assert len(ids) == len(set(ids))

    def test_technique_ids_follow_aml_format(self) -> None:
        for t in ATLAS_TECHNIQUES:
            assert t.id.startswith("AML.T"), f"{t.id} does not start with AML.T"

    def test_every_technique_has_url(self) -> None:
        for t in ATLAS_TECHNIQUES:
            assert t.url.startswith("https://atlas.mitre.org/"), (
                f"{t.id} URL {t.url!r} not under atlas.mitre.org"
            )


class TestDetectorAtlasMapValidity:
    """Every referenced ATLAS technique must be in the list."""

    def test_all_referenced_techniques_are_valid(self) -> None:
        for det_id, tech_ids in DETECTOR_ATLAS_MAP.items():
            for tid in tech_ids:
                assert tid in _VALID_ATLAS_IDS, (
                    f"Detector {det_id!r} references unknown ATLAS technique {tid!r}"
                )

    def test_no_empty_mapping_entries(self) -> None:
        for det_id, tech_ids in DETECTOR_ATLAS_MAP.items():
            assert len(tech_ids) >= 1, (
                f"Detector {det_id!r} has empty ATLAS mapping — "
                f"map to at least one technique or remove the entry"
            )


class TestDetectorCoverage:
    """Every registered detector must be mapped to at least one ATLAS technique."""

    def test_every_detector_has_atlas_mapping(self) -> None:
        for did in ALL_DETECTOR_IDS:
            assert did in DETECTOR_ATLAS_MAP, (
                f"{did} missing from DETECTOR_ATLAS_MAP — "
                f"every new detector must add a MITRE ATLAS mapping"
            )

    def test_no_unknown_detectors_in_map(self) -> None:
        # Non-detector feature keys allowed (canary_tokens, output_*_scanner, etc.)
        # but every key matching the dXXX_ pattern must be a real detector.
        for key in DETECTOR_ATLAS_MAP:
            if key.startswith("d0") and "_" in key:
                assert key in ALL_DETECTOR_IDS, (
                    f"Unknown detector-style key {key!r} in DETECTOR_ATLAS_MAP"
                )


class TestAtlasReport:
    """Coverage report generation."""

    def test_full_coverage_with_all_detectors(self) -> None:
        # Pass all detectors + feature keys to get the upper-bound coverage
        all_keys = list(DETECTOR_ATLAS_MAP.keys())
        report = generate_atlas_report(all_keys)
        assert isinstance(report, AtlasReport)
        assert report.framework == "MITRE ATLAS"
        assert report.total_techniques == len(ATLAS_TECHNIQUES)
        assert report.techniques_covered >= 1
        # With all features wired in, coverage should be high
        assert report.coverage_percentage >= 50.0, (
            f"Full coverage is only {report.coverage_percentage:.1f}% — "
            f"techniques without any detector pointing to them: "
            f"{[c.technique_id for c in report.coverage if not c.is_covered]}"
        )

    def test_empty_detectors_zero_coverage(self) -> None:
        report = generate_atlas_report([])
        assert report.techniques_covered == 0
        assert report.coverage_percentage == 0.0

    def test_single_detector_partial(self) -> None:
        report = generate_atlas_report(["d001_system_prompt_extraction"])
        assert report.techniques_covered >= 1
        assert report.techniques_covered < report.total_techniques

    def test_report_serialisable(self) -> None:
        report = generate_atlas_report(["d001_system_prompt_extraction"])
        # Pydantic model — must round-trip
        data = report.model_dump()
        assert data["framework"] == "MITRE ATLAS"
        assert isinstance(data["coverage"], list)


class TestPrimaryTechniqueCoverage:
    """The two highest-priority ATLAS techniques for an LLM firewall must
    have multiple detectors pointing at them."""

    def test_t0051_prompt_injection_has_multiple_detectors(self) -> None:
        # T0051 LLM Prompt Injection is our core threat model
        report = generate_atlas_report(list(DETECTOR_ATLAS_MAP.keys()))
        row = next(c for c in report.coverage if c.technique_id == "AML.T0051")
        assert len(row.detector_ids) >= 10, (
            f"T0051 only covered by {len(row.detector_ids)} detectors — "
            f"expected at least 10 (most detectors should contribute)"
        )

    def test_t0054_llm_jailbreak_has_coverage(self) -> None:
        report = generate_atlas_report(list(DETECTOR_ATLAS_MAP.keys()))
        row = next(c for c in report.coverage if c.technique_id == "AML.T0054")
        assert row.is_covered
        assert len(row.detector_ids) >= 3
