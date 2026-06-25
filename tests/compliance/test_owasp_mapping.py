"""Tests for OWASP compliance mapping."""

from __future__ import annotations

import pytest

from prompt_shield.compliance.owasp_mapping import (
    _VALID_AGENTIC_IDS,
    _VALID_OWASP_IDS,
    DETECTOR_AGENTIC_MAP,
    DETECTOR_OWASP_MAP,
    EU_AI_ACT_ARTICLES,
    OWASP_AGENTIC_TOP_10,
    OWASP_LLM_TOP_10,
    PROMPT_SHIELD_EU_AI_ACT_COVERAGE,
    generate_agentic_compliance_report,
    generate_compliance_report,
    generate_eu_ai_act_report,
)


# Canonical detector ID list — discovered from the actual registry so the
# test catches drift if a detector is renamed or added without updating the
# compliance map. (The previous hardcoded list went stale for 2 releases.)
def _discover_detector_ids() -> list[str]:
    import importlib
    import pkgutil

    import prompt_shield.detectors as pkg

    ids: set[str] = set()
    for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
        if not modname.startswith("d0"):
            continue
        try:
            mod = importlib.import_module(f"prompt_shield.detectors.{modname}")
        except Exception:
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            det_id = getattr(obj, "detector_id", None)
            if isinstance(obj, type) and det_id and getattr(obj, "__module__", "") == mod.__name__:
                ids.add(det_id)
    return sorted(ids)


ALL_DETECTOR_IDS = _discover_detector_ids()

# Fake metadata matching the IDs
ALL_DETECTOR_METADATA = [
    {"detector_id": did, "name": did.replace("_", " ").title()} for did in ALL_DETECTOR_IDS
]


class TestDetectorMappingCompleteness:
    """Every registered detector must have a mapping entry — both ways."""

    def test_all_registered_detectors_are_mapped(self) -> None:
        for did in ALL_DETECTOR_IDS:
            assert did in DETECTOR_OWASP_MAP, (
                f"{did} missing from DETECTOR_OWASP_MAP — "
                f"every new detector must add an OWASP mapping"
            )

    def test_no_extra_detectors_in_map(self) -> None:
        for did in DETECTOR_OWASP_MAP:
            assert did in ALL_DETECTOR_IDS, (
                f"Unknown detector {did!r} in DETECTOR_OWASP_MAP — "
                f"either the detector was renamed/removed without updating the map, "
                f"or the map has a typo"
            )

    def test_at_least_33_detectors_discoverable(self) -> None:
        # Hard floor — if this fails, the discovery walk likely broke,
        # NOT a missing detector. Adjust upward when adding more.
        assert len(ALL_DETECTOR_IDS) >= 33, (
            f"Detector discovery walk only found {len(ALL_DETECTOR_IDS)} (expected >= 33). "
            f"Check tests/compliance/test_owasp_mapping.py::_discover_detector_ids"
        )


class TestOwaspIdValidity:
    """Every referenced OWASP ID must be in the Top 10 list."""

    def test_all_mapped_ids_are_valid(self) -> None:
        for did, cat_ids in DETECTOR_OWASP_MAP.items():
            for cid in cat_ids:
                assert cid in _VALID_OWASP_IDS, f"Detector {did} references invalid OWASP ID {cid}"

    def test_owasp_top_10_has_ten_entries(self) -> None:
        assert len(OWASP_LLM_TOP_10) == 10

    def test_owasp_ids_are_unique(self) -> None:
        ids = [cat.id for cat in OWASP_LLM_TOP_10]
        assert len(ids) == len(set(ids))


class TestComplianceReportFull:
    """Report generated with all 25 detectors."""

    @pytest.fixture
    def full_report(self):
        return generate_compliance_report(ALL_DETECTOR_IDS, ALL_DETECTOR_METADATA)

    def test_total_detectors(self, full_report) -> None:
        assert full_report.total_detectors == len(ALL_DETECTOR_IDS)

    def test_owasp_version(self, full_report) -> None:
        assert full_report.owasp_version == "2025"

    def test_category_details_count(self, full_report) -> None:
        assert len(full_report.category_details) == 10

    def test_covered_plus_not_covered_equals_ten(self, full_report) -> None:
        assert full_report.categories_covered + full_report.categories_not_covered == 10

    def test_coverage_percentage_range(self, full_report) -> None:
        assert 0.0 <= full_report.coverage_percentage <= 100.0

    def test_at_least_some_categories_covered(self, full_report) -> None:
        assert full_report.categories_covered >= 1

    def test_covered_categories_have_detectors(self, full_report) -> None:
        for cat in full_report.category_details:
            if cat.covered:
                assert len(cat.detector_ids) > 0
                assert len(cat.detector_names) > 0

    def test_uncovered_categories_have_no_detectors(self, full_report) -> None:
        for cat in full_report.category_details:
            if not cat.covered:
                assert len(cat.detector_ids) == 0


class TestComplianceReportPartial:
    """Report generated with a subset of detectors."""

    def test_partial_coverage(self) -> None:
        subset = ["d001_system_prompt_extraction", "d012_data_exfiltration"]
        meta = [{"detector_id": d, "name": d} for d in subset]
        report = generate_compliance_report(subset, meta)
        assert report.total_detectors == 2
        assert report.categories_covered < 10
        assert report.categories_not_covered > 0

    def test_empty_detectors(self) -> None:
        report = generate_compliance_report([], [])
        assert report.total_detectors == 0
        assert report.categories_covered == 0
        assert report.coverage_percentage == 0.0

    def test_single_detector(self) -> None:
        subset = ["d001_system_prompt_extraction"]
        meta = [{"detector_id": "d001_system_prompt_extraction", "name": "SPE"}]
        report = generate_compliance_report(subset, meta)
        assert report.total_detectors == 1
        # d001 maps to LLM01 (Prompt Injection) and LLM07 (System Prompt Leakage)
        covered_ids = [c.category_id for c in report.category_details if c.covered]
        assert "LLM01" in covered_ids
        assert "LLM07" in covered_ids


class TestCoveragePercentage:
    """Coverage percentage arithmetic."""

    def test_full_coverage_percentage(self) -> None:
        report = generate_compliance_report(ALL_DETECTOR_IDS, ALL_DETECTOR_METADATA)
        # With all detectors, we should cover most categories
        expected = round(report.categories_covered / 10 * 100, 1)
        assert report.coverage_percentage == expected

    def test_zero_coverage_percentage(self) -> None:
        report = generate_compliance_report([], [])
        assert report.coverage_percentage == 0.0


# ---------------------------------------------------------------------------
# OWASP Agentic Applications Top 10 (2026)
# ---------------------------------------------------------------------------


class TestAgenticTop10Structure:
    """Validate the OWASP Agentic Top 10 data structure."""

    def test_agentic_top_10_has_ten_entries(self) -> None:
        assert len(OWASP_AGENTIC_TOP_10) == 10

    def test_agentic_ids_are_unique(self) -> None:
        ids = [cat.id for cat in OWASP_AGENTIC_TOP_10]
        assert len(ids) == len(set(ids))

    def test_agentic_ids_start_with_asi(self) -> None:
        for cat in OWASP_AGENTIC_TOP_10:
            assert cat.id.startswith("ASI"), f"{cat.id} does not start with ASI"

    def test_all_agentic_mapped_ids_are_valid(self) -> None:
        for feat_id, cat_ids in DETECTOR_AGENTIC_MAP.items():
            for cid in cat_ids:
                assert cid in _VALID_AGENTIC_IDS, (
                    f"Feature {feat_id} references invalid Agentic ID {cid}"
                )


class TestAgenticComplianceReport:
    """Report generated from the agentic compliance mapping."""

    @pytest.fixture
    def full_agentic_report(self):
        return generate_agentic_compliance_report()

    def test_agentic_compliance_report(self, full_agentic_report) -> None:
        report = full_agentic_report
        assert report.owasp_version == "2026"
        assert report.framework == "owasp-agentic"
        assert len(report.category_details) == 10
        assert report.categories_covered + report.categories_not_covered == 10
        assert 0.0 <= report.coverage_percentage <= 100.0

    def test_agentic_most_categories_covered(self, full_agentic_report) -> None:
        # ASI03 (Identity & Privilege Abuse) is currently a known gap
        assert full_agentic_report.categories_covered >= 9
        assert full_agentic_report.coverage_percentage >= 90.0

    def test_agentic_partial_features(self) -> None:
        report = generate_agentic_compliance_report(feature_ids=["d001_system_prompt_extraction"])
        assert report.total_features == 1
        covered_ids = [c.category_id for c in report.category_details if c.covered]
        assert "ASI01" in covered_ids
        assert "ASI04" in covered_ids

    def test_agentic_empty_features(self) -> None:
        report = generate_agentic_compliance_report(feature_ids=[])
        assert report.total_features == 0
        assert report.categories_covered == 0
        assert report.coverage_percentage == 0.0


# ---------------------------------------------------------------------------
# EU AI Act
# ---------------------------------------------------------------------------


class TestEuAiActCoverage:
    """Validate EU AI Act mapping and report generation."""

    def test_eu_ai_act_coverage(self) -> None:
        report = generate_eu_ai_act_report()
        assert report.framework == "eu-ai-act"
        assert report.articles_total == len(EU_AI_ACT_ARTICLES)
        assert report.articles_covered == len(EU_AI_ACT_ARTICLES)  # all covered
        assert report.coverage_percentage == 100.0

    def test_eu_ai_act_articles_have_coverage_items(self) -> None:
        for article in EU_AI_ACT_ARTICLES:
            items = PROMPT_SHIELD_EU_AI_ACT_COVERAGE.get(article.id, [])
            assert len(items) > 0, f"{article.id} has no coverage items"

    def test_eu_ai_act_article_ids_are_unique(self) -> None:
        ids = [a.id for a in EU_AI_ACT_ARTICLES]
        assert len(ids) == len(set(ids))

    def test_eu_ai_act_report_details(self) -> None:
        report = generate_eu_ai_act_report()
        for detail in report.article_details:
            assert detail.covered is True
            assert len(detail.coverage_items) > 0
