"""Tests for the OutputScanEngine aggregator."""

from __future__ import annotations

import pytest

from prompt_shield.output_scanners import (
    OutputScanEngine,
    OutputScanReport,
    available_scanners,
)


@pytest.fixture()
def engine() -> OutputScanEngine:
    return OutputScanEngine()


def test_available_scanners_lists_nine() -> None:
    catalog = available_scanners()
    assert len(catalog) == 9
    names = {entry["name"] for entry in catalog}
    assert names == {
        "toxicity",
        "code_injection",
        "prompt_leakage",
        "pii",
        "schema_validation",
        "bias_fairness",
        "sentiment",
        "hallucination",
        "relevance",
    }


def test_scan_all_scanners_run(engine: OutputScanEngine) -> None:
    """When no subset is passed, every bundled scanner runs."""
    report = engine.scan("Hello, this is a completely benign sentence.")

    assert isinstance(report, OutputScanReport)
    assert report.total_scanners_run == 9
    assert len(report.flags) == 9
    # Every registered scanner should produce a result.
    seen = {f.scanner_id for f in report.flags}
    assert len(seen) == 9


def test_scan_subset_scanners(engine: OutputScanEngine) -> None:
    """Only the named scanners run when a subset is supplied."""
    report = engine.scan("hello world", scanners=["toxicity", "pii"])
    assert report.total_scanners_run == 2
    scanner_ids = {f.scanner_id for f in report.flags}
    # PII scanner reports "output_pii"; toxicity reports "toxicity".
    assert scanner_ids == {"toxicity", "output_pii"}


def test_scan_subset_accepts_scanner_id(engine: OutputScanEngine) -> None:
    """Users can pass the full scanner_id as well as the short name."""
    report = engine.scan("hello world", scanners=["output_pii"])
    assert report.total_scanners_run == 1
    assert report.flags[0].scanner_id == "output_pii"


def test_scan_unknown_scanner_is_skipped(engine: OutputScanEngine) -> None:
    """Unknown scanner names are ignored, not fatal."""
    report = engine.scan("hello world", scanners=["toxicity", "does_not_exist"])
    assert report.total_scanners_run == 1
    assert report.flags[0].scanner_id == "toxicity"


def test_flagged_when_any_detects(engine: OutputScanEngine) -> None:
    """Aggregate flag is True whenever at least one scanner detects."""
    text = "You should kill yourself, nobody cares."
    report = engine.scan(text, scanners=["toxicity"])
    assert report.flagged is True
    assert report.overall_risk_score > 0.0
    # And the same holds under the "run everything" path.
    full = engine.scan(text)
    assert full.flagged is True


def test_flagged_false_on_benign_input(engine: OutputScanEngine) -> None:
    """Benign, plain-English output should not trigger any scanner."""
    text = "The capital of France is Paris."
    report = engine.scan(text)
    assert report.flagged is False
    assert report.overall_risk_score == 0.0
    # Every individual flag should also be clean.
    assert all(not f.flagged for f in report.flags)


def test_report_exposes_text_and_results_aliases(engine: OutputScanEngine) -> None:
    """The convenience `text` and `results` accessors mirror ScanReport."""
    report = engine.scan("Hello world.", scanners=["toxicity"])
    assert report.text == "Hello world."
    assert isinstance(report.results, list)
    assert report.results[0]["detector_id"] == "toxicity"
    assert "detected" in report.results[0]
    assert "confidence" in report.results[0]
    assert "explanation" in report.results[0]


def test_config_forwarded_to_scanner_setup() -> None:
    """Per-scanner config passes through to setup()."""
    # Bias scanner honours a threshold — set it very high so nothing flags.
    engine = OutputScanEngine(config={"bias_fairness": {"threshold": 100}})
    result = engine.scan(
        "All women are bad at math and all immigrants are lazy.",
        scanners=["bias_fairness"],
    )
    assert result.flagged is False
