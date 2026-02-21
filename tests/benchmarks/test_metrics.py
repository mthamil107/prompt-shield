"""Tests for benchmark metrics computation."""

from __future__ import annotations

import pytest

from prompt_shield.benchmarks.metrics import BenchmarkMetrics, compute_metrics


class TestComputeMetricsPerfect:
    """Perfect classification — no errors."""

    def test_perfect_classification(self) -> None:
        preds = [True, True, False, False]
        labels = [True, True, False, False]
        m = compute_metrics(preds, labels)
        assert m.true_positives == 2
        assert m.true_negatives == 2
        assert m.false_positives == 0
        assert m.false_negatives == 0
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1_score == 1.0
        assert m.accuracy == 1.0

    def test_true_positive_rate_perfect(self) -> None:
        m = compute_metrics([True, True], [True, True])
        assert m.true_positive_rate == 1.0

    def test_false_positive_rate_perfect(self) -> None:
        m = compute_metrics([False, False], [False, False])
        assert m.false_positive_rate == 0.0


class TestComputeMetricsAllFP:
    """All predictions are false positives."""

    def test_all_false_positives(self) -> None:
        preds = [True, True, True]
        labels = [False, False, False]
        m = compute_metrics(preds, labels)
        assert m.false_positives == 3
        assert m.true_positives == 0
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1_score == 0.0
        assert m.false_positive_rate == 1.0


class TestComputeMetricsAllFN:
    """All predictions are false negatives."""

    def test_all_false_negatives(self) -> None:
        preds = [False, False, False]
        labels = [True, True, True]
        m = compute_metrics(preds, labels)
        assert m.false_negatives == 3
        assert m.true_positives == 0
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1_score == 0.0
        assert m.true_positive_rate == 0.0


class TestComputeMetricsMixed:
    """Mixed classification results."""

    def test_mixed_results(self) -> None:
        # 2 TP, 1 TN, 1 FP, 1 FN
        preds = [True, True, False, True, False]
        labels = [True, True, False, False, True]
        m = compute_metrics(preds, labels)
        assert m.true_positives == 2
        assert m.true_negatives == 1
        assert m.false_positives == 1
        assert m.false_negatives == 1
        # precision = 2/(2+1) = 0.6667
        assert abs(m.precision - 0.6667) < 0.001
        # recall = 2/(2+1) = 0.6667
        assert abs(m.recall - 0.6667) < 0.001
        # accuracy = 3/5 = 0.6
        assert m.accuracy == 0.6


class TestComputeMetricsEmpty:
    """Empty input handling."""

    def test_empty_inputs(self) -> None:
        m = compute_metrics([], [])
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1_score == 0.0
        assert m.accuracy == 0.0
        assert m.true_positive_rate == 0.0
        assert m.false_positive_rate == 0.0


class TestComputeMetricsZeroDivision:
    """Edge cases that could cause zero-division errors."""

    def test_no_positives_in_labels(self) -> None:
        preds = [False, False]
        labels = [False, False]
        m = compute_metrics(preds, labels)
        assert m.recall == 0.0  # No actual positives
        assert m.true_positive_rate == 0.0

    def test_no_negatives_in_labels(self) -> None:
        preds = [True, True]
        labels = [True, True]
        m = compute_metrics(preds, labels)
        assert m.false_positive_rate == 0.0  # No actual negatives

    def test_single_sample_tp(self) -> None:
        m = compute_metrics([True], [True])
        assert m.precision == 1.0
        assert m.recall == 1.0

    def test_single_sample_fp(self) -> None:
        m = compute_metrics([True], [False])
        assert m.precision == 0.0
        assert m.false_positive_rate == 1.0


class TestComputeMetricsValidation:
    """Input validation."""

    def test_mismatched_lengths_raises(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            compute_metrics([True, False], [True])


class TestBenchmarkMetricsModel:
    """BenchmarkMetrics pydantic model."""

    def test_default_values(self) -> None:
        m = BenchmarkMetrics()
        assert m.true_positives == 0
        assert m.precision == 0.0
