"""Benchmark runner for prompt-shield accuracy evaluation."""

from __future__ import annotations

import time

import click

from prompt_shield import __version__
from prompt_shield.benchmarks.datasets import BenchmarkSample, load_dataset
from prompt_shield.benchmarks.metrics import BenchmarkResult, compute_metrics
from prompt_shield.exceptions import BenchmarkError


def run_benchmark(
    engine,  # type: ignore[no-untyped-def]  # PromptShieldEngine
    dataset_name: str | None = None,
    samples: list[BenchmarkSample] | None = None,
    data_dir: str | None = None,
    max_samples: int | None = None,
    quiet: bool = False,
) -> BenchmarkResult:
    """Run an accuracy benchmark against a dataset.

    Args:
        engine: A PromptShieldEngine instance.
        dataset_name: Name of a registered dataset to load (ignored if samples given).
        samples: Pre-loaded samples (takes priority over dataset_name).
        data_dir: Data directory for dataset caching.
        max_samples: Cap the number of samples evaluated.
        quiet: Suppress progress bar output (useful for JSON mode).

    Returns:
        BenchmarkResult with metrics, timing, and error details.

    Raises:
        BenchmarkError: If no samples can be loaded.
    """
    if samples is None:
        if dataset_name is None:
            raise BenchmarkError("Either dataset_name or samples must be provided")
        samples = load_dataset(dataset_name, data_dir=data_dir)

    if max_samples and max_samples < len(samples):
        samples = samples[:max_samples]

    if not samples:
        raise BenchmarkError("No samples to benchmark")

    predictions: list[bool] = []
    labels: list[bool] = []
    errors: list[str] = []

    def _scan_samples(iterable):
        for sample in iterable:
            labels.append(sample.is_injection)
            try:
                report = engine.scan(sample.text)
                predicted = report.action.value != "pass"
                predictions.append(predicted)
            except Exception as exc:
                errors.append(f"Error scanning sample: {exc}")
                predictions.append(False)

    start = time.perf_counter()
    if quiet:
        _scan_samples(samples)
    else:
        with click.progressbar(samples, label="  Benchmarking", show_pos=True) as bar:
            _scan_samples(bar)

    elapsed = time.perf_counter() - start
    metrics = compute_metrics(predictions, labels)

    return BenchmarkResult(
        dataset_name=dataset_name or "custom",
        total_samples=len(samples),
        metrics=metrics,
        duration_seconds=round(elapsed, 3),
        scans_per_second=round(len(samples) / elapsed, 1) if elapsed > 0 else 0.0,
        prompt_shield_version=__version__,
        error_count=len(errors),
        error_details=errors,
    )
