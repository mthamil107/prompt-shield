"""ML metrics computation for prompt injection benchmarks."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BenchmarkMetrics(BaseModel):
    """Classification metrics for a benchmark run."""

    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = Field(default=0.0, ge=0.0, le=1.0)
    recall: float = Field(default=0.0, ge=0.0, le=1.0)
    f1_score: float = Field(default=0.0, ge=0.0, le=1.0)
    accuracy: float = Field(default=0.0, ge=0.0, le=1.0)
    true_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)


class BenchmarkResult(BaseModel):
    """Result of a full benchmark run."""

    dataset_name: str
    total_samples: int
    metrics: BenchmarkMetrics
    duration_seconds: float
    scans_per_second: float
    prompt_shield_version: str
    error_count: int = 0
    error_details: list[str] = []


def compute_metrics(
    predictions: list[bool],
    labels: list[bool],
) -> BenchmarkMetrics:
    """Compute classification metrics from predictions and ground-truth labels.

    Args:
        predictions: Model predictions (True = injection detected).
        labels: Ground-truth labels (True = is injection).

    Returns:
        BenchmarkMetrics with all fields populated.
    """
    if len(predictions) != len(labels):
        msg = f"predictions ({len(predictions)}) and labels ({len(labels)}) must have same length"
        raise ValueError(msg)

    tp = tn = fp = fn = 0
    for pred, label in zip(predictions, labels):
        if pred and label:
            tp += 1
        elif not pred and not label:
            tn += 1
        elif pred and not label:
            fp += 1
        else:
            fn += 1

    # Zero-division safe
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
    tpr = recall  # same as recall
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return BenchmarkMetrics(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        accuracy=round(accuracy, 4),
        true_positive_rate=round(tpr, 4),
        false_positive_rate=round(fpr, 4),
    )
