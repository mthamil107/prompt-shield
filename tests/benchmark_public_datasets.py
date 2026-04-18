"""Benchmark prompt-shield on public datasets for verifiable, reproducible results.

Datasets:
- deepset/prompt-injections (116 test samples: 60 injection + 56 benign)
- leolee99/NotInject (339 benign samples across 3 splits — false positive test)

Run: python tests/benchmark_public_datasets.py
"""

from __future__ import annotations

import sys
import time


def load_deepset() -> list[tuple[str, bool]]:
    """Load deepset/prompt-injections test split."""
    from datasets import load_dataset

    ds = load_dataset("deepset/prompt-injections", split="test")
    samples = []
    for row in ds:
        # label 1 = injection, 0 = benign
        samples.append((row["text"], row["label"] == 1))
    return samples


def load_notinject() -> list[tuple[str, bool]]:
    """Load leolee99/NotInject — all benign, tests false positive rate."""
    from datasets import load_dataset

    samples = []
    for split in ["NotInject_one", "NotInject_two", "NotInject_three"]:
        try:
            ds = load_dataset("leolee99/NotInject", split=split)
            for row in ds:
                text = row.get("prompt", row.get("text", ""))
                if text.strip():
                    samples.append((text, False))
        except Exception:
            continue
    return samples


def scan_prompt_shield(samples: list[tuple[str, bool]]) -> tuple[list[dict], float]:
    """Scan with prompt-shield (regex only, no ML for speed)."""
    from prompt_shield.engine import PromptShieldEngine

    engine = PromptShieldEngine(
        config_dict={
            "prompt_shield": {
                "mode": "block",
                "threshold": 0.7,
                "vault": {"enabled": False},
                "feedback": {"enabled": False},
                "canary": {"enabled": False},
                "history": {"enabled": False},
                "detectors": {"d022_semantic_classifier": {"enabled": False}},
            }
        }
    )

    results = []
    start = time.perf_counter()
    for text, is_attack in samples:
        report = engine.scan(text)
        detected = report.action.value in ("block", "flag") or report.overall_risk_score >= 0.5
        results.append(
            {
                "text": text[:80],
                "is_attack": is_attack,
                "detected": detected,
                "score": report.overall_risk_score,
            }
        )
    elapsed = time.perf_counter() - start
    return results, elapsed


def scan_with_model(
    samples: list[tuple[str, bool]], model_name: str, label_map: dict
) -> tuple[list[dict], float]:
    """Scan with a HuggingFace model."""
    try:
        from transformers import pipeline as hf_pipeline
    except ImportError:
        return [], 0

    kwargs = {"model": model_name, "truncation": True, "max_length": 512}
    if "PIGuard" in model_name:
        kwargs["trust_remote_code"] = True

    classifier = hf_pipeline("text-classification", **kwargs)

    results = []
    start = time.perf_counter()
    for text, is_attack in samples:
        try:
            out = classifier(text)[0]
            detected = out["label"] in label_map.get("positive", [])
            score = out["score"] if detected else 1.0 - out["score"]
        except Exception:
            detected = False
            score = 0.0
        results.append(
            {
                "text": text[:80],
                "is_attack": is_attack,
                "detected": detected,
                "score": score,
            }
        )
    elapsed = time.perf_counter() - start
    return results, elapsed


def compute_metrics(results: list[dict]) -> dict:
    """Compute TP, TN, FP, FN, precision, recall, F1, accuracy, FPR."""
    tp = fn = fp = tn = 0
    for r in results:
        if r["is_attack"] and r["detected"]:
            tp += 1
        elif r["is_attack"] and not r["detected"]:
            fn += 1
        elif not r["is_attack"] and r["detected"]:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "fpr": fpr,
    }


def print_results(name: str, metrics: dict, elapsed: float, total: int) -> None:
    """Print formatted results for one scanner."""
    speed = total / elapsed if elapsed > 0 else 0
    print(
        f"  {name:<30} {metrics['precision']:>6.1%} {metrics['recall']:>7.1%} "
        f"{metrics['f1']:>6.1%} {metrics['accuracy']:>6.1%} {metrics['fpr']:>6.1%} "
        f"{speed:>8.0f}/sec  TP:{metrics['tp']:>3} TN:{metrics['tn']:>3} FP:{metrics['fp']:>3} FN:{metrics['fn']:>3}"
    )


def main():
    print("=" * 100)
    print("PROMPT-SHIELD — PUBLIC DATASET BENCHMARK")
    print("=" * 100)
    print()

    # --- Dataset 1: deepset/prompt-injections ---
    print("Loading deepset/prompt-injections (test split)...")
    try:
        deepset_samples = load_deepset()
        n_attack = sum(1 for _, a in deepset_samples if a)
        n_benign = sum(1 for _, a in deepset_samples if not a)
        print(
            f"  Loaded: {len(deepset_samples)} samples ({n_attack} injection + {n_benign} benign)"
        )
    except Exception as e:
        print(f"  FAILED to load: {e}")
        deepset_samples = []

    # --- Dataset 2: NotInject (benign only, FP test) ---
    print("Loading leolee99/NotInject (all splits)...")
    try:
        notinject_samples = load_notinject()
        print(f"  Loaded: {len(notinject_samples)} benign samples (false positive test)")
    except Exception as e:
        print(f"  FAILED to load: {e}")
        notinject_samples = []

    scanners = [
        ("prompt-shield", lambda s: scan_prompt_shield(s)),
        (
            "ProtectAI DeBERTa v2",
            lambda s: scan_with_model(
                s,
                "protectai/deberta-v3-base-prompt-injection-v2",
                {"positive": ["INJECTION"]},
            ),
        ),
        (
            "PIGuard (ACL 2025)",
            lambda s: scan_with_model(
                s,
                "leolee99/PIGuard",
                {"positive": ["INJECTION", "MALICIOUS", "LABEL_1"]},
            ),
        ),
        (
            "Meta Prompt Guard 2",
            lambda s: scan_with_model(
                s,
                "meta-llama/Llama-Prompt-Guard-2-86M",
                {"positive": ["INJECTION", "JAILBREAK", "LABEL_1", "LABEL_2"]},
            ),
        ),
        (
            "Deepset DeBERTa v3",
            lambda s: scan_with_model(
                s,
                "deepset/deberta-v3-base-injection",
                {"positive": ["INJECTION", "LABEL_1"]},
            ),
        ),
    ]

    # --- Benchmark on deepset/prompt-injections ---
    if deepset_samples:
        print()
        print("=" * 100)
        print(f"DATASET: deepset/prompt-injections (test) — {len(deepset_samples)} samples")
        print("=" * 100)
        print()
        header = f"  {'Scanner':<30} {'Prec':>6} {'Recall':>7} {'F1':>6} {'Acc':>6} {'FPR':>6} {'Speed':>10}  {'Details'}"
        print(header)
        print("  " + "-" * 96)

        for name, scanner_fn in scanners:
            print(f"  Running: {name}...", file=sys.stderr, flush=True)
            try:
                results, elapsed = scanner_fn(deepset_samples)
                if not results:
                    print(f"  {name:<30} SKIPPED (not installed or access denied)")
                    continue
                metrics = compute_metrics(results)
                print_results(name, metrics, elapsed, len(deepset_samples))
            except Exception as e:
                print(f"  {name:<30} ERROR: {str(e)[:60]}")

    # --- False Positive test on NotInject ---
    if notinject_samples:
        print()
        print("=" * 100)
        print(
            f"DATASET: leolee99/NotInject — {len(notinject_samples)} benign samples (false positive test)"
        )
        print("=" * 100)
        print()
        print(f"  {'Scanner':<30} {'FP Count':>9} {'FP Rate':>8} {'Total':>6}")
        print("  " + "-" * 60)

        for name, scanner_fn in scanners:
            print(f"  Running: {name}...", file=sys.stderr, flush=True)
            try:
                results, elapsed = scanner_fn(notinject_samples)
                if not results:
                    print(f"  {name:<30} SKIPPED")
                    continue
                fp = sum(1 for r in results if r["detected"])
                fpr = fp / len(results) * 100 if results else 0
                print(f"  {name:<30} {fp:>9} {fpr:>7.1f}% {len(results):>6}")
            except Exception as e:
                print(f"  {name:<30} ERROR: {str(e)[:60]}")

    print()
    print("=" * 100)
    print("Both datasets are publicly available on HuggingFace. Reproduce:")
    print("  pip install prompt-shield-ai datasets transformers")
    print("  python tests/benchmark_public_datasets.py")
    print("=" * 100)


if __name__ == "__main__":
    main()
