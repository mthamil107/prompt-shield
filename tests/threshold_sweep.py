"""Per-detector threshold sweep harness for prompt-shield tuning.

What this measures
------------------
For each detector that fires at all across our benchmark corpus, walks
through thresholds from 0.40 to 0.90 in 0.05 steps and reports:

- FP rate on the BENIGN set (must stay 0% to preserve our moat)
- Detection rate on the 54-attack realistic corpus (strong baseline,
  currently 96% F1 — must not regress)
- Detection rate on HarmBench contextual (weak baseline, currently 31% —
  the gap we're trying to close)

This is PURE MEASUREMENT. It does not modify any detector config or
write to the engine's state. Output drives Stage B (per-detector
threshold YAML edits) of the Path C threshold-tuning project.

Running
-------
    # Requires HarmBench CSV (one-time):
    curl -L -o data/harmbench_behaviors_text_all.csv \\
      https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/\\
data/behavior_datasets/harmbench_behaviors_text_all.csv

    python tests/threshold_sweep.py --csv-out docs/papers/evaluation/threshold_sweep.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
from collections import defaultdict
from pathlib import Path

# UTF-8 stdout on Windows so the per-attack examples don't crash printing
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

from prompt_shield import PromptShieldEngine

# Allow running both as `python tests/threshold_sweep.py` and `pytest tests/`
sys.path.insert(0, str(Path(__file__).parent))
from benchmark_realistic import ATTACKS, BENIGN

# Sweep thresholds — 0.40 to 0.90 in 0.05 steps + boundary values.
THRESHOLDS = [0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]


def load_harmbench_contextual(csv_path: Path) -> list[str]:
    """Return the 100 contextual HarmBench prompts (context_doc + behavior)."""
    if not csv_path.exists():
        return []
    prompts = []
    with csv_path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["FunctionalCategory"] != "contextual":
                continue
            ctx = (row.get("ContextString") or "").strip()
            beh = row["Behavior"].strip()
            prompts.append(f"{ctx}\n\n{beh}" if ctx else beh)
    return prompts


def load_notinject(cache_dir: Path | None = None) -> list[str]:
    """Load leolee99/NotInject (3 splits, ~339 total benign prompts).

    Downloads the parquet files directly from HuggingFace (avoiding the
    `datasets` library version-skew issue with `List` feature type in
    newer dataset uploads). Caches under ``data/notinject/`` for reruns.
    Returns empty list if download or parsing fails.
    """
    try:
        import pyarrow.parquet as pq
    except ImportError:
        return []

    import urllib.request

    cache = cache_dir or Path("data/notinject")
    cache.mkdir(parents=True, exist_ok=True)
    base = "https://huggingface.co/datasets/leolee99/NotInject/resolve/main/data"

    prompts: list[str] = []
    for split in ["NotInject_one", "NotInject_two", "NotInject_three"]:
        local = cache / f"{split}.parquet"
        if not local.exists():
            try:
                urllib.request.urlretrieve(f"{base}/{split}-00000-of-00001.parquet", local)
            except Exception:
                continue
        try:
            table = pq.read_table(local)
            for txt in table.column("prompt").to_pylist():
                if txt and txt.strip():
                    prompts.append(txt)
        except Exception:
            continue
    return prompts


def collect_confidences(prompts: list[str], engine: PromptShieldEngine) -> dict[str, list[float]]:
    """Run all prompts through the engine, return {detector_id: [confidences]}.

    A detector only appears in the dict for prompts where it actually fired.
    To enumerate per-prompt firings consistently, we record one entry per
    prompt — appending 0.0 when a detector didn't fire — so list indices
    line up with prompt indices.
    """
    per_det: dict[str, list[float]] = defaultdict(lambda: [0.0] * len(prompts))
    for idx, prompt in enumerate(prompts):
        report = engine.scan(prompt, context={"source": "threshold_sweep"})
        for det in report.detections:
            per_det[det.detector_id][idx] = float(det.confidence)
    return dict(per_det)


def sweep_rates(confidences: list[float], thresholds: list[float]) -> dict[float, float]:
    """For each threshold, return the fraction of inputs above it."""
    n = len(confidences) or 1
    return {t: sum(1 for c in confidences if c >= t) / n for t in thresholds}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--harmbench-csv",
        type=Path,
        default=Path("data/harmbench_behaviors_text_all.csv"),
        help="HarmBench CSV (used only for the contextual subset)",
    )
    p.add_argument(
        "--csv-out",
        type=Path,
        default=Path("docs/papers/evaluation/threshold_sweep.csv"),
        help="Where to write the machine-readable sweep result",
    )
    p.add_argument(
        "--ml",
        action="store_true",
        help="Enable d022_semantic_classifier (DeBERTa). Slower, GPU/CPU.",
    )
    args = p.parse_args()

    # Datasets
    attacks = [p for cat_prompts in ATTACKS.values() for p in cat_prompts]
    benign_local = list(BENIGN)
    print("Loading leolee99/NotInject from HuggingFace (~339 benign prompts)...")
    notinject = load_notinject()
    benign = benign_local + notinject
    hb_contextual = load_harmbench_contextual(args.harmbench_csv)

    print(f"Loaded {len(attacks)} attack prompts (54-corpus)")
    print(
        f"Loaded {len(benign)} benign prompts "
        f"({len(benign_local)} local + {len(notinject)} NotInject)"
    )
    print(f"Loaded {len(hb_contextual)} HarmBench contextual prompts")
    if not hb_contextual:
        print("  (HarmBench CSV missing — proceeding without it)")
    if not notinject:
        print("  (NotInject unavailable — FP signal is degraded; install `datasets`)")

    # Engine config — threshold=0.01 lets all detector signals through
    # so we can post-hoc sweep without re-running the engine 11 times.
    config_dict: dict[str, object] = {
        "threshold": 0.01,
        "vault": {"enabled": False},
        "feedback": {"enabled": False},
        "fatigue": {"enabled": False},
        "canary": {"enabled": False},
        "history": {"enabled": False},
    }
    if not args.ml:
        config_dict["detectors"] = {"d022_semantic_classifier": {"enabled": False}}

    engine = PromptShieldEngine(config_dict=config_dict)

    print("\nScanning attack corpus...")
    attack_conf = collect_confidences(attacks, engine)
    print(f"  Detectors that fired: {len(attack_conf)}")

    print("Scanning benign corpus...")
    benign_conf = collect_confidences(benign, engine)
    print(f"  Detectors that fired: {len(benign_conf)}")

    if hb_contextual:
        print("Scanning HarmBench contextual corpus...")
        hb_conf = collect_confidences(hb_contextual, engine)
        print(f"  Detectors that fired: {len(hb_conf)}")
    else:
        hb_conf = {}

    # Union of detectors that fired in any dataset
    all_detectors = sorted(set(attack_conf) | set(benign_conf) | set(hb_conf))

    # Per-detector sweep
    print("\n" + "=" * 100)
    print("Per-detector threshold sweep")
    print("=" * 100)

    rows: list[dict] = []

    for det_id in all_detectors:
        a = sweep_rates(attack_conf.get(det_id, [0.0] * len(attacks)), THRESHOLDS)
        b = sweep_rates(benign_conf.get(det_id, [0.0] * len(benign)), THRESHOLDS)
        h = (
            sweep_rates(hb_conf.get(det_id, [0.0] * len(hb_contextual)), THRESHOLDS)
            if hb_contextual
            else {t: 0.0 for t in THRESHOLDS}
        )

        # Skip detectors that never fire above 0.4 on any dataset — uninteresting
        if max(a.values()) == 0.0 and max(b.values()) == 0.0 and max(h.values()) == 0.0:
            continue

        print(f"\n{det_id}")
        if hb_contextual:
            print(f"  {'Threshold':<12} {'54-attack':>10} {'BENIGN(FP)':>12} {'HarmBench-ctx':>15}")
        else:
            print(f"  {'Threshold':<12} {'54-attack':>10} {'BENIGN(FP)':>12}")

        # Pick sweet spot: lowest threshold that keeps FP <= 0%
        sweet = None
        for t in THRESHOLDS:
            star = ""
            if b[t] == 0.0 and sweet is None:
                sweet = t
                star = "  <- max recall @ 0% FP"
            if hb_contextual:
                print(f"  {t:<12.2f} {a[t]:>9.1%} {b[t]:>11.1%} {h[t]:>14.1%}{star}")
            else:
                print(f"  {t:<12.2f} {a[t]:>9.1%} {b[t]:>11.1%}{star}")

            rows.append(
                {
                    "detector_id": det_id,
                    "threshold": t,
                    "attack_rate": a[t],
                    "benign_fp": b[t],
                    "harmbench_ctx_rate": h[t] if hb_contextual else None,
                    "sweet_spot": "*" if t == sweet else "",
                }
            )

    # Write CSV
    args.csv_out.parent.mkdir(parents=True, exist_ok=True)
    with args.csv_out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nWrote {args.csv_out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
