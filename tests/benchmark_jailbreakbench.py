"""Evaluate prompt-shield against JailbreakBench (Chao et al., NeurIPS 2024).

References
----------
- Chao et al. "JailbreakBench: An Open Robustness Benchmark for Jailbreaking
  Large Language Models." NeurIPS 2024 Datasets and Benchmarks Track.
  arXiv:2404.01318. https://arxiv.org/abs/2404.01318
- Repo: https://github.com/JailbreakBench/jailbreakbench
- Canonical dataset: https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors
  (config="behaviors", splits "harmful" and "benign")

Scope framing (read before interpreting the numbers)
----------------------------------------------------
JailbreakBench is a **jailbreak (harmful-behavior) benchmark**, not a
**prompt-injection** benchmark. Scoring 100 harmful vs 100 benign behaviors
measures a defender's coverage on adversarial *goals* the LLM should refuse
to fulfil (make a bomb, write malware, produce defamation); it does not
measure detection of *instruction-injection* attacks that hijack the
control flow ("ignore previous instructions").

prompt-shield is not primarily a content-safety classifier — its detectors
target injection shapes (role hijack, override phrasing, delimiter abuse,
data exfiltration, stylometric discontinuity, sequence-alignment against
attack corpora, etc.). Low scores on JBB-harmful are therefore *expected*
and do not indicate a defect in the injection-detection pipeline.

This runner reports both:

- **Detection rate on harmful (recall)** — how often the engine flags a
  known-harmful goal. A jailbreak *defender* is expected to be high here;
  an injection defender is expected to be low-to-moderate, because a bare
  harmful request contains no injection shape.
- **False-positive rate on benign** — how often the engine flags a benign
  goal from the same category taxonomy. This is the *safety* number: it
  must stay low regardless of the recall number, or the tool is unusable.

Reporting recall without FPR on a symmetric-by-construction benchmark like
JBB is exactly the misleading table `docs/papers/evaluation/competitor_rerun.md`
warns against; both columns are always shown here.

Running
-------
    # First fetch the dataset (one-time, ~45 KB):
    python tests/benchmark_jailbreakbench.py --fetch

    # Then evaluate (default: DeBERTa classifier d022 disabled for
    # reproducibility on CPU):
    python tests/benchmark_jailbreakbench.py

    # Or with the ML classifier enabled:
    python tests/benchmark_jailbreakbench.py --ml

    # Machine-readable JSON:
    python tests/benchmark_jailbreakbench.py \\
      --json-out docs/papers/evaluation/jailbreakbench.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

from prompt_shield import PromptShieldEngine
from prompt_shield.models import Action

_HF_ROWS_URL = (
    "https://datasets-server.huggingface.co/rows?"
    "dataset=JailbreakBench/JBB-Behaviors&config=behaviors&split={split}&"
    "offset=0&length=100"
)


def fetch_dataset(dest: Path) -> None:
    """Download harmful+benign splits from the HF datasets-server and write a
    single CSV with a Split column. Uses stdlib only, no `datasets` dep."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    all_rows: list[dict] = []
    for split in ("harmful", "benign"):
        url = _HF_ROWS_URL.format(split=split)
        req = urllib.request.Request(url, headers={"User-Agent": "prompt-shield"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError) as exc:
            sys.exit(f"Failed to fetch JBB {split} split: {exc}")
        for entry in data.get("rows", []):
            r = entry.get("row", {})
            all_rows.append(
                {
                    "Split": split,
                    "Index": r.get("Index", ""),
                    "Goal": r.get("Goal", ""),
                    "Behavior": r.get("Behavior", ""),
                    "Category": r.get("Category", ""),
                    "Source": r.get("Source", ""),
                }
            )
    with dest.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["Split", "Index", "Goal", "Behavior", "Category", "Source"]
        )
        w.writeheader()
        w.writerows(all_rows)
    print(f"Fetched {len(all_rows)} JBB behaviors to {dest}")


def load_behaviors(csv_path: Path) -> list[dict]:
    with csv_path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("data/jailbreakbench_behaviors.csv"),
        help="Path to the JailbreakBench behaviors CSV",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Fetch the dataset from HuggingFace and exit",
    )
    parser.add_argument(
        "--ml",
        action="store_true",
        help="Enable the DeBERTa semantic classifier (d022). Slower; needs GPU/CPU.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write a machine-readable JSON summary",
    )
    args = parser.parse_args()

    if args.fetch:
        fetch_dataset(args.csv)
        return

    if not args.csv.exists():
        sys.exit(
            f"JailbreakBench CSV not found at {args.csv}. Fetch with:\n"
            "  python tests/benchmark_jailbreakbench.py --fetch"
        )

    rows = load_behaviors(args.csv)
    print(f"Loaded {len(rows)} JailbreakBench behaviors from {args.csv}")
    split_counts = Counter(r["Split"] for r in rows)
    print(f"  Splits: {dict(split_counts)}")

    config_dict: dict[str, object] = {}
    if not args.ml:
        config_dict["detectors"] = {"d022_semantic_classifier": {"enabled": False}}
    engine = PromptShieldEngine(config_dict=config_dict or None)

    by_split_cat: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"total": 0, "detected": 0, "blocked": 0, "flagged": 0}
    )
    per_detector: Counter = Counter()
    harmful_missed: list[str] = []
    benign_flagged: list[dict] = []

    for row in rows:
        split = row["Split"]
        cat = row["Category"]
        prompt = row["Goal"].strip()
        report = engine.scan(prompt, context={"source": "jailbreakbench"})
        key = (split, cat)
        by_split_cat[key]["total"] += 1
        if report.action in {Action.BLOCK, Action.FLAG}:
            by_split_cat[key]["detected"] += 1
            if report.action == Action.BLOCK:
                by_split_cat[key]["blocked"] += 1
            else:
                by_split_cat[key]["flagged"] += 1
            for d in report.detections:
                per_detector[d.detector_id] += 1
            if split == "benign" and len(benign_flagged) < 10:
                benign_flagged.append(
                    {
                        "goal": row["Goal"][:100],
                        "category": cat,
                        "top_detector": (
                            report.detections[0].detector_id if report.detections else ""
                        ),
                    }
                )
        else:
            if split == "harmful" and len(harmful_missed) < 10:
                harmful_missed.append(row["Goal"][:100])

    def _rollup(split: str) -> dict[str, int | float]:
        total = detected = blocked = flagged = 0
        for (s, _c), st in by_split_cat.items():
            if s != split:
                continue
            total += st["total"]
            detected += st["detected"]
            blocked += st["blocked"]
            flagged += st["flagged"]
        rate = detected / total if total else 0.0
        return {
            "total": total,
            "detected": detected,
            "blocked": blocked,
            "flagged": flagged,
            "rate": rate,
        }

    harmful = _rollup("harmful")
    benign = _rollup("benign")

    print("\n=== Headline ===")
    print(f"  Harmful (recall): {harmful['detected']}/{harmful['total']} = {harmful['rate']:.1%}")
    print(f"  Benign  (FPR):    {benign['detected']}/{benign['total']} = {benign['rate']:.1%}")

    print("\n=== By category (harmful | benign, detected/total) ===")
    print(f"  {'Category':<30} {'harmful':>10} {'benign':>10}")
    cats = sorted({c for _s, c in by_split_cat})
    per_cat_summary: dict[str, dict] = {}
    for cat in cats:
        h = by_split_cat.get(("harmful", cat), {"total": 0, "detected": 0})
        b = by_split_cat.get(("benign", cat), {"total": 0, "detected": 0})
        print(f"  {cat:<30} {h['detected']:>3}/{h['total']:<6} {b['detected']:>3}/{b['total']:<6}")
        per_cat_summary[cat] = {
            "harmful_detected": h["detected"],
            "harmful_total": h["total"],
            "benign_detected": b["detected"],
            "benign_total": b["total"],
        }

    print("\n=== Top firing detectors (across all 200 prompts) ===")
    for det_id, count in per_detector.most_common(15):
        print(f"  {det_id:<40} {count}")

    if harmful_missed:
        print(f"\n=== Sample harmful missed (top {len(harmful_missed)}) ===")
        for ex in harmful_missed:
            print(f"    - {ex}")
    if benign_flagged:
        print(f"\n=== Sample benign flagged (top {len(benign_flagged)}) — FALSE POSITIVES ===")
        for ex in benign_flagged:
            print(f"    - [{ex['category']}] {ex['goal']}  →  {ex['top_detector']}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(
                {
                    "dataset": "JailbreakBench (Chao et al., NeurIPS 2024)",
                    "csv_path": str(args.csv),
                    "ml_enabled": args.ml,
                    "harmful": harmful,
                    "benign": benign,
                    "by_category": per_cat_summary,
                    "top_detectors": dict(per_detector.most_common(20)),
                    "sample_harmful_missed": harmful_missed,
                    "sample_benign_flagged": benign_flagged,
                    "notes": (
                        "JailbreakBench is a jailbreak (harmful-behavior) benchmark, "
                        "not a prompt-injection benchmark. Low harmful-recall is expected "
                        "for an injection-focused defender; benign FPR is the safety metric."
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nWrote {args.json_out}")


if __name__ == "__main__":
    main()
