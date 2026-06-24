"""Evaluate prompt-shield against HarmBench (CAIS, Mazeika et al. 2024).

References
----------
- Mazeika et al. "HarmBench: A Standardized Evaluation Framework for
  Automated Red Teaming and Robust Refusal." arXiv:2402.04249 (2024).
  https://arxiv.org/abs/2402.04249
- HarmBench repo: https://github.com/centerforaisafety/HarmBench
- Dataset CSV: https://raw.githubusercontent.com/centerforaisafety/
  HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv

What this measures
------------------
HarmBench is a 400-behavior benchmark that primarily tests **LLM refusal of
harmful content** (chemical/biological, cyber, illegal, harassment,
misinformation, copyright). It is *not* a prompt-injection benchmark in the
narrow sense — most behaviors are direct harmful requests, not "ignore
your instructions" style attacks.

We report transparently by category:

- 200 **standard** behaviors — raw harmful requests with no injection-style
  framing. Detection here is incidental: prompt-shield catches what looks
  like an attack pattern, not what the LLM should refuse on its own.
- 100 **contextual** behaviors — harmful request paired with a context
  document (closest analogue to indirect / RAG-style injection). This is
  the category where prompt-shield is designed to add value.
- 100 **copyright** behaviors — requests for copyrighted lyrics/books.
  Not an injection attack class at all; included for completeness.

The headline numbers below are split by category. Anyone treating the
contextual subset as the relevant prompt-injection-defense signal is
following the methodology in the original paper (§3.2 distinguishes
"context-aware" attacks from direct ones).

Running
-------
    # First fetch the dataset (one-time, ~85 KB):
    curl -L -o data/harmbench_behaviors_text_all.csv \\
      https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/\\
data/behavior_datasets/harmbench_behaviors_text_all.csv

    # Then evaluate:
    python tests/benchmark_harmbench.py \\
      --csv data/harmbench_behaviors_text_all.csv

Honest caveats
--------------
- HarmBench scores prompt-shield on a problem it isn't primarily designed
  to solve (LLM refusal of harmful content). The standard + copyright
  detection rates will be much lower than the contextual rate, and that
  is the *correct* shape: prompt-shield should not pretend to be a
  content-safety classifier.
- The DeBERTa ML classifier (d022) is **disabled by default** for
  reproducibility on CPU. Pass --ml to enable.
- Contextual prompts are scanned as ``context_doc + "\\n\\n" + behavior``
  so both signals are visible to detectors (the way they'd appear in a
  real RAG pipeline).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Force UTF-8 on Windows so the report doesn't crash on Unicode behaviors.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

from prompt_shield import PromptShieldEngine
from prompt_shield.models import Action


def load_behaviors(csv_path: Path) -> list[dict]:
    with csv_path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build_prompt(row: dict) -> str:
    """Build the scannable prompt. For contextual rows, concatenate context
    and the harmful behavior the way they'd be combined in a real RAG flow."""
    behavior = row["Behavior"].strip()
    context = (row.get("ContextString") or "").strip()
    if context:
        return f"{context}\n\n{behavior}"
    return behavior


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("data/harmbench_behaviors_text_all.csv"),
        help="Path to the HarmBench behaviors CSV",
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

    if not args.csv.exists():
        sys.exit(
            f"HarmBench CSV not found at {args.csv}. Fetch with:\n"
            "  curl -L -o data/harmbench_behaviors_text_all.csv \\\n"
            "    https://raw.githubusercontent.com/centerforaisafety/HarmBench/"
            "main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
        )

    rows = load_behaviors(args.csv)
    print(f"Loaded {len(rows)} HarmBench behaviors from {args.csv}")
    cat_counts = Counter(r["FunctionalCategory"] for r in rows)
    print(f"  Categories: {dict(cat_counts)}")

    config_dict: dict[str, object] = {}
    if not args.ml:
        config_dict["detectors"] = {"d022_semantic_classifier": {"enabled": False}}
    engine = PromptShieldEngine(config_dict=config_dict or None)

    by_category: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "detected": 0, "blocked": 0, "flagged": 0}
    )
    per_detector: Counter = Counter()
    detected_examples: dict[str, list[str]] = defaultdict(list)
    missed_examples: dict[str, list[str]] = defaultdict(list)

    for row in rows:
        cat = row["FunctionalCategory"]
        prompt = build_prompt(row)
        report = engine.scan(prompt, context={"source": "harmbench"})
        by_category[cat]["total"] += 1
        if report.action in {Action.BLOCK, Action.FLAG}:
            by_category[cat]["detected"] += 1
            if report.action == Action.BLOCK:
                by_category[cat]["blocked"] += 1
            else:
                by_category[cat]["flagged"] += 1
            for d in report.detections:
                per_detector[d.detector_id] += 1
            if len(detected_examples[cat]) < 3:
                detected_examples[cat].append(row["Behavior"][:100])
        else:
            if len(missed_examples[cat]) < 3:
                missed_examples[cat].append(row["Behavior"][:100])

    print("\n=== Detection rate by FunctionalCategory ===")
    print(
        f"{'Category':<14} {'Total':>6} {'Detected':>9} {'Blocked':>8} {'Flagged':>8} {'Rate':>7}"
    )
    overall_total = 0
    overall_detected = 0
    summary: dict[str, dict] = {}
    for cat in ["standard", "contextual", "copyright"]:
        s = by_category.get(cat)
        if not s:
            continue
        rate = s["detected"] / s["total"] if s["total"] else 0.0
        print(
            f"{cat:<14} {s['total']:>6} {s['detected']:>9} {s['blocked']:>8} "
            f"{s['flagged']:>8} {rate:>6.1%}"
        )
        overall_total += s["total"]
        overall_detected += s["detected"]
        summary[cat] = {**s, "rate": rate}

    overall_rate = overall_detected / overall_total if overall_total else 0.0
    print(
        f"{'OVERALL':<14} {overall_total:>6} {overall_detected:>9} {'':>8} "
        f"{'':>8} {overall_rate:>6.1%}"
    )

    print("\n=== Top firing detectors ===")
    for det_id, count in per_detector.most_common(15):
        print(f"  {det_id:<40} {count}")

    print("\n=== Sample detected (top 3 per category) ===")
    for cat, examples in detected_examples.items():
        print(f"  [{cat}]")
        for ex in examples:
            print(f"    - {ex}")

    print("\n=== Sample missed (top 3 per category) ===")
    for cat, examples in missed_examples.items():
        print(f"  [{cat}]")
        for ex in examples:
            print(f"    - {ex}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(
                {
                    "dataset": "HarmBench (CAIS, Mazeika et al. 2024)",
                    "csv_path": str(args.csv),
                    "ml_enabled": args.ml,
                    "by_category": summary,
                    "overall": {
                        "total": overall_total,
                        "detected": overall_detected,
                        "rate": overall_rate,
                    },
                    "top_detectors": dict(per_detector.most_common(20)),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nWrote {args.json_out}")


if __name__ == "__main__":
    main()
