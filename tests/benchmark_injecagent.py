"""Evaluate prompt-shield against the InjecAgent benchmark.

References
----------
- Zhan, Q., Liang, Z., Ying, Z., Kang, D. *InjecAgent: Benchmarking Indirect
  Prompt Injections in Tool-Integrated Large Language Model Agents.*
  ACL Findings 2024. arXiv:2403.02691.
- Code: https://github.com/uiuc-kang-lab/InjecAgent

What this measures
------------------
InjecAgent is the standard benchmark for *indirect* prompt injection in
tool-integrated agents. Each test case is a malicious tool response —
JSON-shaped agent input where an attacker instruction has been embedded
inside a legitimate-looking data field (e.g., a product review).

We treat each tool response as input to prompt-shield's firewall and
measure what fraction is flagged before the agent acts on it.

Methodology
-----------
- Read all four test files: dh_base, dh_enhanced, ds_base, ds_enhanced
- Use the pre-rendered ``Tool Response`` field (attack already embedded)
- Scan each with prompt-shield (regex-only by default)
- Report detection rate by Attack Type and by attack class (DH / DS)
- A detection is recorded when ``action in {block, flag}``

Honest caveats
--------------
- InjecAgent attacks are designed to be **subtle** — most do not contain
  override keywords. Expect lower detection than override-heavy benchmarks.
- The full InjecAgent metric is end-to-end ASR (agent ASR is what matters);
  we are measuring upstream detector coverage, which is different.
- Some attacks may be near-impossible to flag without context (e.g.,
  "grant access to user X" embedded in a product review is only malicious
  in the agent's specific context).

Running
-------
    # Clone InjecAgent first (one-time):
    git clone https://github.com/uiuc-kang-lab/InjecAgent.git ../InjecAgent

    # Evaluate prompt-shield:
    python tests/benchmark_injecagent.py
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

from prompt_shield import PromptShieldEngine

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DEFAULT_INJECAGENT_DIR = Path("D:/Repo/InjecAgent/data")

TEST_FILES: list[tuple[str, str]] = [
    ("test_cases_dh_base.json", "DH-base"),
    ("test_cases_dh_enhanced.json", "DH-enhanced"),
    ("test_cases_ds_base.json", "DS-base"),
    ("test_cases_ds_enhanced.json", "DS-enhanced"),
]


def _make_engine(disable_ml: bool) -> PromptShieldEngine:
    cfg: dict = {
        "prompt_shield": {
            "mode": "block",
            "threshold": 0.7,
            "vault": {"enabled": False},
            "feedback": {"enabled": False},
            "canary": {"enabled": False},
            "history": {"enabled": False},
        }
    }
    if disable_ml:
        cfg["prompt_shield"]["detectors"] = {
            "d022_semantic_classifier": {"enabled": False}
        }
    return PromptShieldEngine(config_dict=cfg)


def _load_cases(data_dir: Path) -> list[dict]:
    """Load all test cases, annotated with split name and case index."""
    all_cases: list[dict] = []
    for fname, split in TEST_FILES:
        p = data_dir / fname
        if not p.exists():
            print(f"  WARN: missing {p}")
            continue
        cases = json.loads(p.read_text(encoding="utf-8"))
        for i, c in enumerate(cases):
            c["_split"] = split
            c["_idx"] = i
            all_cases.append(c)
        print(f"  {fname}: {len(cases)} cases")
    return all_cases


def _evaluate(engine: PromptShieldEngine, cases: list[dict]) -> dict:
    by_split: dict[str, dict[str, int]] = defaultdict(lambda: {"caught": 0, "total": 0})
    by_type: dict[str, dict[str, int]] = defaultdict(lambda: {"caught": 0, "total": 0})
    t0 = time.perf_counter()

    for c in cases:
        split = c["_split"]
        attack_type = c.get("Attack Type", "unknown")
        text = str(c.get("Tool Response", ""))
        if len(text) > 20_000:
            text = text[:20_000]
        if not text.strip():
            continue
        r = engine.scan(text)
        caught = r.action.value in ("block", "flag")
        by_split[split]["total"] += 1
        by_type[attack_type]["total"] += 1
        if caught:
            by_split[split]["caught"] += 1
            by_type[attack_type]["caught"] += 1

    elapsed = time.perf_counter() - t0
    return {
        "by_split": dict(by_split),
        "by_type": dict(by_type),
        "elapsed_seconds": elapsed,
    }


def _print_table(name: str, mapping: dict[str, dict[str, int]]) -> None:
    rows = sorted(mapping.items())
    width = max((len(k) for k in mapping), default=10)
    print(f"  {name:<{width}}{'Caught':>10}{'Total':>10}{'Rate':>10}")
    print(f"  {'-' * (width + 30)}")
    grand_c = grand_t = 0
    for k, v in rows:
        c, t = v["caught"], v["total"]
        rate = (c / t * 100) if t else 0
        grand_c += c
        grand_t += t
        print(f"  {k:<{width}}{c:>10}{t:>10}{rate:>9.1f}%")
    print(f"  {'-' * (width + 30)}")
    overall = (grand_c / grand_t * 100) if grand_t else 0
    print(f"  {'OVERALL':<{width}}{grand_c:>10}{grand_t:>10}{overall:>9.1f}%")
    print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_INJECAGENT_DIR,
        help="InjecAgent/data directory",
    )
    parser.add_argument("--ml", action="store_true", help="Enable d022 ML classifier")
    parser.add_argument(
        "--save-json", type=Path, default=None, help="Optional JSON output path"
    )
    args = parser.parse_args()

    if not args.data_dir.exists():
        print(f"ERROR: InjecAgent data dir not found: {args.data_dir}")
        print("Clone first: git clone https://github.com/uiuc-kang-lab/InjecAgent.git")
        sys.exit(2)

    print("=" * 78)
    print("  prompt-shield evaluation: InjecAgent (ACL Findings 2024)")
    print("=" * 78)
    print()
    print("Loading test cases...")
    cases = _load_cases(args.data_dir)
    print(f"\nTotal cases: {len(cases)}")
    print(f"ML classifier (d022): {'ENABLED' if args.ml else 'disabled'}")
    print()

    engine = _make_engine(disable_ml=not args.ml)
    results = _evaluate(engine, cases)
    elapsed = results["elapsed_seconds"]

    print(f"Wall time: {elapsed:.1f}s ({len(cases) / max(0.001, elapsed):.0f} scans/sec)")
    print()
    print("=" * 78)
    print("  BY ATTACK CLASS (DH = direct harm, DS = data stealing)")
    print("=" * 78)
    print()
    _print_table("Split", results["by_split"])

    print("=" * 78)
    print("  BY ATTACK TYPE")
    print("=" * 78)
    print()
    _print_table("Type", results["by_type"])

    if args.save_json:
        out = {
            "config": "with_ml" if args.ml else "regex_only",
            "total_cases": len(cases),
            "elapsed_seconds": elapsed,
            "by_split": results["by_split"],
            "by_type": results["by_type"],
        }
        args.save_json.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"Saved per-split/type JSON to {args.save_json}")


if __name__ == "__main__":
    sys.exit(main() or 0)
