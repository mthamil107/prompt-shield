"""Regression gate for prompt-shield.

Re-runs the fast benchmark harness and compares results against
``tests/baseline_v0.3.3.txt``. Fails (non-zero exit) if any of the
following regresses:

- Total pytest pass count drops.
- False-positive count on BENIGN set increases.
- Any per-category attack detection rate drops by more than
  ``CATEGORY_TOLERANCE_PCT`` absolute (default 1 percentage point).
- Overall attack detection rate drops by more than
  ``OVERALL_TOLERANCE_PCT`` absolute (default 1 percentage point).

Improvements never fail the check. New categories (not in the
baseline) are reported but do not fail. The public-datasets benchmark
is NOT re-run here because it requires network + HuggingFace models;
run ``python tests/benchmark_public_datasets.py`` manually when needed.

Usage:

    python tests/regression_check.py                # runs all gates
    python tests/regression_check.py --skip-pytest  # only benchmark
    python tests/regression_check.py --verbose      # show per-category table
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from io import StringIO
from pathlib import Path
from typing import Any

BASELINE_PATH = Path(__file__).parent / "baseline_v0.3.3.txt"
CATEGORY_TOLERANCE_PCT = 1.0
OVERALL_TOLERANCE_PCT = 1.0

# Matches "category.basic_injection:              100" in the baseline.
_BASELINE_CATEGORY_RE = re.compile(r"^category\.(?P<name>[a-zA-Z0-9_]+):\s+(?P<rate>\d+(?:\.\d+)?)")
# Matches "key: value" in the baseline (numeric only).
_BASELINE_KV_RE = re.compile(r"^(?P<key>[a-zA-Z0-9_.]+):\s+(?P<value>\d+(?:\.\d+)?)")


def _parse_baseline(path: Path) -> dict[str, float]:
    """Read the baseline file into a flat dict of metric -> number.

    Lines starting with ``#`` and blank lines are ignored. ``TBD`` values
    are skipped. Category lines are namespaced as ``category.<name>``.
    """
    metrics: dict[str, float] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("="):
            continue
        if "TBD" in line:
            continue
        cat = _BASELINE_CATEGORY_RE.match(line)
        if cat:
            metrics[f"category.{cat.group('name')}"] = float(cat.group("rate"))
            continue
        kv = _BASELINE_KV_RE.match(line)
        if kv:
            metrics[kv.group("key")] = float(kv.group("value"))
    return metrics


def _run_realistic_benchmark() -> dict[str, Any]:
    """Execute benchmark_realistic.run_benchmark() and capture its stdout.

    We invoke the function in-process rather than as a subprocess so the
    test harness uses the working-tree code exactly as-is.
    """
    import contextlib
    import importlib.util

    buf = StringIO()
    spec = importlib.util.spec_from_file_location(
        "_bench_realistic", Path(__file__).parent / "benchmark_realistic.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load benchmark_realistic.py")
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(buf):
        spec.loader.exec_module(module)
        module.run_benchmark()
    return _parse_realistic_output(buf.getvalue())


_REALISTIC_CATEGORY_RE = re.compile(
    r"^[+X~]\s+(?P<name>\w+)\s+\d+\s+\d+\s+\d+\s+(?P<rate>\d+)%"
)
_REALISTIC_TOTAL_RE = re.compile(
    r"^\s+TOTAL\s+ATTACKS\s+(?P<total>\d+)\s+(?P<blocked>\d+)\s+\d+\s+(?P<rate>\d+(?:\.\d+)?)%"
)
_REALISTIC_BENIGN_RE = re.compile(
    r"^\s+BENIGN\s+\(false\s+positives\)\s+(?P<total>\d+)\s+(?P<fp>\d+)\s+\d+\s+(?P<rate>\d+(?:\.\d+)?)%\s+FP"
)


def _parse_realistic_output(text: str) -> dict[str, Any]:
    """Parse the tabular output from benchmark_realistic into metrics."""
    per_category: dict[str, float] = {}
    total_rate: float | None = None
    fp_count: int | None = None
    for line in text.splitlines():
        cat = _REALISTIC_CATEGORY_RE.match(line)
        if cat:
            per_category[cat.group("name")] = float(cat.group("rate"))
            continue
        tot = _REALISTIC_TOTAL_RE.match(line)
        if tot:
            total_rate = float(tot.group("rate"))
            continue
        ben = _REALISTIC_BENIGN_RE.match(line)
        if ben:
            fp_count = int(ben.group("fp"))
    if total_rate is None or fp_count is None:
        raise RuntimeError(
            "could not parse TOTAL ATTACKS or BENIGN line from benchmark_realistic output"
        )
    return {
        "categories": per_category,
        "overall_detection_rate_pct": total_rate,
        "benign_false_positive_count": fp_count,
    }


def _run_pytest() -> int:
    """Run the full pytest suite and return pass count. Exits on any failure."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--no-cov", "-q", "--tb=no"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"(\d+)\s+passed", result.stdout)
    passed = int(match.group(1)) if match else 0
    if "failed" in result.stdout or result.returncode != 0:
        sys.stderr.write(result.stdout[-2000:])
        sys.stderr.write(result.stderr[-2000:])
        raise SystemExit(f"pytest failed — {passed} passed but suite is red. See output above.")
    return passed


def _compare(baseline: dict[str, float], current: dict[str, Any], *, verbose: bool) -> list[str]:
    """Return a list of failure messages. Empty list means all gates pass."""
    failures: list[str] = []

    # Overall detection rate
    base_overall = baseline.get("overall_detection_rate_pct", 0.0)
    cur_overall = current["overall_detection_rate_pct"]
    if cur_overall + OVERALL_TOLERANCE_PCT < base_overall:
        failures.append(
            f"Overall detection rate dropped: baseline {base_overall:.1f}% -> current {cur_overall:.1f}% "
            f"(tolerance {OVERALL_TOLERANCE_PCT}% abs)"
        )

    # False-positive count (strict: never increase)
    base_fp = int(baseline.get("benign_false_positive_count", 0))
    cur_fp = int(current["benign_false_positive_count"])
    if cur_fp > base_fp:
        failures.append(f"False-positive count increased: baseline {base_fp} -> current {cur_fp}")

    # Per-category rates
    for name, cur_rate in current["categories"].items():
        base_rate = baseline.get(f"category.{name}")
        if base_rate is None:
            if verbose:
                print(f"  [new category] {name}: {cur_rate:.0f}% (no baseline, not gated)")
            continue
        delta = cur_rate - base_rate
        if verbose:
            marker = "+" if delta > 0 else "-" if delta < 0 else " "
            print(f"  [{marker}] {name:<30} baseline {base_rate:>5.0f}%  current {cur_rate:>5.0f}%  delta {delta:+.0f}%")
        if cur_rate + CATEGORY_TOLERANCE_PCT < base_rate:
            failures.append(
                f"Category '{name}' detection rate dropped: "
                f"baseline {base_rate:.0f}% -> current {cur_rate:.0f}% "
                f"(tolerance {CATEGORY_TOLERANCE_PCT}% abs)"
            )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="prompt-shield regression gate")
    parser.add_argument("--skip-pytest", action="store_true", help="skip pytest (only run benchmark gate)")
    parser.add_argument("--verbose", action="store_true", help="print per-category comparison table")
    args = parser.parse_args()

    if not BASELINE_PATH.exists():
        print(f"ERROR: baseline file not found at {BASELINE_PATH}", file=sys.stderr)
        return 2

    baseline = _parse_baseline(BASELINE_PATH)

    # Gate 1: pytest
    if not args.skip_pytest:
        print("Running pytest gate...")
        passed = _run_pytest()
        base_passed = int(baseline.get("total_passed", 0))
        print(f"  pytest: {passed} passed (baseline {base_passed})")
        if passed < base_passed:
            print(f"FAIL: pytest pass count dropped: {base_passed} -> {passed}", file=sys.stderr)
            return 1

    # Gate 2: realistic benchmark
    print("Running realistic benchmark gate...")
    current = _run_realistic_benchmark()
    if args.verbose:
        print("Per-category comparison:")
    failures = _compare(baseline, current, verbose=args.verbose)

    if failures:
        print("", file=sys.stderr)
        print("REGRESSION DETECTED:", file=sys.stderr)
        for msg in failures:
            print(f"  - {msg}", file=sys.stderr)
        return 1

    print("")
    print("All regression gates passed.")
    print(f"  overall detection: {current['overall_detection_rate_pct']:.1f}% (baseline {baseline.get('overall_detection_rate_pct', 0):.1f}%)")
    print(f"  false positives:   {current['benign_false_positive_count']} (baseline {int(baseline.get('benign_false_positive_count', 0))})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
