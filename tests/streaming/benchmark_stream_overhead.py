"""Informational latency microbenchmark for ``StreamGuard``.

Compares a raw passthrough (list append + join) against
``StreamGuard(mode="flag")`` with the default stream-safe scanner set, on a
fixed fake stream of 100 benign 20-character chunks.

Run manually::

    python tests/streaming/benchmark_stream_overhead.py

Numbers depend on the machine and on which optional ML extras are
installed (``transformers``, ``optimum``). This is a developer-machine
measurement, not a CI contract; nothing here asserts a threshold. Results
are written to ``benchmark_stream_overhead_results.md`` next to this file.
"""

from __future__ import annotations

import argparse
import importlib.util
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from prompt_shield.streaming import StreamGuard

N_CHUNKS = 100
N_ITER = 20
WARMUP = 3

# Benign text only: no digit runs, no email or phone shapes, no
# injection phrasing, so no finding fires during the timed pass.
CHUNK = "the quick brown fox "
assert len(CHUNK) == 20
CHUNKS = [CHUNK] * N_CHUNKS

RESULTS_PATH = Path(__file__).with_name("benchmark_stream_overhead_results.md")


def raw_pass(chunks: list[str]) -> str:
    buf = []
    for c in chunks:
        buf.append(c)
    return "".join(buf)


def guarded_pass(chunks: list[str]) -> None:
    guard = StreamGuard(mode="flag")
    for c in chunks:
        guard.feed(c)
    guard.finish()


def _time_variant(fn, iterations: int) -> list[int]:
    for _ in range(WARMUP):
        fn(CHUNKS)
    samples: list[int] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn(CHUNKS)
        samples.append(time.perf_counter_ns() - start)
    return samples


def _stats(samples_ns: list[int]) -> dict[str, float]:
    us = [s / 1000.0 for s in samples_ns]
    p95 = statistics.quantiles(us, n=20)[18] if len(us) >= 2 else us[0]
    return {"median": statistics.median(us), "p95": p95, "min": min(us)}


def _extras() -> dict[str, bool]:
    return {
        name: importlib.util.find_spec(name) is not None for name in ("transformers", "optimum")
    }


def run(iterations: int) -> list[tuple[str, dict[str, float], float, float]]:
    raw = _stats(_time_variant(raw_pass, iterations))
    guarded = _stats(_time_variant(guarded_pass, iterations))
    rows = []
    for name, st in (("raw_passthrough", raw), ("stream_guard_flag", guarded)):
        median_delta = (st["median"] - raw["median"]) / N_CHUNKS
        p95_delta = (st["p95"] - raw["p95"]) / N_CHUNKS
        rows.append((name, st, median_delta, p95_delta))
    return rows


def render_table(rows) -> str:
    lines = [
        "| variant | median us/100 chunks | p95 us/100 chunks | min us/100 chunks "
        "| median delta us/chunk | p95 delta us/chunk |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, st, md, pd in rows:
        lines.append(
            f"| {name} | {st['median']:.1f} | {st['p95']:.1f} | {st['min']:.1f} "
            f"| {md:.2f} | {pd:.2f} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=N_ITER)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)

    rows = run(args.iterations)

    print(f"{'variant':20} {'median_us':>10} {'p95_us':>10} {'delta/chunk':>12}")
    for name, st, md, _pd in rows:
        print(f"{name:20} {st['median']:>10.1f} {st['p95']:>10.1f} {md:>12.2f}")

    raw_median = rows[0][1]["median"]
    guarded = rows[1]
    ratio = guarded[1]["median"] / raw_median if raw_median else float("inf")
    print(f"ratio median guarded/raw: {ratio:.1f}x")

    if args.no_write:
        return

    extras = _extras()
    extras_text = ", ".join(f"{k}: {'yes' if v else 'no'}" for k, v in extras.items())
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = "\n".join(
        [
            "# StreamGuard overhead benchmark",
            "",
            f"- Timestamp: {stamp}",
            f"- Platform: {sys.platform} ({platform.machine()}, "
            f"{platform.processor() or 'unknown cpu'})",
            f"- Python: {sys.version.splitlines()[0]}",
            f"- Optional extras importable: {extras_text}",
            f"- Fixture: {N_CHUNKS} benign chunks of {len(CHUNK)} chars; "
            f"warmup {WARMUP}, iterations {args.iterations}; fresh guard per iteration",
            '- Guard config: `StreamGuard(mode="flag")`, default stream-safe scanner set',
            "",
            render_table(rows),
            "",
            f"Median guarded/raw ratio: {ratio:.1f}x.",
            "",
            f"Per-chunk overhead: median {guarded[2]:.2f} us, p95 {guarded[3]:.2f} us "
            f"on {platform.system()} {platform.machine()}. "
            "Informational only; not a release gate.",
            "",
            "Caveats: p95 is rough at this sample size (20 iterations); "
            "run-to-run spread on p95 can be large even when the median is "
            "stable. The guarded/raw ratio is against a bare list-append "
            "baseline, so the absolute ratio (not a meaningful percentage) "
            "measures guard work per chunk, not relative slowdown of a "
            "realistic workload. Numbers are specific to this machine and "
            "to which optional ML extras are importable.",
            "",
        ]
    )
    RESULTS_PATH.write_text(body, encoding="utf-8")
    print(f"wrote {RESULTS_PATH}")


@pytest.mark.skip(
    reason="informational benchmark; run manually via python "
    "tests/streaming/benchmark_stream_overhead.py"
)
def test_stream_overhead_informational() -> None:
    main(["--no-write"])


if __name__ == "__main__":
    main()
