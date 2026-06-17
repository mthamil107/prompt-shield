"""Evaluate prompt-shield against NVIDIA Garak's prompt-injection probes.

References
----------
- Derczynski et al. "garak: A Framework for Security Probing Large Language
  Models." arXiv:2406.11036 (2024). https://arxiv.org/abs/2406.11036
- NVIDIA/garak repository: https://github.com/NVIDIA/garak

What this measures
------------------
Garak is the de-facto open-source vulnerability scanner for LLMs. We use its
prompt-injection probe families (`promptinject` and `latentinjection`) as a
black-box adversary corpus and report what fraction prompt-shield flags or
blocks before they would reach the protected LLM.

How the prompts were obtained
-----------------------------
Garak was run with its `test.Blank` offline mock generator (no real LLM
calls) over the full `promptinject` and `latentinjection` probe sets. Each
attempt's first-turn user content was extracted from the JSONL run reports.

Methodology
-----------
- Read Garak's two JSONL report files (paths set via env or default)
- Extract one attack prompt per attempt (first user turn's content text)
- Scan each with prompt-shield (regex-only by default for reproducibility,
  no GPU)
- Report detection rate per probe class. A detection is recorded when
  ``action in {block, flag}``.

Honest caveats
--------------
- Garak probes mix many attack styles; we treat *every* attempt's user
  prompt as adversarial and report detection rate. This is appropriate
  because every probe is designed as an attack.
- Some `latentinjection` probes embed the payload in a long benign
  document; even when prompt-shield does not flag the document, the
  injection may still fail at the LLM. We're measuring *detector
  coverage*, not end-to-end ASR.
- The ML classifier (d022) is disabled by default for reproducibility on
  CPU-only machines. Pass `--ml` to enable it.

Running
-------
    # First generate the Garak corpus (one-time, ~2 minutes):
    python -m garak --model_type test.Blank --probes promptinject \
        --report_prefix garak_promptinject
    python -m garak --model_type test.Blank --probes latentinjection \
        --report_prefix garak_latentinjection

    # Then evaluate prompt-shield:
    python tests/benchmark_garak.py
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

DEFAULT_GARAK_DIR = Path(os.path.expanduser("~/.local/share/garak/garak_runs"))


def _extract_prompt_text(prompt_obj: object) -> str | None:
    """Extract the first-turn user text from a Garak `prompt` field.

    Garak emits prompts in OpenAI-style turn structure:
        {"turns": [{"role": "user", "content": {"text": "...", ...}}], ...}
    Returns ``None`` if the structure does not match.
    """
    if not isinstance(prompt_obj, dict):
        return None
    turns = prompt_obj.get("turns")
    if not isinstance(turns, list) or not turns:
        return None
    first = turns[0]
    if not isinstance(first, dict):
        return None
    content = first.get("content")
    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, str):
            return text
    if isinstance(content, str):
        return content
    return None


def _load_attempts(jsonl_path: Path) -> list[tuple[str, str]]:
    """Return list of (probe_classname, attack_prompt) from a Garak JSONL run."""
    attempts: list[tuple[str, str]] = []
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("entry_type") != "attempt":
                continue
            probe = str(obj.get("probe_classname", "unknown"))
            text = _extract_prompt_text(obj.get("prompt"))
            if text:
                attempts.append((probe, text))
    return attempts


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
        cfg["prompt_shield"]["detectors"] = {"d022_semantic_classifier": {"enabled": False}}
    return PromptShieldEngine(config_dict=cfg)


def _evaluate(engine: PromptShieldEngine, attempts: list[tuple[str, str]]) -> dict:
    by_probe: dict[str, dict[str, int]] = defaultdict(lambda: {"caught": 0, "total": 0})
    t0 = time.perf_counter()
    for probe, text in attempts:
        # Truncate extremely long prompts (some latentinjection prompts > 100k
        # chars). prompt-shield's detectors have their own caps but very long
        # inputs can stall the d028 alignment grid.
        if len(text) > 20_000:
            text = text[:20_000]
        r = engine.scan(text)
        by_probe[probe]["total"] += 1
        if r.action.value in ("block", "flag"):
            by_probe[probe]["caught"] += 1
    elapsed = time.perf_counter() - t0
    return {"by_probe": dict(by_probe), "elapsed_seconds": elapsed}


def _print_report(label: str, results: dict, attempts: list[tuple[str, str]]) -> None:
    print("=" * 78)
    print(f"  {label}")
    print("=" * 78)
    print()
    by_probe = results["by_probe"]
    total_caught = sum(v["caught"] for v in by_probe.values())
    total_total = sum(v["total"] for v in by_probe.values())
    elapsed = results["elapsed_seconds"]

    print(f"  Total attacks scanned: {total_total}")
    print(
        f"  Caught (block/flag):   {total_caught} ({total_caught / max(1, total_total) * 100:.1f}%)"
    )
    print(
        f"  Wall time:             {elapsed:.1f}s ({total_total / max(0.001, elapsed):.0f} scans/sec)"
    )
    print()
    print(f"  {'Probe':<58}{'Caught':>8}{'Total':>8}{'Rate':>8}")
    print(f"  {'-' * 82}")
    for probe in sorted(by_probe):
        caught = by_probe[probe]["caught"]
        total = by_probe[probe]["total"]
        rate = (caught / total * 100) if total else 0
        # Strip the "promptinject." / "latentinjection." prefix for readability
        display = probe.split(".")[-1] if "." in probe else probe
        print(f"  {display:<58}{caught:>8}{total:>8}{rate:>7.1f}%")
    print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--garak-dir",
        type=Path,
        default=DEFAULT_GARAK_DIR,
        help=f"Directory containing Garak JSONL reports (default: {DEFAULT_GARAK_DIR})",
    )
    parser.add_argument("--ml", action="store_true", help="Enable d022 ML classifier")
    parser.add_argument(
        "--save-json",
        type=Path,
        default=None,
        help="Optional path to dump per-probe JSON results",
    )
    args = parser.parse_args()

    if not args.garak_dir.exists():
        print(f"ERROR: Garak runs dir not found: {args.garak_dir}")
        print("Run garak first:")
        print(
            "  python -m garak --model_type test.Blank --probes promptinject "
            "--report_prefix garak_promptinject"
        )
        print(
            "  python -m garak --model_type test.Blank --probes latentinjection "
            "--report_prefix garak_latentinjection"
        )
        sys.exit(2)

    print("Loading Garak attempts...")
    all_attempts: list[tuple[str, str]] = []
    for fname in ("garak_promptinject.report.jsonl", "garak_latentinjection.report.jsonl"):
        p = args.garak_dir / fname
        if not p.exists():
            print(f"  WARN: missing {p}")
            continue
        a = _load_attempts(p)
        print(f"  {fname}: {len(a)} attempts")
        all_attempts.extend(a)

    if not all_attempts:
        print("No attempts loaded. Run garak first.")
        sys.exit(2)

    print(f"\nTotal attempts: {len(all_attempts)}")
    print(f"ML classifier (d022): {'ENABLED' if args.ml else 'disabled'}\n")

    engine = _make_engine(disable_ml=not args.ml)
    results = _evaluate(engine, all_attempts)
    label = "Garak Detection Rate ({})".format("with d022 ML" if args.ml else "regex-only")
    _print_report(label, results, all_attempts)

    if args.save_json:
        out = {
            "config": "with_ml" if args.ml else "regex_only",
            "total_attempts": len(all_attempts),
            "elapsed_seconds": results["elapsed_seconds"],
            "by_probe": results["by_probe"],
        }
        args.save_json.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"Saved per-probe JSON to {args.save_json}")


if __name__ == "__main__":
    sys.exit(main() or 0)
