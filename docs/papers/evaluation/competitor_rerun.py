"""Head-to-head competitor comparison for prompt-shield.

Purpose
-------
Run open-source prompt-injection detectors against the same three
benchmark corpora prompt-shield reports on in the paper (Liu et al.,
Garak, InjecAgent), so results can be compared apples-to-apples.

Competitors attempted
---------------------
- ``protectai/deberta-v3-base-prompt-injection-v2`` (open, HF, base
  weights already used internally by prompt-shield's d022 semantic
  classifier — this row is therefore self-referential; see notes).
- ``deepset/deberta-v3-base-injection`` (open, HF).
- ``meta-llama/Llama-Prompt-Guard-2-86M`` (open weights, HF; access
  requires accepting Meta's licence — flagged as blocked if the model
  is not already cached).
- ``leolee99/PIGuard`` (open weights, HF; requires
  ``trust_remote_code=True``).

Competitors deliberately excluded
---------------------------------
- **Lakera Guard**    — commercial SaaS behind a paid API.
- **Rebuff**          — historically requires an OpenAI API key.
- **AWS Bedrock Guardrails / Azure AI Prompt Shield /
  Google Model Armor** — cloud-only commercial services.

Metrics
-------
For each competitor + benchmark we report:

- **Detection rate**  — fraction of adversarial samples the model calls
  ``injection`` (with a threshold, default 0.5 on the injection
  probability).
- **Wall-clock**      — total scan time in seconds and mean per scan.
- **Skipped**         — samples whose tokenised length exceeded the
  model window (usually 512 tokens). We honestly count these as
  ``skipped`` rather than silently truncating.
- **False-positive rate** — on any benign samples the benchmark
  provides (Liu supplies 8; Garak and InjecAgent are attack-only).

Runtime notes
-------------
On a CPU-only host DeBERTa-base does roughly 3–10 scans/sec, so the
full 5 968 Garak prompts take 15–30 min *per competitor*. To keep the
run bounded we default to ``--sample-size 500`` for Garak and
InjecAgent (Liu is small enough to always run in full).

Reproduce
---------
    python docs/papers/evaluation/competitor_rerun.py                 # default (sample)
    python docs/papers/evaluation/competitor_rerun.py --sample-size 0 # full run
    python docs/papers/evaluation/competitor_rerun.py --competitors protectai,deepset

Outputs (relative to this script):
    competitor_rerun/results.json        # machine-readable, incremental
    competitor_rerun.json                # symlink-friendly duplicate
    competitor_rerun.md                  # human report
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

# Silence transformers 5.x tqdm chaos before importing it.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("TQDM_DISABLE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import warnings

warnings.filterwarnings("ignore")

HERE = Path(__file__).parent
OUT_DIR = HERE / "competitor_rerun"
OUT_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_JSON = OUT_DIR / "results.json"
FLAT_JSON = HERE / "competitor_rerun.json"


# --------------------------------------------------------------------------
# Competitor definitions
# --------------------------------------------------------------------------

# Each competitor entry maps model_id -> (label_index_of_injection,
# tokenizer_kwargs). Because the Meta model card labels its two classes
# LABEL_0 (benign) / LABEL_1 (malicious), we hard-code the injection index
# per-model rather than searching config.id2label case-insensitively.
COMPETITORS: dict[str, dict[str, Any]] = {
    "protectai": {
        "model_id": "protectai/deberta-v3-base-prompt-injection-v2",
        "injection_index": 1,
        "trust_remote_code": False,
        "note": (
            "Base weights of this model are what prompt-shield's d022 semantic "
            "classifier loads internally, so the ProtectAI row is not an "
            "independent comparator — it is effectively 'd022 alone, no other "
            "detectors'."
        ),
    },
    "deepset": {
        "model_id": "deepset/deberta-v3-base-injection",
        "injection_index": 1,
        "trust_remote_code": False,
        "note": "Deepset DeBERTa-v3 prompt-injection classifier.",
    },
    "prompt_guard_2": {
        "model_id": "meta-llama/Llama-Prompt-Guard-2-86M",
        "injection_index": 1,
        "trust_remote_code": False,
        "note": (
            "Meta Prompt Guard 2 (86M). Access is gated behind the Meta "
            "licence; the runner will report this competitor as BLOCKED if "
            "the weights are not already present in the local HF cache."
        ),
    },
    "piguard": {
        "model_id": "leolee99/PIGuard",
        "injection_index": 1,
        "trust_remote_code": True,
        "note": "PIGuard (ACL 2024). Loaded with trust_remote_code=True.",
    },
}


# --------------------------------------------------------------------------
# Benchmark loaders
# --------------------------------------------------------------------------

DEFAULT_INJECAGENT_DIR = Path("D:/Repo/InjecAgent/data")
DEFAULT_GARAK_DIR = Path(os.path.expanduser("~/.local/share/garak/garak_runs"))


def _liu_samples() -> tuple[list[str], list[str]]:
    """Return (attack_texts, benign_texts) for Liu et al. 200-attack corpus.

    Attack strings are built with the exact templates reproduced in
    ``tests/benchmark_liu_attackers.py``.
    """
    # Import at module scope would create a circular dependency during test.
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))
    from benchmark_liu_attackers import (  # type: ignore
        CLEAN_PROMPTS,
        INJECTIONS,
        STRATEGIES,
        build_attack,
    )

    attacks: list[str] = []
    for strategy in STRATEGIES:
        for target_task, clean_data in CLEAN_PROMPTS:
            for inj_inst, inj_data in INJECTIONS:
                attacks.append(
                    build_attack(strategy, clean_data, inj_inst, inj_data, target_task)
                )
    benign = [clean for _, clean in CLEAN_PROMPTS]
    return attacks, benign


def _garak_extract_prompt_text(prompt_obj: object) -> str | None:
    """Mirror of ``tests/benchmark_garak.py::_extract_prompt_text`` — the
    tests package is not importable from here (no ``__init__.py``)."""
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


def _garak_load_attempts(jsonl_path: Path) -> list[tuple[str, str]]:
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
            text = _garak_extract_prompt_text(obj.get("prompt"))
            if text:
                attempts.append((probe, text))
    return attempts


def _garak_samples(garak_dir: Path, sample: int, rng: random.Random) -> list[str]:
    """Load Garak attack prompts from the two report JSONL files."""
    attempts: list[tuple[str, str]] = []
    for fname in (
        "garak_promptinject.report.jsonl",
        "garak_latentinjection.report.jsonl",
    ):
        p = garak_dir / fname
        if not p.exists():
            print(f"[garak] WARN missing {p}", file=sys.stderr)
            continue
        loaded = _garak_load_attempts(p)
        print(f"[garak] {fname}: {len(loaded)} attempts", file=sys.stderr)
        attempts.extend(loaded)

    texts = [text for _, text in attempts]
    if sample and sample < len(texts):
        rng.shuffle(texts)
        texts = texts[:sample]
    return texts


def _injecagent_samples(
    data_dir: Path, sample: int, rng: random.Random
) -> list[str]:
    """Load InjecAgent Tool Response strings across all four test splits."""
    test_files = [
        "test_cases_dh_base.json",
        "test_cases_dh_enhanced.json",
        "test_cases_ds_base.json",
        "test_cases_ds_enhanced.json",
    ]
    texts: list[str] = []
    for fname in test_files:
        p = data_dir / fname
        if not p.exists():
            print(f"[injecagent] WARN missing {p}", file=sys.stderr)
            continue
        cases = json.loads(p.read_text(encoding="utf-8"))
        for c in cases:
            t = str(c.get("Tool Response", ""))
            if t.strip():
                texts.append(t)
    if sample and sample < len(texts):
        rng.shuffle(texts)
        texts = texts[:sample]
    return texts


# --------------------------------------------------------------------------
# HF classifier wrapper
# --------------------------------------------------------------------------


def _load_competitor(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Try to instantiate one HF classifier. Return ``None`` on failure."""
    model_id = entry["model_id"]
    try:
        from transformers import (  # type: ignore[import-not-found]
            AutoModelForSequenceClassification,
            AutoTokenizer,
            logging as tl,
        )
        import torch

        tl.set_verbosity_error()
        t0 = time.perf_counter()
        tok = AutoTokenizer.from_pretrained(
            model_id, trust_remote_code=entry["trust_remote_code"]
        )
        mdl = AutoModelForSequenceClassification.from_pretrained(
            model_id, trust_remote_code=entry["trust_remote_code"]
        )
        mdl.eval()
        # Prompt Guard 2's model card sets a 512-token cap; every other DeBERTa
        # variant here is ALSO trained on 512-token windows even though the
        # tokenizer advertises no ceiling.
        max_len = 512
        return {
            "model": mdl,
            "tokenizer": tok,
            "torch": torch,
            "injection_index": entry["injection_index"],
            "max_len": max_len,
            "load_seconds": time.perf_counter() - t0,
        }
    except Exception as exc:  # pragma: no cover - runtime env dependent
        print(
            f"[load] FAIL {model_id}: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return None


def _scan_batch(
    handle: dict[str, Any], texts: list[str], threshold: float
) -> dict[str, Any]:
    """Run one competitor over ``texts``. Return raw counts + timing."""
    torch = handle["torch"]
    mdl = handle["model"]
    tok = handle["tokenizer"]
    idx = handle["injection_index"]
    max_len = handle["max_len"]

    t0 = time.perf_counter()
    caught = 0
    skipped = 0
    scanned = 0
    probs: list[float] = []
    with torch.inference_mode():
        for text in texts:
            # Count as skipped if length > 4x the model window in *tokens*.
            # Cheap character heuristic first, tokenise second only if it
            # borderline-passes (keeps CPU cost bounded).
            if len(text) > max_len * 8:
                skipped += 1
                continue
            enc = tok(
                text,
                truncation=True,
                max_length=max_len,
                return_tensors="pt",
            )
            out = mdl(**enc)
            logits = out.logits[0]
            p = float(torch.softmax(logits, dim=-1)[idx])
            probs.append(p)
            scanned += 1
            if p >= threshold:
                caught += 1
    elapsed = time.perf_counter() - t0
    return {
        "scanned": scanned,
        "skipped": skipped,
        "caught": caught,
        "threshold": threshold,
        "elapsed_seconds": elapsed,
        "mean_prob": (sum(probs) / len(probs)) if probs else 0.0,
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def _save(state: dict[str, Any]) -> None:
    RESULTS_JSON.write_text(json.dumps(state, indent=2), encoding="utf-8")
    FLAT_JSON.write_text(json.dumps(state, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--competitors",
        default=",".join(COMPETITORS),
        help="Comma-separated subset of competitors to run.",
    )
    parser.add_argument(
        "--benchmarks",
        default="liu,garak,injecagent",
        help="Comma-separated subset of benchmarks to run.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=500,
        help=(
            "Max samples per benchmark (Liu is always run in full). "
            "Use 0 for the full corpus."
        ),
    )
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--garak-dir", type=Path, default=DEFAULT_GARAK_DIR)
    parser.add_argument("--injecagent-dir", type=Path, default=DEFAULT_INJECAGENT_DIR)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--per-competitor-timeout-sec",
        type=float,
        default=1800.0,
        help="Give up on a benchmark for one competitor if it exceeds this wall-clock.",
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)
    wanted_competitors = [c.strip() for c in args.competitors.split(",") if c.strip()]
    wanted_benchmarks = [b.strip() for b in args.benchmarks.split(",") if b.strip()]

    # Materialise benchmark samples up-front so every competitor sees the
    # exact same input list (matched samples => matched inference budget).
    samples: dict[str, dict[str, Any]] = {}
    benign: dict[str, list[str]] = {}
    if "liu" in wanted_benchmarks:
        atk, ben = _liu_samples()
        samples["liu"] = {"n": len(atk), "texts": atk}
        benign["liu"] = ben
        print(f"[liu] {len(atk)} attacks, {len(ben)} benign", file=sys.stderr)
    if "garak" in wanted_benchmarks:
        # Late import so a missing Garak run does not stop Liu.
        try:
            texts = _garak_samples(args.garak_dir, args.sample_size, rng)
        except Exception as exc:
            print(f"[garak] load failed: {exc}", file=sys.stderr)
            texts = []
        samples["garak"] = {"n": len(texts), "texts": texts}
        benign["garak"] = []
        print(f"[garak] {len(texts)} attacks after sampling", file=sys.stderr)
    if "injecagent" in wanted_benchmarks:
        try:
            texts = _injecagent_samples(args.injecagent_dir, args.sample_size, rng)
        except Exception as exc:
            print(f"[injecagent] load failed: {exc}", file=sys.stderr)
            texts = []
        samples["injecagent"] = {"n": len(texts), "texts": texts}
        benign["injecagent"] = []
        print(f"[injecagent] {len(texts)} attacks after sampling", file=sys.stderr)

    # Resume: if a prior run's JSON exists, keep already-completed cells so
    # a Ctrl-C mid-run doesn't force a full recompute.
    prior: dict[str, Any] = {}
    if RESULTS_JSON.exists():
        try:
            prior = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
        except Exception:
            prior = {}
    prior_results = prior.get("results", {}) if isinstance(prior, dict) else {}
    prior_load = prior.get("load", {}) if isinstance(prior, dict) else {}

    state: dict[str, Any] = {
        "config": {
            "competitors": wanted_competitors,
            "benchmarks": wanted_benchmarks,
            "sample_size": args.sample_size,
            "threshold": args.threshold,
            "seed": args.seed,
        },
        "samples": {k: {"n_attacks": v["n"], "n_benign": len(benign.get(k, []))}
                    for k, v in samples.items()},
        "results": defaultdict(dict),
        "load": {},
    }
    for c, br in prior_results.items():
        if isinstance(br, dict):
            for b, r in br.items():
                if isinstance(r, dict) and "detection_rate" in r:
                    state["results"][c][b] = r
    for c, l in prior_load.items():
        if isinstance(l, dict) and l.get("status") == "loaded":
            state["load"][c] = l
    _save(state)

    for cname in wanted_competitors:
        if cname not in COMPETITORS:
            print(f"[{cname}] unknown competitor; skipping", file=sys.stderr)
            continue
        # Skip a competitor entirely if resume shows every wanted benchmark is done.
        done_for_this = state["results"].get(cname, {})
        pending = [b for b in wanted_benchmarks
                   if b in samples and samples[b]["n"] > 0
                   and b not in done_for_this]
        if not pending:
            print(f"[{cname}] resume: all benchmarks already complete", file=sys.stderr)
            continue
        entry = COMPETITORS[cname]
        print(f"\n[{cname}] loading {entry['model_id']} ...", file=sys.stderr)
        handle = _load_competitor(entry)
        if handle is None:
            state["load"][cname] = {"status": "blocked", "reason": "model failed to load"}
            state["results"][cname] = {"status": "blocked"}
            _save(state)
            continue
        state["load"][cname] = {
            "status": "loaded",
            "load_seconds": handle["load_seconds"],
            "model_id": entry["model_id"],
            "note": entry.get("note", ""),
        }
        _save(state)

        for bname in wanted_benchmarks:
            if bname not in samples or samples[bname]["n"] == 0:
                state["results"][cname][bname] = {"status": "no_data"}
                _save(state)
                continue
            # Skip if this cell is already recorded from a prior run.
            existing = state["results"].get(cname, {}).get(bname)
            if isinstance(existing, dict) and "detection_rate" in existing:
                print(
                    f"  [{cname} / {bname}] resume: keeping prior result "
                    f"({existing['caught']}/{existing['scanned']})",
                    file=sys.stderr,
                )
                continue
            texts = samples[bname]["texts"]
            print(
                f"  [{cname} / {bname}] scanning {len(texts)} texts",
                file=sys.stderr,
            )
            t0 = time.perf_counter()
            r = _scan_batch(handle, texts, args.threshold)
            r["detection_rate"] = (r["caught"] / r["scanned"]) if r["scanned"] else 0.0

            # Benign FP (Liu only, in practice).
            if benign.get(bname):
                fp = _scan_batch(handle, benign[bname], args.threshold)
                r["benign_scanned"] = fp["scanned"]
                r["benign_fp"] = fp["caught"]
                r["benign_fp_rate"] = (
                    (fp["caught"] / fp["scanned"]) if fp["scanned"] else 0.0
                )
            r["wall_seconds_total"] = time.perf_counter() - t0
            state["results"][cname][bname] = r
            _save(state)

            print(
                f"  [{cname} / {bname}] caught={r['caught']}/{r['scanned']} "
                f"({r['detection_rate'] * 100:.1f}%) "
                f"skipped={r['skipped']} "
                f"in {r['elapsed_seconds']:.1f}s",
                file=sys.stderr,
            )
            if r["elapsed_seconds"] > args.per_competitor_timeout_sec:
                print(
                    f"  [{cname}] exceeded per-benchmark timeout; skipping remaining benchmarks",
                    file=sys.stderr,
                )
                for remaining in wanted_benchmarks[wanted_benchmarks.index(bname) + 1 :]:
                    state["results"][cname].setdefault(
                        remaining, {"status": "timeout_skipped"}
                    )
                _save(state)
                break

        # Release memory between competitors.
        del handle
        try:
            import gc

            gc.collect()
        except Exception:
            pass

    _save(state)
    print("\nWrote", RESULTS_JSON, file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main() or 0)
