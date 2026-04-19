"""Public-dataset evaluation harness for d028 Smith-Waterman alignment.

Runs prompt-shield over:
- deepset/prompt-injections (test split: 60 injection + 56 benign)
- leolee99/NotInject (all three splits: 339 benign, FP test)

For each dataset it runs TWO configurations in-process:

    treatment = prompt-shield with d028 enabled (all 27 detectors)
    control   = prompt-shield with d028 disabled (26 detectors, the
                pre-v0.4.0 baseline)

The delta between the two is the concrete numeric evidence of d028's
contribution — what the paper's Evaluation section needs.

ML detectors (d022 semantic classifier) are disabled in both configs so
the comparison isolates d028's regex-alignment contribution and matches
the benchmark used in `tests/baseline_v0.3.3.txt`.

Outputs JSON to `docs/papers/evaluation/d028_public_datasets.json` and
a human-readable markdown table to
`docs/papers/evaluation/d028_public_datasets.md`. Safe to re-run.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from datasets import load_dataset

from prompt_shield.engine import PromptShieldEngine

OUT_DIR = Path(__file__).parent
JSON_OUT = OUT_DIR / "d028_public_datasets.json"
MD_OUT = OUT_DIR / "d028_public_datasets.md"


def _make_engine(*, d028_enabled: bool) -> PromptShieldEngine:
    """Build a scan engine with d022 off and d028 toggleable."""
    return PromptShieldEngine(
        config_dict={
            "prompt_shield": {
                "mode": "block",
                "threshold": 0.7,
                "vault": {"enabled": False},
                "feedback": {"enabled": False},
                "canary": {"enabled": False},
                "history": {"enabled": False},
                "detectors": {
                    "d022_semantic_classifier": {"enabled": False},
                    "d028_sequence_alignment": {"enabled": d028_enabled},
                },
            }
        }
    )


@dataclass
class Metrics:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    elapsed_s: float = 0.0

    @property
    def n(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "tp": self.tp,
            "tn": self.tn,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
            "elapsed_s": round(self.elapsed_s, 2),
            "throughput_per_s": round(self.n / self.elapsed_s, 1) if self.elapsed_s else 0.0,
        }


def _score(samples: list[tuple[str, bool]], *, d028_enabled: bool) -> Metrics:
    """Scan every sample with the given config and return metrics."""
    eng = _make_engine(d028_enabled=d028_enabled)
    m = Metrics()
    start = time.perf_counter()
    for text, is_attack in samples:
        try:
            report = eng.scan(text)
            detected = report.action.value in ("block", "flag") or report.overall_risk_score >= 0.5
        except Exception:
            detected = False
        if is_attack and detected:
            m.tp += 1
        elif is_attack and not detected:
            m.fn += 1
        elif (not is_attack) and detected:
            m.fp += 1
        else:
            m.tn += 1
    m.elapsed_s = time.perf_counter() - start
    return m


def _load_deepset() -> list[tuple[str, bool]]:
    ds = load_dataset("deepset/prompt-injections", split="test")
    return [(row["text"], row["label"] == 1) for row in ds]


def _load_notinject() -> list[tuple[str, bool]]:
    samples: list[tuple[str, bool]] = []
    for split in ("NotInject_one", "NotInject_two", "NotInject_three"):
        try:
            ds = load_dataset("leolee99/NotInject", split=split)
            for row in ds:
                text = row.get("prompt", row.get("text", ""))
                if text and text.strip():
                    samples.append((text, False))
        except Exception as exc:  # noqa: BLE001
            print(f"  warn: split {split}: {exc}")
    return samples


def _load_llmail_inject(max_samples: int = 1000) -> list[tuple[str, bool]]:
    """Load the first ``max_samples`` entries from LLMail-Inject Phase1.

    Every row in the LLMail-Inject challenge is an attempted email-based
    prompt injection, so we treat every sample as an attack (label=True)
    and measure recall. We cap at 1000 rows to bound runtime — the full
    dataset is ~200K.
    """
    ds = load_dataset("microsoft/llmail-inject-challenge", split="Phase1", streaming=True)
    samples: list[tuple[str, bool]] = []
    for i, row in enumerate(ds):
        if i >= max_samples:
            break
        subject = str(row.get("subject", ""))
        body = str(row.get("body", ""))
        text = f"Subject: {subject}\n\n{body}".strip()
        if text:
            samples.append((text, True))
    return samples


def _load_agentharm() -> list[tuple[str, bool]]:
    """Load AgentHarm harmful (attacks) and harmless_benign (negatives)."""
    samples: list[tuple[str, bool]] = []
    try:
        harmful = load_dataset("ai-safety-institute/AgentHarm", "harmful", split="test_public")
        for row in harmful:
            text = row.get("prompt") or row.get("detailed_prompt") or ""
            if text.strip():
                samples.append((text, True))
    except Exception as exc:  # noqa: BLE001
        print(f"  warn: AgentHarm harmful: {exc}")
    try:
        benign = load_dataset(
            "ai-safety-institute/AgentHarm", "harmless_benign", split="test_public"
        )
        for row in benign:
            text = row.get("prompt") or row.get("detailed_prompt") or ""
            if text.strip():
                samples.append((text, False))
    except Exception as exc:  # noqa: BLE001
        print(f"  warn: AgentHarm harmless_benign: {exc}")
    return samples


_AGENTDOJO_CACHE = OUT_DIR / "agentdojo_tasks.json"


def _load_agentdojo() -> list[tuple[str, bool]]:
    """Extract AgentDojo v1.2.1 injection_tasks (attacks) + user_tasks (benign).

    Each suite's ``injection_task.GOAL`` is the attacker-controlled string the
    LLM sees; ``user_task.PROMPT`` is a legitimate user request. On Python 3.14
    the package hits a circular import unless ``agentdojo.task_suite.task_suite``
    is imported before the default-suites package, so we stagger explicitly.

    Results are cached to ``agentdojo_tasks.json`` — re-run with that file
    deleted to re-extract.
    """
    if _AGENTDOJO_CACHE.is_file():
        data = json.loads(_AGENTDOJO_CACHE.read_text(encoding="utf-8"))
        return [(row["text"], row["kind"] == "injection") for row in data]

    import agentdojo.task_suite.task_suite  # noqa: F401 — load first
    import agentdojo.default_suites.v1_2_1  # noqa: F401 — then register
    from agentdojo.task_suite.load_suites import get_suites

    records: list[dict] = []
    for suite_name, suite in get_suites("v1.2.1").items():
        for tid, task in suite.injection_tasks.items():
            goal = str(getattr(task, "GOAL", "")).strip()
            if goal:
                records.append({"suite": suite_name, "kind": "injection", "id": tid, "text": goal})
        for tid, task in suite.user_tasks.items():
            prompt = str(getattr(task, "PROMPT", "")).strip()
            if prompt:
                records.append({"suite": suite_name, "kind": "user", "id": tid, "text": prompt})
    _AGENTDOJO_CACHE.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    return [(r["text"], r["kind"] == "injection") for r in records]


def _delta(tx: Metrics, ctrl: Metrics) -> dict:
    """Compute the treatment-minus-control delta for each metric."""
    return {
        "recall_pp": round((tx.recall - ctrl.recall) * 100, 2),
        "f1_pp": round((tx.f1 - ctrl.f1) * 100, 2),
        "accuracy_pp": round((tx.accuracy - ctrl.accuracy) * 100, 2),
        "fpr_pp": round((tx.fpr - ctrl.fpr) * 100, 2),
        "tp_delta": tx.tp - ctrl.tp,
        "fp_delta": tx.fp - ctrl.fp,
        "fn_delta": tx.fn - ctrl.fn,
    }


def _summary(samples: list[tuple[str, bool]]) -> str:
    att = sum(1 for _, a in samples if a)
    ben = sum(1 for _, a in samples if not a)
    return f"{len(samples)} samples ({att} attack + {ben} benign)"


def main() -> None:
    print("Loading datasets (using HF cache)...")
    loaders: list[tuple[str, callable]] = [
        ("deepset/prompt-injections", _load_deepset),
        ("leolee99/NotInject", _load_notinject),
        ("microsoft/llmail-inject-challenge (Phase1, 1000 subset)", _load_llmail_inject),
        ("ai-safety-institute/AgentHarm", _load_agentharm),
        ("ethz-spylab/agentdojo (v1.2.1)", _load_agentdojo),
    ]
    loaded: list[tuple[str, list[tuple[str, bool]]]] = []
    for name, loader in loaders:
        try:
            samples = loader()
            if samples:
                loaded.append((name, samples))
                print(f"  {name}: {_summary(samples)}")
            else:
                print(f"  {name}: empty — skipping")
        except Exception as exc:  # noqa: BLE001
            print(f"  {name}: FAILED to load — {exc}")

    results: dict[str, dict] = {
        "environment": {
            "note": "Both configurations disable d022 semantic classifier for speed; the delta isolates d028 (Smith-Waterman alignment) against the 26-detector regex baseline.",
            "threshold": 0.7,
            "block_cutoff_risk_score": 0.5,
        },
        "datasets": {},
    }

    for name, samples in loaded:
        print(f"\nEvaluating {name} ...")

        print("  control  (d028 disabled) ...", end="", flush=True)
        ctrl = _score(samples, d028_enabled=False)
        print(f" f1={ctrl.f1:.3f} recall={ctrl.recall:.3f} fpr={ctrl.fpr:.3f}")

        print("  treatment(d028 enabled ) ...", end="", flush=True)
        tx = _score(samples, d028_enabled=True)
        print(f" f1={tx.f1:.3f} recall={tx.recall:.3f} fpr={tx.fpr:.3f}")

        results["datasets"][name] = {
            "sample_count": len(samples),
            "attack_count": sum(1 for _, a in samples if a),
            "benign_count": sum(1 for _, a in samples if not a),
            "control_26_detectors": ctrl.as_dict(),
            "treatment_27_detectors_with_d028": tx.as_dict(),
            "delta_treatment_minus_control": _delta(tx, ctrl),
        }

    # Write JSON
    JSON_OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote {JSON_OUT}")

    # Write markdown
    lines: list[str] = [
        "# d028 Smith-Waterman — public-dataset evaluation",
        "",
        "Evidence that d028 moves the needle on standard public benchmarks, captured as ",
        "the first checkbox in [`project_evaluation_matrix.md`](https://doi.org/10.5281/zenodo.19644135).",
        "",
        "Both configurations use the same 26-regex baseline with `d022_semantic_classifier` ",
        "off. The only independent variable is `d028_sequence_alignment` (enabled in treatment, ",
        "disabled in control). `threshold=0.7`, scan result counted as a detection if ",
        "`action in {block, flag}` or `risk_score >= 0.5`, matching `tests/benchmark_public_datasets.py`.",
        "",
    ]
    for ds_name, row in results["datasets"].items():
        ctrl = row["control_26_detectors"]
        tx = row["treatment_27_detectors_with_d028"]
        delta = row["delta_treatment_minus_control"]
        lines.append(f"## {ds_name} ({ctrl['n']} samples)")
        lines.append("")
        lines.append("| Config | TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | Speed |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        lines.append(
            f"| **Control** (26 detectors, no d028) | {ctrl['tp']} | {ctrl['tn']} | {ctrl['fp']} | {ctrl['fn']} | "
            f"{ctrl['precision']:.3f} | {ctrl['recall']:.3f} | **{ctrl['f1']:.3f}** | {ctrl['accuracy']:.3f} | {ctrl['fpr']:.3f} | "
            f"{ctrl['throughput_per_s']:.0f}/s |"
        )
        lines.append(
            f"| **Treatment** (27 detectors, with d028) | {tx['tp']} | {tx['tn']} | {tx['fp']} | {tx['fn']} | "
            f"{tx['precision']:.3f} | {tx['recall']:.3f} | **{tx['f1']:.3f}** | {tx['accuracy']:.3f} | {tx['fpr']:.3f} | "
            f"{tx['throughput_per_s']:.0f}/s |"
        )
        lines.append(
            f"| **Delta** | {delta['tp_delta']:+d} | — | {delta['fp_delta']:+d} | {delta['fn_delta']:+d} | — | "
            f"**{delta['recall_pp']:+.2f} pp** | — | **{delta['accuracy_pp']:+.2f} pp** | {delta['fpr_pp']:+.2f} pp | — |"
        )
        lines.append("")
    MD_OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {MD_OUT}")


if __name__ == "__main__":
    main()
