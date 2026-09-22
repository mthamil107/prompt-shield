# NotInject FPR probe for `d022` swap candidates

Extends [`competitor_rerun.md`](../competitor_rerun.md) §3.3 (Liu-benign,
n=8) with the larger [NotInject](https://huggingface.co/datasets/leolee99/not_inject)
benign corpus (n=339) for the same four HF classifiers, because Liu's
8-prompt denominator is too small to separate a well-calibrated
classifier from a trained-to-flag one.

## Why this exists

The 2026-08-19 head-to-head reported Deepset DeBERTa v3 at 100 / 100 /
100 on Liu / Garak / InjecAgent and already flagged in §4(b) that this
was "trained-to-flag behaviour, not universal superiority." The Liu-8
FPR (2/8 = 25%) hinted at the problem but wasn't a hard number. This
probe measures against 339 benign prompts on the same harness so the
`d022` swap decision has a comparable FPR column, not just a recall
column.

## Method

Same tokenizer / model / softmax / threshold / truncation as
[`competitor_rerun.py`](../competitor_rerun.py). Offline against local
HF cache. Batch size 16.

- `run_deepset_protectai.py` — Deepset + ProtectAI v2 (originally
  scripted 2026-09-21 as the two-model FPR probe).
- `run_piguard_pg2.py` — extension to PIGuard (with `trust_remote_code=True`)
  and Meta Prompt Guard 2 (weights must already be in the HF cache).

## Results (combined)

See [`results.txt`](results.txt) for the raw probe output including the
three highest-scoring false positives per model.

| Model | NotInject FP / total | NotInject FPR | Liu-benign FPR (§3.3) |
|---|---:|---:|---:|
| meta-llama/Llama-Prompt-Guard-2-86M | 15 / 339 | 4.4% | 0.0% |
| leolee99/PIGuard | 39 / 339 | 11.5% | 0.0% |
| protectai/deberta-v3-base-prompt-injection-v2 (default) | 147 / 339 | 43.4% | 0.0% |
| deepset/deberta-v3-base-injection | 242 / 339 | 71.4% | 25.0% |

Cross-check: InjecGuard (arXiv 2410.22770, Table 1) reports Deepset
over-defense-accuracy 5.31% and benign-accuracy 34.06%; ProtectAI
56.64%. Our 43.4% ProtectAI FPR ↔ 56.6% benign-accuracy — 0.06 pp from
InjecGuard's independent number, so the harness is validated.

## Reproducing

```bash
python docs/papers/evaluation/notinject_fpr/run_deepset_protectai.py
python docs/papers/evaluation/notinject_fpr/run_piguard_pg2.py
```

Both need `NotInject` (`leolee99/not_inject`) and
`deepset/prompt-injections` already downloaded once via `datasets`, plus
the four model weights in the HF cache (see
[`competitor_rerun.md`](../competitor_rerun.md) §6).

## Consequence for `d022`

See [`docs/detectors/d022-classifier-swap.md`](../../../detectors/d022-classifier-swap.md).
Short version: shipped default stays ProtectAI v2; PIGuard is the
recommended swap for deployments that want a stronger classifier
without falling back to the whole engine; Deepset is not recommended
as a default at any FPR budget you would ship to mixed traffic.
