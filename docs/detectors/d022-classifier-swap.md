# d022 semantic classifier — swapping the model

`d022_semantic_classifier` loads a HuggingFace text-classification pipeline
whose weights are what actually decide `INJECTION` vs `SAFE`. The model is
swappable via per-detector config; the shipped default is
`protectai/deberta-v3-base-prompt-injection-v2` and stays that way in v0.8.

## Why the default is what it is

Deepset DeBERTa v3 is the most-recall model on this bench (100 / 100 / 100
on Liu / Garak / InjecAgent — see [`docs/papers/evaluation/competitor_rerun.md`
§3.1](../papers/evaluation/competitor_rerun.md)), and there is a real
temptation to ship it as the default. The same 2026-08-19 rerun already
called this out in §4(b):

> Deepset DeBERTa v3's 100 / 100 / 100 is trained-to-flag behaviour,
> not universal superiority.

The 2026-09-22 NotInject FPR probe (§3.4 of the same file) turned that
into a hard number: **Deepset flags 242 of 339 NotInject benign prompts
(71.4% FPR)**, three-quarters of which are inputs a customer would send in
production ("Please enclose the details of the project…", benign
Chinese-language questions about password hygiene). Making Deepset the
default would regress the paper's headline whole-engine NotInject FPR from
0.9–3.8% to something roughly two orders of magnitude worse — published
against yourself.

**ProtectAI v2 alone has 43% FPR on NotInject; the engine's overall
0.9–3.8% NotInject FPR reported in the paper comes from thresholding +
composition with other detectors, not from the classifier alone.** The
composition is what carries the FPR guarantee, so the classifier line is
free to over-defend a little — but not by as much as Deepset does.

## Validated shortlist (2026-09-22)

Numbers are `d022`-shaped: standalone classifier, threshold P(injection) ≥
0.5, no thresholding, no composition. Higher recall is better; lower FPR
is better. Recall from `competitor_rerun.md` §3.1, NotInject FPR from §3.4.

| Model (HF id) | License | Liu 200 | Garak 500 | InjecAgent 500 | NotInject FPR | Verdict |
|---|---|---:|---:|---:|---:|---|
| `protectai/deberta-v3-base-prompt-injection-v2` **(default)** | Apache-2.0 | 63.5% | 44.5% | 83.4% | 43.4% | Ship default — worst-recall of the reasonable set but relied on by the engine's composition math |
| `leolee99/PIGuard` | MIT (requires `trust_remote_code=True`) | 85.5% | 77.3% | 80.6% | **11.5%** | **Best independent classifier here.** Higher recall + ~4× lower FPR than the default. Swap-in candidate for deployments that want a stronger `d022` without falling back to the whole engine. |
| `deepset/deberta-v3-base-injection` | MIT | 100% | 100% | 100% | **71.4%** | **Not recommended.** The 100/100/100 is trained-to-flag; 71% NotInject FPR is disqualifying on mixed traffic. Use only if you know your traffic is nearly all adversarial. |
| `meta-llama/Llama-Prompt-Guard-2-86M` | Meta gated licence | 44.0% | 56.3% | 56.0% | 4.4% | Lowest recall, lowest FPR. Behind the Meta acceptance gate — see `competitor_rerun.md` §5. |

## How to swap

Per-detector config (YAML shown; JSON works the same):

```yaml
detectors:
  d022_semantic_classifier:
    enabled: true
    config:
      model_name: leolee99/PIGuard
      # PIGuard requires trust_remote_code; this is set inside d022 for
      # this model automatically when the transformers pipeline is loaded.
      device: cpu
      # Chunking (optional): defaults are chunk_size=512, chunk_stride=384,
      # max_chunks=8. These are correct for the DeBERTa/PromptGuard family;
      # override only if you understand the max-pool aggregation in d022.
```

The pipeline is loaded lazily on the first `detect()` call. If the model
isn't in the local HF cache, the first request will attempt a network
fetch — for air-gapped deployments, pre-populate the cache with
`huggingface-cli download <model_name>` at install time.

The `transformers` dependency ships behind the `[ml]` extra:

```bash
pip install "prompt-shield-ai[ml]"
```

Without it, `d022` returns `detected=False` on every call — regex-only
protection still runs, but classifier-shaped attacks bypass this
detector.

## Caveats before you swap

- The engine's composed FPR guarantee (paper §5.5) is measured with the
  ProtectAI default. Swapping to PIGuard is very likely a net win on
  independent traffic (higher recall + lower FPR), but the composed
  guarantee **has not been re-measured** with any other classifier. If
  you swap, run `python docs/papers/evaluation/run_public_datasets.py`
  against your traffic profile before publishing an FPR figure.
- All four models were measured on CPU. PIGuard's per-scan latency is
  ~4/sec (vs. ProtectAI's ~10/sec) per `competitor_rerun.md` §3.2 — a
  ~2× throughput cost for the recall/FPR improvement.
- `d022` uses `pipeline("text-classification")` with `truncation=True`
  and `max_length=512`; longer inputs are handled by the sliding-window
  chunking in `d022_semantic_classifier.py::_chunk`, which max-pools the
  per-chunk `INJECTION` score. This is independent of which model you
  swap in — every classifier in the shortlist above uses the same
  512-token cap.

## Reproducing the FPR numbers

```bash
# Two-model probe (Deepset vs ProtectAI):
python docs/papers/evaluation/notinject_fpr/run_deepset_protectai.py

# Two-model probe (PIGuard + Meta PromptGuard 2):
python docs/papers/evaluation/notinject_fpr/run_piguard_pg2.py

# Full head-to-head rerun (recall table):
python docs/papers/evaluation/competitor_rerun.py
```

All three run offline from the local HF cache; the models must have been
downloaded once (see [`competitor_rerun.md`](../papers/evaluation/competitor_rerun.md)
§6, and [`notinject_fpr/README.md`](../papers/evaluation/notinject_fpr/README.md)
for the FPR-probe context and cross-validation).
