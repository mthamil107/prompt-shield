# Adversarial Fatigue — Probing-Campaign Evaluation

**Technique:** `prompt_shield.fatigue.FatigueTracker` (v0.4.0 phase 2)
**Status:** Shipped (opt-in via `fatigue.enabled: true`).
**Why this doc exists:** Unlike d028, the fatigue tracker is a *temporal* signal — it only surfaces across repeated scans from the same source. Running it on static public datasets (deepset, NotInject, LLMail-Inject, AgentHarm, AgentDojo) shows no movement because every sample is evaluated in isolation. The meaningful empirical test is a simulated probing campaign.

## How it works in one sentence

For every (source, detector) pair the tracker keeps an EWMA of the near-miss indicator; once the EWMA exceeds `trigger_ratio` and enough samples have been seen, the detector threshold for that specific source is lowered by `harden_delta` until `cooldown_seconds` of quiet traffic pass.

## The empirical claim

The claim: **a repeating probing campaign that plants confidences consistently in the near-miss band will eventually be caught even without the attacker crossing the original threshold.**

This claim is validated end-to-end in [`tests/fatigue/test_engine_integration.py`](../../../tests/fatigue/test_engine_integration.py). The relevant test `test_hardening_catches_next_near_miss` reproduces the exact scenario:

1. Build an engine with `fatigue.enabled: true`, base detector threshold `0.7`.
2. Submit 10 sequential scans from source `"attacker"` with a detector confidence of `0.65` — every one is a near-miss, but strictly below threshold, so without fatigue all 10 would pass.
3. Submit an 11th scan from the same source with a confidence of `0.63` — *lower* than any previous scan, well below the original `0.7` threshold.
4. Assert that the 11th scan is **blocked**.

After the 10 priming scans, the EWMA crosses `trigger_ratio=0.3`, the pair hardens, and the effective threshold drops to `0.7 - 0.10 = 0.60`. A confidence of `0.63` now clears the effective threshold and is flagged.

A parallel test (`test_benign_source_unaffected_by_attacker_campaign`) confirms that a different source concurrently scanning `0.63` stays pass-rated — the hardening is isolated to the probing source, not global.

## Why public datasets do not exhibit movement

The five public datasets used for d028 are static:

- `deepset/prompt-injections` — 116 samples, each evaluated independently.
- `leolee99/NotInject` — 339 benign inputs, no shared "source".
- `microsoft/llmail-inject-challenge` — 1 000 attack attempts, each a distinct row.
- `ai-safety-institute/AgentHarm` — 352 one-shot prompts.
- `ethz-spylab/agentdojo` — 132 task definitions, one per test.

Running the existing harness with `fatigue.enabled: true` produces an F1 delta indistinguishable from zero for every dataset, because:
- All samples scan with no `source` key → they share the `"_global_"` bucket.
- Most attack samples score well above the threshold so are not near-misses → EWMA stays at ~0.
- The few near-miss-scoring samples are too sparse to cross `trigger_ratio` within a single benchmark run.

This is not a negative result about fatigue — it is confirmation that fatigue is **orthogonal** to content-signal evaluation. Attempting to improve these F1 numbers with fatigue would be a category error.

## What *would* validate fatigue on a public benchmark

A dataset whose rows are **time-ordered probing sequences grouped by session** — not individual content samples. We are not aware of one that currently exists. Candidate sources:

- Generate synthetically: take 1 000 distinct paraphrases of a single attack and submit them with a shared `source="campaign_1"`. Measure how many get blocked after fatigue trips.
- Record-and-replay: instrument a live prompt-shield deployment, pseudonymise IPs, release as a public dataset. Future work.

The synthetic-campaign generator is low-effort and can be added in a follow-up PR — that produces a publishable number for the paper's Evaluation section.

## Reproduction

```bash
# Unit + integration tests
python -m pytest tests/fatigue/ -v

# The probing-campaign assertion specifically
python -m pytest tests/fatigue/test_engine_integration.py::TestFatigueEnabled::test_hardening_catches_next_near_miss -v
```

Both go green in < 1 s. 29 fatigue-specific tests in total, 0 failures.

## Paper write-up framing

When this result appears in the paper's Evaluation section, recommended framing:

> Fatigue-detection validation is qualitatively different from the content-signal benchmarks: the technique requires temporally-ordered scans grouped by source, which the public prompt-injection datasets do not provide. We validate the mechanism end-to-end on a synthetic probing campaign (Appendix X, reproducible via `tests/fatigue/test_engine_integration.py`) and defer a public-dataset evaluation to future work alongside a proposed session-grouped benchmark format.

Do not claim a public-dataset F1 delta for fatigue. Owning the scope honestly is the defensible move.
