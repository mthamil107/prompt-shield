# prompt-shield vs. Liu et al. (USENIX Security 2024) attack strategies

**Run date:** 2026-05-07
**Script:** [`tests/benchmark_liu_attackers.py`](../../../tests/benchmark_liu_attackers.py)

## Source

Liu, Y., et al. *Formalizing and Benchmarking Prompt Injection Attacks and Defenses.* USENIX Security 2024.
Code: <https://github.com/liu00222/Open-Prompt-Injection>

Liu et al. define five attack strategies — `Naive`, `EscapeChar`, `Ignore`, `FakeComp`, `Combine` — each as a deterministic string template that concatenates a benign data prompt with an injected instruction and data. Their primary metric is **Attack Success Value (ASV)**: whether the underlying LLM is fooled into performing the injected task.

## What this evaluation measures

ASV is a property of the *protected LLM*, not of an input-side firewall. prompt-shield is a detector, so we report a complementary quantity — **detection rate**: the fraction of Liu-generated attacks that prompt-shield flags or blocks before the LLM ever sees them.

A direct head-to-head against Liu's *DataSentinel* defense (IEEE S&P 2025) requires running their fine-tuned checkpoint locally and is left for future work. The numbers below characterise prompt-shield's coverage on the attack distribution Liu et al. defined; they do not, by themselves, support a claim of superiority over DataSentinel.

## Setup

- Attack matrix: 5 strategies × 8 benign clean prompts × 5 injection payloads = **200 attack inputs**
- Benign baseline: 8 clean prompts (sentiment, spam, hate-detection, summarization, grammar correction, math) scanned alone to verify false-positive rate.
- Two engine configurations:
  - **Config A:** regex-only (`d022_semantic_classifier` disabled). Reproducible without a GPU.
  - **Config B:** full engine including the d022 DeBERTa-v3 ML classifier.

## Results

### Benign false-positive rate

| Config | FP / total | FPR |
|---|---:|---:|
| A (regex-only) | 0 / 8 | 0.0% |
| B (with d022 ML) | 0 / 8 | 0.0% |

### Detection rate by strategy

| Strategy   | Config A (regex-only) | Config B (with ML) |
|------------|----------------------:|-------------------:|
| Naive      | 40.0% (16/40)         | 40.0% (16/40)      |
| EscapeChar | 40.0% (16/40)         | 40.0% (16/40)      |
| Ignore     | **100.0% (40/40)**    | **100.0% (40/40)** |
| FakeComp   | 40.0% (16/40)         | 40.0% (16/40)      |
| Combine    | **100.0% (40/40)**    | **100.0% (40/40)** |
| **OVERALL**| **64.0% (128/200)**   | **64.0% (128/200)** |

## Findings

1. **Override-keyword attacks are fully caught.** Both `Ignore` and `Combine` (which contains the literal "Ignore previous instructions" phrase) are caught at 100% by the regex `d003_instruction_override` detector.

2. **Subtle task-hijacking attacks evade the current pipeline.** `Naive`, `EscapeChar`, and `FakeComp` attacks reach 40% detection. The 16/40 caught are attacks whose *injected data* happens to contain a separately-flagged pattern (e.g. the injection asks for the system prompt, which `d001` catches). The remaining 24/40 — those where both the injected instruction and the injected data look like ordinary application content — produce **score 0.0 across all 29 detectors**.

3. **The ML classifier (d022) does not close the gap on this attack class.** Config B is identical to Config A. d022 is trained on prompt-injection-style content; the Liu task-hijacking attacks do not match that distribution because every individual token in them is, in isolation, a plausible legitimate request.

4. **This is the exact gap DataSentinel targets.** Liu et al.'s DataSentinel is a fine-tuned model specifically trained on these subtle task-hijacking patterns, which explains why their reported numbers exceed what a general-purpose regex+ML firewall achieves.

## Implications for prompt-shield

- The current detector suite is strongest where attacks contain explicit override or extraction language and weakest where the injection is a *plausible-looking task instruction*.
- A future detector targeting "data/instruction boundary inversion" — i.e., the structural pattern of a clean prompt followed by an unrelated task instruction — would close this gap. This is the natural complement to d029 (many-shot structural) and d027 (stylometric discontinuity).
- The benign FPR remains 0% in both configurations, so adding a future Liu-style detector has headroom on the false-positive side.

## Honest caveats

- 8 clean prompts and 5 injection payloads is a small evaluation set; numbers are indicative, not definitive. Liu et al. evaluate on full SST-2 / SMS-Spam test splits (hundreds of examples per task).
- A proper head-to-head against DataSentinel requires running their checkpoint on the same inputs and is *not* included here.
- The clean prompts were curated to span Liu's task domains but were not sampled from their exact dataset releases.

## Cite as

Future paper section may cite this as:

> We evaluate prompt-shield against the five attack strategies defined by Liu et al. (USENIX Security 2024). Our regex-and-ML pipeline achieves 100% detection on attacks containing explicit override language (`Ignore`, `Combine`) but only 40% on subtle task-hijacking variants (`Naive`, `EscapeChar`, `FakeComp`) that lack such markers — confirming the niche addressed by Liu's *DataSentinel* (IEEE S&P 2025).
