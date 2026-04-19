# Evaluation Analysis — d028 Smith-Waterman alignment

**Date:** 2026-04-19
**Scope:** Five public datasets (deepset, NotInject, LLMail-Inject, AgentHarm, AgentDojo) with `d028_sequence_alignment` toggled on vs off, keeping every other detector constant. ML detector `d022_semantic_classifier` is disabled in both configurations so the delta isolates d028's regex-alignment contribution.
**Reproduction:** `python docs/papers/evaluation/run_public_datasets.py`. Raw numbers live in [`d028_public_datasets.json`](d028_public_datasets.json) and [`d028_public_datasets.md`](d028_public_datasets.md).

## Headline

| Dataset | Samples | d028-off F1 | d028-on F1 | ΔF1 | ΔRecall | ΔFPR | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| deepset/prompt-injections | 116 | 0.033 | **0.378** | **+34.5 pp** | +21.7 pp | +0.0 pp | Strong win |
| leolee99/NotInject | 339 (all benign) | — | — | — | — | **+2.95 pp** | Regression |
| LLMail-Inject Phase1 (1k) | 1000 | 0.989 | 0.990 | +0.001 | +0.2 pp | +0.0 pp | Saturated |
| AgentHarm | 352 | 0.319 | 0.319 | 0.0 | 0.0 | 0.0 | No effect |
| AgentDojo v1.2.1 | 132 | 0.540 | 0.537 | −0.003 | +2.9 pp | +3.1 pp | Neutral-to-slightly-negative |

## Per-dataset interpretation

### deepset/prompt-injections — the canonical prompt-injection benchmark

- Regex baseline: catches **1 of 60** injections (recall 1.7%, F1 0.033).
- With d028: catches **14 of 60** (recall 23.3%, F1 0.378). **Zero additional false positives.**
- d028 is doing exactly what the design predicted: the dataset is dominated by paraphrased and reworded attacks that verbatim regex can't see but synonym-aware local alignment can. The +34.5 pp F1 improvement is the strongest single-technique result in this evaluation.
- Open-ended: 46 of 60 attacks still pass even with d028. Further techniques (d022 ML, d027 stylometric, d029 spectral) should target those specifically.

### leolee99/NotInject — false-positive stress test

- 339 benign inputs that use attack-adjacent vocabulary in innocuous ways.
- Regex baseline FPR: **3 / 339 = 0.9 %** (already noisy).
- With d028: **13 / 339 = 3.8 %** — d028 adds **10 false positives**.
- This is the real cost of d028's permissive synonym matching: inputs that mention "rules", "instructions", "previous", or "system" in legitimate contexts can accumulate enough alignment score to cross threshold.
- Action items:
    1. Raise d028's strict-above threshold from 0.60 to 0.63 and re-measure; the FPs likely cluster near the boundary.
    2. Narrow the most-common synonym groups (`reveal / expose family`, `previous / above family`) — the current definition is too generous.
    3. Consider a complementary benign-vocabulary dampener: if no distinctive attack token ("override", "jailbreak", "DAN") is present in the matched region, halve the score.

### microsoft/llmail-inject-challenge — saturated (regex already wins)

- 1000-row subset of Phase 1 submissions. Every row is an attempted email-based injection.
- Regex baseline: **978 / 1000** (recall 97.8 %).
- With d028: **980 / 1000** (+2 TPs, recall 98.0 %).
- The baseline is already saturated — these attacks were designed to beat then-deployed LLM filters, but they use direct instruction-override phrasing that `d001/d003` catch. d028's synonym matching is mostly redundant here.
- Takeaway for the paper: do NOT use LLMail-Inject as the headline benchmark; the attack distribution is too easy for any competent regex detector. Cite it to show **saturation** (robustness to variation is maintained) but not to claim improvement.

### AgentHarm — orthogonal attack class

- 176 "harmful" multi-step agent tasks + 176 "harmless_benign" control tasks. The harmful prompts are things like *"Generate a propaganda video showing politician X doing Y"* — intent-based harmfulness, not classical prompt injection.
- Both configurations land at **F1 0.319, recall 0.250, FPR 31.8 %**. d028 literally makes zero change because the harmful tasks don't contain d028's attack-vocabulary — they're requests framed as normal agent work.
- The 31.8 % FPR on benign AgentHarm is itself a finding: existing regex detectors fire spuriously on multi-step agent prompts because phrases like "access the admin panel" or "retrieve user credentials" appear in legitimate agent workflows. This is a motivated lead for the **taint-tracking** technique (#7): intent-and-provenance, not pattern matching, is the right signal here.
- Takeaway: honestly report that prompt-injection detection ≠ agent-harm detection, and that d028 does not generalise to this class. The honest framing is what makes the paper credible.

### ethz-spylab/agentdojo — agentic injection-in-tool-output

- 35 injection tasks (attacker-controlled `GOAL` strings injected into tool outputs) + 97 benign user tasks across banking, slack, travel, workspace suites.
- Regex baseline: F1 **0.540**, recall 48.6 %, FPR 11.3 % (11 FPs on 97 benign).
- With d028: F1 **0.537**, recall 51.4 % (+1 TP), FPR 14.4 % (+3 FPs). Net F1 slightly negative.
- Similar profile to NotInject: d028 catches a few more true positives but at a proportional FPR cost. The FPs are benign user_tasks that contain legitimate action verbs (send, reveal, display) paired with benign nouns (message, report) that the synonym matrix happens to bridge.
- Strong motivation for technique #3 (honeypot tools): AgentDojo injections are payloads smuggled through tool return values. Catching them via text analysis is fundamentally harder than treating any invocation of a never-real decoy tool as a confirmed injection. This is exactly where taint tracking + honeypots should dominate.

## Takeaways for the paper rewrite

1. **Lead with deepset.** +34.5 pp F1 with zero FPR cost is the defensible claim of the seven-technique paper. Put this number in the abstract.
2. **Report the NotInject cost honestly.** Don't hide the +2.95 pp FPR — lead reviewers like Wagner notice, and owning the tradeoff is the credibility play. Frame it as "d028 requires threshold tuning on benign-vocabulary-heavy workloads" with the concrete +0.63 tuning experiment planned.
3. **Do not overclaim LLMail-Inject.** Saturation means both configs get ~99 %, which reviewers will read as "this benchmark is easy" — don't cite it as the primary win.
4. **AgentHarm and AgentDojo motivate the other techniques.** The paper should explicitly say "d028 is not built for this attack class; technique #3 (honeypot) and #7 (taint) target it directly." This turns "d028 didn't move AgentDojo" from a weakness into a structural argument for the full seven-technique portfolio.
5. **Competitor comparison is still owed.** These numbers are all d028-on vs d028-off with our own detectors; the external comparison against Rebuff / Lakera / Meta Prompt Guard 2 / PIGuard on the same datasets is in `tests/benchmark_public_datasets.py` but needs to be rerun with d028 on and added to this report.

## Follow-up benchmarks not yet covered

- **ASB (Agent Security Bench)** — not available on HuggingFace under `agiresearch/ASB`; network access to the main fileset failed. Likely needs the full framework installed from GitHub. Deferred.
- **Adaptive attacks** (NAACL 2025 / ICLR 2025 methodology) — not yet constructed. Planned for the Evaluation v2 report once d027 and d029 land.
- **Multi-detector combinations** (d022 ML on, d028 on) — the current run isolates d028 on purpose; a later matrix should quantify diminishing returns when detectors stack.

## How to re-run

```bash
# one-off, ~5 minutes on a laptop
python docs/papers/evaluation/run_public_datasets.py

# Outputs
# docs/papers/evaluation/d028_public_datasets.json   — raw metrics
# docs/papers/evaluation/d028_public_datasets.md     — per-dataset tables (auto-generated)
# docs/papers/evaluation/agentdojo_tasks.json        — extracted injection/user tasks (cached)
```
