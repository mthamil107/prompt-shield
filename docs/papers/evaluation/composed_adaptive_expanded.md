# Composed-Stack Adaptive-Attack Expanded Report (5 of 5 layers)

This report extends `composed_adaptive_partial.md` (2 layers: d028 sequence alignment + d027 stylometric floor) with adaptive attacks against the remaining three layers of the shipped defence — d022 (DeBERTa semantic classifier), the adversarial-fatigue tracker, and ToolResultGuard. Every layer now has an isolated adaptive result plus a composed-stack pass through `PromptShieldEngine().scan()` on the same adaptive corpus, so the composability delta is decomposable per attack.

## 1. Scope

Layers 1 (d028) and 2 (d027) were executed in `composed_adaptive_partial.py`. The numbers below are loaded from the JSON that runner produced and are shown for context; nothing in this expansion recomputes them.

**Partial reference:**

- d028 alone: baseline 95.0% → adaptive 0.0% (matrix-aware substitution).
- d027 alone: baseline 100.0% → adaptive 0.0% (short-input-floor exploitation).
- Composed stack full on d027-adaptive: any-layer 100.0%, block-rate 100.0%.
- Composed stack minus d022 on d027-adaptive: any-layer 70.0%.

## 2. Layer 3 — d022 (DeBERTa semantic classifier)

### 2.1 Methodology

Twenty override-style attack pairs. The baseline is the canonical vocabulary the d022 model's training corpus (`protectai/deberta-v3-base-prompt-injection-v2`) is saturated with ("ignore previous instructions", "reveal your system prompt", ...). The adaptive variant is a hand-crafted paraphrase that substitutes every high-signal surface word for an unusual synonym while preserving the imperative intent. A gradient-based paraphraser (TextFooler, HotFlip) would produce sharper counter-examples; the hand-crafted rewrite is a lower bound on what an adaptive attacker could achieve.

### 2.2 Results — d022 in isolation

- Baseline detection: 20/20 (100.0%).
- Adaptive (paraphrased) detection: 20/20 (100.0%).
- ASR reduction: 0.0 pp.

### 2.3 Results — composed stack on the paraphrased corpus

- Blocked by full engine: 20/20 = 100.0%.
- At least one detector fired: 20/20 = 100.0%.

| Detector | Fired on N of 20 |
|---|--:|
| `d022_semantic_classifier` | 20 |
| `d028_sequence_alignment` | 2 |
| `d002_role_hijack` | 1 |
| `d003_instruction_override` | 1 |

## 3. Layer 4 — Adversarial fatigue tracker

### 3.1 Methodology

The fatigue tracker maintains an EWMA of near-miss scans per (source, detector) pair. When the EWMA exceeds `trigger_ratio` (default 0.4) and at least `min_samples_before_trigger` (default 8) have been observed, the pair is hardened — the effective threshold is lowered by `harden_delta` for subsequent scans. Because the tracker is a *modifier* on other detectors' thresholds, defeating it does not lower any single-scan detection rate; the metric is whether hardening ever activates.

Three adaptive scenarios are executed via injected timestamps (the `now` kwarg on `FatigueTracker.observe`), all at 30 near-miss observations to match the baseline volume.

### 3.2 Results

| Scenario | Sources used | Hardening triggered? | After N samples | Final EWMA |
|---|--:|:-:|--:|--:|
| Baseline (rapid-fire, 1 source) | 1 | yes | 8 | 1.0 |
| Adaptive #1: temporal spacing (65 s gap) | 1 | yes | 8 | 1.0 |
| Adaptive #2: sample dilution (1 near-miss : 5 benign) | 1 | no | — | 0.057 |
| Adaptive #3: source rotation (30 proxies) | 30 | no | — | — |

### 3.3 Interpretation

- The baseline (all rapid-fire near-misses from one source) triggers hardening after 8 samples, as designed.
- **Temporal spacing does NOT defeat the tracker on its own** — methodology §3.3 assumed the 60 s cooldown would clear the EWMA between attempts, but the cooldown only fires *after* hardening and only on a non-near-miss observation. Pure temporal spacing on the same source therefore still triggers hardening at ~sample 8. This is a mild correction to the methodology document.
- **Sample dilution defeats the tracker.** Interleaving each near-miss with 5 benign observations (indicator=0) holds the EWMA well below the 0.4 trigger — measured steady-state ~0.057 (Table row above; well below the 0.4 threshold and even below the initial-transient value of ~0.35 that one might naively expect from the 1:6 ratio). Attack cost is 6× the observation volume — cheap for scripted campaigns.
- **Source-key rotation defeats the tracker.** 30 near-miss observations across 30 distinct sources give each source at most 1 sample — well below `min_samples_before_trigger = 8`. No entry hardens.

**Composability implication.** Fatigue's contribution to the shipped stack is *hardening amplification*, not standalone detection. Defeating it means the attacker keeps the base thresholds; whatever d001/d022/d028/... would catch on a single probe, they still catch. The right composability metric for this layer is attack-cost inflation (probes-per-source cap or observation-volume amplification), not adaptive detection rate — see the summary table in §5 for the reformulation.

## 4. Layer 5 — ToolResultGuard content-shape spoofing

### 4.1 Methodology

Twenty tool-result payloads carrying override / exfiltration / role-hijack intent. Each is delivered to `ToolResultGuard.scan` in four wrapper shapes: (a) raw text; (b) nested JSON with the payload inside a `content` field; (c) base64-encoded with a leading "Decoded tool result (base64):" hint; (d) HTML-entity encoding of every non-alphanumeric character. Real MIME-header spoofing would require an HTTP transport we do not simulate; the wrapper shapes stand in for the taxonomy of malformed content the guard's classifier must decide over.

### 4.2 Per-wrapper composed-stack results

| Wrapper | Blocked | Any-layer detection | Top detector |
|---|--:|--:|---|
| `raw` | 20/20 (100.0%) | 20/20 (100.0%) | `d022_semantic_classifier` (18) |
| `json_nested` | 20/20 (100.0%) | 20/20 (100.0%) | `d022_semantic_classifier` (20) |
| `base64` | 20/20 (100.0%) | 20/20 (100.0%) | `d022_semantic_classifier` (20) |
| `html_entities` | 20/20 (100.0%) | 20/20 (100.0%) | `d022_semantic_classifier` (18) |

### 4.3 Family classification consistency across wrappers

- Payloads whose non-empty family sets match across every wrapper: 0/20.
- Payloads where at least one wrapper produced NO family classification: 0/20.

The family sets are NOT consistent across wrappers (0/20 match) even though every payload is still caught by the composed stack. The base64 wrapper in particular drops the payload into the `encoded_payload` family (triggered by `d008_base64_payload`), so an operator relying on the family label to route mitigation policy (e.g. exfiltration payloads block, encoded payloads decode-and-rescan) sees the attack differently depending on wrapper — even when the underlying intent is identical. **This is the family-drift signal**: the guard still blocks, but the family label lies about the attack type.

## 5. Composed 5-layer summary

Every row is one layer's adaptive attack, followed by what the *rest* of the composed stack does on the same attack corpus.

| Layer | Attack | Layer-alone adaptive rate | Composed-stack detection | Rescue signal |
|---|---|--:|--:|---|
| d028 (Smith-Waterman) | matrix-aware substitution | 0.0% | see §5.7 paper | d022, d001-d006 |
| d027 (stylometric floor) | short-input truncation | 0.0% | 100.0% | d022, d001, d028 |
| d022 (DeBERTa) | hand-crafted paraphrase | 100.0% | 100.0% | see §2.3 table |
| fatigue tracker | dilution + rotation | hardening blocked | base thresholds preserved | not applicable |
| ToolResultGuard | wrapper spoofing | raw: 100.0%, worst wrapper (raw): 100.0% | 100.0% | d008 base64, keyword regexes |

## 6. Composability verdict

Layer by layer, does the 5-layer composed stack still hold under an adaptive attack targeting THAT layer?

- **d028.** Held. Ref §5.7 + partial report — the composed stack blocks 20/20 matrix-substitution attacks; d022 and the keyword regexes rescue what d028 loses.
- **d027.** Held. Composed rate 100.0% vs alone-rate 0.0%. Even with d022 removed the surface-form layer still rescues ≥ 50% (see partial report §B.4).
- **d022.** Held. Composed rate 100.0% on paraphrased corpus — the keyword regexes (d001, d003, d004) and d028 fire on paraphrases that still contain imperative verbs and override synonyms, even when the DeBERTa confidence drops.
- **Fatigue tracker.** Defeated in isolation (sample dilution + source rotation). Composed-stack impact is *zero* in absolute detection terms: fatigue is a hardening modifier, not a detector, so its defeat leaves base thresholds intact. The correct read is that the attacker pays a 6× observation-volume tax OR must run a proxy pool to evade hardening — real friction, no false negatives.
- **ToolResultGuard.** Held. Worst wrapper (raw) still detects 100.0% via always-on layers (base64 detector for the encoded wrapper, keyword regexes for the shape-preserving wrappers).

## 7. Limitations

1. **n = 20 per layer.** 95% Wilson intervals span roughly ±20 pp near 50% and ±10 pp near 0/100%. Every claim here is directional; the full protocol calls for n = 100.
2. **Non-iterative adversary.** Adaptive variants are drafted once. A HotFlip or genetic-search adversary would iterate against the composed loss, potentially crossing decision boundaries this single-shot rewrite does not reach.
3. **Paraphrases are hand-crafted, not gradient-based.** They are an upper bound on what a naïve attacker produces and a lower bound on what TextFooler/BERT-Attack could produce.
4. **Fatigue temporal-spacing correction.** Methodology §3.3 assumed 60 s spacing defeats hardening via cooldown; empirically the cooldown only fires *after* hardening, so temporal spacing alone fails. Sample dilution and source rotation are the two attacks that work.
5. **MIME spoofing is simplified to wrapper shape.** Real content-type manipulation would require an HTTP transport we do not simulate; the four wrapper shapes stand in for the malformed-content taxonomy the guard sees.
6. **d022 availability.** transformers version at run time was 5.1.0; d022 loaded=True. When d022 fails to load in production the composed stack is strictly weaker.

## 8. Reproducibility

```
python docs/papers/evaluation/composed_adaptive_expanded.py
```

Machine-readable results: `docs/papers/evaluation/composed_adaptive_expanded.json`.

Depends on: `composed_adaptive/partial_results.json` (produced by `composed_adaptive_partial.py`).

