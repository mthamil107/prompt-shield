# Design Notes — prompt-shield v0.5.0

**Author:** Thamilvendhan Munirathinam
**Date:** 2026-06-18
**Project:** prompt-shield — https://github.com/mthamil107/prompt-shield
**Companion paper:** *Beyond Pattern Matching: Seven Cross-Domain Techniques for Prompt Injection Detection*, arXiv:2604.18248 (CC BY 4.0)
**License:** CC BY 4.0
**Code release:** v0.5.1 on PyPI (`prompt-shield-ai`, Apache 2.0); commit `298c01f` on `main`.
**DOI:** [10.5281/zenodo.20809165](https://doi.org/10.5281/zenodo.20809165)
**Zenodo record:** https://zenodo.org/records/20809165

## Purpose and scope

This document is a technical design note for the **novel detection and pre-processing techniques introduced in `prompt-shield` v0.5.0** that are *not* covered in the companion arXiv paper. It is published as a dated public disclosure so that the techniques described here are unambiguously **prior art** as of the timestamp on this document and its DOI on Zenodo.

The companion arXiv paper covers d027 (stylometric discontinuity), d028 (Smith-Waterman sequence alignment with semantic substitution matrix), and the adversarial fatigue tracker. This document covers the seven additional cross-domain techniques shipped in v0.5.0, in enough algorithmic detail to be independently reimplemented from this text alone.

All techniques are released under Apache 2.0 (code) and CC BY 4.0 (this description). The intent of this disclosure is not to restrict use — it is to ensure that no future patent application can claim novelty over these techniques.

## 1. d029 — Many-shot Structural Detection

**Threat model.** Anthropic 2024 disclosed a class of attack in which a prompt contains a large number of structurally identical fake-conversation turns (typically 100+ `Q:` / `A:` pairs) that condition the model to comply with the final, harmful turn. Verbatim regex detection of harmful content in any single turn fails because no individual line is overtly malicious.

**Detection technique.** Structural features of the prompt are computed without regard to lexical content:

1. **Turn marker density.** Count occurrences of canonical turn markers (`Q:`, `A:`, `Human:`, `Assistant:`, `User:`, `AI:`, `H:`, `A:`, `[INST]`, etc.) and divide by total non-whitespace characters. A density above ~1 marker per 80 characters in long prompts is anomalous.
2. **Inter-turn period regularity.** For each adjacent pair of markers, measure the character distance between them. Compute the coefficient of variation (`stdev / mean`). Genuine multi-turn conversations have CV ≥ 0.5; many-shot attacks have CV ≤ 0.15 because the turns are mechanically generated.
3. **Total turn count threshold.** Standalone signal: ≥ 30 turn markers in a single prompt is rare in legitimate use even with conversation history embedded.

**Decision rule.** Detection fires when (turn count ≥ 30) AND (turn density above threshold) AND (CV ≤ 0.15). Confidence scales with how far the regularity exceeds threshold.

**Why this is novel.** Existing literature on many-shot jailbreaking focuses on the *attack* construction. This technique reframes detection as **periodicity analysis on structural markers**, borrowing from time-series anomaly detection — short conversations have irregular intervals, mechanically padded ones do not.

**Implementation reference.** `src/prompt_shield/detectors/d029_many_shot_structural.py`.

## 2. d030 — Custom YAML Rules Engine

**Threat model.** Operators routinely need to block organization-specific terms (internal codenames, sensitive data class names, brand references) that no general detector can know about. Hand-editing detector Python is high-friction; a declarative rule format lowers it.

**Technique.** A directory of YAML rule files is loaded at engine startup. Each rule has the schema:

```yaml
rules:
  - id: internal-codename
    pattern: '\binternal-codename-X\b'
    severity: high                 # critical | high | medium | low
    action: block                  # block | flag | log
    description: "..."
    case_sensitive: false          # optional, default false
```

Loading is **fail-soft per rule**: malformed YAML, invalid regex, or rule entries missing `id` / `pattern` are logged and skipped without aborting the rest of the ruleset. This is critical because operators often hand-author large rulesets and a single typo should never break the engine.

On detection, when multiple rules match the same input, **highest-severity wins** (critical > high > medium > low). The chosen rule's severity, action, and metadata propagate to the engine-level decision.

**Novelty claim.** The fail-soft rule loader + highest-severity-wins precedence + per-rule action verb (`block`/`flag`/`log`) is a distinctive combination — most regex-rule engines are either fail-hard (one bad rule kills the loader) or first-match-wins.

**Implementation reference.** `src/prompt_shield/detectors/d030_custom_rules.py`.

## 3. d031 — Two-Stage Language Enforcement

**Threat model.** Many production deployments are explicitly English-only (or restricted to a small allow-list). Multilingual jailbreak prompts (translations of "ignore previous instructions" into less-trained languages) bypass English-only training signal in safety RLHF. Blocking non-allow-list languages is a cheap, high-precision input gate.

**Technique.** Detection is two-stage to minimize dependency surface:

1. **Fast-path script analysis (no dependencies).** Pre-compiled regexes for Unicode script blocks: Cyrillic, Greek, Arabic, Hebrew, Devanagari, Thai, and the CJK union (Han, Hiragana, Katakana, Hangul). For each script, compute the ratio of matching characters to total non-whitespace, non-digit characters. If any non-allowed script exceeds **15%** of input characters, the inferred language is rejected immediately. The 15% threshold tolerates incidental foreign-language quotation but flags genuinely non-English prose.
2. **Fallback langdetect (optional dependency).** If the input is Latin-script and the fast path doesn't trigger, optionally invoke `langdetect`. Use seed=0 for determinism. Accept the top guess only if probability ≥ 0.75; otherwise treat as allowed (high uncertainty defaults to permissive to avoid false-positives on short or technical input).

**Configuration.**

```yaml
d031_language_enforcement:
  enabled: true
  allowed_languages: ["en"]
  min_input_chars: 32        # silent on shorter inputs
```

**Novelty claim.** The fast-path script-ratio gate is a well-known technique in isolation. The novelty here is the **two-stage gated combination**: script-fraction analysis as a no-dependency fast path, with `langdetect` invoked only when the fast path is inconclusive AND optional dependencies are present. This makes the detector deployable in environments that cannot pull in `langdetect` while still benefiting from it when available.

**Implementation reference.** `src/prompt_shield/detectors/d031_language_enforcement.py`.

## 4. d032 — Operator-Defined Denied Topics

**Threat model.** Deployments often need to block off-topic requests entirely (medical, legal, political opinions in a code-assistant; competitor product comparisons in a customer-support bot). These are not "attacks" in the prompt-injection sense — they are policy violations. The same engine should evaluate them with a single declarative interface.

**Technique.** Operator-defined topic groups, each a named keyword cluster. A detection fires when the number of keyword hits from any single group meets a configurable minimum threshold (default 2).

```yaml
d032_topic_enforcement:
  enabled: true
  denied_topics:
    - name: medical_advice
      keywords: ["diagnose", "prescription", "dosage", "symptoms"]
      severity: high
    - name: legal_advice
      keywords: ["lawsuit", "attorney", "court", "litigation"]
      severity: medium
  min_keyword_hits: 2
  case_sensitive: false
```

Keywords are matched as word-bounded literal phrases (regex `\bKW\b`, escaped). Among multiple matching topics, the topic with the most hits wins; ties resolved by configuration order.

**Novelty claim.** The combination of (a) **multiple competing keyword groups with per-group severity**, (b) **min-hits-per-group threshold** (so isolated word usage doesn't fire — "I'm not asking for medical advice" doesn't trigger on "advice"), and (c) **most-hits-wins** precedence is the distinctive contribution. This sits between naive single-keyword block-lists and full ML topic classifiers.

**Implementation reference.** `src/prompt_shield/detectors/d032_topic_enforcement.py`.

## 5. d033 — Multi-Turn Topic Drift via Jaccard Anchor Similarity

**Threat model.** A class of slow jailbreaks operates across many turns. Each individual turn is benign — a coding question, then a casual aside, then a hypothetical, then an escalated request. No single turn is detected; the *cumulative drift* from the conversation's established topic is what makes the final harmful request succeed. This is a known evaluation gap in single-turn injection detectors.

**Technique — anchored n-gram drift.**

1. **Build the anchor.** Concatenate the first `N` turns of the conversation (default `N=2`). This is the "what the conversation is about" reference. Computed once per session.
2. **Tokenize and stopword-filter** both the anchor and the current turn. Use a small English stoplist (~70 common words) to remove function words that would inflate similarity.
3. **N-gram fingerprint.** Build the set of token n-grams (default bigrams, configurable). Each fingerprint is a `set[tuple[str, ...]]`.
4. **Jaccard similarity** between the anchor fingerprint A and current-turn fingerprint C: `|A ∩ C| / |A ∪ C|`.
5. **Decision.** If similarity is below `min_anchor_similarity` (default 0.05) **AND** the conversation has at least `min_turns` (default 4), fire detection. The minimum-turns gate prevents firing on short interactions that haven't established a topic.

**Confidence scaling.** Confidence is computed from the gap below threshold: `min(0.95, 0.4 + (threshold − similarity) × 4)`. A complete topic flip (similarity = 0) yields high confidence; a borderline drift yields lower confidence.

**Configuration.**

```yaml
d033_topic_drift:
  enabled: true
  anchor_turns: 2
  min_turns: 4
  min_anchor_similarity: 0.05
  ngram_size: 2
```

**Input formats accepted.** Conversation history via `context={"history": [...]}` or `context={"conversation_history": [...]}`, where each entry is either a `str` or a chat-format `{"role": ..., "content": ...}` dict.

**Novelty claim — this is the most distinctive technique in v0.5.0.** Existing multi-turn jailbreak detection focuses on either (a) semantic-embedding distance from a seed prompt (heavy ML dependency) or (b) detecting specific escalation patterns. The Jaccard-against-anchor approach is novel in three ways:

1. **No model dependency.** Pure n-gram set arithmetic. Sub-millisecond evaluation.
2. **The anchor is the conversation's own first turns**, not an externally supplied "safe" prompt. The detector adapts to each conversation's established topic without operator configuration of what the topic is.
3. **Two-gate decision** (`similarity < T` AND `turn_count ≥ M`) prevents false-positives on legitimate topic switches in short conversations.

**Implementation reference.** `src/prompt_shield/detectors/d033_topic_drift.py`. Test coverage: `tests/detectors/test_d033_topic_drift.py` (10 tests).

## 6. Normalization Pipeline (pre-detector)

**Threat model.** Many obfuscation attacks rely on the input visually rendering identically to a known attack while being lexically different — Cyrillic `о` replacing Latin `o`, zero-width characters splitting trigger words, full-width Unicode (`Ｉｇｎｏｒｅ`) reading identically to ASCII. Detectors that match against the raw byte stream miss these.

**Pipeline structure.** Four idempotent stages, each independently togglable:

1. **NFKC normalization.** Unicode normalization form KC: composes combining marks AND maps compatibility characters (full-width Latin, mathematical alphanumerics, fractions, etc.) to their canonical ASCII equivalents.
2. **Zero-width stripping.** Regex-strip U+200B (ZERO WIDTH SPACE), U+200C, U+200D, U+FEFF (BOM), and U+2060.
3. **Cyrillic-to-Latin homoglyph mapping.** A curated table of 30+ visually-identical Cyrillic→Latin mappings (`а→a`, `е→e`, `о→o`, `р→p`, `с→c`, `х→x`, `у→y`, `А→A`, `В→B`, `С→C`, `Е→E`, `Н→H`, `К→K`, `М→M`, `О→O`, `Р→P`, `Т→T`, `Х→X`, etc.). Mapping is one-way Cyrillic→Latin, never reverse, to avoid mangling legitimate Cyrillic text.
4. **Whitespace collapse.** Multi-space, tabs, newlines collapsed to single spaces; leading/trailing trimmed.

Each stage is **idempotent**: running it twice produces the same output as running it once. This guarantees that a normalization-aware detector composed with a non-normalizing detector both see consistent input.

**Result object.** The pipeline returns a `NormalizationResult(text, original, changes: list[str])` so downstream detectors can see *which* normalizations fired — useful both for explanation and as a detection signal in itself (an input that was zero-width-stripped is itself suspect).

**Novelty claim.** The idempotent-stage pipeline with **change-tracking output** is the distinctive contribution. Existing libraries typically apply normalizations destructively without surfacing what changed. The change-tracking output enables a meta-detector ("input contained zero-width characters") on top of the standard detectors.

**Implementation reference.** `src/prompt_shield/normalization/pipeline.py`.

## 7. Multi-Encoding Preprocessor (pre-detector)

**Threat model.** Encoded payloads are the canonical way to smuggle attack content past detectors: base64, hex, URL-encoded, HTML-entity-encoded, ROT13. Single-encoding detectors (decode base64 only, decode hex only) miss combined attacks (`base64(rot13("ignore..."))`).

**Technique — fan-out candidate set.** The preprocessor returns a `DecodedSet` — a list of `DecodedCandidate(text, encoding, source_span)` for each successfully decoded substring. Detectors then run on each candidate independently, treating each as a potential injection vector.

Decoders implemented:

- **Base64.** Regex `(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])` — captures contiguous base64-charset runs of ≥ 16 characters with lookaround to preserve padding `=` characters (a subtle bug source — naive `\b` boundary strips the padding). Decode attempts that fail (invalid UTF-8 output) are silently dropped.
- **Hex.** `(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){6,})(?![0-9a-fA-F])` — even-length hex runs of ≥ 12 characters.
- **URL.** `urllib.parse.unquote` applied to any substring containing `%XX` sequences.
- **HTML entities.** `html.unescape` applied to substrings containing `&XXX;` or `&#NNN;` patterns.
- **ROT13.** Heuristic: any contiguous letters-only word ≥ 7 characters is a candidate; decoded variant is added. The 7-char threshold is empirically tuned — shorter words generate too many spurious candidates.

**Decoded candidates feed back through the detector pipeline.** A detection on a decoded candidate is reported with the original (encoded) span as the match position, so an operator can see where in the input the attack was hidden.

**Novelty claim.** The **fan-out candidate-set model** is the distinctive contribution. Most detectors are written as `decode_if_possible(text) → detect(text)`, which can only handle one encoding per substring. The fan-out model treats decoded variants as additional inputs to the full detector stack, so a base64-encoded ROT13-encoded attack is caught when (a) base64 decode produces ROT13 text, (b) ROT13 decode produces the original attack, (c) any detector matches the final decoded form.

**Implementation reference.** `src/prompt_shield/decoders/preprocessor.py`.

## 8. Removal of d022 Input-Length Cap (semantic ML classifier)

**Prior limitation.** The DeBERTa-v3 semantic classifier (d022) has a 512-token model context window. Inputs longer than ~6000 characters were previously truncated to the first 512 tokens, leaving the tail of long inputs uncovered by the ML detector.

**Technique — sliding chunked max-pool.** Long inputs are split into overlapping chunks (`chunk_size=512` tokens, `chunk_stride=384` tokens, so a 128-token overlap), capped at `max_chunks=8` for compute safety. Each chunk is independently scored by DeBERTa. The final confidence is the **max** over all chunk confidences (max-pool aggregation), not the mean — under the operating assumption that a prompt is malicious if *any* segment is malicious.

**Why max-pool, not mean.** Mean-pool dilutes the signal: a 5000-token prompt with one malicious 100-token segment averages out to "looks fine". Max-pool preserves the signal: any segment scoring high triggers the engine. For a defensive detector, max-pool is the correct aggregation.

**Novelty claim.** The chunking pattern is standard. The combination of (a) **overlap to avoid splitting tokens across chunks**, (b) **max-pool aggregation**, and (c) **a hard chunk cap** (`max_chunks=8`) to bound worst-case compute is the contribution. The cap prevents adversarial input-padding attacks that would force the detector to run for unbounded time.

**Implementation reference.** `src/prompt_shield/detectors/d022_semantic_classifier.py`.

## 9. Sliding-Window Rate Limiter

**Threat model.** A scan API exposed to untrusted clients needs throttling. Per-key, in-process throttling is the simplest first defense; multi-process / cluster deployments would back this with Redis.

**Technique.** Per-key deque of timestamps; on each request, drop timestamps older than the window, accept if current count < `max_requests`, reject otherwise. `check` / `acquire` / `enforce` / `reset` entry points. Thread-safe under a single lock. Bounded memory via `max_tracked_keys` LRU-style eviction. Pluggable `time_func` for deterministic tests.

**Not novel as a primitive.** Sliding-window rate limiting is well-known and is documented here for completeness only.

**Implementation reference.** `src/prompt_shield/ratelimit/limiter.py`.

## 10. Prometheus Metrics Exposition

**Technique.** A `PromptShieldMetrics` class exposes:

- `prompt_shield_scans_total` (counter, label: `action ∈ {block, flag, log, pass}`)
- `prompt_shield_detections_total` (counter, labels: `detector_id`, `severity`)
- `prompt_shield_scan_duration_seconds` (histogram)
- `prompt_shield_scan_input_size_chars` (histogram)
- `prompt_shield_scan_input_size_tokens` (histogram)

`expose()` returns `(body, content_type)` for drop-in HTTP handler integration. `prometheus_client` is a lazy optional dependency.

**Not novel.** Standard Prometheus instrumentation patterns. Documented for completeness so that downstream integrators have a stable interface to depend on.

## 11. Summary table

| Technique | Novel? | Primary novelty claim |
|---|---|---|
| d029 many-shot structural | Yes | Periodicity / CV analysis on turn markers |
| d030 custom YAML rules | Partial | Fail-soft loader + highest-severity-wins |
| d031 language enforcement | Yes | Two-stage script-ratio fast path + optional langdetect fallback |
| d032 topic enforcement | Yes | Multi-group keyword clusters + min-hits-per-group + most-hits-wins |
| **d033 topic drift** | **Yes (strongest)** | Jaccard-against-self-anchor + two-gate decision |
| Normalization pipeline | Partial | Idempotent stages with change-tracking output |
| Multi-encoding preprocessor | Yes | Fan-out candidate set fed back through full detector stack |
| d022 chunking | Partial | Overlap + max-pool + hard chunk cap |
| Sliding-window limiter | No | Documented for completeness |
| Prometheus exposition | No | Documented for completeness |

## 12. Disclosure intent

This document, the companion paper arXiv:2604.18248, the public git history at https://github.com/mthamil107/prompt-shield, and the released artifact `prompt-shield-ai==0.5.0` on PyPI constitute public disclosure of the techniques described above. They are released under permissive licenses (CC BY 4.0 for the text, Apache 2.0 for the code, with the explicit patent grant therein) so that anyone may freely use, modify, extend, or commercially deploy them.

The author makes no claim of patent rights on these techniques and disclaims any intent to seek such rights. This disclosure is intended to **establish prior art** so that no third party may seek patent rights over them either.

## References

1. Munirathinam, T. (2026). *Beyond Pattern Matching: Seven Cross-Domain Techniques for Prompt Injection Detection*. arXiv:2604.18248. https://arxiv.org/abs/2604.18248
2. Anthropic (2024). *Many-shot jailbreaking*. https://www.anthropic.com/research/many-shot-jailbreaking
3. prompt-shield v0.5.0 source code. https://github.com/mthamil107/prompt-shield/tree/v0.5.0 (Apache 2.0)
4. CHANGELOG.md, prompt-shield v0.5.0 entry. https://github.com/mthamil107/prompt-shield/blob/v0.5.0/CHANGELOG.md
