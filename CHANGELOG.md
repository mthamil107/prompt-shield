# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1] - 2026-07-22

**Correctness patch release.** Addresses two shipped-behaviour issues
identified by an independent claim audit (`CLAIM-AUDIT.md`) plus a
handful of accuracy corrections in the surrounding docs. No new features.

### ⚠️ Behaviour change (default flip)

- **`d031_language_enforcement` now ships `enabled: false`.**
  In v0.7.0 and earlier, `d031` was enabled by omission from
  `config/default.yaml` and shipped with `allowed_languages: ["en"]`.
  On any input of ≥ 32 characters in a non-allowed language it flagged
  at risk 1.0 — meaning a general-purpose deployment silently
  reclassified benign French/German/Spanish/Chinese/Japanese/Arabic/Hindi
  input as a security detection while the README's `languages-10` badge
  advertised the opposite. `d031` is a *policy gate*, not an attack
  detector, and should be opt-in.
- **`d032_topic_enforcement` also now explicitly ships `enabled: false`.**
  This was effectively already the case (empty `denied_topics` list
  meant it never fired) but the config is now explicit and documented.
- **What this means for existing users.** If you rely on the previous
  `d031` behaviour, set `d031_language_enforcement: enabled: true` in
  your config. Multilingual *injection* detection (`d024`) is
  unaffected — it remains enabled by default and catches
  "ignore previous instructions"-family attacks in 10 languages.
- **Known limitation not addressed here.** The `d022_semantic_classifier`
  (DeBERTa) may still classify some non-English benign inputs as
  injection at high confidence. That is a separate model-training issue
  tracked for a future release; the v0.7.1 fix only removes the
  language-policy false-positive contribution.

### Fixed — README and Pages accuracy (11 audit findings)

- **NotInject false-positive rate.** README summary row and Benchmark 3
  competitor table now report `3.8% (13/339)` — the shipped-default rate
  — instead of the ablation baseline (`0.9%`) or the placeholder (`0%`).
  Added a "What the 13 false positives are" breakdown paragraph and a
  reproducibility note. GitHub Pages site (`docs/index.md`) updated to
  match.
- **Liu et al. citation.** Fixed a hyperlink typo that pointed to an
  unrelated 2025 SQL-injection paper. Corrected to `arXiv:2310.12815`
  (Liu, Y., Jia, Y., Geng, R., Jia, J., Gong, N. Z. USENIX Security 2024).
- **OWASP coverage.** Pages site now correctly reports 8/10 LLM Top-10
  and 10/10 Agentic Top-10 categories (was 7/10 and 9/10).
- **d022-off vs d022-on mismatch.** Pages deepset with/without cell no
  longer pairs numbers from different detector configurations.
- **False-positives badge.** Now scoped to `(benchmark_1)` with alt text
  disclosing the sample origin (15 self-curated benign inputs).
- **Divergence terminology.** README and research-post docs now correctly
  describe the d027 window-boundary metric as Jensen-Shannon divergence
  (which the code has always used) rather than raw KL divergence.
- **d027 feature count.** README and research-post updated from 8 to 9
  stylometric features; the omitted feature (`allcaps_word_ratio`) is
  the one carrying most of the detector's benchmark contribution.
- **d028 attack-sequence counts.** README and CHANGELOG updated to
  reflect the actual database (187 sequences across 20 categories, not
  "~180 across 13").
- **CITATION.cff abstract.** Refreshed from v0.4.0 shape (27 detectors,
  6 output scanners) to v0.7.x shape (33 detectors, 9 output scanners,
  tool-result injection defense, federated ed25519-signed threat feed).
- **Quickstart risk score comment.** Corrected from `# 0.95` (never
  produced by the code path) to `# 1.0`.

### Fixed — benchmark reproducibility

- **`tests/benchmark_public_datasets.py`** now loads NotInject via
  `huggingface_hub.hf_hub_download` + `pandas.read_parquet` instead of
  `datasets.load_dataset`. The latter raises `Feature type 'List' not found`
  under `datasets>=3.x` because NotInject's dataset config declares a
  `List` feature type that the newer schema resolver renamed to
  `LargeList`. The direct-parquet path is stable and works on a bare
  `pip install huggingface_hub pandas pyarrow`.

### Docs

- `docs/configuration.md` gains a new "Policy Gates" section documenting
  `d031` and `d032` as opt-in operator policy detectors with example
  configs and rationale for the disabled-by-default choice.
- README's "Input Protection (33 Detectors)" table adds a call-out note
  explaining the policy-gate distinction immediately after the table.

### Not addressed here (tracked separately)

- The Dev.to article on d028 Smith-Waterman still mislabels its
  configuration (labels a d022-off number as "Regex + DeBERTa + d028");
  the in-repo draft correction is prepared and the live article will be
  edited as part of Pass 3 of the audit response.
- arXiv v3 with the corrected NotInject specificity claim and KL→JSD
  reference is prepared for filing (interactive step).
- Remaining accuracy cleanup (Benchmark 1 attack count 54→39, d028 smoke
  example replacement, ablation total, delete of `posts/` promo drafts)
  is tracked for a subsequent commit — none affect shipped behaviour.

## [0.7.0] - 2026-07-18

**"Agent-Era Defense" release.** First-class primitive for scanning
tool-result content — the highest-impact unsolved attack surface in
agent-era LLM security — with an attack-family taxonomy that projects
over the existing 33 detectors. Refactors 4 existing integrations to
use the primitive, adds tool-result block scanning to the Anthropic
wrapper, and normalizes a pre-existing gate-string inconsistency in
the Haystack integration.

### Added — `prompt_shield.tool_guard` (new module)

- **`ToolResultGuard`** — reusable primitive with sync `scan()` and
  async `ascan()`. Content-hash LRU cache (default 128 entries). Modes:
  `block` / `flag` (default) / `log` / `sanitize`. Default mode is
  `flag` — not `block` — because tool-result sanitization can destroy
  legitimate agent context (e.g. redacting a URL from a `web_search`
  result breaks the task). Callers opt into `block` explicitly.
- **`scan_tool_result(text, tool_name=..., tool_type=..., ...)`** —
  one-liner using a default engine.
- **`ToolResultAttackFamily`** — 9-value enum (`IMPERATIVE_INJECTION`,
  `DELIMITER_INJECTION`, `CONTEXT_TERMINATION`, `EXFILTRATION_COMMAND`,
  `ROLE_HIJACK`, `TOOL_MISUSE`, `ENCODED_PAYLOAD`, `RENDERED_EXFIL`,
  `UNCLASSIFIED`). Families are a pure *projection* over
  `DetectionResult.detector_id` via `DETECTOR_TO_FAMILY` — no parallel
  regex layer, so classifier F1 tracks detector F1. Two gap-filling
  regexes cover `CONTEXT_TERMINATION` (`</context>`, `---END---`,
  `[END SYSTEM]`) and `EXFILTRATION_COMMAND` phrasing that augments
  `d013_data_exfiltration`.
- **`ToolProvenance`** — `tool_name`, `tool_type`, `source_url`,
  `parent_scan_id` (chains the tool-result scan back to the input scan
  that triggered the tool call — critical for incident forensics).
- **`ScanContext`** — new field on `ScanReport`. Carries `gate`,
  `provenance`, `attack_families`, `is_indirect`,
  `classifier_confidence`, `mitigation`, `sanitized_text`. Forward-
  compatible: additional gates can attach their own metadata via
  new optional fields.
- **`is_indirect: bool`** — derived automatically from `tool_type`
  (`retrieval` / `rag` / `web_search` / `search` → `True`) or
  overridden explicitly. Distinguishes payloads that arrived via
  retrieval from those a user typed directly.

### Added — Anthropic wrapper: `tool_result` block scanning

- `PromptShieldAnthropic` now scans every
  `{"type": "tool_result", "content": ...}` block in a message's
  content list before the request forwards to `messages.create`.
  Handles both string and structured (`list[{"type": "text", ...}]`)
  content shapes. New init flags: `scan_tool_results: bool = True`,
  `tool_result_mode: str = "block"`.

### Changed — 4 integrations delegate through `ToolResultGuard`

- `AgentGuard.scan_tool_result()` — **backward-compatible**: return
  type stays `GateResult`; attack families exposed via
  `GateResult.metadata["attack_families"]` and
  `metadata["scan_context"]`.
- `PromptShieldCallback.on_tool_end()` (LangChain).
- `PromptShieldHandler.scan_retrieved_nodes()` (LlamaIndex).
- `PromptShieldMCPFilter.call_tool()` (MCP).
- `PromptShieldGuard.run()` (Haystack) — **gate-string normalized**
  from `"retrieved_document"` to `"tool_result"` + `"tool_type":
  "retrieval"` sub-context; matches every other integration.

### Added — CLI

- `prompt-shield scan --gate [input|tool_result|output]` flag (default
  `input`). With `--gate tool_result`, additionally accepts
  `--tool-name` and `--tool-type` and prints attack-family
  classification alongside the standard scan output.

### Added — tests (68 new)

- `tests/tool_guard/` — 5 new test files covering the primitive,
  taxonomy, models, one-liner API, and end-to-end precision floor.
- `tests/integrations/test_anthropic_tool_results.py` — 13 tests for
  the new Anthropic `tool_result` block scanning.
- `tests/integrations/test_langchain_on_tool_end.py` and
  `test_llamaindex_retrieved_nodes.py` — **backfill**: zero tests
  existed for these paths before v0.7.0.
- `tests/fixtures/tool_result_attacks.py` — shared 25-sample attack
  corpus (20 attacks across 8 families + 5 clean controls) reused by
  precision tests.
- Registry-drift protection: `test_taxonomy.py` asserts every
  `DETECTOR_TO_FAMILY` key exists in the runtime detector registry —
  same protection pattern introduced for compliance mappings in 0.6.1.
- Full suite: **1155 passing, 18 skipped, 0 failures** (up from 1097).

### Deferred to v0.7.1

- pydantic-ai tool-result primitives, OpenAI wrapper `role="tool"`
  message scanning, and CrewAI `scan_tool_result` method. Each has
  edge cases worth isolating: OpenAI's legacy `function` role,
  pydantic-ai's async validator context, CrewAI's undocumented tool
  wrapping. Splitting keeps a flaky integration from blocking the
  primitive.

## [0.6.1] - 2026-06-25

Docs + compliance-mapping patch release. No runtime behavior change.

### Fixed — compliance mappings (was silently wrong since v0.3)

- **`DETECTOR_OWASP_MAP`** had stale detector IDs from a pre-v0.3
  lineup (e.g. `d010_multilingual_injection` instead of the actual
  `d010_unicode_homoglyph`). The compliance test was hardcoded against
  the same stale IDs, so the drift went undetected for ~2 releases.
  v0.5.0's d030–d033 were also missing entirely. All 33 detector
  mappings are now correct; the test now derives the canonical list
  from the actual detector registry so the same class of drift cannot
  recur silently.
- **`DETECTOR_AGENTIC_MAP`** extended from 12 → 33 detectors
  (OWASP Agentic Top 10 now reports 10/10 categories covered).

### Added — MITRE ATLAS mapping (new module)

- `prompt_shield.compliance.mitre_atlas_mapping` — maps every detector
  + engine feature to MITRE ATLAS techniques (T0051 LLM Prompt Injection,
  T0054 LLM Jailbreak, T0057 LLM Data Leakage, T0053 LLM Plugin
  Compromise, T0052 Publish Poisoned Datasets, T0048 Financial Harm,
  T0042 Verify Attack, T0044 Full ML Model Access, T0049 Exploit
  Public-Facing Application). 9/9 ATLAS techniques covered.
- CLI: `prompt-shield compliance report --framework mitre-atlas`
  (and included in `--framework all`).
- 24 new compliance tests (drift protection + ATLAS structure/coverage).

### Changed — README

- Compliance section now documents 4 frameworks instead of 3, with
  accurate coverage numbers (OWASP LLM 8/10, OWASP Agentic 10/10,
  MITRE ATLAS 9/9, EU AI Act 7 articles).
- Federated threat-intel feed section expanded with concrete signature
  count (56) and trust-model link.

## [0.6.0] - 2026-06-25

First feature release adding the federated threat-intel feed client. Pure-Python ed25519 verification, opt-in by design, ships with the maintainer's public key pinned in source.

### Added — federated threat-intel client (new module `prompt_shield.signatures`)

- **`SignaturesClient`** — fetch + verify the public ed25519-signed
  signature feed at [`prompt-shield-signatures`](https://github.com/mthamil107/prompt-shield-signatures).
  Local on-disk cache at `~/.cache/prompt-shield/signatures.json` is used
  as fallback when the CDN is unreachable. Verification failures NEVER
  overwrite the cache — the last known-good payload stays in effect.
- **`verify_minisign(data, sig_text, public_key)`** — pure-Python
  ed25519 verification of [minisign](https://jedisct1.github.io/minisign/)
  detached signatures. No `minisign` binary required at runtime; uses the
  `cryptography` library that's already pulled in transitively. Supports
  both `Ed` (PureEdDSA) and `ED` (HashEdDSA with BLAKE2b-512) algos.
- **17 tests** (16 hermetic + 1 live-network, opt-in via
  `PROMPT_SHIELD_TEST_LIVE_FEED=1`). Hermetic tests build minisign-format
  signatures from scratch using `cryptography.ed25519` to prove the
  parser + verifier match minisign's wire format byte-for-byte.

### Why this matters

This is the **first open-source federated threat-intel feed for LLM
prompt injection**. Lakera, ProtectAI, Cisco AI Defense keep their attack-
pattern catalogs proprietary — that's their business model. The feed is
CC0-licensed, the code is Apache 2.0, and the maintainer's signing key
lives offline on the maintainer's machine, not in CI.

Companion repo: https://github.com/mthamil107/prompt-shield-signatures

### Benchmarks (carried forward from [Unreleased])

### Added — benchmarks

- **HarmBench evaluation** (`tests/benchmark_harmbench.py`). Runs prompt-shield
  against all 400 behaviors in the CAIS HarmBench benchmark (Mazeika et al.,
  2024) with per-category reporting (standard / contextual / copyright).
  Contextual subset (100 indirect-injection-style behaviors) detected at
  31.0%; standard at 7.0%; copyright at 0%. Raw results in
  `docs/papers/evaluation/harmbench.json`. README §"Benchmark 8" documents
  scope, top-firing detectors, and an honest gap-framing note.
- **PINT benchmark submission** to [lakeraai/pint-benchmark](https://github.com/lakeraai/pint-benchmark)
  via [PR #38](https://github.com/lakeraai/pint-benchmark/pull/38). prompt-shield
  scores 8/8 on the public 8-entry `example-dataset.yaml` sanity-check. The
  proprietary 4,314-input PINT dataset evaluation requires Lakera's team to
  run it on their end; official score pending. README §"Benchmark 9" documents
  scope and the in-flight submission.

### Changed — README positioning

- Benchmark Results section restructured to lead with an 8-dataset / 9,150+
  sample overview table (7 public, 1 self-curated) instead of leading with
  the 54-attack self-curated number. Addresses the "everyone thinks
  prompt-shield benchmarks only on local data" perception.
- Headline framing in the intro changed from "Benchmarked against 5 OSS
  competitors on 54 attacks" to "Evaluated on 8 datasets, 9,150+ samples,
  7 public sources", with a link into the detailed section.

## [0.5.1] - 2026-06-23

Documentation patch release. No code changes.

### Fixed

- README image references switched from relative paths to absolute
  `raw.githubusercontent.com` URLs so they render on PyPI (PyPI's
  camo proxy cannot resolve relative paths; the demo GIFs and
  architecture diagram were broken on the package page).

### Added

- Small star-the-repo prompt under the install command (visible on
  GitHub and PyPI).

## [0.5.0] - 2026-06-17

Operator-policy and observability release. Adds four new input detectors
(d030–d033), three new output scanners, a pre-detector normalization
pipeline, a multi-encoding preprocessor, Prometheus metrics, an
in-process sliding-window rate limiter, and removes the 512-token
input-length cap on the semantic ML classifier.

Total: 33 input detectors, 9 output scanners, 1040 tests passing.

### Added — input detectors (4 new, d030–d033)

- **d030 Custom YAML rules** (`prompt_shield.detectors.d030_custom_rules`).
  Operator-defined regex rules loaded from a configurable directory of
  YAML files. Per-rule `id`, `pattern`, `severity`, `action`,
  `description`, `case_sensitive`. Highest-severity match wins on
  overlap. Skips malformed YAML / invalid regex / incomplete rules
  without aborting the rest of the ruleset.
- **d031 Language enforcement** (`prompt_shield.detectors.d031_language_enforcement`).
  Two-stage detector: fast-path script-range regex (Cyrillic, Greek,
  Arabic, Hebrew, Devanagari, Thai, CJK) and optional `langdetect`
  fallback for Latin-script discrimination. Configurable
  `allowed_languages`, `min_input_chars`. Useful for English-only
  deployments that want to filter multilingual jailbreak attempts.
- **d032 Topic enforcement** (`prompt_shield.detectors.d032_topic_enforcement`).
  Operator-defined denied-topic keyword groups (medical, legal,
  politics, etc.). Per-topic severity, configurable `min_keyword_hits`,
  case-sensitivity. Strongest match wins among multiple matched topics.
- **d033 Multi-turn topic drift** (`prompt_shield.detectors.d033_topic_drift`).
  Jaccard n-gram similarity between the current turn and the
  conversation anchor (first N turns). Flags slow-jailbreak patterns
  where each turn looks innocuous in isolation but the cumulative drift
  moves the model into unsafe territory. Accepts history as
  `list[str]` or chat-format `{role, content}` dicts.

### Added — output scanners (3 new)

- **Sentiment output scanner** (`prompt_shield.output_scanners.sentiment`).
  VADER (`vaderSentiment`) compound-score scanner with a small
  keyword-lexicon fallback for environments without the optional
  dependency. Configurable `threshold` (default −0.5).
- **Bias / fairness output scanner**
  (`prompt_shield.output_scanners.bias_fairness`). Stereotype-template
  regexes plus protected-group + loaded-language proximity matching.
  Configurable `threshold`, `extra_groups`, `extra_loaded_terms`.
  Intentionally a lightweight signal — not a replacement for a full
  fairness audit.
- **Hallucination / grounding output scanner**
  (`prompt_shield.output_scanners.hallucination`). N-gram support ratio
  between the LLM output and grounding documents supplied via
  `context={"documents": [...]}`. Configurable
  `min_support_ratio`, `ngram_size`, `min_output_tokens`. Pure-lexical
  by design — pairs well with NLI / embedding scanners for high-stakes
  RAG.

### Added — pre-detector pipeline

- **Normalization pipeline** (`prompt_shield.normalization`). Four
  idempotent stages — NFKC, zero-width stripping, Cyrillic→Latin
  homoglyph mapping, whitespace collapse — that run before detectors
  to canonicalize evasions.
- **Multi-encoding preprocessor** (`prompt_shield.decoders`). Decodes
  base64, hex, URL, HTML entities, and ROT13 candidates as a fan-out
  set of candidate plaintexts to feed back through detectors. Catches
  layered obfuscation patterns.

### Added — platform

- **Prometheus `/metrics` module** (`prompt_shield.observability`).
  `PromptShieldMetrics` exposes `scans_total` (counter, by action),
  `detections_total` (counter, by detector + severity), and three
  histograms (scan duration, input chars, input tokens). `expose()`
  returns `(body, content_type)` for drop-in HTTP handler use. Lazy
  optional dep — `prometheus_client` not required at install time.
- **Sliding-window rate limiter** (`prompt_shield.ratelimit`).
  Per-key in-process throttle with `check` / `acquire` / `enforce` /
  `reset`. Thread-safe (single lock), bounded memory via
  `max_tracked_keys` LRU-style eviction, pluggable `time_func` for
  deterministic tests. `RateLimitExceededError` raised by `enforce()`
  carries the full decision.

### Changed

- **d022 semantic classifier** input-length cap removed. Long inputs
  are now chunked with overlap (`chunk_size=512`, `chunk_stride=384`,
  `max_chunks=8`) and the per-chunk confidences are max-pooled. Inputs
  past ~6 k tokens previously fell out of coverage; they no longer do.

### Optional dependencies

Three new install extras for the lazy-loaded paths:

- `pip install prompt-shield-ai[observability]` — adds `prometheus_client`
- `pip install prompt-shield-ai[sentiment]` — adds `vaderSentiment`
- `pip install prompt-shield-ai[language]` — adds `langdetect`

`prompt-shield-ai[all]` now includes all three.

### CI / tooling

- Test suite expanded to **1040 tests** (up from 829).
- `pyproject.toml` per-file lint ignores for legitimate homoglyph /
  fullwidth / CJK test data.

## [0.4.0] - 2026-04-19

First release of the cross-domain novel techniques plan. Ships two of the
seven proposed techniques with empirical validation on public datasets;
the remaining five remain in development. Paper on Zenodo with citable
DOI; full evaluation harness in-repo.

### Added — novel techniques (2 of 7)

- **d028 Smith-Waterman alignment detector** (`prompt_shield.detectors.d028_sequence_alignment`).
  Local sequence alignment from bioinformatics adapted to prompt-injection
  detection, with a 15-group semantic substitution matrix analogous to
  BLOSUM. Catches paraphrased, filler-padded, and synonym-swapped attacks
  that verbatim regex misses. Pure Python, no new deps, <5 ms per scan.
  187 curated attack sequences across 20 categories. Ships with 35
  unit + fixture tests.
- **Adversarial fatigue tracker** (`prompt_shield.fatigue.FatigueTracker`).
  EWMA near-miss tracking with per-`(source, detector)` state; lowers the
  detection threshold for offending sources when a probing campaign is
  detected, restores after a configurable cooldown. Opt-in via
  `fatigue.enabled: true` — zero overhead when disabled. Thread-safe
  under parallel detector execution. 29 unit + integration tests.

### Added — evaluation + reproduction

- **Public-dataset ablation** for d028 on five benchmarks:
  `deepset/prompt-injections`, `leolee99/NotInject`,
  `microsoft/llmail-inject-challenge`, `ai-safety-institute/AgentHarm`,
  `ethz-spylab/agentdojo v1.2.1`. Full tables, raw JSON, narrative
  analysis and a one-command reproduction harness under
  `docs/papers/evaluation/`.
- **Regression gate** `tests/regression_check.py` + locked baseline
  `tests/baseline_v0.3.3.txt`. Fails CI if any per-category detection
  rate drops >1 pp or benign FP count increases.
- **Fatigue probing-campaign validation** documented in
  `docs/papers/evaluation/fatigue_probing_campaign.md`. The empirical
  claim (10 priming scans at conf 0.65 → 11th scan at conf 0.63 blocked)
  is exercised end-to-end by
  `tests/fatigue/test_engine_integration.py::test_hardening_catches_next_near_miss`.

### Added — research + citation infrastructure

- **Zenodo DOI** [10.5281/zenodo.19644135](https://doi.org/10.5281/zenodo.19644135)
  for the paper *Beyond Pattern Matching: Seven Cross-Domain Techniques
  for Prompt Injection Detection*.
- **Paper PDF** committed to `docs/papers/cross-domain-techniques.pdf`
  (16 pages, 288 KB) so readers on GitHub can view inline.
- **`CITATION.cff`** at repo root — GitHub's "Cite this repository"
  sidebar renders the Zenodo DOI as preferred citation.

### Headline empirical result

On `deepset/prompt-injections` (regex-only baseline, 116 samples):

| Config | F1 | Recall | FPR |
|---|---|---|---|
| 26 detectors (v0.3.3 baseline, d028 off) | 0.033 | 0.017 | 0.000 |
| 27 detectors (v0.4.0, d028 on) | **0.378** | 0.233 | 0.000 |
| **Δ** | **+34.5 pp** | +21.7 pp | 0.000 |

### Changed

- Engine detector-runner signatures now carry a per-detector
  `base_threshold` alongside the effective threshold, so the fatigue
  tracker can classify near-misses against the un-hardened baseline.
  Wire-compatible with custom `BaseDetector` subclasses.
- `ruff` configuration: line-length set to 100 (from default 88) with
  per-file ignores for data-heavy files (attack-sequence database,
  OWASP URL tables, detector regex patterns). Mypy overrides added for
  FastAPI handlers (`prompt_shield.api`) and the benchmark runner.
- Test suite: 765 → 829 tests. Compliance test detector count assertion
  bumped 26 → 27.
- Test `test_multiple_detections_get_bonus` is now robust to any new
  detector that saturates confidence at 1.0 — skips the assertion when
  `max_conf == 1.0` (no headroom for the ensemble bonus) rather than
  encoding a dependency on which detectors happen to fire.

### Fixed

- CI across Python 3.10 – 3.13 is green for the first time since
  2026-03-29: accumulated ruff/mypy debt cleared (197 ruff errors → 0,
  29 mypy errors → 0); crewai_tools import hardened against version
  skew between local and CI environments.
- Prompt-shield self-scan workflow now consults a repo-local
  `.prompt-shield-ignore` that excludes files that legitimately contain
  attack vocabulary (detector sources, fixtures, docs, README). The
  scan action now supports an `ignore-patterns` input for downstream
  users too.

### Research status

- 2 of 7 novel techniques shipped (d028, fatigue). 5 in development:
  stylometric discontinuity, honeypot tools, prediction market ensemble,
  perplexity spectral analysis, runtime taint tracking.
- Arxiv endorsement: Wagner declined 2026-04-19 citing incomplete
  evaluation (addressed in this release; next attempt will go to a
  different endorser with Zenodo v2.0 including an Evaluation section).
  Alouani + Jacob pending.

## [0.1.1] - 2026-02-17

### Fixed

- **d001 System Prompt Extraction**: patterns now accept article "the" (e.g., "reveal **the** system prompt") in addition to "your"; added verbs `give`, `share`, `disclose`, `expose` and optional indirect objects (`me`, `us`) to the main extraction pattern; added `reveal`, `display`, `give`, `share` to the "show me" pattern
- **d003 Instruction Override**: bare "override system" and similar phrases now detected; previously the pattern required a temporal qualifier (`previous`/`current`) and an instruction noun (`commands`/`instructions`) after the override verb
- **d004 Prompt Leaking**: added `reveal`, `show`, `display` to the repeat-system-message pattern for consistent verb coverage

### Added

- **d001**: two new patterns — contraction form (`what's your system prompt`) and indirect requests (`can you share/tell/give/provide the system prompt`)
- **d003**: two new patterns — system bypass attempts (`override/bypass/circumvent/disable system|safety|security`) and deactivation attempts (`turn off/deactivate/neutralize system|safety|security protections`)

## [0.1.0] - 2025-01-01

### Added

- Core scanning engine with pluggable detector architecture
- 21 built-in detectors covering:
  - Direct injection (d001-d007): system prompt extraction, role hijack, instruction override, prompt leaking, context manipulation, multi-turn escalation, task deflection
  - Encoding/obfuscation (d008-d012): base64 payload, ROT13 substitution, unicode homoglyph, whitespace injection, markdown/HTML injection
  - Indirect injection (d013-d016): data exfiltration, tool/function abuse, RAG poisoning, URL injection
  - Jailbreak patterns (d017-d020): hypothetical framing, academic pretext, dual persona, token smuggling
  - Self-learning (d021): vault similarity detector
- Self-learning attack vault (ChromaDB) with vector similarity detection
- Community threat feed import/export (JSON format)
- User feedback system with auto-tuning of detector thresholds
- Canary token injection and leak detection
- SQLite persistence for scan history, feedback, and audit logs
- AgentGuard: universal 3-gate protection (input, data, output gates)
- MCP tool result filter (PromptShieldMCPFilter)
- Framework integrations: FastAPI, Flask, Django middleware
- LLM framework integrations: LangChain callback, LlamaIndex handler
- CLI with scan, detectors, vault, feedback, and threats commands
- YAML + environment variable configuration
- Plugin registry with auto-discovery, entry points, and runtime registration
- Comprehensive test suite with 315+ test cases
