# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — benchmarks

- **HarmBench evaluation** (`tests/benchmark_harmbench.py`). Runs prompt-shield
  against all 400 behaviors in the CAIS HarmBench benchmark (Mazeika et al.,
  2024) with per-category reporting (standard / contextual / copyright).
  Contextual subset (100 indirect-injection-style behaviors) detected at
  31.0%; standard at 7.0%; copyright at 0%. Raw results in
  `docs/papers/evaluation/harmbench.json`. README §"Benchmark 8" documents
  scope, top-firing detectors, and an honest gap-framing note.

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
  ~180 curated attack sequences across 13 categories. Ships with 35
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
