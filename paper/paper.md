---
title: "prompt-shield: a defense-in-depth stack for prompt injection in LLM applications"
tags:
  - prompt injection
  - LLM security
  - ai safety
  - guardrails
  - python
authors:
  - name: Thamilvendhan Munirathinam
    affiliation: 1
affiliations:
  - name: Independent Researcher
    index: 1
date: 12 August 2026
bibliography: paper.bib
---

# Summary

`prompt-shield` is an Apache 2.0-licensed Python package that hardens
LLM-backed applications against prompt injection at three
architectural boundaries: user input, tool-call output, and model
output. Version 0.7.4 ships 34 input detectors (regex families,
NFKC + homoglyph normalization, a seven-scheme encoding preprocessor,
a DeBERTa semantic classifier, Smith-Waterman sequence alignment
against a 187-attack signature database, forensic-linguistic
stylometric discontinuity scoring, structural many-shot detection,
a honeypot-tool detector (the fourth of seven cross-domain
techniques), and multilingual coverage across ten languages),
9 output scanners
(toxicity, code injection, prompt leakage, PII, schema validation,
jailbreak, sentiment, bias/fairness, and hallucination/grounding), a
first-class `ToolResultGuard` primitive for scanning tool-result content
before it re-enters the model's context, and a federated,
ed25519-signed threat-intelligence feed
(`prompt-shield-signatures`) that the engine's default
`sync_threats(url, public_key=key)` path verifies against a pinned
public key before loading. All input is passed through an idempotent
normalisation pipeline (NFKC, zero-width strip, Cyrillic→Latin
homoglyph map, whitespace collapse) prior to detector dispatch, so
regex-based detectors see the cleaned form and homoglyph-obfuscated
attacks cannot bypass the pattern layer. The library ships with thirteen framework
integrations (LangChain, LlamaIndex, Haystack, Pydantic AI, CrewAI,
MCP, the OpenAI and Anthropic SDKs, FastAPI, Flask, Django, n8n,
Dify), plus a standalone REST/Docker deployment, a Prometheus
`/metrics` endpoint, per-key sliding-window rate limiting, and a
1,232-test regression suite. It is evaluated on nine benchmarks
(eight public, one self-curated) totalling approximately 10,300
samples, including Garak [@nvidia-garak], InjecAgent
[@injecagent-2024], Liu et al. USENIX 2024 [@liu-2024], deepset
[@deepset-injections], NotInject [@notinject-2024], and — via the
companion paper [@prompt-shield-arxiv-2026] — LLMail-Inject,
AgentHarm, and AgentDojo, with per-dataset results reported there. The three architectural patterns that
organize the software — the tool-result boundary gate, a federated
signed threat feed, and a detector-agnostic attack-family taxonomy
— are described in Section 7 of that companion paper.

# Statement of need

Prompt injection is the top-ranked risk in the OWASP LLM Top-10
[@owasp-llm-top10-2025] and the primary attack surface introduced by
tool-augmented agents [@liu-2024]. The open-source landscape in 2026
offers several shapes of defense, none of which cover the full
deployment surface a production LLM application needs. Broad
LLM-policy frameworks — `guardrails-ai` [@guardrails-ai-2023] and
NVIDIA `NeMo Guardrails` [@nemo-guardrails-2023] — provide validator
and dialogue-flow abstractions but leave detector implementation to
the user. Commercial-backed single-technique tools — `llm-guard`
[@llm-guard-2023] and `rebuff` [@rebuff-2023], the latter
unmaintained since August 2024 — offer one or two detection
strategies and no tool-result boundary. A growing academic cohort
ships strong single-technique detectors — PromptSentinel-X
[@prompt-sentinel-x-2026] and DataSentinel [@data-sentinel-2025] as
trained ML classifiers, AgentWatcher [@agent-watcher-2026] as a
rule-based monitor — or runtime-enforcement systems — ClawGuard
[@claw-guard-2026], AgentSpec [@agent-spec-2026], Prismata
[@prismata-2026], DualView [@dual-view-2026], and Token-Flow Firewall
[@token-flow-firewall-2026] — but each is a research prototype rather
than an integrated deployment stack. See the companion paper's
Related Work section for the full cluster map.

`prompt-shield` addresses a different point in the design space: an
integrated defense-in-depth stack packaged as a single `pip install`,
combining input scanning, output scanning, a tool-result boundary
gate, and a federated signed threat feed behind one API, with
thirteen framework integrations and a reproducible benchmark
harness. It does not win the false-positive beauty contest on any
single benchmark — in-distribution supervised classifiers report
lower FPR by construction, and the companion paper is explicit about
this trade-off.

We report the JOSS-relevant evidence of research use available at
submission time. The companion paper [@prompt-shield-arxiv-2026]
records 166 total views (154 unique) and 87 total downloads (59
unique) on Zenodo [@prompt-shield-zenodo-paper] in the three months
since publication, and the design-notes preprint
[@prompt-shield-zenodo-designnotes] records 47 total views (source:
https://zenodo.org/records/19644135 and https://zenodo.org/records/20809165 stats pages,
snapshot 2026-07-28). The federated feed repository
[@prompt-shield-signatures-2026] shows 38 CDN requests over the
trailing 30 days (source: jsDelivr public stats API for
`mthamil107/prompt-shield-signatures`; includes CI polling and mirror
traffic). PyPI records approximately 11,130 all-time downloads with
1,600 in the trailing 30 days (source: pepy.tech, snapshot
2026-07-28). The GitHub repository shows 10 stars and 3 forks at the
same snapshot; the project is solo-maintained.
The reproducible cross-benchmark harness at
`tests/benchmark_public_datasets.py` was patched in v0.7.1 to load
NotInject via `huggingface_hub` and `pandas` directly, working around
a `datasets>=3.x` schema-resolver regression — a reproducibility fix
visible in the CHANGELOG that we highlight because JOSS reviewers
can now re-run every benchmark row on a bare Python environment.

# Design principles

Section 7 of the companion paper [@prompt-shield-arxiv-2026]
describes the three architectural patterns that organize the
software; we summarise them here.

The **Tool-Result Boundary Gate** addresses the observation that
agent tool output re-enters the LLM context and can carry
adversary-controlled instructions. Between April and July 2026 four
independent research prototypes converged on this pattern without a
common name [@claw-guard-2026; @dual-view-2026; @prismata-2026;
@token-flow-firewall-2026], and a fifth [@agent-spec-2026] subsumes
it as a special case of a broader runtime-enforcement DSL. The
companion paper attempts to name and describe its reference
structure: intercept every string returned by a tool call before it
re-enters the LLM context, run it through the detector stack, and
enforce a `block` / `flag` / `sanitize` policy.

**Federated Signed Threat Intelligence** applies the
Abuse.ch / VirusTotal model — familiar in network security — to
LLM defense. Attack signatures live in a public
`prompt-shield-signatures` [@prompt-shield-signatures-2026]
repository, are ed25519-signed with an offline key (never present
in CI), and delivered via CDN. Clients verify signatures with
pure-code cryptography and no vendor SDK. This is a novel
application of an existing pattern rather than a novel formalism,
and the companion paper says so.

**Attack-Family Taxonomic Projection** exposes detection results to
downstream policy engines and dashboards through a stable
nine-family taxonomy implemented as a pure projection function
over the concrete `detector_id`. Detector churn does not break
downstream policy configuration; the taxonomy is orthogonal to the
detector set. We describe this as a pattern in the hope that other
detector-stack maintainers adopt it; at time of writing
prompt-shield is its only known implementation. Design details are
in the companion design-notes preprint [@prompt-shield-zenodo-designnotes].

The software is Apache 2.0-licensed, the benchmark data is CC0, and
the federated feed's signing key lives offline.

# Acknowledgements

We thank the authors of ClawGuard, DualView, Prismata, Token-Flow
Firewall, and AgentSpec whose concurrent, independent
implementations of the tool-result boundary pattern in 2026 made
it legible as a pattern worth naming. We also thank the
independent reviewer whose `CLAIM-AUDIT.md` corrections informed
the v0.7.1 accuracy release.

# AI usage disclosure

Portions of `prompt-shield`'s development and this paper's drafting
were assisted by AI tools, primarily Anthropic Claude Code (for
code generation, refactoring, documentation, and iterative paper
editing) and Anthropic Fable 5 (as an independent-review agent
across multiple review passes on both the software and the
paper). All final decisions on architecture, detection algorithms,
threshold tuning, evaluation methodology, and research claims are
the author's own. AI-generated code was reviewed and tested before
commit; AI-suggested paper text was verified against the actual
implementation and empirical measurements before inclusion. All
empirical numbers reported in this paper and the companion arXiv
preprint were produced by scripts in the repository (paths cited in
each subsection) and are independently reproducible.

# References
