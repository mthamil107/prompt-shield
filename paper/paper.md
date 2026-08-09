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
date: 09 August 2026
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
a honeypot-tool detector, and multilingual coverage across ten
languages), 9 output scanners (toxicity, code injection, prompt
leakage, PII, schema validation, jailbreak, sentiment, bias/fairness,
hallucination/grounding), a first-class `ToolResultGuard` primitive
for scanning tool-result content before it re-enters the model's
context, and a federated ed25519-signed threat-intelligence feed
(`prompt-shield-signatures`) that the engine verifies against a
pinned public key before loading. All input is passed through an
idempotent normalisation pipeline (NFKC, zero-width strip, Cyrillic
to Latin homoglyph map, whitespace collapse) prior to detector
dispatch. The library ships with thirteen framework integrations
(LangChain, LlamaIndex, Haystack, Pydantic AI, CrewAI, MCP, the
OpenAI and Anthropic SDKs, FastAPI, Flask, Django, n8n, Dify) plus
a standalone REST/Docker deployment, a Prometheus `/metrics`
endpoint, per-key sliding-window rate limiting, and a 1,250-test
regression suite (1,232 passing + 18 skipped).

# Statement of need

Prompt injection is the top-ranked risk in the OWASP LLM Top-10
[@owasp-llm-top10-2025] and the primary attack surface introduced by
tool-augmented agents [@liu-2024]. Production LLM applications need
defense at three architectural boundaries — user input, tool-call
output, and model output — plus a threat-intelligence supply chain
to catch novel attack patterns as they emerge. No single existing
open-source tool covers this full surface as an integrated,
`pip install`-deployable stack (see the State of the field
comparison below).

`prompt-shield` addresses this gap: a defense-in-depth stack
combining input scanning, output scanning, a tool-result boundary
gate, and a federated signed threat feed behind one API with a
reproducible benchmark harness. It does not win the false-positive
beauty contest on any single benchmark — in-distribution supervised
classifiers report lower FPR by construction, and the companion
paper [@prompt-shield-arxiv-2026] is explicit about this trade-off.

# State of the field

The 2026 open-source landscape for prompt-injection defense splits
into four shapes, none of which addresses the full production
deployment surface:

**Broad policy frameworks** — `guardrails-ai` [@guardrails-ai-2023]
and NVIDIA `NeMo Guardrails` [@nemo-guardrails-2023] — provide
validator and dialogue-flow abstractions but leave detector
implementation to the user, offering no shipped detection stack.

**Commercial-backed single-technique tools** — `llm-guard`
[@llm-guard-2023] and `rebuff` [@rebuff-2023] (the latter
unmaintained since August 2024) — offer one or two detection
strategies (pattern matching, canary tokens) and no tool-result
boundary primitive.

**Academic single-technique detectors** — PromptSentinel-X
[@prompt-sentinel-x-2026] and DataSentinel [@data-sentinel-2025] as
trained ML classifiers, AgentWatcher [@agent-watcher-2026] as a
rule-based monitor — publish strong per-technique numbers on
in-distribution benchmarks but ship as research prototypes rather
than integrated libraries.

**Runtime-enforcement systems** — ClawGuard [@claw-guard-2026],
AgentSpec [@agent-spec-2026], Prismata [@prismata-2026], DualView
[@dual-view-2026], and Token-Flow Firewall
[@token-flow-firewall-2026] — confine what a compromised agent can
do at execution time, but do not themselves classify whether the
incoming context is compromised.

`prompt-shield` occupies a distinct point in this design space: an
integrated defense-in-depth stack packaged as a single `pip install`,
combining 34 input detectors, 9 output scanners, a tool-result
boundary gate, and a federated ed25519-signed threat feed under one
API with reproducible per-benchmark evaluation scripts checked into
the repository. The companion paper's Related Work section (§2.4)
[@prompt-shield-arxiv-2026] maps the full 2026 concurrent-contribution
cluster and positions each system relative to the others.

# Software design

Section 7 of the companion paper [@prompt-shield-arxiv-2026]
formalises three architectural patterns that organise the software;
we summarise them here.

The **Tool-Result Boundary Gate** addresses the observation that
agent tool output re-enters the LLM context and can carry
adversary-controlled instructions. Between April and July 2026 four
independent research prototypes converged on this pattern without a
common name [@claw-guard-2026; @dual-view-2026; @prismata-2026;
@token-flow-firewall-2026]; a fifth [@agent-spec-2026] subsumes it
as a special case of a broader runtime-enforcement DSL. `prompt-shield`
implements the pattern via `ToolResultGuard`: intercept every string
returned by a tool call before it re-enters the LLM context, run it
through the detector stack, and enforce a `block` / `flag` /
`sanitize` policy.

**Federated Signed Threat Intelligence** applies the Abuse.ch and
VirusTotal model — familiar in network security — to LLM defense.
Attack signatures live in a public `prompt-shield-signatures`
[@prompt-shield-signatures-2026] repository, are ed25519-signed with
an offline key (never present in CI), and delivered via CDN. Clients
verify signatures with pure-code cryptography and no vendor SDK.
This is a novel application of an established pattern rather than a
novel formalism, and the companion paper is explicit about that
distinction.

**Attack-Family Taxonomic Projection** exposes detection results to
downstream policy engines and dashboards through a stable nine-family
taxonomy implemented as a pure projection function over the concrete
`detector_id`. Detector churn does not break downstream policy
configuration; the taxonomy is orthogonal to the detector set. We
describe this as a pattern in the hope that other detector-stack
maintainers adopt it; at time of writing `prompt-shield` is its
only known implementation. Design details are in the companion
design-notes preprint [@prompt-shield-zenodo-designnotes].

The software is Apache 2.0-licensed, the benchmark data is CC0, and
the federated feed's signing key lives offline.

# Research impact statement

`prompt-shield`'s research contribution is documented in the
companion peer-review-prepared preprint [@prompt-shield-arxiv-2026]
on arXiv (2604.18248v4, 31 pages) and mirrored on Zenodo
[@prompt-shield-zenodo-paper]. The preprint proposes seven detection
techniques, each porting a mechanism from a discipline outside
large-language-model security: forensic linguistics, materials-science
fatigue analysis, deception technology, local-sequence alignment
from bioinformatics, mechanism design, spectral signal analysis, and
taint tracking. Four of the seven are implemented as shipped detectors
in this software (d027 stylometric discontinuity, d028 Smith-Waterman
sequence alignment, adversarial fatigue tracker, and d034 honeypot
tool definitions); the remaining three are documented as design
specifications for future work.

The paper reports independent evaluation across three peer-reviewed
academic benchmarks — Liu et al. USENIX Security 2024 [@liu-2024],
NVIDIA Garak [@nvidia-garak], and InjecAgent (ACL Findings 2024,
[@injecagent-2024]) — totalling 8,276 unseen attack prompts, none
of which were used to design or tune any `prompt-shield` detector,
alongside in-distribution recall and specificity evaluation on
`deepset/prompt-injections` [@deepset-injections] and the NotInject
benign-prompt set [@notinject-2024]. The paper also publishes
empirical findings against self-interest: Section 5.8 reports the
d027 stylometric detector collapsing from 1.000 F1 on the synthetic
benchmark it was designed against to 0.000 F1 on a 50-document
held-out realistic-document corpus, with the composed engine
recovering 0.815 F1. Section 5.7 reports a
Nasr-style adaptive-attack evaluation showing d028's detection
dropping from 95.0% to 0.0% under a matrix-aware second-mover
adversary — quantifying the operating envelope publicly rather than
obscuring it.

The project has been publicly developed since 2026-02-12 (178 days
at JOSS submission on 2026-08-09, crossing the JOSS six-month
public-development threshold on 2026-08-12 — three days after
submission), with 183 total commits (158 excluding merges), 20
releases published to PyPI (19 tagged in git), and 25 pull requests
visible in the public history. There is no private prehistory;
every commit has been public from day one. All commits, releases,
and pull requests to date are by the original author; external
contributions are invited via a public `CONTRIBUTING.md` at the
repository root, with the acknowledgement that JOSS treats
external-contributor engagement as welcome but non-essential.

Every empirical number reported in the paper is produced by scripts
checked into the repository at pinned release tags. PyPI adoption
stands at approximately 12,600 all-time downloads and 2,600 in the
trailing 30 days (source: pepy.tech, snapshot 2026-08-09); GitHub
stars are at 12 with 3 forks; the project has been externally
covered by a technical article on the Towards AI publication that
drove sustained referrer traffic. The federated-feed repository
[@prompt-shield-signatures-2026] records approximately 90 CDN
requests over the trailing 30 days (source: jsDelivr public stats
API for `mthamil107/prompt-shield-signatures`).

# Acknowledgements

We thank the authors of ClawGuard, DualView, Prismata, Token-Flow
Firewall, and AgentSpec whose concurrent, independent implementations
of the tool-result boundary pattern in 2026 made it legible as a
pattern worth naming. We also acknowledge the accuracy audit
documented in `CLAIM-AUDIT.md`, whose findings informed the v0.7.1
correctness release.

# AI usage disclosure

Portions of `prompt-shield`'s development and this paper's drafting
were assisted by AI tools, primarily Anthropic Claude Code (for
code generation, refactoring, documentation, and iterative paper
editing) and Anthropic Fable 5 (as an independent-review agent
across multiple review passes on both the software and the paper).
All final decisions on architecture, detection algorithms, threshold
tuning, evaluation methodology, and research claims are the author's
own. AI-generated code was reviewed and tested before commit;
AI-suggested paper text was verified against the actual implementation
and empirical measurements before inclusion. All empirical numbers
reported in this paper and the companion arXiv preprint were produced
by scripts in the repository (paths cited in each subsection) and are
independently reproducible.

# References
