---
layout: home
title: prompt-shield — OSS prompt-injection firewall
description: Apache 2.0 prompt-injection detection engine for LLM applications. 33 input detectors, 9 output scanners, federated ed25519-signed threat-intel feed. Paper + benchmarks + integrations for LangChain, LlamaIndex, CrewAI.
seo:
  type: SoftwareApplication
  name: prompt-shield
image: https://raw.githubusercontent.com/mthamil107/prompt-shield/main/prompt-shield-logo.png
---

# prompt-shield

**Open-source [prompt injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/) firewall for LLM applications.**
Apache 2.0. 33 input detectors, 9 output scanners, first OSS federated threat-intel feed for LLM defense.

- 📦 **Install:** `pip install prompt-shield-ai`
- 💻 **Repo:** [github.com/mthamil107/prompt-shield](https://github.com/mthamil107/prompt-shield)
- 📄 **Paper:** [arXiv:2604.18248](https://arxiv.org/abs/2604.18248) (CC BY 4.0)
- 🔖 **Design notes:** [Zenodo DOI 10.5281/zenodo.20809165](https://doi.org/10.5281/zenodo.20809165)

## What it catches

| Category | Detectors | What |
|---|---|---|
| Direct injection | d001-d007 | System prompt extraction, role hijack, instruction override |
| Obfuscation | d008-d012, d020, d025 | Base64, ROT13, Unicode homoglyph, zero-width, hex, URL, HTML entities |
| Multilingual | d024 | 10 languages including CJK, Arabic, Devanagari |
| Indirect injection | d013-d016 | Data exfiltration, RAG poisoning, tool/function abuse |
| Jailbreak | d017-d019 | Hypothetical framing, HILL, dual persona |
| ML semantic | d022 | DeBERTa-v3 classifier for paraphrased attacks |
| Cross-domain novel | d027-d029 | Stylometric discontinuity, Smith-Waterman, many-shot structural |
| Operator policy | d030-d033 | Custom YAML rules, language enforcement, denied topics, multi-turn drift |
| Self-learning | d021 | Vector similarity vault |
| Data protection | d023, output-PII | Email, phone, SSN, credit card, API keys |

## Novel techniques

Seven cross-domain techniques nobody else ships as of 2026:

### Smith-Waterman sequence alignment (d028)

Bioinformatics local alignment with a BLOSUM-style semantic substitution matrix. Catches paraphrased attacks where regex fails. **+34.5 pp F1 on the deepset benchmark, 0% false-positive cost.** [Write-up](https://dev.to/mthamil107/how-smith-waterman-from-bioinformatics-catches-prompt-injections-that-regex-misses-1mc2).

### Stylometric discontinuity (d027)

Forensic-linguistics style-break detection. Catches indirect injections where malicious content is inserted into otherwise-benign documents.

### Multi-turn topic drift via Jaccard anchor (d033)

Slow-jailbreak detection without ML dependencies. Sub-millisecond evaluation.

### Adversarial fatigue tracker

EWMA + per-source threshold hardening. Treats probing campaigns as the signal, not individual prompts.

### Federated threat-intel feed (v0.6.0)

**First OSS-with-no-commercial-strings signed public feed for LLM defense.** Pure-Python ed25519 verification, hourly-pollable, opt-in. Subscribe in 3 lines:

```python
from prompt_shield.signatures import SignaturesClient
update = SignaturesClient().fetch()
# update.signature_count == 56, ed25519-verified against pinned key
```

Feed source: [`prompt-shield-signatures`](https://github.com/mthamil107/prompt-shield-signatures)

### Multi-encoding fan-out preprocessor

Chains decoders (base64, hex, URL, HTML entities, ROT13) — catches layered attacks like `base64(rot13("ignore..."))`. Fan-out candidate set feeds back through the full detector stack.

### Idempotent normalization pipeline with change tracking

NFKC + zero-width + Cyrillic→Latin homoglyph + whitespace collapse. Change-tracking output enables meta-detection (an input that needed zero-width stripping is itself suspect).

## Independent benchmarks

Section 5.6 of the paper reports evaluation on five public datasets:

| Benchmark | Attack count | Detection |
|---|---|---|
| Liu et al. (USENIX Sec 2024) attack strategies | 200 | 64.0% |
| NVIDIA Garak `promptinject` + `latentinjection` | 5,968 | 55.2% |
| InjecAgent (ACL Findings 2024) indirect injection | 2,108 | 85.2% |
| deepset/prompt-injections | 116 | F1 0.378 with d028, 0.033 without (both regex-only, d022 off) — +34.5 pp |
| leolee99/NotInject (benign) | 339 | 3.8% false positives (13/339) — [breakdown](https://github.com/mthamil107/prompt-shield#benchmark-3-public-dataset----notinject-339-benign-samples) |

## Framework integrations

Ships with LangChain, LlamaIndex, CrewAI, FastAPI, Flask, Django, OpenAI, Anthropic, MCP.

## Compliance

Maps every detector to four frameworks:
- OWASP LLM Top 10 (2025) — 8/10 categories (LLM01, LLM02, LLM04–LLM08, LLM10), all 33 detectors mapped
- OWASP Agentic Top 10 — 10/10 categories (ASI01–ASI10), 41 detector mappings
- EU AI Act (Aug 2026 deadline) — article-level mapping
- MITRE ATLAS — 9/9 techniques (T0048, T0049, T0051-T0054, T0057)

## Cite the paper

```bibtex
@misc{munirathinam2026prompt,
  title={Beyond Pattern Matching: Seven Cross-Domain Techniques for Prompt Injection Detection},
  author={Munirathinam, Thamilvendhan},
  year={2026},
  eprint={2604.18248},
  archivePrefix={arXiv},
  primaryClass={cs.CR}
}
```

## Full documentation

- [README](https://github.com/mthamil107/prompt-shield/blob/main/README.md) — install, quickstart, examples
- [Design notes (v0.5.0)](design-notes-v0.5.0.html) — algorithmic detail for each novel technique
- [CHANGELOG](https://github.com/mthamil107/prompt-shield/blob/main/CHANGELOG.md) — release history
- [Roadmap](https://github.com/mthamil107/prompt-shield/blob/main/ROADMAP.md)
- [Contributing](https://github.com/mthamil107/prompt-shield/blob/main/CONTRIBUTING.md)

---

<sub>prompt-shield is developed by [Thamilvendhan Munirathinam](https://github.com/mthamil107). Code is Apache 2.0. Paper and design notes are CC BY 4.0. Federated feed signatures are hand-curated from public sources (Garak corpus, OWASP LLM Top 10, HackerOne disclosures, community submissions).</sub>
