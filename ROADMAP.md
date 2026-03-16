# prompt-shield Roadmap

## v0.1.x
- 22 detectors, DeBERTa ML classifier, ensemble scoring
- OpenAI/Anthropic client wrappers
- Self-learning vault (local ChromaDB)
- CLI, FastAPI/Flask/Django middleware, LangChain/LlamaIndex/MCP integrations

## v0.2.0

### OWASP LLM Top 10 Compliance Mapping
All 22 detectors mapped to OWASP LLM Top 10 (2025) categories. Coverage reports show which categories are covered and where gaps remain.
- `prompt-shield compliance report` — formatted coverage matrix
- `prompt-shield compliance mapping` — detector-to-OWASP mapping with optional `--detector` filter
- JSON output support for CI/CD integration
- Python API: `generate_compliance_report()` for programmatic access

### Standardized Benchmarking
Accuracy benchmarking framework with ML metrics (precision, recall, F1, accuracy, TPR, FPR).
- Bundled 50-sample dataset (25 injection + 25 benign) for offline evaluation
- Dataset loaders for CSV, JSON, and HuggingFace Hub
- `prompt-shield benchmark accuracy --dataset sample` — run accuracy benchmarks
- `prompt-shield benchmark performance -n 100` — throughput measurement
- `prompt-shield benchmark datasets` — list available datasets
- Save results to JSON for tracking over time

## v0.3.0 (current) — Community, Plugins & Trust

### PII Detection & Redaction ✅
New `d023_pii_detection` detector and standalone `PIIRedactor` for detecting and redacting personally identifiable information before prompts reach the LLM. Mapped to OWASP LLM02 (Sensitive Information Disclosure).
- 6 entity types: email, phone, SSN, credit card, API key, IP address (16 regex patterns)
- Entity-type-aware redaction placeholders (`[EMAIL_REDACTED]`, `[SSN_REDACTED]`, etc.)
- CLI commands: `prompt-shield pii scan` and `prompt-shield pii redact` with JSON output
- Per-entity enable/disable and custom patterns via YAML config
- Integrated into AgentGuard `_sanitize_text()` for automatic PII redaction in the sanitize flow
- Standalone `PIIRedactor` usable directly from Python API

### Community & Integrations
- `prompt-shield-threats` public repo — community-contributed attack fingerprints via PRs
- Client-side import from threat repo URL (free, no server)
- Dify plugin (Tool type)
- n8n community node
- CrewAI integration
- Get listed on awesome-llm-security lists

### Prometheus Metrics Endpoint
Expose a `/metrics` endpoint for scan counts, block rates, detector hit rates, latency percentiles, and vault size — so users can plug prompt-shield into their existing monitoring stack without waiting for a dashboard.

### Docker & Helm Charts
Production-ready container images and Kubernetes deployment manifests for enterprise adoption.

## v0.4.0 — Closing the Gaps

### Gap Analysis (2025-2026 Research)
Security research audit identified 12 attack techniques that bypass prompt-shield's current 23 detectors. Sources: ACL 2025, NSS 2025, CSA 2026, arXiv, OWASP LLM01:2025, AWS Security, NVIDIA.

#### P0 — Critical Gaps (prompt-shield is blind)
| Gap | Attack | Impact | New Detector |
|-----|--------|--------|-------------|
| GAP 9 | Multilingual attacks (French, Chinese, Arabic injections) | All 22 regex detectors are English-only | d024: Multilingual injection detection |
| GAP 8 | Cipher/encoding bypass (hex, leetspeak, Morse, Caesar) | Only base64 and ROT13 decoded | d025: Multi-encoding decoder |
| GAP 5 | Many-shot jailbreaking (50-200 fake Q&A pairs) | No prompt length/structure analysis | d026: Structural anomaly detector |

#### P1 — High Priority
| Gap | Attack | Impact | Fix |
|-----|--------|--------|-----|
| GAP 1 | Multimodal injection (images, audio, EXIF) | Text-only scanning architecture | d027: Multimodal scanner (OCR + metadata) |
| GAP 2 | HILL (educational reframing of harmful queries) | Looks like normal academic questions | d028: Intent classifier |
| GAP 4 | TokenBreak (Unicode combining marks, variation selectors) | Only 14 invisible chars in d011 | Expand d010/d011 Unicode coverage |
| GAP 6 | Tool-disguised attacks (iMIST via RL) | d014 is keyword-only | d029: Structured payload scanner |

#### P2 — Medium Priority
| Gap | Attack | Fix |
|-----|--------|-----|
| GAP 7 | Sophisticated multi-turn (semantic escalation, no keywords) | Enhance d006 with topic drift tracking |
| GAP 12 | Dual intention escape (harmful intent in legitimate request) | d030: Embedded intent detector |
| GAP 10 | MCP/agent protocol exploitation | Protocol-level scanning utilities |
| GAP 3 | Prompt-in-content (hidden text in PDFs/docs) | Document parsing utilities |
| GAP 11 | Fuzzing-generated jailbreaks (99% success rate) | Shift weight to ML classifiers |

#### Architectural Fixes
- **Text normalization pipeline** — Strip invisible chars + map homoglyphs BEFORE running all detectors (currently only d010/d011 do this)
- **Multi-encoding preprocessor** — Decode base64, hex, URL-encoding, ROT13, leetspeak in a single pass, then re-scan decoded output
- **Remove 512-token limit on d022** — Attacks after token 512 bypass ML entirely; chunk and scan
- **Output scanning** — Detect when injection succeeded by scanning model responses

### Adversarial Self-Testing (Red Team Loop) ← NEW
LLM-powered red team that continuously attacks prompt-shield, reports bypasses, and auto-generates fixes.
- `prompt-shield redteam` CLI command — runs Claude/OpenAI as attacker against prompt-shield
- Configurable time budget (e.g., `--duration 1h`)
- Covers all 12 gap categories: multilingual, cipher, many-shot, multimodal, HILL, TokenBreak, tool-disguised, multi-turn, dual-intention, MCP, document, fuzzing
- Generates detailed report: attacks tried, bypasses found, severity, suggested fixes
- Auto-fix mode: generates new regex patterns or detector code for discovered bypasses
- Python API: `RedTeamRunner` class for programmatic use
- No other open-source tool has this: attack → detect → fix → re-attack loop

### Live Collaborative Threat Network (Paid Hub)
Real-time threat intelligence sharing across all deployments. Every blocked attack silently contributes an anonymized fingerprint; every user benefits instantly.
- Phase 1: Free community threat repo on GitHub (build traction first)
- Phase 2: Central hub API (Fly.io + Supabase pgvector) — only when 500+ stars / active demand
- Phase 3: Freemium tiers — Community (read-only, delayed), Contributor (real-time), Pro ($29/mo dashboard + analytics), Enterprise ($99+/mo SLA + on-prem)

### Behavioral Drift Detection
Monitor LLM outputs — not just inputs. Detect when model behavior diverges from its baseline (tone shift, instruction leakage, unexpected tool calls). Flag compromised sessions regardless of what the input looked like.

### Per-Session Trust Scoring
Track user behavior across a conversation. Build a risk profile over time. Detect slow multi-turn escalation attacks that look safe message-by-message but form an attack pattern in aggregate.

### SaaS Dashboard
Hosted dashboard with real-time analytics, attack trends, team alerts, one-click threshold tuning, and deployment management.

### Agentic Honeypots
Active deception beyond canary tokens. Plant realistic fake credentials, fake APIs, fake sensitive data. If the agent touches them, the session is compromised.

### OpenTelemetry & Langfuse Integration
Native observability export so prompt-shield scan data flows into existing monitoring stacks.
- OpenTelemetry spans and metrics for every scan (latency, risk score, detectors triggered)
- Langfuse integration — trace-level prompt security annotations

### Denial of Wallet Detection
Detect prompts designed to trigger excessive token usage — extremely long outputs, recursive tool calls, infinite loops.
- Token budget enforcement per session
- Cost anomaly alerting

### Webhook Alerting
Real-time incident notifications to Slack, PagerDuty, Discord, email, or custom webhooks when attacks are detected or block rates spike.

---

## Competitive Landscape

Projects with meaningful overlap or complementary positioning.

### Direct Competitors / Overlap

| Project | What It Does | Relation to prompt-shield |
|---------|-------------|--------------------------|
| [JavelinGuard](https://arxiv.org/abs/2506.07330) | Suite of ~400M-param BERT-variant classifiers (5 architectures) for detecting malicious LLM interactions. Benchmarked on 9 adversarial datasets. | Closest ML-level competitor. Their multi-architecture approach (attention-weighted pooling, multi-task loss) is more sophisticated than our single DeBERTa classifier. |
| [TSZ (Thyris Safe Zone)](https://github.com/thyrisAI/safe-zone) | Open-source guardrails & data security layer between apps and LLMs. PII redaction, rule-based + semantic guardrails, output schema validation. Apache 2.0, self-hosted. | Similar architecture (middleware layer, rule + ML hybrid). Their PII focus and output validation are features we lack. |
| [promptfoo](https://www.promptfoo.dev/blog/building-a-security-scanner-for-llm-apps/) | Security scanner for LLM apps. Tests for prompt injection, jailbreaks, and related vulnerabilities. | Testing/evaluation tool, not runtime defense. Could be used to benchmark prompt-shield. |
| [PenStrike](https://penstrike.io/) | Automated security scanning SaaS for LLM applications. | SaaS scanner; we are self-hosted runtime defense. Different delivery model, same problem space. |

### Complementary Tools (Red-Team / Testing)

| Project | What It Does | Relation to prompt-shield |
|---------|-------------|--------------------------|
| [DeepTeam](https://github.com/confident-ai/deepteam) | Open-source red-teaming framework. 40+ risk categories, 10+ attack methods (jailbreaks, ROT13, prompt injection, data extraction). | Offensive testing tool — ideal for validating prompt-shield's detection coverage. Candidate for CI integration. |
| [Compliant LLM](https://github.com/fiddlecube/compliant-llm) | Automated scanner for SQL injection, code injection, template injection, prompt obfuscation, and data exfiltration via LLM tool calls. | Scanner that tests the exact attack types our detectors defend against. Good validation source. |
| [SiteIQ](https://github.com/sastrophy/siteiq) | Web security scanner with LLM security module — prompt injection, jailbreaking, system prompt leakage, Denial of Wallet attacks. | Their "Denial of Wallet" attack category is one we don't cover yet. |

### Conceptually Related

| Project | What It Does | Relation to prompt-shield |
|---------|-------------|--------------------------|
| [Action Authorization Boundary](https://news.ycombinator.com/item?id=42918344) | Deterministic YAML policy layer outside the agent context for intercepting and authorizing tool calls. | Aligns with our AgentGuard concept. Their CAR (Canonical Action Representation) spec is a more formal approach to tool-call governance. |
| [Pre-Trained Security LLM 8B](https://arxiv.org/abs/2504.21039) | Security-domain fine-tuned 8B LLM. | Potential replacement or enhancement for our DeBERTa classifier — could power an LLM-as-judge detector. |
| [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | Industry-standard risk taxonomy for LLM applications. | Our detectors already address LLM01 (Prompt Injection) and LLM06 (Sensitive Info Disclosure). Use as coverage checklist. |
| [RAG + FGA (Permit.io)](https://www.permit.io/blog/building-ai-applications-with-enterprise-grade-security-using-fga-and-rag) | Fine-Grained Authorization for RAG/LLM apps. | Complementary to our RAG poisoning detector (d015). Their access-control layer is orthogonal to our injection detection. |

---

## Features to Bring from Competitors

Capabilities observed in comparable projects that would strengthen prompt-shield.

### From JavelinGuard
- **Multi-architecture classifier ensemble** — Instead of a single DeBERTa model, offer multiple lightweight classifiers (attention-weighted pooling, multi-task heads) and ensemble their predictions. Would improve detection robustness significantly.
- **Specialized loss functions** — Their Raudra architecture uses multi-task loss to handle borderline cases. Apply this to our semantic classifier training to reduce false positives on ambiguous inputs.
- **Standardized adversarial benchmarking** — Benchmark prompt-shield against their 9 datasets (NotInject, BIPIA, Garak, ToxicChat, WildGuard, JavelinBench) to produce comparable accuracy numbers.

### From TSZ (Thyris Safe Zone)
- ~~**PII detection and redaction**~~ — ✅ Shipped in v0.3.0 (`d023_pii_detection` + `PIIRedactor`).
- **Output schema validation** — Validate that LLM structured outputs conform to expected schemas. Catch malformed JSON or unexpected fields that could indicate injection in tool-use workflows.
- **Blocked/redacted response metadata** — Return structured signals (redacted output, metadata, blocked flag) so downstream apps can decide how to proceed rather than just block/pass.

### From DeepTeam
- **Built-in red-team attack suite** — Bundle attack simulation capabilities directly into prompt-shield so users can self-test their deployment. A `prompt-shield attack` CLI command that runs jailbreaks, ROT13, data extraction attempts against the user's own configuration.
- **OWASP/NIST compliance mapping** — Map each detector to OWASP LLM Top 10 and NIST AI RMF categories. Produce compliance reports showing which risks are covered and at what confidence level.

### From SiteIQ
- **Denial of Wallet detection** — Detect prompts designed to trigger excessive token usage (extremely long outputs, recursive tool calls, infinite loops). A new detector category we currently lack entirely.

### From Action Authorization Boundary (AAB)
- **Canonical Action Representation** — Formalize tool-call interception in AgentGuard with a declarative policy spec (YAML/JSON). Let users define allowed/blocked tool actions, parameter constraints, and sequence rules without writing code.
- **Stateful intent tracking** — Detect action sequences that are individually safe but collectively dangerous (e.g., read sensitive DB → POST to external API = exfiltration). Extends our multi-turn escalation detector (d006) to the tool-call level.

### From Compliant LLM
- **Template injection detection** — Add a detector for template injection attacks (Jinja2, Handlebars, etc.) targeting LLM tool-call outputs. Currently a gap in our obfuscation detector family.
- **Downstream tool-call injection testing** — Specifically test whether LLM outputs can inject SQL, shell commands, or code into downstream tool calls. Extends d014 (Tool/Function Abuse) coverage.

### From Pre-Trained Security LLM 8B
- **LLM-as-judge detector** — Use a small security-tuned LLM as an additional detector for cases that evade both regex and DeBERTa. Higher latency but catches novel/creative attacks that pattern matching misses. Already on roadmap (v0.3.0) — these models make it more practical.
