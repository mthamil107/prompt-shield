# prompt-shield Roadmap

## v0.1.x
- 22 detectors, DeBERTa ML classifier, ensemble scoring
- OpenAI/Anthropic client wrappers
- Self-learning vault (local ChromaDB)
- CLI, FastAPI/Flask/Django middleware, LangChain/LlamaIndex/MCP integrations

## v0.2.0 (current)

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

## v0.3.0 — Community, Plugins & Trust

### Community & Integrations
- `prompt-shield-threats` public repo — community-contributed attack fingerprints via PRs
- Client-side import from threat repo URL (free, no server)
- Dify plugin (Tool type)
- n8n community node
- CrewAI integration
- Get listed on awesome-llm-security lists

### PII Detection & Redaction
Detect and redact personally identifiable information (SSNs, emails, credit cards, phone numbers, API keys, secrets) before prompts reach the LLM. Extends the data exfiltration detector (d013) into a full data protection layer.
- Redaction mode — mask sensitive data before forwarding to LLM
- Configurable entity types and custom patterns
- Structured metadata in scan reports (redacted fields, entity counts)

### Prometheus Metrics Endpoint
Expose a `/metrics` endpoint for scan counts, block rates, detector hit rates, latency percentiles, and vault size — so users can plug prompt-shield into their existing monitoring stack without waiting for a dashboard.

### Docker & Helm Charts
Production-ready container images and Kubernetes deployment manifests for enterprise adoption.

## v0.4.0 — Game Changers

### 1. Live Collaborative Threat Network (Paid Hub)
Real-time threat intelligence sharing across all deployments. Every blocked attack silently contributes an anonymized fingerprint; every user benefits instantly. CrowdStrike model for LLM security.
- Phase 1: Free community threat repo on GitHub (build traction first)
- Phase 2: Central hub API (Fly.io + Supabase pgvector) — only when 500+ stars / active demand
- Phase 3: Freemium tiers — Community (read-only, delayed), Contributor (real-time), Pro ($29/mo dashboard + analytics), Enterprise ($99+/mo SLA + on-prem)

### 2. Adversarial Self-Testing (Red Team Loop)
Use an LLM to continuously attack prompt-shield, evolve bypass strategies, and auto-generate new detector rules. A red team that never sleeps.

### 3. Behavioral Drift Detection
Monitor LLM outputs — not just inputs. Detect when model behavior diverges from its baseline (tone shift, instruction leakage, unexpected tool calls). Flag compromised sessions regardless of what the input looked like.

### 4. Per-Session Trust Scoring
Track user behavior across a conversation. Build a risk profile over time. Detect slow multi-turn escalation attacks that look safe message-by-message but form an attack pattern in aggregate.

### 5. SaaS Dashboard
Hosted dashboard with real-time analytics, attack trends, team alerts, one-click threshold tuning, and deployment management. The library is distribution; the platform is the product.

### 6. Agentic Honeypots
Active deception beyond canary tokens. Plant realistic fake credentials, fake APIs, fake sensitive data. If the agent touches them, the session is compromised. Active defense, not just passive detection.

### 7. OpenTelemetry & Langfuse Integration
Native observability export so prompt-shield scan data flows into existing monitoring stacks.
- OpenTelemetry spans and metrics for every scan (latency, risk score, detectors triggered)
- Langfuse integration — trace-level prompt security annotations
- Compatible with Datadog, Arize, WhyLabs, and any OTel collector

### 8. Denial of Wallet Detection
Detect prompts designed to trigger excessive token usage — extremely long outputs, recursive tool calls, infinite loops. A new detector category that no other open-source tool covers.
- Token budget enforcement per session
- Cost anomaly alerting

### 9. Multi-Language Attack Detection
Extend detectors beyond English. Attacks in non-English languages, mixed-language prompts, and transliteration-based obfuscation currently bypass English-only regex patterns.

### 10. Webhook Alerting
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
- **PII detection and redaction** — Detect and redact personally identifiable information (SSNs, emails, credit cards, API keys) before prompts reach the LLM. A natural extension of our data exfiltration detector (d013).
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
