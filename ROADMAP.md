# prompt-shield Roadmap

## v0.1.x (current)
- 22 detectors, DeBERTa ML classifier, ensemble scoring
- OpenAI/Anthropic client wrappers
- Self-learning vault (local ChromaDB)
- CLI, FastAPI/Flask/Django middleware, LangChain/LlamaIndex/MCP integrations

## v0.2.0 — Community & Plugins
- `prompt-shield-threats` public repo — community-contributed attack fingerprints via PRs
- Client-side import from threat repo URL (free, no server)
- Dify plugin (Tool type)
- n8n community node
- Get listed on awesome-llm-security lists

## v0.3.0 — Game Changers

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
