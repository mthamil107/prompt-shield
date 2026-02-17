# Changelog

## v0.1.1 (Pattern Coverage Fix)

### Detectors

- **d001 System Prompt Extraction** — Fixed patterns that rejected the article "the" (e.g., "reveal the system prompt" was not detected). Broadened verb coverage with `give`, `share`, `disclose`, `expose` and added optional indirect objects (`me`/`us`). Added two new patterns: contraction form ("what's your system prompt") and indirect requests ("can you share the system prompt").
- **d003 Instruction Override** — Added two new patterns for system-level bypass attempts ("override system", "bypass safety filters", "circumvent the system restrictions", "disable safety guardrails") and deactivation attempts ("turn off content filters", "deactivate safety protections"). Previously the override pattern required a temporal qualifier and instruction noun, so bare phrases like "override system" were missed.
- **d004 Prompt Leaking** — Added `reveal`, `show`, `display` verbs to the repeat-system-message pattern for consistent coverage across detectors.

---

## v0.1.0 (Initial Release)

### Engine
- Core `PromptShieldEngine` with scan, batch scan, feedback, and threat management
- Layered configuration system (YAML + env vars + dict overrides)
- Allowlist and blocklist regex pattern support
- Scan history with SQLite persistence and configurable retention

### Detectors (21 built-in)
- **Direct injection**: d001 System Prompt Extraction, d002 Role Hijack, d003 Instruction Override, d004 Prompt Leaking, d005 Context Manipulation, d006 Multi-Turn Escalation, d007 Task Deflection
- **Obfuscation**: d008 Base64 Payload, d009 ROT13/Character Substitution, d010 Unicode Homoglyph, d011 Whitespace/Zero-Width Injection, d012 Markdown/HTML Injection, d020 Token Smuggling
- **Indirect injection**: d013 Data Exfiltration, d014 Tool/Function Abuse, d015 RAG Poisoning, d016 URL Injection
- **Jailbreak**: d017 Hypothetical Framing, d018 Academic/Research Pretext, d019 Dual Persona
- **Self-learning**: d021 Vault Similarity

### Self-Learning
- ChromaDB-backed attack vault with sentence-transformer embeddings
- Automatic storage of detected attacks for similarity matching
- User feedback system (true positive / false positive)
- Auto-tuner for per-detector threshold adjustment
- Community threat feed export, import, and remote sync

### Agentic Security
- `AgentGuard` with 3-gate model (input, data, output)
- Canary token injection and leak detection
- `PromptShieldMCPFilter` for transparent MCP server protection
- Tool argument and result scanning

### Integrations
- FastAPI / Starlette middleware
- Flask WSGI middleware
- Django middleware
- LangChain callback handler
- LlamaIndex handler

### CLI
- `prompt-shield scan` with file/stdin/text input
- `prompt-shield detectors list/info`
- `prompt-shield config init/validate`
- `prompt-shield vault stats/search/clear`
- `prompt-shield feedback`
- `prompt-shield threats export/import/sync/stats`
- `prompt-shield test` and `prompt-shield benchmark`

### Plugin System
- `BaseDetector` interface for custom detectors
- Auto-discovery of detectors in the `prompt_shield.detectors` package
- Entry point discovery for third-party detector packages
- Runtime registration via `engine.register_detector()`
