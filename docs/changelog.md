# Changelog

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
