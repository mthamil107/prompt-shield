# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
