# Agentic Security Demo

Demonstrates the 3-gate `AgentGuard` pattern and `PromptShieldMCPFilter` for protecting agentic AI applications.

## Setup

```bash
pip install prompt-shield
```

## Run

Agent loop with 3-gate protection:

```bash
python examples/agentic_demo/app.py
```

MCP server filter:

```bash
python examples/agentic_demo/mcp_server.py
```

## The 3-Gate Model

| Gate | What it protects | Method |
|---|---|---|
| **Gate 1 — Input** | User messages | `guard.scan_input()` |
| **Gate 2 — Data** | Tool results (MCP, function calls, RAG) | `guard.scan_tool_result()` |
| **Gate 3 — Output** | LLM responses | `guard.prepare_prompt()` + `guard.scan_output()` |

Gate 2 is the most critical for agentic apps because tool results are the primary vector for indirect prompt injection. Content from databases, web searches, and MCP servers can contain hidden instructions that the agent blindly follows.

## MCP Filter

`PromptShieldMCPFilter` wraps any MCP server as a transparent proxy. It scans tool arguments before execution and tool results after execution. Modes: `"block"` (reject), `"sanitize"` (redact), or `"flag"` (log only).
