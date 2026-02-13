# Architecture

This document describes the internal architecture of prompt-shield, covering all components, their responsibilities, data flow, and key design decisions.

---

## System Overview

```
                    ┌───────────────────────────────────┐
                    │       PromptShieldEngine           │
                    │       (engine.py)                  │
                    ├───────────────────────────────────┤
                    │  scan()          feedback()        │
                    │  scan_batch()    add_canary()      │
                    │  export_threats() check_canary()   │
                    │  import_threats() sync_threats()   │
                    │  register_detector()               │
                    └──────────┬────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
    ┌─────▼─────┐     ┌───────▼───────┐    ┌──────▼──────┐
    │  Registry  │     │  Attack Vault │    │  Feedback   │
    │ (registry  │     │  (ChromaDB +  │    │  System     │
    │  .py)      │     │   Embedder)   │    │             │
    ├────────────┤     ├──────────────┤    ├─────────────┤
    │ auto_      │     │ store()      │    │ FeedbackStore│
    │ discover() │     │ query()      │    │ AutoTuner   │
    │ register() │     │ remove()     │    │             │
    │ list_all() │     │ import/export│    │ tune()      │
    └─────┬──────┘     └──────┬───────┘    └──────┬──────┘
          │                   │                   │
    ┌─────▼──────┐     ┌─────▼───────┐    ┌─────▼───────┐
    │ Detectors  │     │ ThreatFeed  │    │  Database   │
    │ d001-d021  │     │  Manager    │    │  Manager    │
    │ (21 files) │     │ (import/    │    │  (SQLite)   │
    └────────────┘     │  export/    │    └─────────────┘
                       │  sync)      │
                       └─────────────┘

    ┌───────────────────────────────────────────────────┐
    │                 Integrations                       │
    ├──────────────┬──────────────┬─────────────────────┤
    │ AgentGuard   │ Middleware   │ LLM Framework       │
    │ (3-gate)     │ FastAPI      │ LangChain callback  │
    │              │ Flask        │ LlamaIndex handler   │
    │ MCP Filter   │ Django       │                     │
    └──────────────┴──────────────┴─────────────────────┘
```

---

## Core Components

### PromptShieldEngine (`engine.py`)

The central orchestrator. All public API methods go through the engine. It coordinates detectors, vault, feedback, canary, and persistence.

**Construction sequence:**

```
1. load_config()          → Merge YAML + dict + env vars
2. resolve_data_dir()     → Find or create data directory
3. DatabaseManager()      → SQLite with WAL mode + auto-migration
4. AttackVault()          → ChromaDB PersistentClient (if enabled)
5. FeedbackStore()        → SQLite feedback table (if enabled)
6. AutoTuner()            → Threshold adjustment engine (if enabled)
7. CanaryTokenGenerator() → Token generation (if enabled)
8. LeakDetector()         → Response scanning (if enabled)
9. ThreatFeedManager()    → Import/export/sync (if vault enabled)
10. DetectorRegistry()    → Auto-discover + entry points
11. Wire vault into d021  → d021.vault = vault instance
12. Run detector.setup()  → Pass per-detector config
13. Compile allowlist/blocklist regex patterns
```

**Scan pipeline:**

```
Input Text
    │
    ├── Allowlist check → PASS (if matched)
    │
    ├── Blocklist check → BLOCK (if matched)
    │
    ├── For each enabled detector:
    │     ├── Get effective threshold (config or auto-tuned)
    │     ├── Call detector.detect(input_text, context)
    │     ├── Apply severity override from config
    │     └── Include if detected=True AND confidence >= threshold
    │
    ├── Aggregate: risk_score = max(confidence)
    │
    ├── Determine action by highest-severity detection
    │
    ├── Log to scan_history (SQLite)
    │
    ├── Auto-store in vault (if confidence >= min_confidence_to_store)
    │
    ├── Auto-tune check (every tune_interval scans)
    │
    └── Return ScanReport
```

### DetectorRegistry (`registry.py`)

Manages detector lifecycle with three discovery methods:

| Method | How | When |
|--------|-----|------|
| Auto-discovery | `pkgutil.iter_modules` on `prompt_shield.detectors` package | Engine init |
| Entry points | `importlib.metadata.entry_points(group="prompt_shield.detectors")` | Engine init |
| Manual | `engine.register_detector(instance)` | Runtime |

The registry stores detector instances in a `dict[str, BaseDetector]` keyed by `detector_id`. It supports `register()`, `unregister()`, `get()`, `list_all()`, `list_metadata()`, and `__contains__()`.

### Detectors (`detectors/`)

All 21 built-in detectors extend `BaseDetector` (abstract base class). They are stateless and independent: each receives input text and optional context, and returns a structured `DetectionResult`.

**Detector types:**

| Type | Detectors | Technique |
|------|-----------|-----------|
| Pattern-based (regex) | d001-d007, d012-d019 | Compile regex patterns, iterate `finditer`, collect `MatchDetail` objects |
| Custom logic | d008, d009, d010, d011, d020 | Decode/transform input, then analyze (base64 decode, ROT13, homoglyph normalization, etc.) |
| Context-aware | d006 | Uses `context["conversation_history"]` for multi-turn analysis |
| Vector similarity | d021 | Queries ChromaDB vault, no regex involved |

### Attack Vault (`vault/attack_vault.py`)

ChromaDB-backed vector store. Core responsibilities:

- **store()**: Embed input → SHA-256 hash as document → store in ChromaDB with metadata
- **query()**: Embed input → cosine nearest-neighbor search → return `VaultMatch` list
- **remove()**: Delete entry by UUID (used for false positive cleanup)
- **import_threats()**: Bulk insert from `ThreatEntry` objects with deduplication
- **export_threats()**: Extract locally-sourced entries as `ThreatEntry` list
- **stats()**: Count total entries grouped by source
- **clear()**: Delete collection and recreate empty

**Key implementation detail:** ChromaDB's `PersistentClient` stores data on disk at `<data_dir>/vault/`. The collection uses `hnsw:space: cosine` for the distance metric. An `_EmbedderBridge` class adapts the `Embedder` interface to ChromaDB's `EmbeddingFunction` protocol.

### Embedder (`vault/embedder.py`)

Thin wrapper around `sentence-transformers`:

- **Lazy loading**: The `SentenceTransformer` model is not loaded until the first `encode()` call. This keeps import time fast (~0ms vs ~2-5s).
- **Model**: `all-MiniLM-L6-v2` (384 dimensions, ~22MB, CPU-only)
- **Cache**: Model weights saved to `<data_dir>/models/`
- **API**: `encode(text) → list[float]` and `encode_batch(texts) → list[list[float]]`

### Feedback System (`feedback/`)

**FeedbackStore** (`feedback_store.py`):
- SQLite CRUD for feedback entries: `record(scan_id, detector_id, is_correct, notes)`
- `get_detector_stats(detector_id)` → `{total, true_positives, false_positives, fp_rate}`
- `get_all_stats()` → dict of all detectors with feedback

**AutoTuner** (`auto_tuner.py`):
- Reads stats from `FeedbackStore`
- Adjusts thresholds in `detector_tuning` SQLite table
- `get_effective_threshold(detector_id, default)` → float (used by engine on every scan)
- `reset(detector_id=None)` → clear tuning data

### Canary System (`canary/`)

**CanaryTokenGenerator** (`token_generator.py`):
- Generates random hex tokens via `secrets.token_hex(length // 2)`
- Injects into prompts using configurable header format: `<-@!-- {canary} --@!->`
- Returns `(modified_prompt, canary_token)` tuple

**LeakDetector** (`leak_detector.py`):
- Checks LLM responses for full or partial canary token presence
- Partial match: any substring >= 8 characters matching the token
- Case-insensitive comparison

### Threat Feed Manager (`vault/threat_feed.py`)

- **export_feed()**: Queries vault for `source: "local"` entries → serializes as `ThreatFeed` JSON
- **import_feed()**: Validates feed file (embedding model compatibility) → bulk imports via `vault.import_threats()`
- **sync_feed()**: Downloads remote JSON → saves locally → imports

### Persistence (`persistence/`)

**DatabaseManager** (`database.py`):
- SQLite with WAL (Write-Ahead Logging) mode for concurrent reads during middleware use
- Auto-migration on construction
- `connection()` context manager
- `prune_scan_history(retention_days)` for automatic cleanup

**Migrations** (`migrations.py`):
- `CURRENT_VERSION = 1`
- Creates 6 tables: `schema_version`, `scan_history`, `feedback`, `detector_tuning`, `vault_log`, `sync_history`
- Creates 2 indexes: `idx_scan_history_timestamp`, `idx_feedback_detector`

### Configuration (`config/__init__.py` + `config/default.yaml`)

**Design note:** The config module lives at `config/__init__.py` (not a standalone `config.py`) to avoid a Python namespace conflict with the `config/default.yaml` file in the same directory.

Layered configuration with four sources merged in priority order:

```
Priority 1: Environment variables (PROMPT_SHIELD_*)
Priority 2: config_dict parameter (Python dict)
Priority 3: YAML config file (config_path parameter)
Priority 4: Built-in defaults (config/default.yaml)
```

Key functions:
- `load_config()` → Deep-merge all sources
- `resolve_data_dir()` → Explicit > CWD `.prompt-shield.yaml` > `~/.prompt_shield/`
- `get_detector_config()` → Per-detector config with global fallbacks
- `get_action_for_severity()` → Maps severity to action string
- `validate_config()` → Returns list of error strings (empty = valid)
- `_deep_merge()` → Recursive dict merge
- `_apply_env_overrides()` → Reads `PROMPT_SHIELD_*` env vars

### Integrations (`integrations/`)

| Module | Class | Purpose | Key Methods |
|--------|-------|---------|-------------|
| `agent_guard.py` | `AgentGuard` | 3-gate protection for agent loops | `scan_input()`, `scan_tool_result()`, `scan_tool_call()`, `prepare_prompt()`, `scan_output()`, `scan_multi_hop()` |
| `mcp.py` | `PromptShieldMCPFilter` | Transparent MCP server proxy | `call_tool()`, `list_tools()` |
| `fastapi_middleware.py` | `PromptShieldMiddleware` | Starlette ASGI middleware | Scans POST/PUT/PATCH bodies |
| `flask_middleware.py` | `PromptShieldMiddleware` | WSGI middleware | Wraps `wsgi.input` stream |
| `django_middleware.py` | `PromptShieldMiddleware` | Django middleware | `__call__(request)` |
| `langchain_callback.py` | `PromptShieldCallback` | LangChain callback handler | `on_llm_start()`, `on_tool_end()`, `on_llm_end()` |
| `llamaindex_handler.py` | `PromptShieldHandler` | LlamaIndex handler | `scan_query()`, `scan_retrieved_nodes()`, `scan_response()` |

### CLI (`cli.py`)

Click-based CLI with nested command groups:

```
prompt-shield
├── --version
├── -c / --config-file
├── --data-dir
├── --json-output
├── scan [TEXT] [-f FILE]
├── detectors
│   ├── list
│   └── info <DETECTOR_ID>
├── config
│   ├── init [-o OUTPUT]
│   └── validate <CONFIG_FILE>
├── vault
│   ├── stats
│   ├── search <QUERY>
│   └── clear
├── feedback --scan-id <ID> [--correct|--incorrect] [--notes TEXT]
├── threats
│   ├── export -o <OUTPUT>
│   ├── import -s <SOURCE>
│   ├── sync [--url URL]
│   └── stats
├── test
└── benchmark
```

---

## Data Flow Diagram

```
                        User Input (untrusted text)
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Allowlist Check     │──── Match → Action: PASS
                    └───────────┬───────────┘
                                │ No match
                                ▼
                    ┌───────────────────────┐
                    │   Blocklist Check     │──── Match → Action: BLOCK (score=1.0)
                    └───────────┬───────────┘
                                │ No match
                                ▼
              ┌─────────────────────────────────────┐
              │  Run Enabled Detectors (d001-d021)  │
              │                                     │
              │  For each detector:                 │
              │    threshold = auto_tuned or config │
              │    result = detector.detect(input)  │
              │    if detected AND conf >= threshold │
              │      → add to detections list       │
              └─────────────────┬───────────────────┘
                                │
                                ▼
              ┌─────────────────────────────────────┐
              │        Aggregate Results            │
              │                                     │
              │  risk_score = max(confidence)       │
              │  action = severity → action mapping │
              │  vault_matched = d021 in detections │
              └─────────────────┬───────────────────┘
                                │
                  ┌─────────────┼─────────────┐
                  │             │             │
                  ▼             ▼             ▼
            ┌──────────┐ ┌──────────┐ ┌──────────────┐
            │  Log to  │ │ Store in │ │  Auto-Tune   │
            │  SQLite  │ │  Vault   │ │  (periodic)  │
            │ History  │ │ if conf  │ │  every N     │
            │          │ │ >= 0.7   │ │  scans       │
            └──────────┘ └──────────┘ └──────────────┘
                                │
                                ▼
                          ScanReport
                    ┌─────────────────┐
                    │ scan_id         │
                    │ input_hash      │
                    │ timestamp       │
                    │ risk_score      │
                    │ action          │
                    │ detections[]    │
                    │ total_run       │
                    │ scan_duration   │
                    │ vault_matched   │
                    └─────────────────┘
```

---

## Pydantic Models (`models.py`)

All data structures are Pydantic v2 models:

| Model | Purpose | Key Fields |
|-------|---------|------------|
| `Severity` | Enum | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `Action` | Enum | `BLOCK`, `FLAG`, `LOG`, `PASS` |
| `MatchDetail` | Single pattern match | `pattern`, `matched_text`, `position: tuple[int,int]`, `description` |
| `DetectionResult` | One detector's output | `detector_id`, `detected`, `confidence`, `severity`, `matches`, `explanation` |
| `ScanReport` | Aggregated scan result | `scan_id`, `input_hash`, `timestamp`, `overall_risk_score`, `action`, `detections`, `total_detectors_run`, `scan_duration_ms`, `vault_matched` |
| `GateResult` | AgentGuard gate output | `gate`, `action`, `blocked`, `scan_report`, `explanation`, `sanitized_text`, `canary_leaked` |
| `ThreatEntry` | Single threat feed entry | `id`, `pattern_hash`, `embedding`, `detector_id`, `severity`, `confidence`, `first_seen`, `report_count`, `tags` |
| `ThreatFeed` | Complete feed document | `version`, `generated_at`, `generator`, `embedding_model`, `embedding_dim`, `total_threats`, `threats` |

---

## Key Design Decisions

### 1. Config as Package (`config/__init__.py`)

The config loader lives at `config/__init__.py` rather than `config.py` because the `config/` directory also contains `default.yaml`. In Python, a directory with `__init__.py` takes priority as a package, so having both `config.py` and `config/` would create an import conflict.

### 2. Lazy Model Loading

The sentence-transformers model is loaded on first use (not on import). This means `from prompt_shield import PromptShieldEngine` is fast (~0ms) even with the vault enabled. The ~2-5 second model load only happens when the first scan hits d021 or stores a detection.

### 3. No Raw Text Storage

The vault stores SHA-256 hashes as documents and embedding vectors for similarity search. Raw attack text is never persisted. This is a privacy-by-design decision that protects against data breach exposure.

### 4. SQLite with WAL Mode

WAL (Write-Ahead Logging) allows concurrent readers with a single writer, which is critical for middleware contexts where multiple HTTP requests may scan simultaneously while the auto-tuner writes threshold updates.

### 5. `regex` Over `re`

The `regex` package provides better Unicode support (character properties like `\p{Cyrillic}`), which is essential for the homoglyph detector (d010) and for detecting attacks in non-Latin scripts.

### 6. Stateless Detectors

Detectors are designed to be stateless and independent. They don't share state with each other or maintain internal caches. This makes them safe for concurrent use and easy to test in isolation. The one exception is d006, which reads conversation history from the `context` parameter (but doesn't maintain its own state).

### 7. Three Registration Methods

Supporting auto-discovery (for built-in detectors), entry points (for third-party packages), and runtime registration (for application-specific detectors) maximizes flexibility. The registry handles deduplication by `detector_id`.

---

## File Structure

```
src/prompt_shield/
├── __init__.py              # Public API exports
├── engine.py                # Core orchestrator (258 lines)
├── registry.py              # Plugin registry
├── models.py                # Pydantic models
├── exceptions.py            # 9 custom exceptions
├── utils.py                 # Homoglyph map, invisible chars, hashing, normalization
├── cli.py                   # Click CLI (477 lines)
├── config/
│   ├── __init__.py          # Config loader (load, resolve, validate)
│   └── default.yaml         # Built-in default configuration
├── detectors/
│   ├── base.py              # Abstract BaseDetector
│   ├── d001_system_prompt_extraction.py
│   ├── d002_role_hijack.py
│   ├── ... (d003-d020)
│   └── d021_vault_similarity.py
├── vault/
│   ├── embedder.py          # sentence-transformers wrapper
│   ├── attack_vault.py      # ChromaDB vector store
│   └── threat_feed.py       # Feed import/export/sync
├── feedback/
│   ├── feedback_store.py    # SQLite feedback CRUD
│   └── auto_tuner.py        # Threshold adjustment engine
├── canary/
│   ├── token_generator.py   # Canary token creation + injection
│   └── leak_detector.py     # Response scanning for leaked tokens
├── persistence/
│   ├── database.py          # SQLite connection manager
│   └── migrations.py        # Schema creation + versioning
└── integrations/
    ├── agent_guard.py       # 3-gate AgentGuard
    ├── mcp.py               # MCP server filter proxy
    ├── fastapi_middleware.py # Starlette ASGI middleware
    ├── flask_middleware.py   # WSGI middleware
    ├── django_middleware.py  # Django middleware
    ├── langchain_callback.py # LangChain lifecycle hooks
    └── llamaindex_handler.py # LlamaIndex query/retrieval handler
```
