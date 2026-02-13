# Configuration

prompt-shield uses a layered configuration system. Settings are resolved in this priority order (highest first):

1. Environment variables
2. `config_dict` parameter passed to `PromptShieldEngine()`
3. YAML config file
4. Built-in defaults

## YAML Format

Generate a default config file:

```bash
prompt-shield config init -o prompt_shield.yaml
```

Full reference:

```yaml
prompt_shield:
  # Operating mode: "block" (reject), "monitor" (log only), or "flag"
  mode: block

  # Global confidence threshold (0.0 - 1.0).
  # Detections below this threshold are ignored.
  threshold: 0.7

  # Action mapping by severity level
  actions:
    critical: block
    high: block
    medium: flag
    low: log

  # Logging configuration
  logging:
    level: INFO          # DEBUG, INFO, WARNING, ERROR
    format: json         # "json" or "text"
    output: stdout       # "stdout" or a file path

  # Data directory for vault, database, and models.
  # null = auto-resolve (~/.prompt_shield or ./.prompt_shield)
  data_dir: null

  # Attack vault (vector similarity store)
  vault:
    enabled: true
    embedding_model: "all-MiniLM-L6-v2"
    similarity_threshold: 0.85    # Min cosine similarity for a vault match
    max_entries: 100000
    auto_store_detections: true   # Auto-store detected attacks
    min_confidence_to_store: 0.7  # Min confidence to store in vault

  # Feedback and auto-tuning
  feedback:
    enabled: true
    auto_tune: true        # Enable automatic threshold adjustment
    tune_interval: 100     # Run auto-tuner every N scans
    max_threshold_adjustment: 0.15  # Max +/- threshold change

  # Canary token system (prompt leakage detection)
  canary:
    enabled: true
    token_length: 16
    header_format: "<-@!-- {canary} --@!->"

  # Community threat feed
  threat_feed:
    enabled: true
    auto_sync: false
    feed_url: "https://raw.githubusercontent.com/prompt-shield/threat-feed/main/feeds/latest.json"
    sync_interval_hours: 24

  # Scan history persistence
  history:
    enabled: true
    retention_days: 90
    store_input_text: false  # Never store raw input text (privacy)

  # Per-detector overrides
  detectors:
    d001_system_prompt_extraction:
      enabled: true
      severity: critical
      threshold: 0.6       # Override global threshold for this detector
    d002_role_hijack:
      enabled: true
      severity: critical
    # ... (see default.yaml for all 21 detectors)

  # Regex allowlist — matching inputs skip scanning entirely
  allowlist:
    patterns: []

  # Regex blocklist — matching inputs are immediately blocked
  blocklist:
    patterns: []
```

## Environment Variables

Override any setting with environment variables using the `PROMPT_SHIELD_` prefix:

| Variable | Maps to | Example |
|---|---|---|
| `PROMPT_SHIELD_MODE` | `mode` | `monitor` |
| `PROMPT_SHIELD_THRESHOLD` | `threshold` | `0.8` |
| `PROMPT_SHIELD_DATA_DIR` | `data_dir` | `/tmp/ps` |
| `PROMPT_SHIELD_VAULT_ENABLED` | `vault.enabled` | `false` |
| `PROMPT_SHIELD_VAULT_SIMILARITY_THRESHOLD` | `vault.similarity_threshold` | `0.9` |
| `PROMPT_SHIELD_FEEDBACK_ENABLED` | `feedback.enabled` | `false` |
| `PROMPT_SHIELD_CANARY_ENABLED` | `canary.enabled` | `false` |
| `PROMPT_SHIELD_LOGGING_LEVEL` | `logging.level` | `DEBUG` |

Boolean values are case-insensitive (`true`/`false`). Numeric values are auto-coerced.

## Per-Detector Overrides

Each detector can be individually configured under `detectors.<detector_id>`:

```yaml
prompt_shield:
  detectors:
    d001_system_prompt_extraction:
      enabled: true       # Enable/disable this detector
      severity: critical  # Override severity level
      threshold: 0.6      # Override confidence threshold
```

## Programmatic Configuration

Pass a dict directly:

```python
engine = PromptShieldEngine(config_dict={
    "mode": "monitor",
    "threshold": 0.8,
    "vault": {"enabled": False},
})
```

## Data Directory Resolution

The data directory stores the vault database, scan history, and model weights. Resolution order:

1. Explicit `data_dir` in config or `PROMPT_SHIELD_DATA_DIR` env var
2. If `.prompt-shield.yaml` exists in CWD: `./.prompt_shield/` (project-scoped)
3. Default: `~/.prompt_shield/` (global)

## Validation

Validate a config file:

```bash
prompt-shield config validate prompt_shield.yaml
```
