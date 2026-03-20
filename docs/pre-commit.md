# Pre-commit Hook Integration

Prompt Shield provides pre-commit hooks that scan staged files for prompt
injection patterns and PII before every commit. This catches security issues
early, before they enter your repository.

## Available Hooks

| Hook ID | Description |
|---------|-------------|
| `prompt-shield-scan` | Scans for prompt injection patterns (role hijacking, instruction override, etc.) |
| `prompt-shield-pii` | Scans for PII (emails, phone numbers, SSNs, credit card numbers, etc.) |

## Setup

### 1. Install pre-commit

```bash
pip install pre-commit
```

### 2. Add to your `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/mthamil107/prompt-shield
    rev: v0.3.0
    hooks:
      - id: prompt-shield-scan
      - id: prompt-shield-pii
```

### 3. Install the hooks

```bash
pre-commit install
```

Now Prompt Shield will automatically scan every staged text file when you run
`git commit`.

## Configuration

### Threshold

Adjust the confidence threshold for prompt injection detection (default: 0.7).
Lower values are more sensitive; higher values reduce false positives.

```yaml
repos:
  - repo: https://github.com/mthamil107/prompt-shield
    rev: v0.3.0
    hooks:
      - id: prompt-shield-scan
        args: ["--threshold", "0.8"]
```

### Excluding Files

Skip files that match glob patterns:

```yaml
repos:
  - repo: https://github.com/mthamil107/prompt-shield
    rev: v0.3.0
    hooks:
      - id: prompt-shield-scan
        args: ["--exclude", "*.min.js", "--exclude", "vendor/*"]
      - id: prompt-shield-pii
        args: ["--exclude", "tests/fixtures/*"]
```

You can also use the built-in `exclude` key from pre-commit:

```yaml
hooks:
  - id: prompt-shield-scan
    exclude: "^(vendor/|node_modules/)"
```

### Using Only One Hook

You do not need to enable both hooks. Pick the ones relevant to your project:

```yaml
# Only scan for prompt injection
hooks:
  - id: prompt-shield-scan
```

```yaml
# Only scan for PII
hooks:
  - id: prompt-shield-pii
```

## How It Works

### Prompt Injection Hook

The `prompt-shield-scan` hook runs each staged text file through the
PromptShieldEngine with a lightweight configuration optimized for speed:

- Vault, feedback, canary, and history subsystems are disabled
- The semantic classifier (which requires ML model downloads) is disabled
- Only fast regex-based and heuristic detectors run

Files that trigger any detector above the confidence threshold cause the commit
to be blocked.

### PII Hook

The `prompt-shield-pii` hook uses the PIIRedactor to scan for common PII
patterns including:

- Email addresses
- Phone numbers
- Social Security Numbers
- Credit card numbers
- IP addresses
- AWS keys and other API credentials

Any PII detection blocks the commit.

## Output

Clean files show green PASS output:

```
PASS src/app.py
PASS config/settings.yaml
```

Detections show red FAIL output with details:

```
FAIL prompts/system.txt — 2 detection(s), risk score 0.85
  [HIGH] d001_instruction_override (confidence: 0.82)
    Detected instruction override pattern
    Line 5: 'ignore all previous instructions'
```

## Running Manually

Run the hooks against all files without committing:

```bash
pre-commit run prompt-shield-scan --all-files
pre-commit run prompt-shield-pii --all-files
```

Run against specific files:

```bash
pre-commit run prompt-shield-scan --files src/prompts/*.txt
```

## CI Integration

Add to your CI pipeline to scan all files on every push:

```yaml
# GitHub Actions example
- name: Run Prompt Shield hooks
  run: |
    pip install pre-commit
    pre-commit run prompt-shield-scan --all-files
    pre-commit run prompt-shield-pii --all-files
```
