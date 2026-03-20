# Prompt Shield GitHub Action

Automatically scan pull requests for prompt injection attacks and PII leakage. The action analyzes changed files, posts findings as a PR comment, and optionally blocks the PR if threats are detected.

## Quick Start

Add this workflow to your repository at `.github/workflows/prompt-shield.yml`:

```yaml
name: Prompt Shield Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
        with:
          threshold: "0.7"
          pii-scan: "true"
```

> **Note:** Replace `prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main` with the correct path if you are vendoring the action locally or referencing a specific release tag.

## How It Works

1. **Detects changed files** in the PR using `git diff` against the base branch.
2. **Filters files** based on configurable glob patterns (defaults to common text and code formats).
3. **Scans each file** using the `prompt-shield-ai` engine with all heuristic and pattern detectors enabled. Vault, feedback, and canary subsystems are disabled for CI speed.
4. **Optionally scans for PII** (emails, phone numbers, SSNs, API keys, etc.) using the built-in PII redactor.
5. **Posts a PR comment** with a detailed Markdown summary table of findings.
6. **Fails the check** if detections are found above the threshold (configurable).

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `threshold` | `0.7` | Risk score threshold (0.0-1.0). Detections at or above this score are reported. |
| `mode` | `block` | Scan mode: `block` (fail on detection), `flag` (warn only), `monitor` (log only). |
| `scan-patterns` | `**/*.py,**/*.js,**/*.ts,**/*.md,**/*.txt,**/*.yaml,**/*.yml,**/*.json` | Comma-separated glob patterns for files to scan. |
| `pii-scan` | `true` | Enable PII scanning alongside prompt injection detection. |
| `fail-on-detection` | `true` | Fail the workflow step if detections are found above threshold. |
| `python-version` | `3.12` | Python version to use. |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-results` | Full JSON scan results. |
| `detection-count` | Number of files with prompt injection detections. |
| `pii-count` | Number of files with PII findings. |
| `has-detections` | `true` or `false` indicating whether detections were found. |

## Examples

### Basic Setup

Scan all PRs with default settings. Blocks the PR if prompt injection is detected with a risk score of 0.7 or higher:

```yaml
name: Prompt Shield Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
```

### Custom Threshold

Use a lower threshold for stricter detection. A threshold of `0.5` catches more potential threats at the cost of higher false positives:

```yaml
      - uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
        with:
          threshold: "0.5"
```

### Flag Mode (Non-Blocking)

Report findings in a PR comment without failing the check. Useful for initial rollout or evaluation:

```yaml
      - uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
        with:
          mode: "flag"
          fail-on-detection: "false"
```

### PII-Only Scanning

If you only want PII detection and do not need prompt injection blocking, set the threshold high to avoid false positives on injection, but keep PII scanning enabled:

```yaml
      - uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
        with:
          threshold: "0.99"
          pii-scan: "true"
          mode: "flag"
```

### Scanning Specific File Types

Only scan Markdown and YAML files (for example, documentation or configuration repos):

```yaml
      - uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
        with:
          scan-patterns: "**/*.md,**/*.yaml,**/*.yml"
```

### Monorepo Setup

Run scans on specific paths within a monorepo by combining scan patterns with path filters on the workflow trigger:

```yaml
name: Prompt Shield Scan

on:
  pull_request:
    types: [opened, synchronize, reopened]
    paths:
      - "services/ai-gateway/**"
      - "prompts/**"
      - "config/**"

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
        with:
          scan-patterns: "services/ai-gateway/**/*.py,prompts/**/*.txt,prompts/**/*.md,config/**/*.yaml"
          threshold: "0.6"
```

### Using Scan Results in Downstream Steps

Access the action outputs in subsequent workflow steps:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - id: shield
        uses: prompt-shield/prompt-shield/.github/actions/prompt-shield-scan@main
        with:
          mode: "flag"
          fail-on-detection: "false"

      - name: Process results
        if: steps.shield.outputs.has-detections == 'true'
        run: |
          echo "Found ${{ steps.shield.outputs.detection-count }} file(s) with prompt injection"
          echo "Found ${{ steps.shield.outputs.pii-count }} file(s) with PII"
          echo "Full results: ${{ steps.shield.outputs.scan-results }}"
```

## PR Comment Format

The action posts (or updates) a comment on the PR with a summary table:

- **Prompt Injection Detections** — files with injection findings, including risk score, severity, detector IDs, and explanations.
- **PII Detections** — files containing PII, including entity counts and types found.
- **Scan Errors** — files that could not be scanned (binary, too large, encoding issues), collapsed in a details block.

If no issues are found, the comment confirms all files passed.

The comment is updated on each push to the PR rather than creating duplicates.

## Performance

- The scanner disables vault, feedback, canary, and history subsystems in CI mode for fast startup.
- Files larger than 1 MB are automatically skipped.
- Binary files are detected and skipped.
- Typical scan time is under 5 seconds for most PRs.

## Troubleshooting

**The action fails to install `prompt-shield-ai`:**
Ensure your workflow has internet access. If you are on a self-hosted runner behind a proxy, configure pip accordingly.

**No files are being scanned:**
Check that your `scan-patterns` input matches the file extensions of changed files. The default patterns cover `.py`, `.js`, `.ts`, `.md`, `.txt`, `.yaml`, `.yml`, and `.json`.

**False positives:**
Increase the `threshold` value (e.g., `0.85`) or switch to `mode: "flag"` during initial evaluation. You can also narrow `scan-patterns` to only scan files that contain prompts or user-facing text.

**The PR comment is not posted:**
Ensure the workflow has `pull-requests: write` permission. For organization repositories, check that GitHub Actions is allowed to create PR comments.
