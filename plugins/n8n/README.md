# n8n-nodes-prompt-shield

This is an [n8n](https://n8n.io/) community node package that integrates [Prompt Shield](https://github.com/mthamil107/prompt-shield) into your n8n workflows. It allows you to scan text for prompt injection attacks and detect or redact personally identifiable information (PII).

## Prerequisites

- [n8n](https://docs.n8n.io/) installed and running
- [prompt-shield](https://github.com/mthamil107/prompt-shield) CLI installed (`pip install prompt-shield`)

## Installation

Follow the [n8n community node installation guide](https://docs.n8n.io/integrations/community-nodes/installation/):

1. Go to **Settings > Community Nodes**
2. Select **Install**
3. Enter `n8n-nodes-prompt-shield`
4. Agree to the risks and select **Install**

Alternatively, install via npm in your n8n custom extensions directory:

```bash
npm install n8n-nodes-prompt-shield
```

## Operations

| Operation   | Description                                      |
|-------------|--------------------------------------------------|
| Scan        | Scan text for prompt injection attacks            |
| PII Scan    | Scan text for personally identifiable information |
| PII Redact  | Redact PII from text, replacing it with placeholders |

## Configuration

### Credentials (Optional)

The **Prompt Shield** credentials allow you to configure the path to the `prompt-shield` CLI binary. This is only needed if the CLI is not available on the system PATH.

| Field           | Description                              | Default          |
|-----------------|------------------------------------------|------------------|
| CLI Binary Path | Path to the prompt-shield CLI executable | `prompt-shield`  |

### Node Parameters

| Parameter    | Type    | Description                                | Default |
|--------------|---------|--------------------------------------------|---------|
| Operation    | Options | The operation to perform (Scan, PII Scan, PII Redact) | Scan    |
| Input Text   | String  | The text to analyze                        | —       |
| JSON Output  | Boolean | Return structured JSON output              | true    |

## Usage Examples

### Scan for Prompt Injection

1. Add the **Prompt Shield** node to your workflow
2. Set **Operation** to **Scan**
3. Enter the text to analyze in **Input Text**
4. Execute the node to get injection detection results

### Detect PII

1. Add the **Prompt Shield** node to your workflow
2. Set **Operation** to **PII Scan**
3. Enter text containing potential PII in **Input Text**
4. Execute to see detected PII entities

### Redact PII

1. Add the **Prompt Shield** node to your workflow
2. Set **Operation** to **PII Redact**
3. Enter text containing PII in **Input Text**
4. Execute to get the redacted text output

## AI Tool Usage

This node has `usableAsTool` enabled, which means it can be used as a tool by n8n's AI Agent node. The AI agent can automatically invoke Prompt Shield to scan or redact text as part of a larger AI workflow.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Lint
npm run lint
```

## License

MIT
