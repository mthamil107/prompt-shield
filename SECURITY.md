# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in prompt-shield, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security concerns to the project maintainers via GitHub's
private vulnerability reporting feature on this repository.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix timeline**: Depends on severity, typically within 2 weeks for critical issues

## Security Considerations

prompt-shield is a **detection** tool, not a guarantee of security. It should be used as one layer in a defense-in-depth strategy.

### Data Privacy

- By default, prompt-shield **never stores raw input text** in its database
- Only SHA-256 hashes and vector embeddings are persisted
- The `history.store_input_text` config option exists but defaults to `false`
- Threat feed exports contain only hashes and embeddings, never raw attack text

### Local-First Architecture

- All data is stored locally (SQLite + ChromaDB files)
- No data is sent to external servers unless you explicitly enable threat feed sync
- The community threat feed is opt-in and pull-only

### Embedding Model

- The default embedding model (all-MiniLM-L6-v2) runs locally on CPU
- No API calls are made for embedding generation
- Model files are cached locally after first download

## Responsible Disclosure

We follow responsible disclosure practices. Security researchers who report
vulnerabilities responsibly will be credited in the changelog (with permission).
