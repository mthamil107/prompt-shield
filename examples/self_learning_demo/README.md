# Self-Learning Demo

Demonstrates the self-hardening feedback loop: vault storage, similarity matching, feedback, and threat export.

## Setup

```bash
pip install prompt-shield
```

## Run

```bash
python examples/self_learning_demo/app.py
```

## How the Self-Learning Loop Works

1. **Detection**: Engine scans input with 21 detectors
2. **Vault storage**: Detected attacks are automatically embedded and stored in ChromaDB
3. **Similarity matching**: Future inputs are compared against stored embeddings (d021_vault_similarity)
4. **Feedback**: Users mark false positives/true positives via `engine.feedback()`
5. **Auto-tuning**: After every N scans, the auto-tuner adjusts per-detector thresholds based on accumulated feedback
6. **Threat export**: Locally-detected attacks can be exported as anonymized JSON for community sharing
7. **Threat import**: Other instances import feeds to strengthen their vaults without seeing raw attack text

Each blocked attack makes the system more resistant to paraphrased variants.
