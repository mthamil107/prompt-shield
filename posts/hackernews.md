# Hacker News Post

---

**Title:** Show HN: Prompt-Shield – Self-learning prompt injection detection for LLM apps

**URL:** https://github.com/mthamil107/prompt-shield

**Comment (post after submission):**

Hi HN, I built prompt-shield because existing prompt injection defenses are either too simplistic (keyword blocklists that get bypassed with basic encoding) or too expensive (routing every request through another LLM).

prompt-shield takes a different approach: layer 22 specialized detectors with a DeBERTa-v3 semantic classifier and ensemble scoring that amplifies weak signals. The system learns from every detection — each blocked attack gets embedded and stored in a local vector database, so future attack variants are caught by similarity even when they bypass all pattern matching.

**Key design decisions:**

1. *Ensemble over threshold* — Instead of one monolithic classifier, use many specialized detectors. A single detector might fire at 0.6 confidence (below threshold), but three detectors at 0.6 + ensemble bonus → 0.7 (caught). This makes it much harder for adversaries to craft inputs that evade detection.

2. *Pattern matching + ML + vector similarity* — Three orthogonal detection strategies. Regex catches known patterns instantly. DeBERTa catches paraphrased attacks that bypass regex. The vault catches variants of previously-seen attacks. An attacker needs to beat all three.

3. *Self-learning feedback loop* — False positive? Remove from vault, auto-tune thresholds. True positive? Embed and store. Every deployment gets hardened against the specific attacks it sees.

4. *Agent-aware security* — A 3-gate model: scan user inputs (obvious), scan tool results / RAG context (indirect injection is the real threat), and canary token leak detection on outputs. Tool results from MCP, search APIs, and document retrieval are the most dangerous attack surface in agentic apps.

**What it catches:**
- Direct injection (system prompt extraction, role hijack, instruction override)
- Encoded attacks (Base64, ROT13, Unicode homoglyphs, zero-width characters)
- Indirect injection (data exfiltration URLs, tool abuse patterns, RAG poisoning)
- Jailbreak techniques (hypothetical framing, dual persona, academic pretext)
- Paraphrased attacks via DeBERTa classifier
- Variants of previously-seen attacks via vector similarity

100% accuracy on 116 test prompts, zero false positives on safe inputs. Apache 2.0, runs entirely locally (no API keys or cloud services).

```bash
pip install prompt-shield-ai
```

```python
from prompt_shield import PromptShieldEngine
engine = PromptShieldEngine()
report = engine.scan("Ignore all previous instructions")
# Action.BLOCK, risk=0.95
```

Interested in feedback on the ensemble scoring approach and adversarial robustness.
