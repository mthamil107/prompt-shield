# Held-out indirect-injection corpus

50 realistic-looking documents (emails, meeting notes, wiki pages,
incident postmortems, and product specs) used to evaluate d027
(stylometric discontinuity) and the full prompt-shield engine on
long-form inputs. 30 documents contain a paraphrased indirect-injection
payload; 20 are clean.

The ground-truth labels are in `manifest.json`. Generated documents
are under `docs/`.

## HONESTY LIMITATION — please read

**These documents are LLM-template-generated, NOT human-authored.**
Each document is produced by slot-filling one of 3-5 templates per
document type with a deterministic PRNG seed. Attack payloads are
slot-filled paraphrases of 8 hand-written attack templates spanning
5 attack families (system-prompt-extraction, role-hijack,
instruction-override, data-exfiltration, tool-abuse).

This corpus is a **partial** improvement over the original synthetic
self-benchmark (`indirect_injection_samples.jsonl`), which was built
with knowledge of what d027 measures. What this corpus does add:

- Longer, structurally-varied documents that look like realistic
  business writing, not five hand-picked genre paragraphs
- 8 paraphrased attack templates so no injection is a verbatim
  regex-known string
- Injection insertion at plausible per-doc-type locations rather than
  at a fixed splice point

What this corpus does NOT do:

- It is not human-authored. A truly held-out set would require
  crowdsourced writing from participants who have never seen d027's
  feature definition.
- Stylistic diversity is bounded by the template library. Real inbox /
  wiki data would exhibit more idiosyncratic voice.
- Attack paraphrasing is bounded by the slot vocabulary; a human
  attacker would use more creative rewrites.

A v5 upgrade would replace this generator with a corpus of
gold-labelled documents authored by domain experts and paraphrased
attackers, drawn from anonymised real-world sources.

## Regeneration

```
python docs/papers/evaluation/build_held_out_corpus.py --seed 42
```

Runs offline (stdlib only). Regenerating with the same seed reproduces
the exact same 50 documents.

## Downstream evaluator

```
python docs/papers/evaluation/run_held_out_benchmark.py
```

Runs each document through the full engine and through d027 in
isolation, then emits `held_out_indirect_injection.json` and
`held_out_indirect_injection.md` (one directory above this one).
