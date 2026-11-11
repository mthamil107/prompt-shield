# HuggingFace Paper Page Diff - arXiv 2604.18248

## Status

NEEDS CHANGE (HF page is stale relative to arXiv v4).

The arXiv v4 abstract below is a verbatim copy retrieved from the public arXiv API (`export.arxiv.org/api/query?id_list=2604.18248v4`). The HF page summary was retrieved from the public HF API (`huggingface.co/api/papers/2604.18248`).

## Last updated

2026-11-11

## Sources

| Source | URL | Outcome |
|---|---|---|
| arXiv v4 | https://arxiv.org/abs/2604.18248v4 | Verbatim abstract retrieved 2026-11-11 via the arXiv API. Version banner confirms v4 (30 Jul 2026, 31 pages). |
| HF paper page | https://huggingface.co/papers/2604.18248 | Page exists. API summary shows the pre-v3 abstract; `publishedAt` is 2026-05-18. The author entry carries no linked HF user. No author-editable abstract field is known. |

Version history seen on arXiv: v1 20 Apr 2026, v2 18 May 2026, v3 28 Jul 2026, v4 30 Jul 2026.
Title: Beyond Pattern Matching: Seven Cross-Domain Techniques for Prompt Injection Detection.
Subject tags: cs.CR (primary), cs.CL.

## Current HF page text

Fetched state (summary of the HF abstract):

- Proposes seven prompt-injection detection techniques adapted from fields outside LLM security.
- "Three of the seven techniques are implemented in the prompt-shield v0.4.1 release ... across six datasets".
- Headline results in the abstract: local-alignment detector raises F1 on deepset/prompt-injections from 0.033 to 0.378; stylometric detector adds 11.1 percentage points of F1 on an indirect-injection benchmark.
- Shown as "Published on May 18" (the v2 date).

Scope caveat: v1 and v2 both say "Three of the seven", so the content alone cannot separate them. The HF text is best described as the pre-v3 state; the May 18 date is the only pointer to v2.

This matches the pre-v3 draft state: three techniques implemented, six datasets, v0.4.1.

## Current arXiv v4 abstract

Verbatim (single paragraph, copied from the arXiv API record for v4):

```
Current open-source prompt-injection detectors converge on two architectural choices: regular-expression pattern matching and fine-tuned transformer classifiers. Both share failure modes recent work has made concrete. Regular expressions miss paraphrased attacks. Fine-tuned classifiers are vulnerable to adaptive adversaries: a 2025 NAACL Findings study reported that eight published indirect-injection defenses were bypassed with greater than fifty percent attack-success rates under adaptive attacks. This work proposes seven detection techniques that each port a mechanism from a discipline outside LLM security: forensic linguistics, materials-science fatigue analysis, deception technology, local-sequence alignment from bioinformatics, mechanism design, spectral signal analysis, and taint tracking. Each produces a signal architecturally independent of both regex matching and transformer classification, so the seven compose with existing defenses rather than replacing them. Four of seven are now implemented in prompt-shield v0.7.3 (Apache 2.0): d028 sequence alignment, d027 stylometric discontinuity, materials-fatigue tracking, and d034 honeypot tool definitions (new in v4.0). A four-configuration ablation across nine benchmarks (~10,300 samples) covers deepset, NotInject, LLMail-Inject, AgentHarm, AgentDojo, and an independent evaluation against three peer-reviewed academic benchmarks (Liu USENIX 2024, Garak, InjecAgent). This revision adds Section 5.7 (composed-stack adaptive-attack partial run, evidence for the composability thesis), Section 5.8 (50-document held-out benchmark: d027 collapses 1.000 to 0.000 F1 in isolation but the composed engine recovers 0.815 F1), and Section 7 (three architectural patterns extracted from prompt-shield in Gang-of-Four format). All code, data, and reproduction scripts are released Apache 2.0.
```

Resolved checks against this text:

- Four implemented techniques - confirmed (not the stale three).
- d034 honeypot tool definitions - confirmed, named in the abstract ("new in v4.0").
- Version v0.7.3 - confirmed.
- The F1 headline figures (0.033 to 0.378; +11.1 pp stylometric) are ABSENT from the v4 abstract. After a re-sync the HF card will no longer show these numbers in the abstract.
- Section 5.7 is a composed-stack adaptive-attack partial run, not a full evaluation. Do not describe it as a full evaluation anywhere.

## Proposed replacement

The replacement is the verbatim arXiv v4 abstract in the section above. No paraphrase is provided or to be used.

Clean-copy guidance: when copying from arXiv, omit the "Abstract:" label prefix and paste as a single paragraph (arXiv may inject line breaks).

## Dated correction note

| Claim | Old (HF, pre-v3) | New (arXiv v4) | Reason |
|---|---|---|---|
| Techniques implemented | 3 | 4 | v4 implements a fourth technique (d034 honeypot tool definitions) |
| Release referenced | v0.4.1 | v0.7.3 | Abstract references the later release |
| Evaluation scope | 6 datasets | 9 benchmarks, ~10,300 samples | Expanded ablation in later revisions |
| Headline F1 results (0.033 to 0.378; +11.1 pp stylometric) | Stated in abstract | Not in the v4 abstract | v4 abstract drops these headline numbers; pipeline F1s still appear in the paper body |
| New content | absent | Section 5.7 composed-stack adaptive-attack partial run, Section 5.8 50-document held-out benchmark, Section 7 architectural patterns | Added in v4 |

Note on headline numbers: the F1 figures disappear from the abstract, but they remain in the paper body, so no retraction is implied and no separate correction on the headline is needed. After the re-sync, the HF card will not carry those numbers.

Two variants of the public note. Use exactly one, matching what has actually happened.

Variant A - request pending (use when only a re-sync request has been sent):

```
Re-sync request sent to HF staff on <date>. The HF page abstract may
still show the pre-v3 text (3 implemented techniques, 6 datasets,
v0.4.1) until they process it. The current abstract is arXiv v4
(30 Jul 2026): 4 implemented techniques, 9-benchmark ablation,
prompt-shield v0.7.3. This is a sync request, not a factual revision.
```

Variant B - post-update (use ONLY after I have confirmed HF actually updated the page):

```
Correction note (<date>): Page re-synced to arXiv v4 (30 Jul 2026).
Previous text reflected the pre-v3 abstract (3 implemented techniques,
6 datasets, v0.4.1). Current claims: 4 implemented techniques and a
9-benchmark ablation, matching the arXiv v4 abstract. The earlier
headline F1 figures are no longer in the abstract but remain in the
paper body. No prior claim is retracted - this is a sync, not a
factual revision.
```

## Manual apply steps

1. Claim authorship on the HF paper page if not already done (the authors field may be unlinked; the API author entry has no linked user). Click the author name, choose "Claim authorship", and wait for HF staff approval.
2. PRIMARY PATH: open a Community discussion at https://huggingface.co/papers/2604.18248/discussions asking HF staff to re-sync the page to the arXiv v4 abstract. Paste the post text below. Escalate to HF support if unanswered.
3. Post Variant A of the correction note (request pending) only. Do not post Variant B yet.
4. Re-check the page periodically. Auto-refresh has not occurred: v4 dates from 30 Jul 2026 and the page still showed the pre-v3 abstract on 2026-11-11.
5. Once the page visibly shows four implemented techniques and nine benchmarks, post Variant B with the confirmation date.
6. SECONDARY PATH (only if HF ever exposes an author edit flow for the abstract): open https://arxiv.org/abs/2604.18248v4, copy the abstract (omit the "Abstract:" label; paste as a single paragraph, since arXiv may inject line breaks), paste it into the HF edit control, save, then continue from step 5.

Community discussion post text (paste as-is, fill in nothing but the date if desired):

```
Title: Please re-sync the abstract to arXiv v4

Hello HF team,

I am the author of arXiv 2604.18248. This page still shows the
pre-v3 abstract (three of seven techniques implemented, prompt-shield
v0.4.1, six datasets; shown as published May 18). The current arXiv
version is v4 (30 Jul 2026), whose abstract reports four of seven
techniques implemented in prompt-shield v0.7.3 and a four-configuration
ablation across nine benchmarks (~10,300 samples).

Could you please re-sync the page metadata to the arXiv v4 abstract?
Source: https://arxiv.org/abs/2604.18248v4

Thank you.
```

## Fallback notes

- All four earlier open questions are now closed: (a) verbatim v4 abstract is embedded above; (b) d034 honeypot tool definitions is named in it; (c) the F1 figures 0.033 to 0.378 and +11.1 pp are absent from v4; (d) the abstract says v0.7.3 and is frozen at submission, so do not change it to the current repo version 0.8.1.
- Auto-sync from arXiv metadata has not happened in over three months, so do not rely on it.
- Nothing has been pushed or published yet; the HF page has not been edited and no discussion has been opened.
