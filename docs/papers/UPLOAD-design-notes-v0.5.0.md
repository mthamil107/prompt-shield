# Uploading the v0.5.0 design notes — arXiv + Zenodo checklist

This is the step-by-step you (Thamil) follow to publish the v0.5.0 design notes
as a citable, dated prior-art record on **both** arXiv and Zenodo. Total
hands-on time: ~30 min once Word is open.

Source-of-truth files in this repo:
- `docs/design-notes-v0.5.0.md` — canonical prose (CC BY 4.0)
- `docs/papers/build_design_notes_v0_5_0.py` — DOCX builder
- `docs/papers/design-notes-v0.5.0.docx` — generated DOCX (do not hand-edit)

## Step 0 — DOCX → PDF (already done)

The PDF is committed at `docs/papers/design-notes-v0.5.0.pdf` (~380 KB).
Re-generate from source any time with:

```
python docs/papers/build_design_notes_v0_5_0.py
```

(requires Word + `docx2pdf` on Windows/Mac, or LibreOffice + `soffice
--headless --convert-to pdf` on Linux. The script auto-detects and
falls back gracefully if neither is present.)

## Step 1 — Zenodo (DONE — DOI 10.5281/zenodo.20809165)

Published 2026-06-23 at https://zenodo.org/records/20809165. Use this DOI
in the arXiv submission below.

## Step 1 (archived, for reference) — Zenodo (5 min, gets a DOI)

Zenodo is fastest and unlocks a citable DOI right away. Patent examiners
don't search Zenodo as routinely as arXiv, but a DOI + permanent archive
is still solid prior-art evidence.

1. Log into https://zenodo.org with the same ORCID / email you used for the
   main paper (Zenodo DOI `10.5281/zenodo.19644135`).
2. Click **New upload**.
3. Upload **`docs/papers/design-notes-v0.5.0.pdf`**.
4. Paste this metadata (copy verbatim):

   - **Resource type**: Publication → Technical note
   - **Title**:
     `Design Notes: Seven Cross-Domain Pre-processing and Detection Techniques for Prompt-Injection Defense (prompt-shield v0.5.0)`
   - **Authors**: `Munirathinam, Thamilvendhan` (link your ORCID if you have one)
   - **Description (abstract)**: paste the abstract block from
     `docs/design-notes-v0.5.0.md` (or §0 of the DOCX).
   - **Publication date**: `2026-06-18`
   - **Keywords**:
     `prompt injection; LLM security; AI safety; prior art; many-shot jailbreak; topic drift; homoglyph normalization; multi-encoding decoder; language enforcement`
   - **License**: `Creative Commons Attribution 4.0 International (CC BY 4.0)`
   - **Related identifiers**: add three rows:
     - `Is supplement to` → `arXiv:2604.18248`
     - `Is documentation of` → `https://github.com/mthamil107/prompt-shield/tree/v0.5.0`
     - `Cites` → `10.5281/zenodo.19644135`
   - **Communities**: optional — skip if unsure.

5. Click **Publish**. You'll get a DOI like `10.5281/zenodo.XXXXXXXXX`.

6. Once you have the DOI, copy it back into the design-notes markdown
   (replace the placeholder in `docs/design-notes-v0.5.0.md` if you've added
   one) and the README.

## Step 2 — arXiv (15 min active + ~24h moderation)

You're already an endorsed cs.CR author (paper 2604.18248 is yours), so this
goes straight into moderation without an endorsement loop.

1. Log into https://arxiv.org with your existing account.
2. Click **Start New Submission**.
3. Submission type: **Article**.
4. Upload **`docs/papers/design-notes-v0.5.0.pdf`** as the primary file.
   - arXiv prefers LaTeX source, but it accepts PDF-only submissions and your
     main paper followed the same PDF-upload path. Keep it consistent.
5. Metadata:

   - **Title**: `Design Notes: Seven Cross-Domain Pre-processing and Detection Techniques for Prompt-Injection Defense (prompt-shield v0.5.0)`
   - **Authors**: `Thamilvendhan Munirathinam`
   - **Abstract**: paste the abstract block from the DOCX / md.
   - **Comments**: `Companion technical note to arXiv:2604.18248. 9 pages. Published as dated prior art. Code at https://github.com/mthamil107/prompt-shield (Apache 2.0). DOI: 10.5281/zenodo.XXXXXXXXX (paste the Zenodo DOI from step 1).`
   - **Primary category**: `cs.CR` (Cryptography and Security)
   - **Cross-list**: `cs.CL` (Computation and Language) — same as the main paper.
   - **License**: `Creative Commons Attribution 4.0`
   - **MSC / ACM**: skip (optional)
   - **Journal-ref / DOI**: paste the Zenodo DOI from step 1.

6. **Important caveat**: arXiv silently rejects certain Unicode chars in the
   title / abstract / comments fields. Before submission, run the abstract
   through the `paper-polish` skill (or just open it in a plain editor and
   confirm no em-dashes / curly quotes / non-breaking spaces) — these are the
   usual offenders.

7. Click **Submit**. Moderation typically completes within 24h on weekdays.
   You'll receive an email with the arXiv ID (`2606.XXXXX`).

## Step 3 — link the artifacts back into the repo

Once both DOIs are live, edit `docs/design-notes-v0.5.0.md` to:

- Add the Zenodo DOI badge near the top:
  `[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.XXXXXXXXX.svg)](https://doi.org/10.5281/zenodo.XXXXXXXXX)`
- Add the arXiv badge:
  `[![arXiv](https://img.shields.io/badge/arXiv-2606.XXXXX-b31b1b.svg)](https://arxiv.org/abs/2606.XXXXX)`

Then add a short pointer in the main `README.md` under a new "Prior art /
design notes" subsection so visitors can find both citations.

## What this gets you

After both uploads are live, the prior-art coverage looks like:

| Anchor | Indexed by | Timestamp |
|---|---|---|
| Git commit on `main` | GitHub | Already live (commit `2d9f269`, 2026-06-18) |
| Zenodo PDF + DOI | Google Scholar, CrossRef, OpenAIRE | After step 1 |
| arXiv PDF | arXiv search, Google Scholar, Semantic Scholar | After step 2, ~24h moderation |
| PyPI release `0.5.0` | PyPI index | Already live (2026-06-17) |

All four anchors point to the same commit hash and reference each other.
Any future patent search for d033 Jaccard-anchor drift, the fan-out
multi-encoding preprocessor, or the change-tracking normalization pipeline
will hit at least one of these and reject the application.
