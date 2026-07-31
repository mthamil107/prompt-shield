# Development freeze — JOSS submission window

**Effective**: 2026-07-31
**Ends**: on JOSS acceptance decision (typically 2–6 weeks after
submission on/around 2026-08-12).

## Why

`paper/paper.md` submitted to JOSS references specific repo state
(version `0.7.3`, 34 detectors, 1,232 tests, `d034_honeypot_tool`
shipped, §5.8 held-out benchmark). JOSS reviewers clone the repository
at HEAD when they review; any drift between the paper's claims and
what the reviewer sees creates unnecessary back-and-forth.

The freeze protects reviewers from a moving target and protects the
maintainer from having to re-explain state changes mid-review.

## What is frozen

No commits to `main` for:

- New features
- Refactoring / cleanup
- Non-critical bug fixes
- README / docs rewrites
- New paper drafts (v5 work waits)
- Version bumps (v0.8.0 planning waits)
- Dependency updates that change behaviour

## Exceptions

The freeze does **not** apply to any of the following. These can and
should ship as patch releases (`v0.7.4`, `v0.7.5`, ...) as needed, with
a CHANGELOG entry noting the freeze-window exception:

1. **Security vulnerability at CVE severity** — anything a security
   researcher would file a GHSA for. Must fix, must ship immediately.
2. **JOSS-reviewer-requested change** — required to address specific
   review feedback. Encouraged.
3. **CI or release pipeline broken** — must fix; without green CI the
   reviewer cannot verify the build.
4. **License / compliance issue** — must fix.
5. **Broken PyPI install** — anything that stops
   `pip install prompt-shield-ai==0.7.3` from succeeding.
6. **README / paper factual error surfaced by a reader** that the
   reviewer would rightly flag. Doc-only edits are cheap; ship them.

Anything else — including features requested via GitHub issue, ideas
that arrive from research, external-review recommendations, everything
that this repo would normally welcome — waits for the freeze to lift.
File the request as a GitHub issue tagged `post-joss` for the backlog.

## Signalling this to contributors

Solo-maintained project, so no team announcement needed. External
contributors landing on the repo will see this file at the root and
know why open PRs may sit longer than usual during the window.

Existing open issues will not receive substantive reply-with-fix
during the window; comments acknowledging receipt and pointing at
this file are fine.

## When the freeze lifts

On the day JOSS acceptance lands (or is decisively rejected):

1. Merge or close the `post-joss` backlog.
2. Delete this file.
3. Cut `v0.8.0` per the plan in `CHANGELOG.md`'s "Not in this release"
   section (Sigstore signing, MCP scanner, `sync_threats()` hard-flip,
   remaining framework integrations).
4. Announce nothing — organic growth continues per project policy.

## Contact

Report any freeze-exception candidate via GitHub issue with the label
`joss-window-exception` (create the label if needed on first use).
