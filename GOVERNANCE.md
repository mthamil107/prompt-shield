# Governance

prompt-shield is a single-maintainer open-source project. This document is
honest about what that means for anyone who ships the library, the MCP
server, or the signed threat-intel feed. If a detail below changes, it
changes here first.

## Maintainer

- **Thamilvendhan Munirathinam** (`mthamil107`) — sole maintainer.
- Responsibilities: code review and merge, PyPI release, feed curation and
  signing, security disclosures, this document.
- All releases ship under Apache-2.0 (code) and CC0 (threat-feed data).
- External contributions are welcomed via GitHub pull requests; merge
  authority is held by the maintainer.

## Threat-feed signing

The federated threat-intel feed at
[prompt-shield-signatures](https://github.com/mthamil107/prompt-shield-signatures)
is signed with a single offline ed25519 key.

- **Key holder.** One person — the maintainer above.
- **Key storage.** Private key held offline on a single workstation,
  encrypted at rest. It is never committed and never exposed to CI.
- **Signing cadence.** Manual, approximately daily when new patterns are
  merged. There is no automated signing pipeline today.
- **Public key.** Pinned in source at
  `src/prompt_shield/signatures/client.py` (key ID
  `31F125ADDE54B24A`). Clients trust this embedded key, not a runtime
  fetch, so a CDN compromise on its own cannot substitute a key.
- **Verification.** Pure-Python ed25519 via the `cryptography` library.
  Verification failure never overwrites the local cache at
  `~/.cache/prompt-shield/signatures.json`.

## Submission vetting

- Signatures are **not** accepted from anonymous submitters today.
- The feed contains patterns the maintainer authors or imports from open
  threat corpora (Garak, InjecAgent, deepset, HarmBench) with explicit
  attribution in the signatures repo.
- Pattern pull requests against the signatures repo are reviewed by the
  maintainer before signing. A pattern that triggers a false positive on
  the benign evaluation set (`tests/benchmark_public_datasets.py` plus
  `example-dataset.yaml`) is rejected.
- A pattern later found to over-match is removed in the next signing
  pass and the removal is recorded in the signatures repo `CHANGELOG.md`.

## Key rotation and revocation

- **Scheduled rotation.** There is no scheduled rotation today. The key
  is single-point-of-failure by design, as called out in the README.
  A scheduled rotation is tracked as a follow-up.
- **Emergency rotation.** If the signing key is suspected compromised:
  1. A `SECURITY ADVISORY` is published on this repo and on the
     signatures repo naming the key ID and the suspected compromise
     window.
  2. A new prompt-shield release is cut that embeds a new public key.
     From that release onward, signatures made under the old key fail
     verification.
  3. The signatures repo is rotated to the new key. Users on older
     prompt-shield releases will stop receiving new signatures until
     they upgrade. This is intentional — they must not silently accept
     entries signed by a key we now consider compromised.
- There is no cross-signed transition period today. This is a known
  limitation of the single-key model and will be revisited when a
  Sigstore migration is scoped.

## Compromise response

- **In-band channel.** Report via GitHub's private vulnerability
  reporting on this repo (see `SECURITY.md`).
- **Acknowledgement.** Within 48 hours.
- **Fix window.** Typically within 2 weeks for critical issues; faster
  for an active signing-key compromise.
- **Public disclosure.** On a timeline proportional to severity, after a
  fixed release is available or at 90 days — whichever is sooner.
- The maintainer email on PyPI is the fallback channel if GitHub's
  private reporting is unreachable.

## Succession

This is a solo-maintained project. If the maintainer stops working on
it, the default is **freeze, not transfer**:

- The PyPI name `prompt-shield-ai` will not be handed to a third party.
  The last-released version continues to work; no new releases are cut
  under that name.
- The signatures repo stops signing new entries. Clients on the current
  release will continue to verify existing entries but will see the feed
  go stale.
- The `SECURITY.md` disclosure channel stops being monitored. Users
  should pin a specific release and plan to migrate.
- This default exists because a security tool with a quietly-transferred
  signing key is more dangerous than a tool that stops.

A succession notice will be posted on the repo `README.md` and tagged as
a GitHub release titled `succession-notice` if this ever happens.

## Scope of the feed

- The feed is **opt-in and pull-only**. No prompt-shield install sends
  data outbound unless you explicitly configure the feed client.
- Feed updates ship only hashes and embeddings; raw attack text is never
  transmitted (see `SECURITY.md` → *Data Privacy*).

## Changes to this document

Changes to GOVERNANCE.md go through a normal pull request on this repo.
A material change — key handling, succession default, or scope of the
feed — is also noted in the `CHANGELOG.md` entry for the release that
ships it.
