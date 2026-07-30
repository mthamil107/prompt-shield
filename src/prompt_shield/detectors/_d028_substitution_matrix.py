"""Semantic substitution matrix for the Smith-Waterman alignment detector (d028).

Analogous to the BLOSUM scoring matrix in bioinformatics: words that are
literally identical score as a full match, words that are semantically
equivalent (synonyms) score as a partial match, and unrelated words count as
a mismatch.

The groups below were curated by hand from the attack-vocabulary present in
the existing d001-d020 regex patterns. Each group lists words that prompt
injection attackers use interchangeably in published corpora. A token is a
synonym of another if and only if they appear in the same group.

Keeping this module `_` prefixed so the detector auto-discovery iterator
can import it safely (it contains no BaseDetector subclass).
"""

from __future__ import annotations

from typing import Final

# Fifteen synonym groups covering the attack vocabulary seen in d001-d020.
# Add words to a group ONLY if they are used interchangeably by attackers
# in genuine injection attempts. Do not add casual synonyms — false
# positives on benign text are the cost.
#
# Each entry is ``(group, dampening_factor)``. The dampening factor is a
# multiplier applied to ``synonym_bonus`` when two words from this group
# align. Most groups use 1.0 (full synonym credit); families that overlap
# heavily with benign English get < 1.0 so their synonym matches count
# only fractionally.
#
# The reveal family carries dampening_factor=0.5 (v0.7.3): it contains
# show / tell / share / read / report / print / output — verbs that appear
# constantly in benign user queries ("show me the docs", "tell me about
# X", "share the link"). Dampening was applied per the paper §5.4 planned
# tuning as forward hardening. Note: empirical NotInject FP count is
# unchanged (11 before, 11 after); the actual FPs are driven by
# role_hijack and data_exfiltration needles, not reveal-family synonym
# slippage. This dampening prevents FUTURE reveal-family regressions
# but does not by itself lower the paper's reported 3.8% FPR — that
# needs needle-level work in a subsequent release.
SYNONYM_GROUPS: Final[tuple[tuple[frozenset[str], float], ...]] = (
    # ignore / negate family
    (
        frozenset(
            {
                "ignore",
                "disregard",
                "forget",
                "skip",
                "bypass",
                "overlook",
                "overrule",
                "nullify",
                "abandon",
                "omit",
                "discard",
            }
        ),
        1.0,
    ),
    # instructions / rules family
    (
        frozenset(
            {
                "instructions",
                "instruction",
                "directives",
                "directive",
                "rules",
                "rule",
                "guidelines",
                "guideline",
                "commands",
                "command",
                "orders",
                "order",
                "constraints",
                "restrictions",
                "policies",
                "policy",
                "protocol",
                "protocols",
            }
        ),
        1.0,
    ),
    # reveal / expose family — dampened (see module docstring)
    (
        frozenset(
            {
                "show",
                "reveal",
                "display",
                "output",
                "print",
                "expose",
                "disclose",
                "share",
                "tell",
                "echo",
                "repeat",
                "emit",
                "dump",
                "leak",
                "extract",
                "report",
                "read",
            }
        ),
        0.5,
    ),
    # system / internal family
    (
        frozenset(
            {
                "system",
                "initial",
                "original",
                "hidden",
                "internal",
                "secret",
                "base",
                "core",
                "foundational",
                "prior",
                "underlying",
                "private",
            }
        ),
        1.0,
    ),
    # prompt / configuration family (tokens that name the thing an
    # attacker wants to extract — prompt, config, etc. "instruction"
    # singular lives here because "what is your instruction" targets
    # the same noun class as "what is your prompt".)
    (
        frozenset(
            {
                "prompt",
                "prompts",
                "message",
                "messages",
                "content",
                "contents",
                "configuration",
                "config",
                "setup",
                "settings",
                "context",
                "instruction",
            }
        ),
        1.0,
    ),
    # previous / above family (positional references)
    (
        frozenset(
            {
                "previous",
                "prior",
                "earlier",
                "above",
                "preceding",
                "before",
                "former",
                "past",
                "foregoing",
                "aforementioned",
            }
        ),
        1.0,
    ),
    # pretend / roleplay family
    (
        frozenset(
            {
                "pretend",
                "act",
                "behave",
                "imagine",
                "assume",
                "suppose",
                "simulate",
                "roleplay",
                "play",
                "perform",
                "impersonate",
            }
        ),
        1.0,
    ),
    # mode / persona family
    (
        frozenset(
            {
                "mode",
                "state",
                "profile",
                "persona",
                "character",
                "role",
                "identity",
                "form",
                "version",
            }
        ),
        1.0,
    ),
    # unrestricted / jailbreak family
    (
        frozenset(
            {
                "unrestricted",
                "unlimited",
                "uncensored",
                "jailbroken",
                "free",
                "unbound",
                "liberated",
                "unfiltered",
                "unconstrained",
                "dan",
                "unrestrained",
                "raw",
            }
        ),
        1.0,
    ),
    # execute / run family
    (
        frozenset(
            {
                "execute",
                "run",
                "perform",
                "invoke",
                "activate",
                "trigger",
                "call",
                "launch",
                "start",
                "do",
                "carry",
            }
        ),
        1.0,
    ),
    # decode / decrypt family
    (
        frozenset(
            {
                "decode",
                "translate",
                "convert",
                "interpret",
                "parse",
                "decipher",
                "decrypt",
                "unescape",
                "unobfuscate",
            }
        ),
        1.0,
    ),
    # override / replace family
    (
        frozenset(
            {
                "override",
                "replace",
                "supersede",
                "overrule",
                "cancel",
                "terminate",
                "revoke",
                "rescind",
                "countermand",
                "suspend",
            }
        ),
        1.0,
    ),
    # admin / root family
    (
        frozenset(
            {
                "admin",
                "administrator",
                "root",
                "developer",
                "god",
                "superuser",
                "master",
                "sudo",
                "owner",
                "operator",
            }
        ),
        1.0,
    ),
    # new / reset family
    (
        frozenset(
            {
                "new",
                "fresh",
                "reset",
                "restart",
                "reboot",
                "reinitialize",
                "reinitialise",
                "reload",
                "updated",
                "revised",
            }
        ),
        1.0,
    ),
    # all / every family (quantifiers often used with ignore-family)
    (
        frozenset(
            {
                "all",
                "every",
                "each",
                "any",
                "entire",
                "complete",
                "full",
                "whole",
                "total",
            }
        ),
        1.0,
    ),
)

# Reverse index: word -> set of group indices it belongs to.
# A word may belong to multiple groups (e.g., "instruction" is in both
# "instructions-family" and "prompt-family"). Two words are synonyms if
# they share ANY group.
_WORD_TO_GROUPS: Final[dict[str, frozenset[int]]] = {}
_GROUP_DAMPENING: Final[dict[int, float]] = {}
for _idx, (_group, _damp) in enumerate(SYNONYM_GROUPS):
    _GROUP_DAMPENING[_idx] = _damp
    for _word in _group:
        _existing = _WORD_TO_GROUPS.get(_word, frozenset())
        _WORD_TO_GROUPS[_word] = _existing | {_idx}


def are_synonyms(a: str, b: str) -> bool:
    """Return True if ``a`` and ``b`` are in the same synonym group.

    Comparison is case-insensitive. Identical words are not considered
    synonyms (that's an exact match — a different, higher-scoring case).
    """
    if a == b:
        return False
    a_groups = _WORD_TO_GROUPS.get(a.lower())
    b_groups = _WORD_TO_GROUPS.get(b.lower())
    if a_groups is None or b_groups is None:
        return False
    return bool(a_groups & b_groups)


def _shared_group_dampening(a: str, b: str) -> float | None:
    """Return the *maximum* dampening factor across groups that both
    ``a`` and ``b`` belong to, or ``None`` if they share no group.

    "Maximum" is intentional: if the two words are synonyms in a
    non-dampened group as well as in a dampened one, they get the more
    generous credit. This keeps genuine attack vocabulary (which sits
    in the more specific, undampened groups) from being over-penalized
    just because one of the two words also appears in the reveal
    family.
    """
    if a == b:
        return None
    a_groups = _WORD_TO_GROUPS.get(a.lower())
    b_groups = _WORD_TO_GROUPS.get(b.lower())
    if a_groups is None or b_groups is None:
        return None
    shared = a_groups & b_groups
    if not shared:
        return None
    return max(_GROUP_DAMPENING[i] for i in shared)


def score_pair(
    a: str,
    b: str,
    *,
    match_bonus: int,
    synonym_bonus: int,
    mismatch_penalty: int,
) -> int:
    """Score a single aligned pair of tokens.

    - Exact match (case-insensitive): ``match_bonus``
    - Synonym (same group): ``synonym_bonus`` scaled by the group's
      ``dampening_factor`` (see :data:`SYNONYM_GROUPS`). If a word pair
      shares multiple groups, the highest (least dampened) factor wins.
      Rounded to the nearest integer so the alignment matrix stays in
      ``int``. Never dips below ``mismatch_penalty``.
    - Unrelated: ``mismatch_penalty`` (typically negative)
    """
    if a == b or a.lower() == b.lower():
        return match_bonus
    damp = _shared_group_dampening(a, b)
    if damp is None:
        return mismatch_penalty
    dampened = round(synonym_bonus * damp)
    # Floor at mismatch_penalty so a dampened synonym never scores
    # worse than an unrelated token. In practice synonym_bonus is
    # positive and mismatch_penalty is negative, so this only matters
    # in exotic config overrides.
    return max(dampened, mismatch_penalty)
