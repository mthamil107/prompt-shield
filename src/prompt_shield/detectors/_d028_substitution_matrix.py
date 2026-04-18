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
SYNONYM_GROUPS: Final[tuple[frozenset[str], ...]] = (
    # ignore / negate family
    frozenset({
        "ignore", "disregard", "forget", "skip", "bypass", "overlook",
        "overrule", "nullify", "abandon", "omit", "discard",
    }),
    # instructions / rules family
    frozenset({
        "instructions", "instruction", "directives", "directive", "rules",
        "rule", "guidelines", "guideline", "commands", "command",
        "orders", "order", "constraints", "restrictions", "policies",
        "policy", "protocol", "protocols",
    }),
    # reveal / expose family
    frozenset({
        "show", "reveal", "display", "output", "print", "expose",
        "disclose", "share", "tell", "echo", "repeat", "emit",
        "dump", "leak", "extract", "report", "read",
    }),
    # system / internal family
    frozenset({
        "system", "initial", "original", "hidden", "internal", "secret",
        "base", "core", "foundational", "prior", "underlying", "private",
    }),
    # prompt / configuration family (tokens that name the thing an
    # attacker wants to extract — prompt, config, etc. "instruction"
    # singular lives here because "what is your instruction" targets
    # the same noun class as "what is your prompt".)
    frozenset({
        "prompt", "prompts", "message", "messages", "content", "contents",
        "configuration", "config", "setup", "settings", "context",
        "instruction",
    }),
    # previous / above family (positional references)
    frozenset({
        "previous", "prior", "earlier", "above", "preceding", "before",
        "former", "past", "prior", "foregoing", "aforementioned",
    }),
    # pretend / roleplay family
    frozenset({
        "pretend", "act", "behave", "imagine", "assume", "suppose",
        "simulate", "roleplay", "play", "perform", "impersonate",
    }),
    # mode / persona family
    frozenset({
        "mode", "state", "profile", "persona", "character", "role",
        "identity", "form", "version",
    }),
    # unrestricted / jailbreak family
    frozenset({
        "unrestricted", "unlimited", "uncensored", "jailbroken", "free",
        "unbound", "liberated", "unfiltered", "unconstrained", "dan",
        "unrestrained", "raw",
    }),
    # execute / run family
    frozenset({
        "execute", "run", "perform", "invoke", "activate", "trigger",
        "call", "launch", "start", "do", "carry",
    }),
    # decode / decrypt family
    frozenset({
        "decode", "translate", "convert", "interpret", "parse", "decipher",
        "decrypt", "unescape", "unobfuscate",
    }),
    # override / replace family
    frozenset({
        "override", "replace", "supersede", "overrule", "cancel",
        "terminate", "revoke", "rescind", "countermand", "suspend",
    }),
    # admin / root family
    frozenset({
        "admin", "administrator", "root", "developer", "god", "superuser",
        "master", "sudo", "owner", "operator",
    }),
    # new / reset family
    frozenset({
        "new", "fresh", "reset", "restart", "reboot", "reinitialize",
        "reinitialise", "reload", "updated", "revised",
    }),
    # all / every family (quantifiers often used with ignore-family)
    frozenset({
        "all", "every", "each", "any", "entire", "complete", "full",
        "whole", "total",
    }),
)

# Reverse index: word -> set of group indices it belongs to.
# A word may belong to multiple groups (e.g., "instruction" is in both
# "instructions-family" and "prompt-family"). Two words are synonyms if
# they share ANY group.
_WORD_TO_GROUPS: Final[dict[str, frozenset[int]]] = {}
for _idx, _group in enumerate(SYNONYM_GROUPS):
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
    - Synonym (same group): ``synonym_bonus``
    - Unrelated: ``mismatch_penalty`` (typically negative)
    """
    if a == b or a.lower() == b.lower():
        return match_bonus
    if are_synonyms(a, b):
        return synonym_bonus
    return mismatch_penalty
