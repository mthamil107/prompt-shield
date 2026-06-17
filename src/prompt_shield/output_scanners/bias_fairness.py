"""Bias / fairness output scanner.

Detects loaded language and stereotyped phrasing in LLM outputs targeting
protected attributes (race, gender, religion, etc.). Designed as a
lightweight signal — not a replacement for a full fairness audit, but a
practical guardrail for customer-facing deployments.

Detection approach:
    1. **Stereotype phrase patterns** — high-precision regexes for the
       "all X are Y" / "X people always Z" / "as a [group] you should"
       constructions that flag obvious bias.
    2. **Loaded language pairs** — a small curated lexicon of protected
       group references combined with negatively-loaded adjectives.

Configuration:
    bias_fairness:
      enabled: true
      threshold: 1                 # flag at this many hits or above
      extra_groups: []             # optional: additional group keywords
      extra_loaded_terms: []       # optional: additional pejoratives
"""
from __future__ import annotations

import logging
import re
from typing import ClassVar

from prompt_shield.models import MatchDetail
from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult

logger = logging.getLogger(__name__)


# Protected-group references (single words or short phrases).
_PROTECTED_GROUPS: tuple[str, ...] = (
    "women", "men", "girls", "boys", "females", "males",
    "blacks", "whites", "asians", "latinos", "latinas", "hispanics",
    "jews", "muslims", "christians", "hindus", "buddhists", "atheists",
    "immigrants", "foreigners", "refugees",
    "gays", "lesbians", "trans people", "transgender people",
    "old people", "elderly", "disabled people", "poor people",
)

# Negative / loaded adjectives commonly used in biased framing.
_LOADED_TERMS: tuple[str, ...] = (
    "lazy", "stupid", "violent", "criminal", "dirty", "greedy",
    "untrustworthy", "dangerous", "primitive", "inferior", "superior",
    "subhuman", "savage", "barbaric", "deceitful", "treacherous",
)

# High-precision stereotype templates.
_STEREOTYPE_TEMPLATES: tuple[str, ...] = (
    r"\ball\s+(?:{groups})\s+are\s+\w+",
    r"\b(?:{groups})\s+(?:are\s+(?:all\s+)?|always\s+|tend\s+to\s+be\s+)\w+",
    r"\bas\s+a\s+(?:woman|man|girl|boy|black|white|asian|jew|muslim|christian|hindu|gay|lesbian|trans(?:gender)?(?:\s+person)?|immigrant)\s*,\s*you\s+(?:should|must|need\s+to|ought\s+to)\b",
    r"\btypical\s+(?:{groups})\s+\w+",
)


class BiasFairnessOutputScanner(BaseOutputScanner):
    """Flag LLM outputs containing biased framing of protected groups."""

    scanner_id: ClassVar[str] = "bias_fairness"
    name: ClassVar[str] = "Bias / Fairness"
    description: ClassVar[str] = (
        "Flag LLM outputs that frame protected groups with loaded language "
        "or stereotype templates."
    )

    def __init__(self) -> None:
        self._threshold: int = 1
        self._loaded_pattern: re.Pattern | None = None
        self._stereotype_patterns: list[re.Pattern] = []

    def setup(self, config: dict[str, object]) -> None:
        threshold = config.get("threshold", 1)
        self._threshold = (
            int(threshold) if isinstance(threshold, (int, float, str)) else 1
        )
        extra_groups = config.get("extra_groups", [])
        extra_loaded = config.get("extra_loaded_terms", [])
        groups = list(_PROTECTED_GROUPS)
        if isinstance(extra_groups, list):
            groups.extend(str(g) for g in extra_groups if isinstance(g, str))
        loaded = list(_LOADED_TERMS)
        if isinstance(extra_loaded, list):
            loaded.extend(str(t) for t in extra_loaded if isinstance(t, str))

        groups_alt = "|".join(re.escape(g) for g in groups)
        loaded_alt = "|".join(re.escape(t) for t in loaded)

        # Loaded-language: group reference followed within a window by a
        # loaded adjective (or the reverse). Word-bounded and IGNORECASE.
        self._loaded_pattern = re.compile(
            r"\b(?:" + groups_alt + r")\b[^.!?\n]{0,60}\b(?:" + loaded_alt + r")\b"
            r"|\b(?:" + loaded_alt + r")\b[^.!?\n]{0,60}\b(?:" + groups_alt + r")\b",
            re.IGNORECASE,
        )
        self._stereotype_patterns = [
            re.compile(tpl.format(groups=groups_alt), re.IGNORECASE)
            for tpl in _STEREOTYPE_TEMPLATES
        ]

    def scan(
        self,
        output_text: str,
        context: dict[str, object] | None = None,
    ) -> OutputScanResult:
        if not output_text or not output_text.strip():
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="empty output",
            )

        if self._loaded_pattern is None:
            # setup() not called — be permissive
            self.setup({})

        hits: list[MatchDetail] = []
        # Stereotype templates: high-signal hits.
        for pat in self._stereotype_patterns:
            for m in pat.finditer(output_text):
                hits.append(
                    MatchDetail(
                        pattern="stereotype_template",
                        matched_text=m.group(0)[:120],
                        position=(m.start(), m.end()),
                        description="stereotype template match",
                    )
                )
        # Loaded-language proximity.
        assert self._loaded_pattern is not None
        for m in self._loaded_pattern.finditer(output_text):
            hits.append(
                MatchDetail(
                    pattern="loaded_proximity",
                    matched_text=m.group(0)[:120],
                    position=(m.start(), m.end()),
                    description="protected-group + loaded-term proximity",
                )
            )

        flagged = len(hits) >= self._threshold
        confidence = min(0.95, 0.4 + 0.15 * len(hits)) if flagged else 0.0

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=flagged,
            confidence=confidence,
            categories=["biased_framing"] if flagged else [],
            matches=hits[:10],
            explanation=(
                f"Matched {len(hits)} bias indicator(s) "
                f"(threshold {self._threshold})"
                if flagged
                else "No bias indicators above threshold"
            ),
            metadata={
                "hit_count": len(hits),
                "threshold": self._threshold,
            },
        )
