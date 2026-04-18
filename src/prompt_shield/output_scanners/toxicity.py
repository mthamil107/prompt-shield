"""Output scanner that detects toxic, harmful, and inappropriate content."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.models import MatchDetail
from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult

# Maximum characters of matched text to include in results.
_MATCH_PREVIEW_LEN = 30


class ToxicityScanner(BaseOutputScanner):
    """Detects toxic, hateful, violent, sexual, self-harm, and dangerous content.

    Patterns are deliberately anchored to *actionable* or *targeted* phrasing so
    that purely educational/historical text (e.g. "The history of weapons
    includes...") does not trigger false positives.
    """

    scanner_id: str = "toxicity"
    name: str = "Toxicity Scanner"
    description: str = (
        "Detects toxic, hateful, violent, sexual, self-harm, "
        "and dangerous instruction content in LLM outputs"
    )

    _base_confidence: float = 0.90
    _confidence_per_extra_category: float = 0.03

    # ------------------------------------------------------------------
    # Pattern catalogue — (regex, human-readable description)
    # Grouped by category for clarity; flattened into a lookup at init.
    # ------------------------------------------------------------------

    _CATEGORY_PATTERNS: ClassVar[dict[str, list[tuple[str, str]]]] = {
        "hate_speech": [
            # Group-targeted dehumanisation / calls to violence
            (
                r"(?:all|those|these)\s+(?:\w+\s+){0,2}"
                r"(?:should\s+(?:die|be\s+killed|be\s+eliminated|go\s+back)"
                r"|are\s+(?:subhuman|inferior|animals|vermin|parasites))",
                "Group-targeted dehumanisation or call for harm",
            ),
            (
                r"(?:death\s+to|exterminate|ethnic\s+cleansing)\s+(?:all\s+)?\w+",
                "Genocidal or exterminatory language",
            ),
            (
                r"(?:commit|carry\s+out|perform|launch)\s+(?:a\s+)?genocide",
                "Genocide incitement",
            ),
            # Directive hate — telling someone they are sub-human
            (
                r"(?:you(?:'re|\s+are)\s+(?:a\s+)?(?:subhuman|vermin|parasite|animal|cockroach))",
                "Direct dehumanisation of addressee",
            ),
        ],
        "violence": [
            # How-to harm a person
            (
                r"(?:how\s+to|steps?\s+to|guide\s+to|instructions?\s+(?:for|to))\s+"
                r"(?:kill|murder|assassinate|poison|strangle|stab|shoot)\s+"
                r"(?:a\s+)?(?:person|someone|people|human)",
                "Instructions to harm a person",
            ),
            # Weapon / explosive construction
            (
                r"(?:build|make|construct|assemble|create)\s+"
                r"(?:a\s+)?(?:bomb|explosive|weapon|firearm|IED|pipe\s+bomb|molotov)",
                "Weapon or explosive construction",
            ),
            # Synthesis of dangerous substances
            (
                r"(?:synthesize|produce|manufacture|cook|make)\s+"
                r"(?:meth|fentanyl|sarin|ricin|anthrax|VX|mustard\s+gas|nerve\s+agent)",
                "Dangerous substance synthesis",
            ),
        ],
        "self_harm": [
            (
                r"(?:how\s+to|ways?\s+to|methods?\s+(?:for|of|to))\s+"
                r"(?:kill\s+yourself|commit(?:ting)?\s+suicide|end\s+your\s+life|take\s+your\s+own\s+life)",
                "Suicide method instructions",
            ),
            (
                r"(?:you\s+should|you\s+could|try\s+to|consider)\s+"
                r"(?:kill(?:ing)?\s+yourself|end(?:ing)?\s+it\s+all|harm(?:ing)?\s+yourself)",
                "Encouragement of self-harm",
            ),
        ],
        "sexual_explicit": [
            # Child exploitation — always flag (high-signal keywords)
            (
                r"(?:child|minor|underage|pre-?teen|infant)\s+"
                r"(?:porn(?:ography)?|sex(?:ual)?|nude|naked|exploit(?:ation)?)",
                "Child exploitation content",
            ),
            (
                r"(?:porn(?:ography)?|sex(?:ual)?|nude|naked|exploit(?:ation)?)\s+"
                r"(?:of|with|involving)\s+(?:a\s+)?(?:child|minor|underage|pre-?teen|infant)",
                "Child exploitation content (inverted)",
            ),
            # Graphic / explicit sexual instructions
            (
                r"(?:step[- ]by[- ]step|detailed|explicit)\s+"
                r"(?:guide|instructions?|description)\s+"
                r"(?:for|to|on|of)\s+(?:having\s+)?(?:sex(?:ual)?|intercourse|sodomy|rape)",
                "Explicit sexual instruction",
            ),
        ],
        "dangerous_instructions": [
            # Step-by-step harmful procedures
            (
                r"(?:step\s+\d|first|next|then|finally)\s*[:.]"
                r"\s*(?:mix|combine|heat|dissolve|inject|ignite|detonate|connect\s+the\s+wires)",
                "Step-by-step dangerous procedure",
            ),
            # Materials list for harmful substances
            (
                r"(?:ingredients?|materials?|supplies|you(?:'ll)?\s+need)\s*:\s*"
                r"(?:[\s\S]{0,120})"
                r"(?:ammonium\s+nitrate|potassium\s+chlorate|sulfuric\s+acid"
                r"|acetone\s+peroxide|black\s+powder|thermite)",
                "Dangerous materials list",
            ),
        ],
    }

    def __init__(self) -> None:
        # Pre-compile patterns once, storing (compiled, description, category).
        self._compiled: list[tuple[regex.Pattern[str], str, str]] = []
        for category, patterns in self._CATEGORY_PATTERNS.items():
            for pattern_str, description in patterns:
                compiled = regex.compile(pattern_str, regex.IGNORECASE)
                self._compiled.append((compiled, description, category))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, output_text: str, context: dict[str, object] | None = None) -> OutputScanResult:
        matches: list[MatchDetail] = []
        categories_seen: set[str] = set()

        for compiled, description, category in self._compiled:
            for m in compiled.finditer(output_text):
                matched_text = m.group()
                # Truncate potentially sensitive content in the result.
                preview = (
                    matched_text[:_MATCH_PREVIEW_LEN] + "..."
                    if len(matched_text) > _MATCH_PREVIEW_LEN
                    else matched_text
                )
                matches.append(
                    MatchDetail(
                        pattern=compiled.pattern,
                        matched_text=preview,
                        position=(m.start(), m.end()),
                        description=description,
                    )
                )
                categories_seen.add(category)

        if not matches:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="No toxic or harmful content detected",
            )

        sorted_categories = sorted(categories_seen)
        extra = max(0, len(sorted_categories) - 1)
        confidence = min(1.0, self._base_confidence + self._confidence_per_extra_category * extra)

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=True,
            confidence=confidence,
            categories=sorted_categories,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} pattern(s) across categories: "
                f"{', '.join(sorted_categories)}"
            ),
        )
