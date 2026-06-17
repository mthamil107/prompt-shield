"""Many-shot structural analysis detector (d029).

Detects many-shot jailbreaking attacks (Anthropic, 2024) by counting
repeated dialogue or example markers in the prompt and flagging when
the structural density exceeds a calibrated threshold.

Many-shot attacks work by stuffing the prompt with many demonstration
pairs (Q/A, User/Assistant, Example N: ...) that condition the model to
follow the demonstrated pattern, then placing the harmful target query
at the end. Effectiveness rises with shot count and saturates around
32-256 shots.

Detection signal
----------------

1. Scan the input with line-anchored regexes that match dialogue or
   example markers across six families (Q/A, Question/Answer,
   User/Assistant, Example N:, Input/Output, Prompt/Response).
2. For each family compute ``pair_count`` (the minimum of the question-
   side and answer-side counts; for the numbered family, the count
   itself). Pick the family with the highest ``pair_count``.
3. Compute ``density = pair_count / non_empty_line_count``. A typical
   many-shot attack is *dense* (every 1-3 lines is a marker); legitimate
   FAQs and articles use markers sparsely.
4. Fire when ``pair_count >= min_shots`` AND ``density >= min_density``.
   Confidence ramps linearly from ``min_shots`` to ``min_shots + 24``.
   An optional small boost is applied if the final question block
   contains a token from a harmful-intent lexicon — this helps separate
   suspicious-but-benign few-shot teaching from confirmed attacks but
   never gates the detection itself.

The detector is intentionally conservative: ``min_shots = 8`` skips the
3-7 shot range that legitimate few-shot teaching prompts occupy.
"""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

# (regex_source, marker_label, family_id, role)
# role is "q" (question side), "a" (answer side), or "n" (numbered).
_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"(?im)^[ \t]*Q[ \t]*[:\.\)][ \t]+\S", "Q:", "qa_short", "q"),
    (r"(?im)^[ \t]*A[ \t]*[:\.\)][ \t]+\S", "A:", "qa_short", "a"),
    (r"(?im)^[ \t]*Question[ \t]*[:\.\)][ \t]+\S", "Question:", "qa_long", "q"),
    (r"(?im)^[ \t]*Answer[ \t]*[:\.\)][ \t]+\S", "Answer:", "qa_long", "a"),
    (r"(?im)^[ \t]*(?:User|Human)[ \t]*[:\.\)][ \t]+\S", "User:", "chat", "q"),
    (r"(?im)^[ \t]*(?:Assistant|AI|Bot|Chatbot)[ \t]*[:\.\)][ \t]+\S", "Assistant:", "chat", "a"),
    (r"(?im)^[ \t]*Example[ \t]*\d+[ \t]*[:\.\)][ \t]+\S", "Example N:", "numbered", "n"),
    (r"(?im)^[ \t]*Demo(?:nstration)?[ \t]*\d+[ \t]*[:\.\)][ \t]+\S", "Demo N:", "numbered", "n"),
    (r"(?im)^[ \t]*Sample[ \t]*\d+[ \t]*[:\.\)][ \t]+\S", "Sample N:", "numbered", "n"),
    (r"(?im)^[ \t]*Input[ \t]*[:\.\)][ \t]+\S", "Input:", "io", "q"),
    (r"(?im)^[ \t]*Output[ \t]*[:\.\)][ \t]+\S", "Output:", "io", "a"),
    (r"(?im)^[ \t]*Prompt[ \t]*[:\.\)][ \t]+\S", "Prompt:", "prompt_response", "q"),
    (r"(?im)^[ \t]*Response[ \t]*[:\.\)][ \t]+\S", "Response:", "prompt_response", "a"),
]

_HARMFUL_PIVOT_RE = regex.compile(
    # Trailing s? + \b lets each lemma also match its plural / -s form
    # (e.g. "explosives", "weapons", "credentials"). The leading \b stays
    # strict so we don't match these as substrings of unrelated words.
    r"\b(?:hack(?:ing|er|s)?|bomb(?:ing|s)?|malware|weapons?|kill(?:ing|s)?|"
    r"exploits?|bypass(?:es|ing)?|credentials?|passwords?|"
    r"synthesi[sz]e[sd]?|synthesizing|synthesis|payloads?|ddos|phish(?:ing)?|"
    r"backdoors?|ransom(?:ware)?|cyanide|meth(?:amphetamine)?|"
    r"fentanyl|smuggl(?:e|ing)|stalk(?:ing)?|deepfakes?|"
    r"poison(?:ing|s)?|chloroform|nerve[\W_]*agents?|sarin|napalm|"
    r"grenades?|explosives?)\b",
    regex.IGNORECASE,
)


class ManyShotStructuralDetector(BaseDetector):
    """Detects many-shot jailbreaking by structural pattern repetition."""

    detector_id: str = "d029_many_shot_structural"
    name: str = "Many-Shot Structural"
    description: str = (
        "Detects many-shot jailbreaking attacks (Anthropic 2024) by counting "
        "repeated dialogue / example markers (Q/A, User/Assistant, Example N, "
        "Input/Output, Prompt/Response) and gating on density. Fires when 8+ "
        "paired markers occur at high density. Optional confidence boost "
        "when the final example pivots toward a harmful topic."
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["direct_injection", "many_shot", "novel"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    # Defaults — overridable via per-detector config.
    _min_shots: int = 8
    _min_density: float = 0.15
    _max_input_chars: int = 200_000
    _pivot_boost: float = 0.10

    def __init__(self) -> None:
        self._compiled = [
            (regex.compile(src), label, family, role) for src, label, family, role in _PATTERNS
        ]

    def setup(self, config: dict[str, object]) -> None:
        def _as_int(key: str, default: int) -> int:
            v = config.get(key, default)
            return int(v) if isinstance(v, (int, float, str)) else default

        def _as_float(key: str, default: float) -> float:
            v = config.get(key, default)
            return float(v) if isinstance(v, (int, float, str)) else default

        self._min_shots = _as_int("min_shots", self._min_shots)
        self._min_density = _as_float("min_density", self._min_density)
        self._max_input_chars = _as_int("max_input_chars", self._max_input_chars)
        self._pivot_boost = _as_float("pivot_boost", self._pivot_boost)

    def _score(self, pair_count: int, density: float, has_pivot: bool) -> float:
        if pair_count < self._min_shots or density < self._min_density:
            return 0.0
        # Linear ramp: min_shots -> 0.55, min_shots + 24 -> 0.95.
        base = 0.55 + 0.40 * min(1.0, (pair_count - self._min_shots) / 24.0)
        # Density bonus tops out at +0.05 when density gets to ~0.50.
        density_bonus = 0.05 * min(1.0, max(0.0, (density - self._min_density) / 0.35))
        score = base + density_bonus
        if has_pivot:
            score = min(0.99, score + self._pivot_boost)
        return min(1.0, score)

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        if not input_text or len(input_text) < 16:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Input too short for many-shot analysis",
            )

        # Safety cap so very long inputs don't blow the regex budget.
        text = input_text[: self._max_input_chars]

        # Count non-empty lines for density.
        line_count = sum(1 for ln in text.splitlines() if ln.strip())
        if line_count == 0:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No non-empty lines",
            )

        # Run each compiled pattern and collect matches per family.
        # match_positions: family -> role -> list of (start, end, label)
        family_role_matches: dict[str, dict[str, list[tuple[int, int, str]]]] = {}
        for pat, label, family, role in self._compiled:
            for m in pat.finditer(text):
                family_role_matches.setdefault(family, {}).setdefault(role, []).append(
                    (m.start(), m.end(), label)
                )

        # Pick the dominant family: max paired count (or numbered count).
        best_family: str = ""
        best_pair_count: int = 0
        best_q_matches: list[tuple[int, int, str]] = []
        best_a_matches: list[tuple[int, int, str]] = []

        for family, roles in family_role_matches.items():
            q = roles.get("q", [])
            a = roles.get("a", [])
            n = roles.get("n", [])
            if family == "numbered":
                pair_count = len(n)
                q_match, a_match = n, []
            else:
                pair_count = min(len(q), len(a))
                q_match, a_match = q, a
            if pair_count > best_pair_count:
                best_pair_count = pair_count
                best_family = family
                best_q_matches = q_match
                best_a_matches = a_match

        if best_pair_count == 0:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No dialogue or example markers found",
            )

        density = best_pair_count / line_count

        # Look for harmful pivot in the LAST question block (text from the
        # last question marker to either the next answer marker or EOF).
        has_pivot = False
        pivot_excerpt = ""
        if best_q_matches:
            last_q_start, _, _ = best_q_matches[-1]
            # End of last question block = next answer marker after it, or EOF.
            block_end = len(text)
            for a_start, _, _ in best_a_matches:
                if a_start > last_q_start:
                    block_end = a_start
                    break
            block = text[last_q_start:block_end]
            pivot_match = _HARMFUL_PIVOT_RE.search(block)
            if pivot_match:
                has_pivot = True
                # 60-char window around the pivot match for explanation.
                pivot_excerpt = block[: min(len(block), 200)].strip()

        confidence = self._score(best_pair_count, density, has_pivot)
        if confidence == 0.0:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    f"Below threshold (family={best_family}, "
                    f"pairs={best_pair_count}, density={density:.2f})"
                ),
                metadata={
                    "family": best_family,
                    "pair_count": best_pair_count,
                    "density": round(density, 3),
                    "line_count": line_count,
                },
            )

        # Build a small set of MatchDetail entries (first, last, pivot if any).
        matches: list[MatchDetail] = []
        if best_q_matches:
            first_start, first_end, first_label = best_q_matches[0]
            matches.append(
                MatchDetail(
                    pattern=first_label,
                    matched_text=text[first_start:first_end],
                    position=(first_start, first_end),
                    description=f"First {best_family} marker",
                )
            )
            last_start, last_end, last_label = best_q_matches[-1]
            if (last_start, last_end) != (first_start, first_end):
                matches.append(
                    MatchDetail(
                        pattern=last_label,
                        matched_text=text[last_start:last_end],
                        position=(last_start, last_end),
                        description=f"Last {best_family} marker (shot #{best_pair_count})",
                    )
                )
        if has_pivot:
            matches.append(
                MatchDetail(
                    pattern="harmful_pivot",
                    matched_text=pivot_excerpt[:120],
                    position=None,
                    description="Final example pivots toward harmful topic",
                )
            )

        explanation = (
            f"Many-shot structural pattern detected: {best_pair_count} "
            f"'{best_family}' shots at density {density:.2f}"
            + (" with harmful pivot in final example" if has_pivot else "")
        )

        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=explanation,
            metadata={
                "family": best_family,
                "pair_count": best_pair_count,
                "density": round(density, 3),
                "line_count": line_count,
                "has_pivot": has_pivot,
            },
        )
