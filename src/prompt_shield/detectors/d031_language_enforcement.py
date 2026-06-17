"""Language enforcement detector (d031).

Flags inputs in disallowed languages. Useful for English-only deployments
to filter out non-English jailbreak attempts that legitimate users
wouldn't produce.

Detection is heuristic when ``langdetect`` is unavailable — we use a
small character-script analysis as a fallback (Cyrillic, CJK, Arabic,
Devanagari, etc.). With ``langdetect`` installed we get more accurate
language ID for Latin-script languages too (French, German, Spanish).

Configuration:
    d031_language_enforcement:
      enabled: true
      allowed_languages: ["en"]   # default
      min_input_chars: 32         # silent on short inputs
"""
from __future__ import annotations

import logging
from typing import ClassVar

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger(__name__)

# Script-range regex patterns for the fallback detector.
_SCRIPT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("cyrillic", r"\p{Cyrillic}"),
    ("greek", r"\p{Greek}"),
    ("arabic", r"\p{Arabic}"),
    ("hebrew", r"\p{Hebrew}"),
    ("devanagari", r"\p{Devanagari}"),
    ("thai", r"\p{Thai}"),
    ("cjk", r"[\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}]"),
)

_SCRIPT_TO_LANG = {
    "cyrillic": "ru",
    "greek": "el",
    "arabic": "ar",
    "hebrew": "he",
    "devanagari": "hi",
    "thai": "th",
    "cjk": "zh",  # rough — could be ja/ko, but treated as not-en
}


class LanguageEnforcementDetector(BaseDetector):
    """Flag inputs in disallowed languages."""

    detector_id: str = "d031_language_enforcement"
    name: str = "Language Enforcement"
    description: str = (
        "Flag inputs in disallowed languages. Useful for English-only deployments "
        "to filter multilingual jailbreak attempts that legitimate users would not "
        "produce."
    )
    severity: Severity = Severity.MEDIUM
    tags: ClassVar[list[str]] = ["multilingual", "policy", "operator-defined"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        self._allowed: tuple[str, ...] = ("en",)
        self._min_input_chars: int = 32
        self._langdetect_available: bool | None = None
        self._compiled_scripts: list[tuple[str, regex.Pattern]] = []

    def setup(self, config: dict[str, object]) -> None:
        allowed = config.get("allowed_languages")
        if isinstance(allowed, list) and all(isinstance(x, str) for x in allowed):
            self._allowed = tuple(x.lower() for x in allowed)
        min_chars = config.get("min_input_chars", 32)
        self._min_input_chars = (
            int(min_chars) if isinstance(min_chars, (int, float, str)) else 32
        )
        # Pre-compile script regexes once.
        self._compiled_scripts = [
            (name, regex.compile(pat, regex.UNICODE)) for name, pat in _SCRIPT_PATTERNS
        ]

    def _ensure_langdetect(self) -> bool:
        if self._langdetect_available is not None:
            return self._langdetect_available
        try:
            import langdetect  # noqa: F401

            self._langdetect_available = True
        except ImportError:
            self._langdetect_available = False
        return self._langdetect_available

    def detect(
        self,
        input_text: str,
        context: dict[str, object] | None = None,
    ) -> DetectionResult:
        if not input_text or len(input_text) < self._min_input_chars:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Input too short for language enforcement",
            )

        # Fast path: any non-allowed script ratio above threshold = disallowed.
        non_latin_findings = self._script_check(input_text)
        if non_latin_findings:
            primary_script, ratio = non_latin_findings[0]
            inferred_lang = _SCRIPT_TO_LANG.get(primary_script, "non-en")
            if inferred_lang not in self._allowed:
                return self._reject(
                    input_text=input_text,
                    lang=inferred_lang,
                    reason=f"Script {primary_script!r} suggests language {inferred_lang!r}",
                    confidence=min(0.95, 0.5 + ratio),
                )

        # Latin-script path: if langdetect is installed, use it. Otherwise
        # assume Latin script == English-compatible enough.
        if self._ensure_langdetect():
            from langdetect import DetectorFactory, LangDetectException, detect_langs

            DetectorFactory.seed = 0  # deterministic
            try:
                guesses = detect_langs(input_text)
                if not guesses:
                    return self._accept(input_text)
                top = guesses[0]
                top_lang = str(top.lang).lower()
                top_prob = float(top.prob)
                if top_lang in self._allowed:
                    return self._accept(input_text)
                if top_prob >= 0.75:
                    return self._reject(
                        input_text=input_text,
                        lang=top_lang,
                        reason=f"langdetect classified as {top_lang!r} (prob {top_prob:.2f})",
                        confidence=top_prob,
                    )
            except LangDetectException as exc:
                logger.debug("langdetect failed: %s", exc)

        return self._accept(input_text)

    def _script_check(self, text: str) -> list[tuple[str, float]]:
        """Return [(script_name, ratio), ...] sorted by ratio descending."""
        total = max(1, sum(1 for c in text if not c.isspace() and not c.isdigit()))
        findings: list[tuple[str, float]] = []
        for name, pat in self._compiled_scripts:
            count = len(pat.findall(text))
            if count == 0:
                continue
            ratio = count / total
            if ratio >= 0.15:  # script makes up at least 15% of non-ws chars
                findings.append((name, ratio))
        findings.sort(key=lambda x: -x[1])
        return findings

    def _accept(self, input_text: str) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            detected=False,
            confidence=0.0,
            severity=self.severity,
            explanation=f"Language allowed (allow-list: {list(self._allowed)})",
        )

    def _reject(
        self, *, input_text: str, lang: str, reason: str, confidence: float
    ) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=[
                MatchDetail(
                    pattern=f"language:{lang}",
                    matched_text=input_text[:80] + ("..." if len(input_text) > 80 else ""),
                    position=(0, len(input_text)),
                    description=reason,
                )
            ],
            explanation=(
                f"Detected language {lang!r} not in allow-list "
                f"{list(self._allowed)} — {reason}"
            ),
            metadata={"language": lang, "allowed_languages": list(self._allowed)},
        )
