"""Text normalization pipeline implementation."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Zero-width and invisible control characters commonly used in token smuggling.
_ZERO_WIDTH_CHARS = (
    "​"  # ZERO WIDTH SPACE
    "‌"  # ZERO WIDTH NON-JOINER
    "‍"  # ZERO WIDTH JOINER
    "⁠"  # WORD JOINER
    "﻿"  # ZERO WIDTH NO-BREAK SPACE
    "­"  # SOFT HYPHEN
    "͏"  # COMBINING GRAPHEME JOINER
    "⁡"  # FUNCTION APPLICATION
    "⁢"  # INVISIBLE TIMES
    "⁣"  # INVISIBLE SEPARATOR
    "⁤"  # INVISIBLE PLUS
)
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH_CHARS}]")
_WHITESPACE_RUN_RE = re.compile(r"[ \t]{2,}")

# Cyrillic letters that visually match Latin letters in many fonts.
_CYRILLIC_TO_LATIN = {
    "а": "a",
    "А": "A",  # CYRILLIC SMALL/CAPITAL LETTER A
    "е": "e",
    "Е": "E",  # E
    "о": "o",
    "О": "O",  # O
    "р": "p",
    "Р": "P",  # ER
    "с": "c",
    "С": "C",  # ES
    "х": "x",
    "Х": "X",  # HA
    "у": "y",
    "У": "Y",  # U
    "ұ": "h",
    "Ұ": "H",  # STRAIGHT U → loosely h/H
    "і": "i",
    "І": "I",  # BYELORUSSIAN-UKRAINIAN I
    "ј": "j",
    "Ј": "J",  # JE
    "к": "k",
    "К": "K",  # KA
    "м": "m",
    "М": "M",  # EM
    "н": "n",
    "Н": "H",  # EN → looks like H in capital
    "в": "v",
    "В": "B",  # VE → looks like B capital
    "т": "t",
    "Т": "T",  # TE
    "б": "b",
    "Б": "B",  # BE
}


@dataclass(frozen=True)
class NormalizationResult:
    """The output of running the normalization pipeline on a text input."""

    text: str
    """The normalized text — what detectors that don't need raw input will see."""

    original: str
    """The original text — preserved for detectors that need the raw form."""

    changes: tuple[str, ...]
    """Names of stages that actually modified the text. Useful for diagnostics."""

    @property
    def modified(self) -> bool:
        return len(self.changes) > 0


class NormalizationPipeline:
    """Run a configurable text normalization pipeline before detector dispatch.

    All stages are idempotent: running the pipeline twice produces the same
    result as running it once. This guarantees that downstream re-normalization
    (e.g. inside a chained detector) is a no-op.
    """

    def __init__(
        self,
        *,
        nfkc: bool = True,
        strip_zero_width: bool = True,
        homoglyph_map: bool = True,
        collapse_whitespace: bool = True,
    ) -> None:
        self.nfkc = nfkc
        self.strip_zero_width = strip_zero_width
        self.homoglyph_map = homoglyph_map
        self.collapse_whitespace = collapse_whitespace

    def normalize(self, text: str) -> NormalizationResult:
        """Apply all enabled stages to `text` and return the result."""
        if not isinstance(text, str):
            return NormalizationResult(text=text, original=text, changes=())

        original = text
        changes: list[str] = []

        if self.nfkc:
            after = unicodedata.normalize("NFKC", text)
            if after != text:
                changes.append("nfkc")
                text = after

        if self.strip_zero_width:
            after = _ZERO_WIDTH_RE.sub("", text)
            if after != text:
                changes.append("zero_width")
                text = after

        if self.homoglyph_map:
            after = text.translate(str.maketrans(_CYRILLIC_TO_LATIN))  # type: ignore[arg-type]
            if after != text:
                changes.append("homoglyph")
                text = after

        if self.collapse_whitespace:
            after = _WHITESPACE_RUN_RE.sub(" ", text).strip()
            if after != text:
                changes.append("whitespace")
                text = after

        return NormalizationResult(text=text, original=original, changes=tuple(changes))

    @classmethod
    def from_config(cls, config: dict[str, object]) -> NormalizationPipeline:
        """Build a pipeline from a `normalization` config block."""

        def as_bool(key: str, default: bool) -> bool:
            v = config.get(key, default)
            return bool(v) if isinstance(v, (bool, int)) else default

        return cls(
            nfkc=as_bool("nfkc", True),
            strip_zero_width=as_bool("strip_zero_width", True),
            homoglyph_map=as_bool("homoglyph_map", True),
            collapse_whitespace=as_bool("collapse_whitespace", True),
        )
