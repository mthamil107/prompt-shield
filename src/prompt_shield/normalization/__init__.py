"""Text normalization pipeline applied BEFORE detector dispatch.

The normalizer addresses a class of evasion attacks that bypass individual
detectors by inserting zero-width characters, mixing scripts (Cyrillic
homoglyphs), or scattering whitespace through attack keywords. Rather than
making every detector handle these variants, we normalize once at the engine
level and detectors operate on cleaned text.

Detectors that NEED the raw input (d010 unicode homoglyph, d011 whitespace
injection, d020 token smuggling) receive the original via context, while
the standard `input_text` argument to .detect() carries the normalized form.

Pipeline stages (applied in order):
1. Unicode NFKC normalization (collapse compatibility characters)
2. Zero-width character stripping (U+200B, U+200C, U+200D, U+FEFF, etc.)
3. Cyrillic→Latin homoglyph mapping
4. Whitespace collapse (collapse multiple spaces, trim)

Disabled by default to preserve backward compatibility; opt-in via the
`normalization.enabled` config flag.
"""

from __future__ import annotations

from .pipeline import NormalizationPipeline, NormalizationResult

__all__ = ["NormalizationPipeline", "NormalizationResult"]
