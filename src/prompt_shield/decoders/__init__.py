"""Multi-encoding preprocessor.

Detects and decodes common payload encodings (base64, hex, URL, HTML entity,
ROT13) in a single pass. Detectors that need to inspect decoded variants
(d008, d009, d025) consume the decoded streams rather than re-implementing
detection.

Returns a DecodedSet — the original text plus a list of decoded candidates,
each annotated with the encoding that produced it. Detectors can iterate the
candidates and apply their patterns to each.
"""
from __future__ import annotations

from .preprocessor import DecodedCandidate, DecodedSet, MultiEncodingPreprocessor

__all__ = ["DecodedCandidate", "DecodedSet", "MultiEncodingPreprocessor"]
