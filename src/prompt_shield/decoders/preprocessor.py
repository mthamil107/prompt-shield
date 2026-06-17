"""Multi-encoding preprocessor implementation."""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import unquote

Encoding = Literal["base64", "hex", "url", "html_entity", "rot13"]

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){6,})(?![0-9a-fA-F])")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);")
_ROT13_HINT_RE = re.compile(r"\b[a-zA-Z]{7,}\b")


@dataclass(frozen=True)
class DecodedCandidate:
    """A successfully decoded substring from the input."""

    text: str
    encoding: Encoding
    span: tuple[int, int]
    """Start/end character positions in the original input where the encoded
    substring was found. Detectors can use this for accurate match reporting."""


@dataclass(frozen=True)
class DecodedSet:
    """The result of running the preprocessor over a text input."""

    original: str
    candidates: tuple[DecodedCandidate, ...] = field(default_factory=tuple)

    def for_encoding(self, encoding: Encoding) -> tuple[DecodedCandidate, ...]:
        return tuple(c for c in self.candidates if c.encoding == encoding)

    @property
    def has_any(self) -> bool:
        return len(self.candidates) > 0


class MultiEncodingPreprocessor:
    """Detect and decode common encodings in a single pass.

    Stages run independently — a payload encoded with base64-of-hex will
    produce both a base64 candidate (the outer layer) and, if the base64
    decode happens to contain hex, a hex candidate too. Detectors decide
    how to interpret nested encodings.
    """

    def __init__(
        self,
        *,
        decode_base64: bool = True,
        decode_hex: bool = True,
        decode_url: bool = True,
        decode_html_entities: bool = True,
        decode_rot13: bool = False,
        min_decoded_length: int = 8,
    ) -> None:
        self.decode_base64 = decode_base64
        self.decode_hex = decode_hex
        self.decode_url = decode_url
        self.decode_html_entities = decode_html_entities
        self.decode_rot13 = decode_rot13
        self.min_decoded_length = min_decoded_length

    def preprocess(self, text: str) -> DecodedSet:
        if not isinstance(text, str) or not text:
            return DecodedSet(original=text)

        out: list[DecodedCandidate] = []

        if self.decode_base64:
            out.extend(self._decode_base64(text))
        if self.decode_hex:
            out.extend(self._decode_hex(text))
        if self.decode_url:
            out.extend(self._decode_url(text))
        if self.decode_html_entities:
            out.extend(self._decode_html_entities(text))
        if self.decode_rot13:
            out.extend(self._decode_rot13(text))

        return DecodedSet(original=text, candidates=tuple(out))

    # -----------------------------------------------------------------------
    # Stage implementations
    # -----------------------------------------------------------------------

    def _decode_base64(self, text: str) -> list[DecodedCandidate]:
        out: list[DecodedCandidate] = []
        for m in _BASE64_RE.finditer(text):
            chunk = m.group(1)
            try:
                decoded = base64.b64decode(chunk, validate=True).decode("utf-8", errors="strict")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if len(decoded) >= self.min_decoded_length and decoded.isprintable():
                out.append(
                    DecodedCandidate(
                        text=decoded,
                        encoding="base64",
                        span=(m.start(), m.end()),
                    )
                )
        return out

    def _decode_hex(self, text: str) -> list[DecodedCandidate]:
        out: list[DecodedCandidate] = []
        for m in _HEX_RE.finditer(text):
            chunk = m.group(1)
            try:
                decoded = bytes.fromhex(chunk).decode("utf-8", errors="strict")
            except (ValueError, UnicodeDecodeError):
                continue
            if len(decoded) >= self.min_decoded_length and decoded.isprintable():
                out.append(
                    DecodedCandidate(
                        text=decoded,
                        encoding="hex",
                        span=(m.start(), m.end()),
                    )
                )
        return out

    def _decode_url(self, text: str) -> list[DecodedCandidate]:
        out: list[DecodedCandidate] = []
        for m in _URL_ENCODED_RE.finditer(text):
            chunk = m.group()
            decoded = unquote(chunk)
            if decoded != chunk and len(decoded) >= self.min_decoded_length // 3:
                out.append(
                    DecodedCandidate(
                        text=decoded,
                        encoding="url",
                        span=(m.start(), m.end()),
                    )
                )
        return out

    def _decode_html_entities(self, text: str) -> list[DecodedCandidate]:
        if not _HTML_ENTITY_RE.search(text):
            return []
        decoded = html.unescape(text)
        if decoded == text:
            return []
        return [
            DecodedCandidate(
                text=decoded,
                encoding="html_entity",
                span=(0, len(text)),
            )
        ]

    def _decode_rot13(self, text: str) -> list[DecodedCandidate]:
        # ROT13 has weak signals; only attempt full-text rot13 if the
        # original contains many long lowercase-only words (a heuristic
        # that ROT13 was applied to the whole input).
        long_words = _ROT13_HINT_RE.findall(text)
        if len(long_words) < 2:
            return []
        try:
            decoded = codecs.decode(text, "rot_13")
        except Exception:
            return []
        if decoded != text:
            return [
                DecodedCandidate(
                    text=decoded,
                    encoding="rot13",
                    span=(0, len(text)),
                )
            ]
        return []

    # -----------------------------------------------------------------------
    # Convenience
    # -----------------------------------------------------------------------

    @classmethod
    def from_config(cls, config: dict[str, object]) -> MultiEncodingPreprocessor:
        def as_bool(key: str, default: bool) -> bool:
            v = config.get(key, default)
            return bool(v) if isinstance(v, (bool, int)) else default

        def as_int(key: str, default: int) -> int:
            v = config.get(key, default)
            return int(v) if isinstance(v, (int, float, str)) else default

        return cls(
            decode_base64=as_bool("decode_base64", True),
            decode_hex=as_bool("decode_hex", True),
            decode_url=as_bool("decode_url", True),
            decode_html_entities=as_bool("decode_html_entities", True),
            decode_rot13=as_bool("decode_rot13", False),
            min_decoded_length=as_int("min_decoded_length", 8),
        )
