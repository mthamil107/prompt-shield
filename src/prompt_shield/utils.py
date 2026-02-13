"""Shared utilities for prompt-shield."""

from __future__ import annotations

import hashlib
import unicodedata

import regex

# Mapping of common homoglyph characters to their ASCII equivalents
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u0406": "I", "\u041a": "K", "\u041c": "M",
    "\u041e": "O", "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0455": "s", "\u0458": "j",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p",
    # Fullwidth
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
    "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
    "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
    "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
    "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
    "\uff39": "Y", "\uff3a": "Z",
}

# Zero-width and invisible characters
INVISIBLE_CHARS: set[str] = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u00ad",  # Soft hyphen
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\u180e",  # Mongolian vowel separator
    "\u034f",  # Combining grapheme joiner
}


def sha256_hash(text: str) -> str:
    """Compute SHA-256 hash of text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    """Normalize text by replacing homoglyphs, stripping invisible chars, and lowercasing."""
    result = []
    for char in text:
        if char in INVISIBLE_CHARS:
            continue
        mapped = _HOMOGLYPH_MAP.get(char)
        if mapped:
            result.append(mapped)
        else:
            result.append(char)
    normalized = "".join(result)
    normalized = unicodedata.normalize("NFKC", normalized)
    return normalized.lower()


def strip_invisible(text: str) -> str:
    """Remove all invisible/zero-width characters from text."""
    return "".join(c for c in text if c not in INVISIBLE_CHARS)


def has_mixed_scripts(text: str) -> bool:
    """Check if text contains characters from multiple Unicode scripts in the same word."""
    words = regex.findall(r"\w+", text)
    for word in words:
        scripts: set[str] = set()
        for char in word:
            cat = unicodedata.category(char)
            if cat.startswith("L"):
                try:
                    script = unicodedata.name(char).split()[0]
                    scripts.add(script)
                except ValueError:
                    pass
        if len(scripts) > 1:
            return True
    return False


def decode_base64_safe(text: str) -> str | None:
    """Attempt to decode base64 text. Returns decoded string or None."""
    import base64

    cleaned = text.strip()
    # Must be at least 4 chars and have valid base64 chars
    if len(cleaned) < 4:
        return None
    try:
        # Add padding if needed
        padding = 4 - len(cleaned) % 4
        if padding != 4:
            cleaned += "=" * padding
        decoded = base64.b64decode(cleaned, validate=True)
        return decoded.decode("utf-8", errors="strict")
    except Exception:
        return None


def decode_rot13(text: str) -> str:
    """Apply ROT13 decoding to text."""
    import codecs

    return codecs.decode(text, "rot_13")
