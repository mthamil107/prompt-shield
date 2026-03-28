"""Invisible Unicode watermarking for system prompts."""

from __future__ import annotations

import hashlib
import hmac

# Unicode invisible characters used to encode watermark bits.
WATERMARK_CHARS = [
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # zero-width no-break space
]

# The set of all watermark characters, for fast lookup.
_WATERMARK_SET = frozenset(WATERMARK_CHARS)

# Number of invisible characters in a single watermark sequence.
_WATERMARK_LENGTH = 16


class CanaryWatermark:
    """Embeds and detects invisible Unicode watermarks in text.

    A deterministic sequence of zero-width Unicode characters is derived
    from *secret* using HMAC-SHA256.  The sequence is embedded between
    words at evenly-spaced positions, making it invisible to the naked
    eye but detectable programmatically.

    Parameters
    ----------
    secret:
        A shared secret used to generate the watermark sequence.
        Different secrets produce different watermarks.
    """

    def __init__(self, secret: str = "prompt-shield") -> None:
        self._secret = secret
        self._sequence = self._derive_sequence(secret)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def embed(self, text: str) -> str:
        """Embed an invisible watermark into *text*.

        The watermark sequence is inserted between words at positions
        determined by the secret so that the visible content is unchanged.

        Parameters
        ----------
        text:
            The text to watermark (e.g. a system prompt).

        Returns
        -------
        str
            The text with invisible watermark characters embedded.
        """
        words = text.split(" ")
        if len(words) < 2:
            # Not enough word boundaries; prepend the watermark.
            return self._sequence + text

        # Determine insertion positions evenly across word boundaries.
        n_gaps = len(words) - 1
        positions = self._insertion_positions(n_gaps)

        result_parts: list[str] = []
        seq_idx = 0
        for i, word in enumerate(words):
            result_parts.append(word)
            if i < n_gaps:
                if i in positions and seq_idx < len(self._sequence):
                    # Inject one watermark character at this gap.
                    result_parts.append(self._sequence[seq_idx])
                    seq_idx += 1
                result_parts.append(" ")

        # If the sequence wasn't fully placed (short text), append remainder.
        if seq_idx < len(self._sequence):
            result_parts.append(self._sequence[seq_idx:])

        return "".join(result_parts)

    def detect(self, text: str) -> bool:
        """Check whether the watermark is present in *text*.

        Detection succeeds when the full watermark character sequence
        appears in the text in order (not necessarily contiguous, but
        with each character appearing after the previous one).

        Parameters
        ----------
        text:
            The text to scan for the watermark.

        Returns
        -------
        bool
            ``True`` if the watermark is detected.
        """
        seq = self._sequence
        seq_idx = 0
        for ch in text:
            if seq_idx >= len(seq):
                break
            if ch == seq[seq_idx]:
                seq_idx += 1
        return seq_idx >= len(seq)

    def strip(self, text: str) -> str:
        """Remove all watermark characters from *text*.

        Parameters
        ----------
        text:
            The watermarked text.

        Returns
        -------
        str
            The text with all zero-width watermark characters removed.
        """
        return "".join(ch for ch in text if ch not in _WATERMARK_SET)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_sequence(secret: str) -> str:
        """Derive a deterministic watermark sequence from *secret*."""
        digest = hmac.new(
            secret.encode("utf-8"),
            b"canary-watermark-v1",
            hashlib.sha256,
        ).digest()

        chars: list[str] = []
        for byte in digest[:_WATERMARK_LENGTH]:
            chars.append(WATERMARK_CHARS[byte % len(WATERMARK_CHARS)])
        return "".join(chars)

    def _insertion_positions(self, n_gaps: int) -> set[int]:
        """Choose which word-boundary gaps to place watermark chars at."""
        needed = min(len(self._sequence), n_gaps)
        if needed <= 0:
            return set()
        if needed >= n_gaps:
            return set(range(n_gaps))
        # Spread evenly.
        step = n_gaps / needed
        return {int(i * step) for i in range(needed)}
