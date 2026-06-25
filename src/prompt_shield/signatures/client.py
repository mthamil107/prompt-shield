"""Pure-Python client for the prompt-shield-signatures federated feed.

This client fetches the published signatures.json file from a public CDN,
verifies its detached minisign signature against the maintainer's pinned
ed25519 public key, and returns the parsed signature entries.

No external binary dependency — verification is done in pure Python using
the ``cryptography`` library (already pulled in transitively).

Minisign signature format (https://jedisct1.github.io/minisign/):
    line 1: ``untrusted comment: <free text>``
    line 2: base64( 2-byte algo || 8-byte key_id || 64-byte ed25519_sig )
    line 3: ``trusted comment: <free text>``
    line 4: base64( ed25519_sig over (raw_sig || trusted_comment_text) )

Algo bytes:
    ``Ed`` (0x45 0x64) — PureEdDSA, signature over the raw message
    ``ED`` (0x45 0x44) — HashEdDSA, signature over BLAKE2b-512(message)

The published feed is signed with HashEdDSA (the minisign default), so we
implement that path; the PureEdDSA path is kept as a fallback for v0.7.0
when we migrate to Sigstore (which signs the raw digest).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger(__name__)

# Maintainer ed25519 public key for prompt-shield-signatures v1.
# Key ID: 31F125ADDE54B24A (generated 2026-06-24).
# To rotate, see https://github.com/mthamil107/prompt-shield-signatures/blob/main/THREAT-MODEL.md.
MAINTAINER_PUBLIC_KEY: str = "RWRKslTerSXxMfTgML57AMf7Hwu8djP7mYxdRFopQriPW4+9UG4zcdVi"

DEFAULT_FEED_URL: str = (
    "https://cdn.jsdelivr.net/gh/mthamil107/prompt-shield-signatures@main/v1/signatures.json"
)
DEFAULT_SIG_URL: str = (
    "https://cdn.jsdelivr.net/gh/mthamil107/prompt-shield-signatures"
    "@main/v1/signatures.json.minisig"
)

# Where we cache the last good feed so an offline client keeps working.
DEFAULT_CACHE_DIR: Path = Path.home() / ".cache" / "prompt-shield"
DEFAULT_CACHE_FILE: Path = DEFAULT_CACHE_DIR / "signatures.json"

_MINISIGN_ALGO_PURE = b"Ed"
_MINISIGN_ALGO_HASHED = b"ED"
_MINISIGN_PUBKEY_ALGO = b"Ed"


class SignatureVerificationError(Exception):
    """Raised when the fetched feed cannot be verified against the pinned key."""


@dataclass
class SignaturesUpdate:
    """Result of one fetch attempt against the federated feed."""

    success: bool
    signature_count: int = 0
    generated_at: str | None = None
    source: str = "skipped"  # "remote" | "cache" | "skipped" | "stale_cache"
    error: str | None = None
    signatures: list[dict[str, Any]] = field(default_factory=list)

    def __repr__(self) -> str:
        if self.success:
            return (
                f"SignaturesUpdate(success=True, signature_count={self.signature_count}, "
                f"source={self.source!r}, generated_at={self.generated_at!r})"
            )
        return f"SignaturesUpdate(success=False, source={self.source!r}, error={self.error!r})"


def _decode_pubkey(b64: str) -> tuple[bytes, bytes]:
    """Decode a minisign public key string into (key_id, ed25519_pk).

    Returns ``(key_id_8_bytes, ed25519_public_key_32_bytes)`` or raises
    ``SignatureVerificationError`` on malformed input.
    """
    try:
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
        raise SignatureVerificationError(f"invalid pubkey base64: {e}") from e
    if len(raw) != 42:
        raise SignatureVerificationError(f"pubkey must be 42 bytes (got {len(raw)})")
    if raw[0:2] != _MINISIGN_PUBKEY_ALGO:
        raise SignatureVerificationError(
            f"pubkey algo {raw[0:2]!r} != expected {_MINISIGN_PUBKEY_ALGO!r}"
        )
    return raw[2:10], raw[10:42]


def _parse_minisig(sig_text: str) -> tuple[bytes, bytes, bytes, bytes, str]:
    """Parse a minisign signature file.

    Returns:
        (algo, key_id, raw_signature, global_signature, trusted_comment_text)
    """
    lines = sig_text.strip().splitlines()
    if len(lines) < 4:
        raise SignatureVerificationError(
            f"minisign file must have at least 4 lines (got {len(lines)})"
        )

    if not lines[2].startswith("trusted comment: "):
        raise SignatureVerificationError("line 3 must start with 'trusted comment: '")
    trusted_text = lines[2][len("trusted comment: ") :]

    try:
        sig_bytes = base64.b64decode(lines[1], validate=True)
    except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
        raise SignatureVerificationError(f"line 2 not valid base64: {e}") from e
    if len(sig_bytes) != 74:
        raise SignatureVerificationError(f"line 2 must decode to 74 bytes (got {len(sig_bytes)})")
    algo = sig_bytes[0:2]
    key_id = sig_bytes[2:10]
    raw_signature = sig_bytes[10:74]

    try:
        global_sig = base64.b64decode(lines[3], validate=True)
    except (ValueError, base64.binascii.Error) as e:  # type: ignore[attr-defined]
        raise SignatureVerificationError(f"line 4 not valid base64: {e}") from e
    if len(global_sig) != 64:
        raise SignatureVerificationError(
            f"global signature must be 64 bytes (got {len(global_sig)})"
        )

    return algo, key_id, raw_signature, global_sig, trusted_text


def verify_minisign(
    data: bytes,
    sig_text: str,
    public_key: str = MAINTAINER_PUBLIC_KEY,
) -> str:
    """Verify a minisign signature against ``public_key``.

    Returns the trusted-comment text on success, or raises
    ``SignatureVerificationError`` on any failure.
    """
    pk_key_id, pk_ed25519 = _decode_pubkey(public_key)
    algo, sig_key_id, raw_sig, global_sig, trusted_text = _parse_minisig(sig_text)

    if sig_key_id != pk_key_id:
        raise SignatureVerificationError(
            f"key_id mismatch: signature {sig_key_id.hex().upper()} "
            f"vs pubkey {pk_key_id.hex().upper()}"
        )

    if algo == _MINISIGN_ALGO_HASHED:
        message = hashlib.blake2b(data, digest_size=64).digest()
    elif algo == _MINISIGN_ALGO_PURE:
        message = data
    else:
        raise SignatureVerificationError(
            f"unknown signature algo {algo!r} (expected b'Ed' or b'ED')"
        )

    pk = Ed25519PublicKey.from_public_bytes(pk_ed25519)
    try:
        pk.verify(raw_sig, message)
    except InvalidSignature as e:
        raise SignatureVerificationError("data signature invalid") from e

    # Global signature is over the raw signature bytes || trusted_comment_text.
    # We use latin-1 here so that whatever bytes the maintainer's signing tool
    # wrote into the .minisig file are reproduced verbatim — minisign treats
    # the trusted comment as opaque bytes, not a Unicode string.
    global_message = raw_sig + trusted_text.encode("latin-1")
    try:
        pk.verify(global_sig, global_message)
    except InvalidSignature as e:
        raise SignatureVerificationError("global signature invalid") from e

    return trusted_text


class SignaturesClient:
    """Fetch, verify, and cache the prompt-shield-signatures feed.

    Typical usage::

        client = SignaturesClient()
        update = client.fetch()
        if update.success:
            # update.signatures is a list[dict] with the verified entries
            ...

    All network operations have a hard timeout (``timeout`` seconds, default
    10s). On verification failure the cache is NOT updated. On network failure
    the most recent verified cache is returned with ``source="cache"``.
    """

    def __init__(
        self,
        feed_url: str = DEFAULT_FEED_URL,
        sig_url: str = DEFAULT_SIG_URL,
        public_key: str = MAINTAINER_PUBLIC_KEY,
        cache_file: Path | str | None = None,
        timeout: float = 10.0,
        min_fetch_interval_seconds: float = 60.0,
    ) -> None:
        self.feed_url = feed_url
        self.sig_url = sig_url
        self.public_key = public_key
        self.cache_file = Path(cache_file) if cache_file else DEFAULT_CACHE_FILE
        self.timeout = timeout
        self.min_fetch_interval_seconds = min_fetch_interval_seconds
        self._last_fetch_attempt: float = 0.0

    def fetch(self, *, force: bool = False) -> SignaturesUpdate:
        """Fetch the feed, verify the signature, return parsed entries.

        Returns ``SignaturesUpdate`` with ``source`` indicating whether the
        result came from the network (``"remote"``), the local cache
        (``"cache"`` on network failure, ``"stale_cache"`` if forced re-use),
        or was skipped due to throttling (``"skipped"``).
        """
        now = time.monotonic()
        if not force and (now - self._last_fetch_attempt) < self.min_fetch_interval_seconds:
            cached = self._read_cache()
            return (
                cached
                if cached.success
                else SignaturesUpdate(
                    success=False,
                    source="skipped",
                    error=(f"throttled (last attempt < {self.min_fetch_interval_seconds}s ago)"),
                )
            )
        self._last_fetch_attempt = now

        try:
            data = self._http_get(self.feed_url)
            # latin-1 round-trips every byte 0-255, so non-UTF-8 trusted
            # comments (e.g., a maintainer's shell pasted a cp1252 em-dash)
            # don't break parsing. The verification math is on raw bytes
            # anyway — only the layout is text.
            sig_text = self._http_get(self.sig_url).decode("latin-1")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning("Signatures feed unreachable (%s); falling back to cache", e)
            cached = self._read_cache()
            if cached.success:
                cached.source = "cache"
                cached.error = f"remote fetch failed: {e}"
                return cached
            return SignaturesUpdate(
                success=False,
                source="cache",
                error=f"remote unreachable and no cache: {e}",
            )

        try:
            verify_minisign(data, sig_text, self.public_key)
        except SignatureVerificationError as e:
            logger.error("Signature verification FAILED: %s", e)
            cached = self._read_cache()
            if cached.success:
                cached.source = "cache"
                cached.error = f"verification failed; using last good cache: {e}"
                return cached
            return SignaturesUpdate(
                success=False,
                source="remote",
                error=f"verification failed and no cache: {e}",
            )

        try:
            parsed = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return SignaturesUpdate(
                success=False,
                source="remote",
                error=f"feed is valid signature but invalid JSON: {e}",
            )

        signatures = parsed.get("signatures", [])
        if not isinstance(signatures, list):
            return SignaturesUpdate(
                success=False,
                source="remote",
                error="feed.signatures is not a list",
            )

        self._write_cache(data)

        return SignaturesUpdate(
            success=True,
            signature_count=len(signatures),
            generated_at=parsed.get("generated_at"),
            source="remote",
            signatures=signatures,
        )

    def _http_get(self, url: str) -> bytes:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "prompt-shield-signatures-client/1.0"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data: bytes = resp.read()
            return data

    def _read_cache(self) -> SignaturesUpdate:
        if not self.cache_file.exists():
            return SignaturesUpdate(success=False, source="cache", error="no cache")
        try:
            with self.cache_file.open("rb") as f:
                data = f.read()
            parsed = json.loads(data.decode("utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            return SignaturesUpdate(
                success=False,
                source="cache",
                error=f"cache unreadable: {e}",
            )
        signatures = parsed.get("signatures", [])
        if not isinstance(signatures, list):
            return SignaturesUpdate(success=False, source="cache", error="cache shape invalid")
        return SignaturesUpdate(
            success=True,
            signature_count=len(signatures),
            generated_at=parsed.get("generated_at"),
            source="cache",
            signatures=signatures,
        )

    def _write_cache(self, data: bytes) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_file.with_suffix(self.cache_file.suffix + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(self.cache_file)
        except OSError as e:
            logger.warning("Could not write signature cache: %s", e)
