"""Tests for the prompt-shield-signatures federated-feed client.

These tests use a hermetic minisign signature generated against a fresh
ed25519 keypair (no network, no binary dependency). The signature is
hand-built using Python's ``cryptography`` library to match the on-the-wire
minisign format, which is what the real feed uses.

A separate integration test fetches the actual published feed and verifies
the maintainer's pinned key. That test is marked with ``pytest.mark.network``
and is skipped by default in CI.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prompt_shield.signatures import SignaturesClient, SignatureVerificationError
from prompt_shield.signatures.client import (
    MAINTAINER_PUBLIC_KEY,
    _decode_pubkey,
    _parse_minisig,
    verify_minisign,
)

if TYPE_CHECKING:
    from pathlib import Path


def _make_keypair_and_pubkey_b64() -> tuple[Ed25519PrivateKey, bytes, str]:
    """Generate an ed25519 keypair and a minisign-formatted base64 pubkey."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes_raw()
    key_id = os.urandom(8)
    pk_blob = b"Ed" + key_id + pk_bytes
    return sk, key_id, base64.b64encode(pk_blob).decode("ascii")


def _make_minisig(
    sk: Ed25519PrivateKey,
    key_id: bytes,
    data: bytes,
    trusted_text: str = "test",
    hashed: bool = True,
) -> str:
    """Build a minisign signature file for ``data`` using ``sk``."""
    if hashed:
        digest = hashlib.blake2b(data, digest_size=64).digest()
        algo = b"ED"
        message = digest
    else:
        algo = b"Ed"
        message = data

    raw_sig = sk.sign(message)  # 64 bytes ed25519
    sig_blob = algo + key_id + raw_sig
    line2 = base64.b64encode(sig_blob).decode("ascii")

    global_message = raw_sig + trusted_text.encode("utf-8")
    global_sig = sk.sign(global_message)
    line4 = base64.b64encode(global_sig).decode("ascii")

    return (
        f"untrusted comment: hermetic test signature\n"
        f"{line2}\n"
        f"trusted comment: {trusted_text}\n"
        f"{line4}\n"
    )


@pytest.fixture
def keypair():
    return _make_keypair_and_pubkey_b64()


@pytest.fixture
def signed_feed(keypair):
    sk, key_id, pubkey_b64 = keypair
    feed = {
        "$schema": "https://example.invalid/schema",
        "version": "1",
        "generated_at": "2026-06-25T00:00:00Z",
        "signature_count": 2,
        "signatures": [
            {
                "id": "sig-0001",
                "type": "regex",
                "pattern": "(?i)ignore previous instructions",
                "category": "instruction_override",
                "severity": "high",
                "attack_class": "direct_injection",
                "source": {"origin": "test", "reference": "hermetic"},
                "first_seen": "2026-06-25",
                "description": "test entry 1",
            },
            {
                "id": "sig-0002",
                "type": "substring",
                "pattern": "DAN MODE",
                "category": "dan_jailbreak",
                "severity": "critical",
                "attack_class": "direct_injection",
                "source": {"origin": "test", "reference": "hermetic"},
                "first_seen": "2026-06-25",
                "description": "test entry 2",
            },
        ],
    }
    data = json.dumps(feed, indent=2).encode("utf-8")
    sig = _make_minisig(sk, key_id, data, trusted_text="test-feed-v1")
    return pubkey_b64, data, sig


# ---------------------------------------------------------------------------
# Hermetic verification primitives
# ---------------------------------------------------------------------------


class TestParsing:
    def test_decode_pubkey_round_trip(self, keypair):
        _sk, key_id, pubkey_b64 = keypair
        decoded_id, decoded_pk = _decode_pubkey(pubkey_b64)
        assert decoded_id == key_id
        assert len(decoded_pk) == 32

    def test_decode_pubkey_rejects_wrong_length(self):
        with pytest.raises(SignatureVerificationError, match="42 bytes"):
            _decode_pubkey(base64.b64encode(b"Ed" + b"\x00" * 10).decode())

    def test_decode_pubkey_rejects_wrong_algo(self):
        bad = base64.b64encode(b"XX" + b"\x00" * 40).decode()
        with pytest.raises(SignatureVerificationError, match="pubkey algo"):
            _decode_pubkey(bad)

    def test_parse_minisig_round_trip(self, signed_feed):
        _pk, _data, sig = signed_feed
        algo, key_id, raw_sig, global_sig, trusted = _parse_minisig(sig)
        assert algo == b"ED"
        assert len(key_id) == 8
        assert len(raw_sig) == 64
        assert len(global_sig) == 64
        assert trusted == "test-feed-v1"

    def test_parse_minisig_too_few_lines(self):
        with pytest.raises(SignatureVerificationError, match="at least 4 lines"):
            _parse_minisig("untrusted comment: x\nabcd==\ntrusted comment: x\n")

    def test_parse_minisig_missing_trusted(self, signed_feed):
        _pk, _data, sig = signed_feed
        # Replace the trusted-comment line with something invalid
        lines = sig.splitlines()
        lines[2] = "bogus line"
        with pytest.raises(SignatureVerificationError, match="trusted comment"):
            _parse_minisig("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# verify_minisign — happy path + adversarial paths
# ---------------------------------------------------------------------------


class TestVerify:
    def test_valid_signature_accepted(self, signed_feed):
        pubkey, data, sig = signed_feed
        trusted = verify_minisign(data, sig, public_key=pubkey)
        assert trusted == "test-feed-v1"

    def test_pure_ed_path_also_works(self, keypair):
        sk, key_id, pubkey_b64 = keypair
        data = b"hello world"
        sig = _make_minisig(sk, key_id, data, hashed=False)
        verify_minisign(data, sig, public_key=pubkey_b64)

    def test_tampered_payload_rejected(self, signed_feed):
        pubkey, data, sig = signed_feed
        tampered = data + b"\x00"
        with pytest.raises(SignatureVerificationError, match="data signature"):
            verify_minisign(tampered, sig, public_key=pubkey)

    def test_wrong_pubkey_rejected(self, signed_feed):
        _pubkey, data, sig = signed_feed
        _other_sk, _other_id, other_pubkey = _make_keypair_and_pubkey_b64()
        with pytest.raises(SignatureVerificationError, match="key_id mismatch"):
            verify_minisign(data, sig, public_key=other_pubkey)

    def test_tampered_trusted_comment_rejected(self, signed_feed):
        pubkey, data, sig = signed_feed
        lines = sig.splitlines()
        lines[2] = "trusted comment: i-am-evil"
        bad_sig = "\n".join(lines) + "\n"
        with pytest.raises(SignatureVerificationError, match="global signature"):
            verify_minisign(data, bad_sig, public_key=pubkey)


# ---------------------------------------------------------------------------
# SignaturesClient — local cache + offline fallback
# ---------------------------------------------------------------------------


class TestClientLocal:
    def test_fetch_succeeds_via_mocked_http(self, monkeypatch, signed_feed, tmp_path: Path):
        pubkey, data, sig = signed_feed
        cache = tmp_path / "sigs.json"

        client = SignaturesClient(
            public_key=pubkey,
            cache_file=cache,
            min_fetch_interval_seconds=0,
        )

        def fake_get(self_, url):  # type: ignore[no-untyped-def]
            return data if "json" in url and "minisig" not in url else sig.encode()

        monkeypatch.setattr(SignaturesClient, "_http_get", fake_get)

        update = client.fetch()
        assert update.success is True
        assert update.source == "remote"
        assert update.signature_count == 2
        assert update.generated_at == "2026-06-25T00:00:00Z"
        assert cache.exists()

    def test_cached_fallback_on_network_failure(self, monkeypatch, signed_feed, tmp_path: Path):
        pubkey, data, _ = signed_feed
        cache = tmp_path / "sigs.json"
        cache.write_bytes(data)

        client = SignaturesClient(
            public_key=pubkey,
            cache_file=cache,
            min_fetch_interval_seconds=0,
        )

        def boom(self_, url):  # type: ignore[no-untyped-def]
            raise OSError("network down")

        monkeypatch.setattr(SignaturesClient, "_http_get", boom)

        update = client.fetch()
        assert update.success is True
        assert update.source == "cache"
        assert update.signature_count == 2
        assert "network down" in (update.error or "")

    def test_verification_failure_does_not_corrupt_cache(
        self, monkeypatch, signed_feed, tmp_path: Path
    ):
        pubkey, data, _ = signed_feed
        cache = tmp_path / "sigs.json"
        cache.write_bytes(data)  # seed with the known-good payload
        good_mtime = cache.stat().st_mtime

        forged_sig_line = base64.b64encode(b"ED" + b"\x00" * 72).decode()
        forged_global_line = base64.b64encode(b"\x00" * 64).decode()
        bad_sig = (
            "untrusted comment: forged\n"
            f"{forged_sig_line}\n"
            "trusted comment: forged\n"
            f"{forged_global_line}\n"
        )

        client = SignaturesClient(
            public_key=pubkey,
            cache_file=cache,
            min_fetch_interval_seconds=0,
        )

        def serve(self_, url):  # type: ignore[no-untyped-def]
            return data if "minisig" not in url else bad_sig.encode()

        monkeypatch.setattr(SignaturesClient, "_http_get", serve)
        update = client.fetch()
        # We expect verification to fail; client must fall back to the existing
        # cache rather than overwriting it with the unverified payload.
        assert update.success is True  # cache was good
        assert update.source == "cache"
        assert "verification failed" in (update.error or "").lower()
        assert cache.stat().st_mtime == pytest.approx(good_mtime, abs=2)

    def test_no_remote_and_no_cache_returns_failure(self, monkeypatch, tmp_path: Path):
        client = SignaturesClient(
            cache_file=tmp_path / "missing.json",
            min_fetch_interval_seconds=0,
        )

        def boom(self_, url):  # type: ignore[no-untyped-def]
            raise OSError("offline")

        monkeypatch.setattr(SignaturesClient, "_http_get", boom)
        update = client.fetch()
        assert update.success is False
        assert "offline" in (update.error or "").lower()


class TestPinnedKeyShape:
    def test_pinned_public_key_decodes(self):
        # Just confirm the constant we ship in source is a valid pubkey blob.
        key_id, ed25519_pk = _decode_pubkey(MAINTAINER_PUBLIC_KEY)
        assert len(key_id) == 8
        assert len(ed25519_pk) == 32


# ---------------------------------------------------------------------------
# Live network test — disabled by default
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("PROMPT_SHIELD_TEST_LIVE_FEED") != "1",
    reason="Set PROMPT_SHIELD_TEST_LIVE_FEED=1 to hit the real CDN.",
)
def test_fetch_real_feed():
    """End-to-end test against the actually-published feed.

    Skipped by default to keep CI hermetic. To run::

        PROMPT_SHIELD_TEST_LIVE_FEED=1 pytest tests/signatures/ -k real_feed
    """
    client = SignaturesClient(min_fetch_interval_seconds=0)
    update = client.fetch()
    assert update.success is True, update.error
    assert update.signature_count >= 50
    assert update.source in {"remote", "cache"}
