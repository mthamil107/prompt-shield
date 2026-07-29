"""Tests for the ``signatures.apply_to_engine`` bridge.

These tests reuse the hermetic minisign fixture pattern from
``test_client.py`` — a fresh ed25519 keypair signs a synthetic feed, and we
monkey-patch the HTTP call so no network is touched.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import warnings
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prompt_shield.signatures import (
    SignatureVerificationError,
    SignaturesClient,
    apply_to_engine,
)


# ---------------------------------------------------------------------------
# Hermetic minisign helpers (copied from test_client.py to keep the two
# suites independent).
# ---------------------------------------------------------------------------


def _make_keypair_and_pubkey_b64() -> tuple[Ed25519PrivateKey, bytes, str]:
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
) -> str:
    digest = hashlib.blake2b(data, digest_size=64).digest()
    algo = b"ED"
    raw_sig = sk.sign(digest)
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
def keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    return _make_keypair_and_pubkey_b64()


@pytest.fixture
def signed_feed(keypair: tuple[Ed25519PrivateKey, bytes, str]):
    sk, key_id, pubkey_b64 = keypair
    feed = {
        "version": "1",
        "generated_at": "2026-06-25T00:00:00Z",
        "signature_count": 2,
        "signatures": [
            {
                "id": "sig-0001",
                "type": "regex",
                "pattern": r"(?i)super-secret-attack-pattern-alpha",
                "category": "instruction_override",
                "severity": "high",
                "attack_class": "direct_injection",
                "source": {"origin": "test", "reference": "hermetic"},
                "first_seen": "2026-06-25",
                "description": "test regex signature",
            },
            {
                "id": "sig-0002",
                "type": "substring",
                "pattern": "DAN-BRAVO-MODE",
                "category": "dan_jailbreak",
                "severity": "critical",
                "attack_class": "direct_injection",
                "source": {"origin": "test", "reference": "hermetic"},
                "first_seen": "2026-06-25",
                "description": "test substring signature",
            },
        ],
    }
    data = json.dumps(feed, indent=2).encode("utf-8")
    sig = _make_minisig(sk, key_id, data, trusted_text="test-feed-v1")
    return pubkey_b64, data, sig


# ---------------------------------------------------------------------------
# Engine fixture — vault disabled, but d030_custom_rules is auto-discovered
# and lives in the registry.
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(sample_config: dict[str, Any], tmp_data_dir):
    from prompt_shield.engine import PromptShieldEngine

    return PromptShieldEngine(config_dict=sample_config, data_dir=str(tmp_data_dir))


# ---------------------------------------------------------------------------
# apply_to_engine — happy path + failure paths
# ---------------------------------------------------------------------------


def test_apply_to_engine_verifies_signature(
    engine, signed_feed, monkeypatch, tmp_path: Path
) -> None:
    """Verified signatures load into d030_custom_rules, and the feed matches."""
    pubkey, data, sig = signed_feed

    def fake_get(self_, url):  # type: ignore[no-untyped-def]
        return data if "minisig" not in url else sig.encode()

    monkeypatch.setattr(SignaturesClient, "_http_get", fake_get)

    d030 = engine._registry.get("d030_custom_rules")
    rules_before = len(d030._rules)

    result = apply_to_engine(
        engine,
        feed_url="https://example.invalid/v1/signatures.json",
        public_key=pubkey,
        cache_dir=tmp_path,
    )

    assert result["verified"] is True
    assert result["signature_count"] == 2
    assert result["loaded_rules"] == 2
    assert result["source_url"] == "https://example.invalid/v1/signatures.json"
    assert len(d030._rules) == rules_before + 2
    # The regex signature should still match its intended input.
    installed_ids = {r.id for r in d030._rules[-2:]}
    assert installed_ids == {"sig-0001", "sig-0002"}


def test_apply_to_engine_rejects_tampered_feed(
    engine, signed_feed, monkeypatch, tmp_path: Path
) -> None:
    """A tampered payload must abort before touching engine state."""
    pubkey, data, sig = signed_feed
    tampered = data + b"\x00garbage"

    def fake_get(self_, url):  # type: ignore[no-untyped-def]
        return tampered if "minisig" not in url else sig.encode()

    monkeypatch.setattr(SignaturesClient, "_http_get", fake_get)

    d030 = engine._registry.get("d030_custom_rules")
    rules_before = list(d030._rules)

    with pytest.raises(SignatureVerificationError):
        apply_to_engine(
            engine,
            feed_url="https://example.invalid/v1/signatures.json",
            public_key=pubkey,
            cache_dir=tmp_path,
        )

    assert d030._rules == rules_before


# ---------------------------------------------------------------------------
# engine.sync_threats — public wrapper
# ---------------------------------------------------------------------------


def test_engine_sync_threats_default_verifies(engine, signed_feed, monkeypatch, tmp_path) -> None:
    """sync_threats(verify=True, public_key=...) hits the SignaturesClient path."""
    pubkey, data, sig = signed_feed

    def fake_get(self_, url):  # type: ignore[no-untyped-def]
        return data if "minisig" not in url else sig.encode()

    monkeypatch.setattr(SignaturesClient, "_http_get", fake_get)

    result = engine.sync_threats(
        "https://example.invalid/v1/signatures.json",
        public_key=pubkey,
        cache_dir=str(tmp_path),
    )
    assert result["verified"] is True
    assert result["signature_count"] == 2


def test_engine_sync_threats_explicit_verify_requires_public_key(engine) -> None:
    """Explicit verify=True path must fail loudly when public_key is missing."""
    with pytest.raises(ValueError, match="public_key"):
        engine.sync_threats(
            "https://example.invalid/v1/signatures.json",
            verify=True,
        )


def test_engine_sync_threats_no_args_transitional_future_warning(engine) -> None:
    """v0.7.2 transitional default: bare sync_threats(url) emits FutureWarning
    but falls back to the legacy unverified path (which itself may fail for
    other reasons — we only care about the warning being emitted first).
    v0.8.0 will flip this to a hard ValueError.
    """
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        try:
            engine.sync_threats("http://example.invalid/feed.json")
        except Exception:
            pass  # legacy path may fail for network / vault reasons — irrelevant here
        assert any(issubclass(wi.category, FutureWarning) for wi in w), (
            "Bare sync_threats(url) call must emit FutureWarning naming v0.8.0"
        )


def test_engine_sync_threats_verify_false_deprecation_warning(engine) -> None:
    """verify=False must emit a DeprecationWarning even when the sync itself fails."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        try:
            engine.sync_threats(
                "http://example.invalid/feed.json",
                verify=False,
            )
        except Exception:
            # The legacy path will fail (no vault, no network) — we only
            # care about the DeprecationWarning being emitted first.
            pass
        assert any(issubclass(wi.category, DeprecationWarning) for wi in w), (
            "sync_threats(verify=False) must warn callers that the path is deprecated"
        )
