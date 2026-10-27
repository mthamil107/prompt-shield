"""Tests for the JWS/JWT capability-receipt adapter."""

from __future__ import annotations

import base64
import json
import time

import pytest

from prompt_shield.capabilities import ReceiptVerificationError
from prompt_shield.capabilities.jws import JWSAdapter

jwt = pytest.importorskip("jwt", reason="PyJWT not installed")

SECRET = "test-secret-do-not-use-in-production"


def _make_token(**claims: object) -> str:
    payload: dict[str, object] = {
        "tool_name": "read_email",
        "iss": "test-orchestrator",
        "exp": int(time.time()) + 300,
    }
    payload.update(claims)
    return jwt.encode(payload, SECRET, algorithm="HS256")


def _b64url(obj: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class TestHappyPath:
    def test_valid_matching_token_returns_trusted(self):
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(_make_token(), tool_name="read_email")
        assert result.trusted is True
        assert result.adapter_name == "jws"
        assert result.issuer == "test-orchestrator"
        assert result.expires_at is not None
        assert result.policy_violations == []


class TestTamper:
    def test_bad_signature_returns_untrusted(self):
        token = _make_token()
        adapter = JWSAdapter(verification_key="different-secret", algorithms=("HS256",))
        result = adapter.verify(token, tool_name="read_email")
        assert result.trusted is False
        assert "signature invalid" in result.reason

    def test_alg_none_is_rejected(self):
        """Build a real alg=none token and confirm the adapter rejects it.

        The prior test with the same name never built an alg=none token —
        it round-tripped a normal HS256 token and asserted True. Fable
        called it 'happy-path test wearing an attack's name.'
        """
        header = _b64url({"alg": "none", "typ": "JWT"})
        payload = _b64url({"tool_name": "x", "exp": int(time.time()) + 60})
        alg_none_token = f"{header}.{payload}."  # empty signature segment
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(alg_none_token, tool_name="x")
        assert result.trusted is False, "alg=none must be rejected on any allowlist"
        assert "invalid" in result.reason.lower() or "signature" in result.reason.lower()

    def test_algorithm_confusion_rsa_pubkey_as_hmac_secret_rejected(self):
        """RSA-shaped PEM used as HS256 secret must not crash — must return untrusted.

        F2: this used to raise jwt.InvalidKeyError (a PyJWTError but NOT
        an InvalidTokenError) and escape scan() as a crash.
        """
        rsa_like_pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "\n-----END PUBLIC KEY-----"
        )
        # Sign an HS256 token with the PEM as the "secret".
        header = _b64url({"alg": "HS256", "typ": "JWT"})
        payload = _b64url({"tool_name": "x", "exp": int(time.time()) + 60})
        # PyJWT will refuse to accept a PEM-shaped key as HMAC secret at
        # decode time — the adapter must handle that as trusted=False,
        # not crash.
        forged = f"{header}.{payload}.deadbeef"
        adapter = JWSAdapter(verification_key=rsa_like_pem, algorithms=("HS256",))
        result = adapter.verify(forged, tool_name="x")
        assert result.trusted is False
        # Whatever specific PyJWT error came out, it should be flattened
        # to "invalid" — no crash escaped.
        assert "invalid" in result.reason.lower() or "signature" in result.reason.lower()

    def test_non_utf8_bytes_return_untrusted_not_crash(self):
        """F2: non-UTF-8 receipt bytes must not raise UnicodeDecodeError."""
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(b"\xff\xfe not utf8", tool_name="x")
        assert result.trusted is False
        assert "UTF-8" in result.reason or "utf" in result.reason.lower()


class TestExpiry:
    def test_expired_token_returns_untrusted(self):
        token = _make_token(exp=int(time.time()) - 10)
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(token, tool_name="read_email")
        assert result.trusted is False
        assert "expired" in result.reason.lower()

    def test_missing_exp_rejected_by_default(self):
        token = jwt.encode({"tool_name": "x"}, SECRET, algorithm="HS256")
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(token, tool_name="x")
        assert result.trusted is False


class TestBinding:
    def test_tool_name_mismatch_returns_untrusted(self):
        token = _make_token(tool_name="send_email")
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(token, tool_name="read_email")
        assert result.trusted is False
        assert "tool_name mismatch" in result.reason

    def test_missing_tool_name_claim_rejected(self):
        token = jwt.encode({"iss": "test", "exp": int(time.time()) + 60}, SECRET, algorithm="HS256")
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(token, tool_name="anything")
        assert result.trusted is False
        assert "missing tool_name" in result.reason

    def test_tool_name_mismatch_rejected_even_when_require_tool_name_false(self):
        """F7: a present-and-contradicting tool_name claim is never legitimate,
        regardless of require_tool_name."""
        token = _make_token(tool_name="delete_all")
        adapter = JWSAdapter(
            verification_key=SECRET, algorithms=("HS256",), require_tool_name=False
        )
        result = adapter.verify(token, tool_name="read_email")
        assert result.trusted is False
        assert "tool_name mismatch" in result.reason

    def test_arg_hash_mismatch_returns_untrusted(self):
        token = _make_token(arg_hash="sha256:AAA")
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(token, tool_name="read_email", arg_hash="sha256:BBB")
        assert result.trusted is False
        assert "arg_hash mismatch" in result.reason

    def test_arg_hash_requested_but_missing_from_claim_rejected(self):
        """F7: caller asks for arg_hash binding; token has no claim → fail.

        Was silently accepted (trusted=True). A replayed token from
        before the issuer emitted arg_hash then bound to any arguments.
        """
        token = _make_token()  # no arg_hash claim
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(token, tool_name="read_email", arg_hash="sha256:XYZ")
        assert result.trusted is False
        assert "arg_hash" in result.reason
        assert "no arg_hash claim" in result.reason


class TestInputShape:
    def test_dict_input_raises_verification_error(self):
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        with pytest.raises(ReceiptVerificationError, match="compact JWT string"):
            adapter.verify({"payload": "..."}, tool_name="x")

    def test_bytes_input_accepted(self):
        token = _make_token()
        adapter = JWSAdapter(verification_key=SECRET, algorithms=("HS256",))
        result = adapter.verify(token.encode("utf-8"), tool_name="read_email")
        assert result.trusted is True


class TestConstruction:
    def test_algorithms_is_required(self):
        """F6: the docstring says 'Explicit list is required' — enforce it."""
        with pytest.raises(TypeError):
            JWSAdapter(verification_key=SECRET)  # type: ignore[call-arg]
