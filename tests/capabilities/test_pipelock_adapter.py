"""Tests for the Pipelock v1 capability-receipt adapter.

The adapter delegates verification to ``pipelock-verify``; these tests
mock its module surface so the tests run without a live Pipelock
mediator or the third-party package installed. Contract validated:
verdict → trusted mapping, arg_hash binding refusal, required
public_key_hex.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from prompt_shield.capabilities import ReceiptVerificationError
from prompt_shield.capabilities.pipelock import PipelockAdapter

VALID_KEY = "a" * 64


class _FakeResult:
    def __init__(
        self,
        *,
        valid: bool,
        verdict: str = "allow",
        target: str = "https://api.example.com/read_email",
        action_id: str = "conformance-00000",
        signer_key: str | None = None,
        error: str | None = None,
    ) -> None:
        self.valid = valid
        self.verdict = verdict
        self.target = target
        self.action_id = action_id
        self.signer_key = signer_key
        self.error = error


@pytest.fixture
def fake_pipelock(monkeypatch: pytest.MonkeyPatch):
    """Install a stub ``pipelock_verify`` module and expose a hook to set its return value."""
    stub = types.ModuleType("pipelock_verify")
    box: dict[str, Any] = {"result": _FakeResult(valid=True)}

    def verify(receipt: object, public_key_hex: object = None) -> _FakeResult:
        return box["result"]

    stub.verify = verify  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pipelock_verify", stub)
    yield box


class TestConstruction:
    """F3: PipelockAdapter must not silently self-certify."""

    def test_missing_key_raises_value_error(self):
        with pytest.raises(ValueError, match="requires public_key_hex"):
            PipelockAdapter(public_key_hex="")  # type: ignore[call-arg]

    def test_none_key_would_raise_if_supplied(self):
        with pytest.raises((ValueError, TypeError)):
            # Passing None to a str-typed field is a construction-time error.
            PipelockAdapter(public_key_hex=None)  # type: ignore[arg-type]

    def test_no_default_key(self):
        """Bare PipelockAdapter() must not be valid — no self-certifying default."""
        with pytest.raises(TypeError):
            PipelockAdapter()  # type: ignore[call-arg]


class TestHappyPath:
    def test_valid_allow_returns_trusted(self, fake_pipelock):
        fake_pipelock["result"] = _FakeResult(valid=True, verdict="allow")
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        result = adapter.verify(b'{"any":"json"}', tool_name="read_email")
        assert result.trusted is True
        assert result.adapter_name == "pipelock"
        # issuer surfaces the anchoring public key.
        assert result.issuer == VALID_KEY

    def test_signer_key_from_result_takes_precedence(self, fake_pipelock):
        signer = "b" * 64
        fake_pipelock["result"] = _FakeResult(valid=True, verdict="allow", signer_key=signer)
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        result = adapter.verify(b"{}")
        assert result.issuer == signer


class TestVerdictMapping:
    @pytest.mark.parametrize("verdict", ["block", "warn", "ask", "strip", "forward", "redirect"])
    def test_non_allow_verdicts_return_untrusted(self, fake_pipelock, verdict):
        fake_pipelock["result"] = _FakeResult(valid=True, verdict=verdict)
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        result = adapter.verify(b"{}")
        assert result.trusted is False
        assert verdict in result.reason


class TestTamper:
    def test_invalid_signature_returns_untrusted(self, fake_pipelock):
        fake_pipelock["result"] = _FakeResult(valid=False, error="ed25519 signature mismatch")
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        result = adapter.verify(b"{}")
        assert result.trusted is False
        assert "signature invalid" in result.reason
        assert "ed25519 signature mismatch" in result.reason


class TestArgHashBinding:
    """F7: pipelock v1 receipts carry no arg_hash — a caller that asks
    for that binding must not be silently accepted.
    """

    def test_arg_hash_requested_returns_untrusted(self, fake_pipelock):
        fake_pipelock["result"] = _FakeResult(valid=True, verdict="allow")
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        result = adapter.verify(b"{}", tool_name="read", arg_hash="sha256:XYZ")
        assert result.trusted is False
        assert any("arg_hash" in v for v in result.policy_violations)
        assert any("JWSAdapter" in v for v in result.policy_violations)

    def test_no_arg_hash_no_violation(self, fake_pipelock):
        fake_pipelock["result"] = _FakeResult(valid=True, verdict="allow")
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        result = adapter.verify(b"{}", tool_name="anything")
        assert result.trusted is True
        assert result.policy_violations == []


class TestMissingPackage:
    def test_missing_package_raises_clear_error(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "pipelock_verify", None)
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        with pytest.raises(ReceiptVerificationError, match="capabilities-pipelock"):
            adapter.verify(b"{}")


class TestMalformedInput:
    def test_value_error_wrapped(self, monkeypatch):
        stub = types.ModuleType("pipelock_verify")

        def bad_verify(*args, **kwargs):
            raise ValueError("not JSON")

        stub.verify = bad_verify  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "pipelock_verify", stub)
        adapter = PipelockAdapter(public_key_hex=VALID_KEY)
        with pytest.raises(ReceiptVerificationError, match="malformed"):
            adapter.verify(b"not-json")
