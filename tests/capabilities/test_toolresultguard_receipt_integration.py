"""Integration tests — ``ToolResultGuard.scan()`` wired with receipt adapters.

Uses a stub adapter (no third-party deps) to prove the wiring is correct.
Adapter-specific behavior is covered by ``test_pipelock_adapter.py`` and
``test_jws_adapter.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from prompt_shield.capabilities import ReceiptVerificationError
from prompt_shield.models import ReceiptVerification, Severity, ToolResultAttackFamily
from prompt_shield.tool_guard import ToolResultGuard


@dataclass(frozen=True)
class _StubAdapter:
    """Test double: returns a canned verification result."""

    canned: ReceiptVerification
    name: str = "stub"

    def verify(self, receipt, *, tool_name=None, arg_hash=None):
        return self.canned


@dataclass(frozen=True)
class _RaisingAdapter:
    """Test double: verify() raises the given exception."""

    exc: BaseException
    name: str = "raising"

    def verify(self, receipt, *, tool_name=None, arg_hash=None):
        raise self.exc


def _trusted(reason: str = "ok") -> ReceiptVerification:
    return ReceiptVerification(adapter_name="stub", trusted=True, reason=reason)


def _untrusted(reason: str = "bad signature") -> ReceiptVerification:
    return ReceiptVerification(
        adapter_name="stub", trusted=False, reason=reason, policy_violations=["fail"]
    )


class TestNoReceiptBackwardCompatible:
    def test_missing_receipt_behaves_as_before(self, engine):
        """Existing callers that don't pass receipt / adapter keep working unchanged."""
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        report = guard.scan("Paris is the capital of France.", tool_name="web_search")
        assert report.scan_context is not None
        assert report.scan_context.receipt_verification is None
        assert ToolResultAttackFamily.UNTRUSTED_ORIGIN not in report.scan_context.attack_families


class TestTrustedReceipt:
    def test_trusted_verification_attached_no_family(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_trusted())
        report = guard.scan(
            "Paris is the capital of France.",
            tool_name="web_search",
            receipt=b"opaque",
            receipt_adapter=adapter,
        )
        assert report.scan_context is not None
        v = report.scan_context.receipt_verification
        assert v is not None and v.trusted is True
        assert ToolResultAttackFamily.UNTRUSTED_ORIGIN not in report.scan_context.attack_families


class TestUntrustedReceipt:
    def test_untrusted_adds_untrusted_origin_family(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_untrusted())
        report = guard.scan(
            "Paris is the capital of France.",
            tool_name="web_search",
            receipt=b"opaque",
            receipt_adapter=adapter,
        )
        assert report.scan_context is not None
        assert ToolResultAttackFamily.UNTRUSTED_ORIGIN in report.scan_context.attack_families
        assert report.scan_context.mitigation != ""


class TestFailClosedOnMissingReceipt:
    """F1: adapter configured but receipt missing must fail-closed.

    Was previously enshrined as a no-op — Fable's adversarial review
    caught that a rogue upstream stripping the receipt would then
    silently bypass verification. Configuring an adapter now declares
    that receipts are required from that point on.
    """

    def test_missing_receipt_with_adapter_flags_untrusted_origin(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_trusted())  # canned trusted; must NEVER be called
        report = guard.scan(
            "Paris is the capital of France.",
            tool_name="web_search",
            receipt=None,
            receipt_adapter=adapter,
        )
        assert report.scan_context is not None
        v = report.scan_context.receipt_verification
        assert v is not None
        assert v.trusted is False
        assert "not provided" in v.reason
        assert "missing receipt" in v.policy_violations
        assert ToolResultAttackFamily.UNTRUSTED_ORIGIN in report.scan_context.attack_families

    def test_receipt_without_adapter_raises_typeerror(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        with pytest.raises(TypeError, match="nothing can verify it"):
            guard.scan(
                "Paris is the capital of France.",
                tool_name="web_search",
                receipt=b"opaque",
                receipt_adapter=None,
            )


class TestAdapterExceptionsFailClosed:
    """F2: exceptions from an adapter must not crash scan() — they must
    land as trusted=False so mode enforcement fires normally.
    """

    def test_receipt_verification_error_becomes_untrusted(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _RaisingAdapter(ReceiptVerificationError("malformed bytes"))
        report = guard.scan("text", tool_name="w", receipt=b"opaque", receipt_adapter=adapter)
        assert report.scan_context is not None
        v = report.scan_context.receipt_verification
        assert v is not None and v.trusted is False
        assert "adapter error" in v.reason
        assert ToolResultAttackFamily.UNTRUSTED_ORIGIN in report.scan_context.attack_families

    def test_unexpected_exception_becomes_untrusted(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _RaisingAdapter(RuntimeError("boom"))
        report = guard.scan("text", tool_name="w", receipt=b"opaque", receipt_adapter=adapter)
        assert report.scan_context is not None
        v = report.scan_context.receipt_verification
        assert v is not None and v.trusted is False
        assert "RuntimeError" in v.reason
        assert ToolResultAttackFamily.UNTRUSTED_ORIGIN in report.scan_context.attack_families

    def test_block_mode_raises_not_crashes_on_adapter_exception(self, engine):
        guard = ToolResultGuard(engine=engine, mode="block", cache_size=0)
        adapter = _RaisingAdapter(ValueError("garbage"))
        with pytest.raises(ValueError, match="untrusted origin"):
            guard.scan("text", tool_name="w", receipt=b"opaque", receipt_adapter=adapter)


class TestReceiptFailureVisibleToIntegrations:
    """F8: failed receipts must appear in report.detections so downstream
    integrations gating on `if report.detections:` fire correctly.
    """

    def test_synthetic_detection_appended_on_untrusted(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_untrusted("signature invalid"))
        report = guard.scan(
            "clean benign text",
            tool_name="w",
            receipt=b"opaque",
            receipt_adapter=adapter,
        )
        rec_dets = [d for d in report.detections if d.detector_id == "receipt_verification"]
        assert len(rec_dets) == 1
        assert rec_dets[0].detected is True
        assert rec_dets[0].severity == Severity.HIGH
        assert "signature invalid" in rec_dets[0].explanation

    def test_action_promoted_from_pass_to_at_least_flag(self, engine):
        from prompt_shield.models import Action

        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_untrusted())
        report = guard.scan(
            "clean benign text",
            tool_name="w",
            receipt=b"opaque",
            receipt_adapter=adapter,
        )
        assert report.action != Action.PASS

    def test_no_synthetic_detection_on_trusted(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_trusted())
        report = guard.scan("text", tool_name="w", receipt=b"opaque", receipt_adapter=adapter)
        rec_dets = [d for d in report.detections if d.detector_id == "receipt_verification"]
        assert rec_dets == []


class TestBlockModeEnforcement:
    def test_block_mode_raises_on_untrusted_receipt(self, engine):
        guard = ToolResultGuard(engine=engine, mode="block", cache_size=0)
        adapter = _StubAdapter(_untrusted())
        with pytest.raises(ValueError, match="untrusted origin"):
            guard.scan(
                "Paris is the capital of France.",
                tool_name="web_search",
                receipt=b"opaque",
                receipt_adapter=adapter,
            )

    def test_block_mode_silent_on_trusted_and_clean(self, engine):
        guard = ToolResultGuard(engine=engine, mode="block", cache_size=0)
        adapter = _StubAdapter(_trusted())
        report = guard.scan(
            "Paris is the capital of France.",
            tool_name="web_search",
            receipt=b"opaque",
            receipt_adapter=adapter,
        )
        assert report.scan_context is not None


class TestCacheBypass:
    def test_cache_skipped_when_adapter_present(self, engine):
        """A cached (no-adapter) report must not be returned when an adapter is passed."""
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=4)
        r1 = guard.scan("same text", tool_name="w")  # populates cache
        adapter = _StubAdapter(_untrusted())
        r2 = guard.scan("same text", tool_name="w", receipt=b"opaque", receipt_adapter=adapter)
        assert r1 is not r2  # a fresh report was produced, not the cached one
        assert r2.scan_context is not None
        assert r2.scan_context.receipt_verification is not None

    def test_no_receipt_cache_still_works(self, engine):
        guard = ToolResultGuard(engine=engine, mode="log", cache_size=4)
        r1 = guard.scan("same text", tool_name="w")
        r2 = guard.scan("same text", tool_name="w")
        assert r1 is r2  # normal path unchanged


class TestAsyncPath:
    def test_ascan_forwards_receipt(self, engine):
        import asyncio

        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_untrusted())

        async def run():
            return await guard.ascan(
                "text",
                tool_name="w",
                receipt=b"opaque",
                receipt_adapter=adapter,
            )

        report = asyncio.run(run())
        assert report.scan_context is not None
        assert ToolResultAttackFamily.UNTRUSTED_ORIGIN in report.scan_context.attack_families

    def test_ascan_fails_closed_on_missing_receipt(self, engine):
        import asyncio

        guard = ToolResultGuard(engine=engine, mode="log", cache_size=0)
        adapter = _StubAdapter(_trusted())  # canned trusted; MUST NOT be reached

        async def run():
            return await guard.ascan("text", tool_name="w", receipt_adapter=adapter)

        report = asyncio.run(run())
        assert report.scan_context is not None
        v = report.scan_context.receipt_verification
        assert v is not None and v.trusted is False
