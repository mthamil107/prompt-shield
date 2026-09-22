"""Pipelock v1 action-receipt adapter.

Consumes Ed25519-signed ``action_receipt_v1`` envelopes emitted by
the Pipelock mediator (https://pipelab.org/learn/action-receipt-spec/).
Verification is delegated to the ``pipelock-verify`` PyPI package;
the adapter maps its verdict enum onto ``ReceiptVerification``.

Verdict mapping:

- ``allow`` → ``trusted=True``
- ``block`` / ``strip`` → ``trusted=False`` (upstream mediator refused)
- ``warn`` / ``ask`` → ``trusted=False`` (upstream mediator flagged)
- ``forward`` / ``redirect`` → ``trusted=False`` (needs downstream
  adjudication that prompt-shield cannot perform)
- anything else → ``trusted=False`` with reason naming the verdict

Pipelock v1 receipts carry a ``target`` URL and an ``action_id`` but no
``arg_hash`` binding. If the caller supplies ``arg_hash=``, the adapter
records a policy violation and returns ``trusted=False`` — refuse to
silently accept an unbound token when the caller asked for a binding
we can't check. Use :class:`~prompt_shield.capabilities.jws.JWSAdapter`
if you need rigorous ``arg_hash`` binding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from prompt_shield.capabilities._base import ReceiptVerificationError
from prompt_shield.models import ReceiptVerification

_TRUSTED_VERDICTS = frozenset({"allow"})


@dataclass(frozen=True)
class PipelockAdapter:
    """Verify a Pipelock v1 action receipt.

    Parameters
    ----------
    public_key_hex :
        The 64-hex-char Ed25519 trust anchor. **Required.** Passing the
        empty string or ``None`` is rejected at construction: the
        upstream library treats a missing key as "trust the embedded
        signer_key", which is a forgery vector — any Ed25519 keypair
        can then mint an accepted receipt.
    """

    public_key_hex: str
    name: str = field(default="pipelock")

    def __post_init__(self) -> None:
        if not self.public_key_hex:
            raise ValueError(
                "PipelockAdapter requires public_key_hex — passing None / empty "
                "trusts the receipt's embedded signer_key, which is a forgery vector"
            )

    def verify(
        self,
        receipt: bytes | str | dict[str, object],
        *,
        tool_name: str | None = None,
        arg_hash: str | None = None,
    ) -> ReceiptVerification:
        try:
            import pipelock_verify  # type: ignore[import-not-found]
        except ImportError as e:
            raise ReceiptVerificationError(
                "pipelock-verify is required. Install with: "
                "pip install prompt-shield-ai[capabilities-pipelock]"
            ) from e

        try:
            result = pipelock_verify.verify(receipt, public_key_hex=self.public_key_hex)
        except (ValueError, TypeError) as e:
            raise ReceiptVerificationError(f"malformed pipelock receipt: {e}") from e

        if not result.valid:
            return ReceiptVerification(
                adapter_name=self.name,
                trusted=False,
                reason=f"signature invalid: {result.error or 'unknown'}",
            )

        verdict = getattr(result, "verdict", None) or ""
        target = getattr(result, "target", None)
        action_id = getattr(result, "action_id", None)
        signer_key = getattr(result, "signer_key", None)

        policy_violations: list[str] = []
        # Pipelock v1 does not carry an arg_hash binding — refusing to
        # silently accept when caller asked for one is the honest choice.
        if arg_hash is not None:
            policy_violations.append(
                "pipelock v1 receipts carry no arg_hash binding; use JWSAdapter if you need it"
            )
        # tool_name binding is advisory in Pipelock: target is a URL,
        # not a tool name, so no reliable exact check. We surface the
        # target via issuer/reason for logging but don't fail on it.
        _ = tool_name  # kept in signature for protocol conformance

        if verdict not in _TRUSTED_VERDICTS:
            return ReceiptVerification(
                adapter_name=self.name,
                trusted=False,
                reason=(f"verdict={verdict!r} is not in trusted set {sorted(_TRUSTED_VERDICTS)!r}"),
                issuer=signer_key or self.public_key_hex,
                policy_violations=policy_violations,
            )

        trusted = not policy_violations
        reason = (
            f"verdict={verdict!r}, action_id={action_id!r}, target={target!r}"
            if trusted
            else "; ".join(policy_violations)
        )
        return ReceiptVerification(
            adapter_name=self.name,
            trusted=trusted,
            reason=reason,
            issuer=signer_key or self.public_key_hex,
            policy_violations=policy_violations,
        )


__all__ = ["PipelockAdapter"]
