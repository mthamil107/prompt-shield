"""``ReceiptAdapter`` protocol + shared exception type.

Adapters live in their own module (``pipelock.py``, ``jws.py``) and are
imported lazily so their optional third-party deps only load when a
caller explicitly uses them.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from prompt_shield.models import ReceiptVerification


class ReceiptVerificationError(Exception):
    """Raised when receipt input is malformed before signature verification.

    Signature-failure and expired-receipt cases are reported through the
    ``ReceiptVerification.trusted=False`` path so callers can inspect
    the reason without exception handling; this exception is reserved
    for structural problems (e.g. non-JSON receipt bytes, missing
    required envelope fields).
    """


@runtime_checkable
class ReceiptAdapter(Protocol):
    """Verify an upstream capability receipt for a tool call.

    Adapters are stateless value objects. Construct once per trust anchor
    (e.g. a public key) and pass the instance into
    ``ToolResultGuard.scan(receipt=..., receipt_adapter=...)`` on every
    scan that has a receipt to check.
    """

    name: str

    def verify(
        self,
        receipt: bytes | str | dict[str, object],
        *,
        tool_name: str | None = None,
        arg_hash: str | None = None,
    ) -> ReceiptVerification:
        """Verify ``receipt`` and return a ``ReceiptVerification``.

        ``tool_name`` and ``arg_hash`` are optional bindings — when
        provided, the adapter MUST ensure the receipt authorises this
        specific tool invocation, not just any tool call the signer has
        approved. Concretely:

        - If the receipt format carries the binding claim, the adapter
          must reject on mismatch AND on missing claim (silent accept
          would let a replayed token bind to any arguments).
        - If the format does not carry the binding at all and the
          caller requested it, the adapter must return ``trusted=False``
          with a reason naming that limitation.

        Verification-time failures (bad signature, expired, malformed)
        should be reported through the ``trusted=False`` path so callers
        can inspect the reason without exception handling.
        ``ReceiptVerificationError`` is reserved for structural /
        deployment problems (e.g. non-JSON receipt bytes, missing
        third-party package).
        """
        ...  # pragma: no cover — Protocol definition


__all__ = ["ReceiptAdapter", "ReceiptVerification", "ReceiptVerificationError"]
