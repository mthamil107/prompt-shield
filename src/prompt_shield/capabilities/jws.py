"""RFC-7515 JWS / RFC-7519 JWT adapter (generic fallback).

Adapts a JWT-shaped capability receipt with an optional payload binding
to ``tool_name`` and ``arg_hash``. Callers issue tokens with claims like::

    {
      "tool_name": "read_email",
      "arg_hash": "sha256:...",
      "iss": "my-orchestrator",
      "exp": 1727100000
    }

and prompt-shield verifies the signature + expiry + binding on the return
path. When ``arg_hash`` is supplied by the caller, the token MUST carry a
matching ``arg_hash`` claim — a missing claim is treated as a binding
failure, not a silent accept.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from prompt_shield.capabilities._base import ReceiptVerificationError
from prompt_shield.models import ReceiptVerification


@dataclass(frozen=True)
class JWSAdapter:
    """Verify a JWT (JWS-signed JSON payload) capability receipt.

    Parameters
    ----------
    verification_key :
        Secret (for HS*) or PEM-encoded public key (for RS*/ES*/EdDSA).
        Passed straight to ``jwt.decode``.
    algorithms :
        Allowed signature algorithms — REQUIRED, no default. Mixing HMAC
        and asymmetric families in one list enables key-confusion
        attacks; prefer a single-family list (e.g. ``("EdDSA",)`` or
        ``("ES256",)`` for asymmetric, ``("HS256",)`` for HMAC).
    require_tool_name :
        When True (default), the token must carry a ``tool_name`` claim.
        Independent of this flag, if the token DOES carry a
        ``tool_name`` claim and the caller passes ``tool_name=``, a
        mismatch is always rejected.
    require_exp :
        When True (default), tokens without an ``exp`` claim are rejected —
        capability receipts should always expire.
    audience :
        Optional ``aud`` claim to enforce.
    issuer :
        Optional ``iss`` claim to enforce (exact match; PyJWT>=2.13
        avoids the CVE-2024-53861 partial-match issue).
    """

    verification_key: str | bytes
    algorithms: tuple[str, ...]
    require_tool_name: bool = True
    require_exp: bool = True
    audience: str | None = None
    issuer: str | None = None
    name: str = "jws"

    def verify(
        self,
        receipt: bytes | str | dict[str, object],
        *,
        tool_name: str | None = None,
        arg_hash: str | None = None,
    ) -> ReceiptVerification:
        try:
            import jwt  # type: ignore[import-not-found]
        except ImportError as e:
            raise ReceiptVerificationError(
                "PyJWT is required. Install with: pip install prompt-shield-ai[capabilities-jws]"
            ) from e

        if isinstance(receipt, dict):
            raise ReceiptVerificationError("JWS adapter expects a compact JWT string, not a dict")
        try:
            token = receipt.decode("utf-8") if isinstance(receipt, bytes) else receipt
        except UnicodeDecodeError as e:
            return ReceiptVerification(
                adapter_name=self.name, trusted=False, reason=f"receipt not UTF-8: {e}"
            )

        options: dict[str, object] = {}
        if self.require_exp:
            options["require"] = ["exp"]

        try:
            payload = jwt.decode(
                token,
                self.verification_key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                options=options,
            )
        except jwt.ExpiredSignatureError:
            return ReceiptVerification(
                adapter_name=self.name, trusted=False, reason="token expired"
            )
        except jwt.InvalidSignatureError:
            return ReceiptVerification(
                adapter_name=self.name, trusted=False, reason="signature invalid"
            )
        except jwt.PyJWTError as e:
            # Parent of InvalidTokenError AND InvalidKeyError — the latter
            # is raised on algorithm-confusion attempts (RSA pubkey used
            # as HMAC secret), and used to escape as a crash.
            return ReceiptVerification(
                adapter_name=self.name, trusted=False, reason=f"invalid token: {e}"
            )

        violations: list[str] = []
        claim_tool = payload.get("tool_name")
        if self.require_tool_name and not claim_tool:
            violations.append("missing tool_name claim")
        # Independent of require_tool_name: if the token carries a claim
        # AND the caller supplies tool_name, a mismatch is never legitimate.
        if claim_tool and tool_name and claim_tool != tool_name:
            violations.append(f"tool_name mismatch: claim={claim_tool!r}, expected={tool_name!r}")
        if arg_hash is not None:
            claim_hash = payload.get("arg_hash")
            if not claim_hash:
                violations.append("arg_hash binding requested but token carries no arg_hash claim")
            elif claim_hash != arg_hash:
                violations.append(f"arg_hash mismatch: claim={claim_hash!r}, expected={arg_hash!r}")

        exp_raw = payload.get("exp")
        expires_at = (
            datetime.fromtimestamp(exp_raw, tz=timezone.utc)
            if isinstance(exp_raw, int | float)
            else None
        )

        trusted = not violations
        reason = (
            f"iss={payload.get('iss')!r}, tool_name={payload.get('tool_name')!r}"
            if trusted
            else "; ".join(violations)
        )
        return ReceiptVerification(
            adapter_name=self.name,
            trusted=trusted,
            reason=reason,
            issuer=str(payload.get("iss")) if payload.get("iss") else None,
            expires_at=expires_at,
            policy_violations=violations,
        )


__all__ = ["JWSAdapter"]
