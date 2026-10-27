"""Receipt-format adapters for ``ToolResultGuard``.

Verifies signed capability receipts issued by upstream capability
enforcement layers. Two adapters ship today:

- ``pipelock.PipelockAdapter`` — Pipelock v1 Ed25519 action receipts
  (via ``pipelock-verify``)
- ``jws.JWSAdapter`` — RFC-7515 JWS / RFC-7519 JWT (via ``PyJWT``)

prompt-shield does not mint tokens; it verifies receipts issued
elsewhere.

The receipt tells us whether the tool call was authorized upstream.
It does NOT tell us whether the content of the result is safe. The
dominant indirect-injection case — an authorized tool returning
malicious content — is still the job of the other detectors.

See also — adjacent projects in the same space. None of them currently
ship a wire format the two adapters here can consume; listed for context
because a real deployment often runs one of them upstream and
prompt-shield downstream. Interop notes in
``docs/capabilities/receipt-adapter.md``.

- Invariant Guardrails (github.com/invariantlabs-ai/invariant) —
  Apache-2, rule-based guardrails on tool calls + data flows. Uses a
  policy DSL, not a signed receipt format.
- mcp-gate (github.com/ananthaprakashb/mcp-gate) — HMAC-signed
  single-use capability tokens for MCP tool calls. No published wire
  format spec.
- agentauth (github.com/Algo-Vision404/agentauth) — macaroon-style
  capability tokens. No published wire format spec.
- Progent (arXiv:2504.11703, github.com/sunblaze-ucb/progent) —
  in-process policy enforcement library, no serialized receipt.

Adapter implementations are lazy-imported so the base install stays
lean. Install extras as needed:

- ``pip install prompt-shield-ai[capabilities-pipelock]``
- ``pip install prompt-shield-ai[capabilities-jws]``
"""

from __future__ import annotations

from prompt_shield.capabilities._base import ReceiptAdapter, ReceiptVerificationError
from prompt_shield.models import ReceiptVerification

__all__ = [
    "ReceiptAdapter",
    "ReceiptVerification",
    "ReceiptVerificationError",
]
