# Receipt-format adapters for `ToolResultGuard`

## What it does

`ToolResultGuard` can verify an upstream capability receipt alongside its content scan. Pass a `receipt` (bytes / str / dict) plus a `receipt_adapter` to `scan()` or `ascan()`; the adapter checks the receipt's signature and any bindings you supply (`tool_name`, `arg_hash`), and the outcome is attached to `scan_context.receipt_verification`. A failed verification adds `UNTRUSTED_ORIGIN` to `attack_families`, appends a synthetic `DetectionResult` (`detector_id="receipt_verification"`) so integrations that gate on `if report.detections:` still fire, and is enforced according to the guard's `mode` (`block` raises, `flag` warns, `log`/`sanitize` pass through). Adapters are stateless — construct once per trust anchor, reuse.

## What it does NOT do

**The receipt tells us whether the tool call was authorized upstream. It does NOT tell us whether the content of the result is safe. The dominant indirect-injection case — an authorized tool returning malicious content (e.g. an email body that says "ignore previous instructions") — is still the job of the other detectors.**

Do not disable content scans on trusted-receipt results.

## Fail-closed policy

Configuring a `receipt_adapter` declares that receipts are required from that point on. The guard is fail-closed:

- `receipt` present + adapter present → verify.
- `receipt` **missing** + adapter present → **flagged `UNTRUSTED_ORIGIN`** with reason `"receipt required by adapter but not provided"`. A rogue upstream that strips the receipt is a rogue upstream, not a happy path.
- `receipt` present + adapter **missing** → `TypeError`. Nothing can verify the receipt — this is a caller misconfiguration and refusing loudly is safer than silently ignoring.
- Any exception raised inside the adapter (malformed input, algorithm confusion, upstream library bug) → treated as `trusted=False` with the exception in `reason`. Verification failures must never crash `scan()` in flag/log mode.

## Known limitations

### Pipelock replay window (v0.8.0)

Pipelock v1 receipts do not carry an expiry claim, and the v0.8.0 adapter reads `timestamp` but does not enforce a `max_age`. A captured Pipelock `allow` receipt can be replayed indefinitely — a receipt dated 2020 or dated 2099 both verify successfully today. Chain verification (`verify_chain()` in `pipelock-verify`) is also not attempted.

Callers who need freshness guarantees should use `JWSAdapter` with `exp` claim required (`require_exp=True`) until a later release lands `max_age` enforcement for Pipelock.

## Adjacent projects (interop, not competitors)

prompt-shield is the content-scanning layer. Capability enforcement itself lives in projects like these; a real deployment usually runs both.

- [`invariantlabs-ai/invariant`](https://github.com/invariantlabs-ai/invariant) — Apache-2.0, guardrails on tool calls and data flows, MCP gateway
- [`ananthaprakashb/mcp-gate`](https://github.com/ananthaprakashb/mcp-gate) — ephemeral HMAC-signed capability tokens for MCP
- [`Algo-Vision404/agentauth`](https://github.com/Algo-Vision404/agentauth) — macaroon-style capability tokens for AI agents
- [`sunblaze-ucb/progent`](https://github.com/sunblaze-ucb/progent) — per-task privilege policies (arXiv:2504.11703), evaluated on AgentDojo
- [`luckyPipewrench/pipelock`](https://github.com/luckyPipewrench/pipelock) — Ed25519-signed action receipts, spec at [pipelab.org](https://pipelab.org/learn/action-receipt-spec/)

## Supported adapters

### Pipelock v1 action receipts

Installation:
```
pip install prompt-shield-ai[capabilities-pipelock]
```

Usage:
```python
from prompt_shield.tool_guard import ToolResultGuard
from prompt_shield.capabilities.pipelock import PipelockAdapter

guard = ToolResultGuard(mode="flag")
# public_key_hex is REQUIRED — passing None trusts the receipt's embedded
# signer_key, which is a forgery vector. Anchor to a key you control.
adapter = PipelockAdapter(public_key_hex="<64-hex-char Ed25519 trust anchor>")

with open("action_receipt.json", "rb") as f:
    receipt = f.read()

report = guard.scan(
    tool_output_text,
    tool_name="read_email",
    receipt=receipt,
    receipt_adapter=adapter,
)

if report.scan_context.receipt_verification.trusted:
    # call was authorized upstream — content scan still applies
    ...
```

Verdict mapping (from the Pipelock spec):
- `allow` → `trusted=True`
- `block`, `strip`, `warn`, `ask`, `forward`, `redirect` → `trusted=False` with the verdict in `reason`

**Bindings.** Pipelock v1 receipts carry `target` (URL) and `action_id` but no `arg_hash`. If you pass `arg_hash=` to `scan()`, the adapter records a policy violation and returns `trusted=False` — better to refuse than to silently accept an unbound token. `tool_name` binding on Pipelock is advisory (the target is a URL, not a tool name); use `JWSAdapter` if you need rigorous `tool_name`+`arg_hash` binding.

### JWS / JWT

Installation:
```
pip install prompt-shield-ai[capabilities-jws]
```

Usage:
```python
from prompt_shield.capabilities.jws import JWSAdapter

adapter = JWSAdapter(
    verification_key=public_key_pem,           # or shared secret for HS256
    algorithms=("EdDSA",),                     # REQUIRED — no default
    require_tool_name=True,
    require_exp=True,
    issuer="my-orchestrator",
)

# Callers issue tokens with claims like:
#   {"tool_name": "read_email", "arg_hash": "sha256:...",
#    "iss": "my-orchestrator", "exp": 1727100000}

report = guard.scan(
    tool_output_text,
    tool_name="read_email",
    arg_hash="sha256:...",
    receipt=jwt_token_string,
    receipt_adapter=adapter,
)
```

**Algorithm allowlist is required.** No default is provided — mixing HMAC and asymmetric families in one list enables key-confusion attacks. Prefer a single-family list: `("EdDSA",)` or `("ES256",)` for asymmetric, `("HS256",)` for HMAC when both issuer and verifier share the same secret out of band.

**Bindings.**
- `require_tool_name=True` (default): the token must carry a `tool_name` claim. Independent of this flag, a present-and-contradicting `tool_name` claim vs. the caller's `tool_name=` argument is always rejected.
- `arg_hash=`: when the caller supplies it, the token MUST carry a matching `arg_hash` claim. A missing claim is a binding failure — a replayed token from before the issuer emitted `arg_hash` would otherwise bind to any arguments.

## Custom adapters

Any object implementing the `ReceiptAdapter` protocol works:

```python
from prompt_shield.capabilities import ReceiptAdapter, ReceiptVerification

class MyAdapter:
    name = "custom"
    def verify(self, receipt, *, tool_name=None, arg_hash=None) -> ReceiptVerification:
        # ... your verification logic ...
        return ReceiptVerification(
            adapter_name=self.name,
            trusted=True,
            reason="verified",
            issuer="my-issuer",
        )

# Runtime-checkable Protocol lets you assert conformance:
assert isinstance(MyAdapter(), ReceiptAdapter)
```

**Contract.** If the caller supplies `tool_name` or `arg_hash` and your receipt format carries the binding, reject on mismatch AND on missing claim. If the format doesn't carry the binding at all, return `trusted=False` with a reason naming the limitation — do not silently accept. Verification-time failures (bad signature, expired) belong in `trusted=False` returns; raise `ReceiptVerificationError` only for structural / deployment problems (non-JSON bytes, missing third-party package).

## Deployment recommendation

**Pair receipt verification with `mode="flag"` (the `ToolResultGuard` default) rather than `mode="block"` on the first deployment.** Upstream receipt-issuance problems — key rotation lags, clock skew, verifier version drift — should not hard-fail production traffic. Watch the flags in Prometheus / your log pipeline for a week, tune, then move to `block` once the false-negative rate on your own issuance path is understood.

## Caching

The guard cache (`OrderedDict`, per-instance `threading.Lock`) is bypassed automatically when a receipt_adapter is configured. A cached verification would be a correctness bug — the receipt outcome must always be fresh. The no-adapter path retains the O(1) cached lookup.
