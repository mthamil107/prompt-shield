"""``ToolResultGuard`` — first-class primitive for scanning tool-result content.

Scans text returned from an agent's tool call (retrieved documents, web
search results, code-exec output, MCP tool responses) and classifies any
detections into a compact attack-family taxonomy.

Two entry points:

- ``scan_tool_result(text, ...)`` — one-liner using a default engine.
- ``ToolResultGuard(engine, mode).scan(text, ...)`` — reusable primitive
  with an optional content-hash cache and an async ``ascan`` variant.

Returns a standard ``ScanReport`` with ``scan_context`` populated —
callers that don't care about families can ignore it; callers that do
get typed access to families, provenance, mitigation, and a sanitized
version of the text.

**Default mode is** ``"flag"`` **(not** ``"block"``\\ **)**: tool-result
sanitization can silently destroy legitimate agent context (e.g.
redacting a URL from a web-search result breaks the task). Callers opt
into ``"block"`` explicitly.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import (
    Action,
    DetectionResult,
    ReceiptVerification,
    ScanContext,
    ScanReport,
    Severity,
    ToolProvenance,
    ToolResultAttackFamily,
)
from prompt_shield.tool_guard._sanitize import sanitize_text
from prompt_shield.tool_guard._taxonomy import build_mitigation, classify

if TYPE_CHECKING:
    from prompt_shield.capabilities._base import ReceiptAdapter

logger = logging.getLogger("prompt_shield.tool_guard")

_VALID_MODES = ("block", "flag", "log", "sanitize")


class ToolResultGuard:
    """Scan tool-result content and classify detections into attack families.

    Parameters
    ----------
    engine :
        Optional pre-built ``PromptShieldEngine``. Defaults to the
        standard 33-detector engine (lazily constructed on first scan).
    mode :
        ``"block"`` raises ``ValueError`` on any detection.
        ``"flag"`` (default) logs a warning and returns the report.
        ``"log"`` returns silently.
        ``"sanitize"`` returns the report with ``scan_context.sanitized_text`` populated.
    cache_size :
        LRU cache size keyed by content hash. ``0`` disables caching.
        The cache is thread-safe; a single guard may be shared across
        threads or concurrent ``ascan`` callers.
    sanitize_replacement :
        Placeholder string used when ``mode="sanitize"`` for non-PII spans.
    """

    def __init__(
        self,
        engine: PromptShieldEngine | None = None,
        mode: str = "flag",
        cache_size: int = 128,
        sanitize_replacement: str = "[REDACTED by prompt-shield]",
    ) -> None:
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")
        if cache_size < 0:
            raise ValueError(f"cache_size must be >= 0, got {cache_size}")
        self._engine = engine
        self.mode = mode
        self.cache_size = cache_size
        self.sanitize_replacement = sanitize_replacement
        self._cache: OrderedDict[str, ScanReport] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def engine(self) -> PromptShieldEngine:
        if self._engine is None:
            self._engine = PromptShieldEngine()
        return self._engine

    def _cache_lookup(self, cache_key: str | None) -> ScanReport | None:
        if not cache_key:
            return None
        with self._lock:
            if cache_key in self._cache:
                self._cache.move_to_end(cache_key)
                return self._cache[cache_key]
        return None

    def _cache_set(self, cache_key: str | None, report: ScanReport) -> None:
        if not cache_key:
            return
        with self._lock:
            self._cache[cache_key] = report
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)

    def scan(
        self,
        text: str,
        *,
        tool_name: str | None = None,
        tool_type: str | None = None,
        source_url: str | None = None,
        parent_scan_id: str | None = None,
        is_indirect: bool | None = None,
        receipt: bytes | str | dict[str, object] | None = None,
        receipt_adapter: ReceiptAdapter | None = None,
        arg_hash: str | None = None,
    ) -> ScanReport:
        """Scan ``text`` and return a ``ScanReport`` with ``scan_context`` populated.

        When ``receipt_adapter`` is provided, receipt verification runs
        alongside the content scan and the outcome is attached as
        ``scan_context.receipt_verification``:

        - ``receipt`` present + adapter present → verify.
        - ``receipt`` MISSING + adapter present → **fail-closed**: record
          a "receipt required but not provided" verification and flag
          ``UNTRUSTED_ORIGIN``. Configuring an adapter declares that
          receipts are required from that point on; a rogue upstream
          that strips the receipt must not silently bypass the check.
        - ``receipt`` present + adapter MISSING → ``TypeError`` (nothing
          can verify it — caller misconfiguration).

        A failed verification adds ``UNTRUSTED_ORIGIN`` to
        ``attack_families``, appends a synthetic ``DetectionResult`` to
        ``report.detections`` (so integrations that gate on
        ``if report.detections:`` still fire), and enforces per the
        guard's ``mode`` (block/flag/log). The content scan runs
        unchanged; the receipt tells prompt-shield whether the *call*
        was authorized, not whether the content is safe.

        The cache is bypassed when an adapter is configured so
        verification results are always fresh (a stale cached
        verification would be a correctness bug).
        """
        if receipt is not None and receipt_adapter is None:
            raise TypeError(
                "receipt given without receipt_adapter — nothing can verify it. "
                "Pass receipt_adapter= alongside receipt=."
            )
        # Skip cache when an adapter is configured — see docstring.
        use_cache = receipt_adapter is None
        cache_key = self._cache_key(text, tool_name, tool_type) if use_cache else None
        cached = self._cache_lookup(cache_key) if use_cache else None
        if cached is not None:
            self._enforce(cached, tool_name=tool_name)
            return cached

        engine_context: dict[str, object] = {"gate": "tool_result"}
        if tool_name is not None:
            engine_context["tool_name"] = tool_name
        if tool_type is not None:
            engine_context["tool_type"] = tool_type
        if source_url is not None:
            engine_context["source_url"] = source_url
        if parent_scan_id is not None:
            engine_context["parent_scan_id"] = parent_scan_id

        report = self.engine.scan(text, context=engine_context)
        families, confidence = classify(report, text)

        verification: ReceiptVerification | None = None
        if receipt_adapter is not None:
            verification = self._verify_receipt(
                receipt_adapter, receipt, tool_name=tool_name, arg_hash=arg_hash
            )
            if not verification.trusted and ToolResultAttackFamily.UNTRUSTED_ORIGIN not in families:
                families.append(ToolResultAttackFamily.UNTRUSTED_ORIGIN)

        mitigation = build_mitigation(families)

        indirect = (
            bool(is_indirect)
            if is_indirect is not None
            else (tool_type or "").lower() in {"retrieval", "rag", "web_search", "search"}
        )

        sanitized: str | None = None
        if self.mode == "sanitize" and report.detections:
            sanitized = sanitize_text(text, report, replacement=self.sanitize_replacement)

        report.scan_context = ScanContext(
            gate="tool_result",
            provenance=ToolProvenance(
                tool_name=tool_name,
                tool_type=tool_type,
                source_url=source_url,
                parent_scan_id=parent_scan_id,
            ),
            attack_families=families,
            is_indirect=indirect,
            classifier_confidence=confidence,
            mitigation=mitigation,
            sanitized_text=sanitized,
            receipt_verification=verification,
        )

        # Surface receipt failure through the standard report surfaces so
        # integrations that gate on `if report.detections:` (LangChain
        # callback, OpenAI/Anthropic wrappers, agent_guard) still fire.
        if verification is not None and not verification.trusted:
            report.detections.append(
                DetectionResult(
                    detector_id="receipt_verification",
                    detected=True,
                    confidence=1.0,
                    severity=Severity.HIGH,
                    explanation=(
                        f"upstream capability receipt failed to verify: {verification.reason}"
                    ),
                    metadata={
                        "adapter_name": verification.adapter_name,
                        "policy_violations": list(verification.policy_violations),
                    },
                )
            )
            # Promote action so `action != PASS` gates fire; guard mode
            # still governs whether we raise / log / warn below.
            if report.action == Action.PASS:
                report.action = Action.FLAG

        if use_cache:
            self._cache_set(cache_key, report)
        # UNTRUSTED_ORIGIN needs enforcement even without a content detection —
        # a failed receipt is a policy-level signal, not a content detection.
        if verification is not None and not verification.trusted:
            self._enforce_untrusted_origin(report, tool_name=tool_name)
        else:
            self._enforce(report, tool_name=tool_name)
        return report

    def _verify_receipt(
        self,
        adapter: ReceiptAdapter,
        receipt: bytes | str | dict[str, object] | None,
        *,
        tool_name: str | None,
        arg_hash: str | None,
    ) -> ReceiptVerification:
        """Call an adapter and turn any raised exception into a fail-closed verdict.

        Fail-closed on missing receipt is F1's core fix: configuring an
        adapter declares "receipts required from here." Fail-closed on
        adapter exceptions is F2: verification bugs (jwt.InvalidKeyError,
        UnicodeDecodeError, ReceiptVerificationError, etc.) must not
        turn scan() into a crash in flag/log mode — they must land as
        trusted=False so the enforcement path fires normally.
        """
        # Import locally to avoid at-startup cost when capabilities is unused.
        from prompt_shield.capabilities._base import ReceiptVerificationError

        if receipt is None:
            return ReceiptVerification(
                adapter_name=adapter.name,
                trusted=False,
                reason="receipt required by adapter but not provided",
                policy_violations=["missing receipt"],
            )
        try:
            return adapter.verify(receipt, tool_name=tool_name, arg_hash=arg_hash)
        except ReceiptVerificationError as e:
            return ReceiptVerification(
                adapter_name=adapter.name,
                trusted=False,
                reason=f"adapter error: {e}",
                policy_violations=[f"adapter error: {type(e).__name__}"],
            )
        except Exception as e:  # defensive: typed catch, logged, converted to trusted=False
            logger.exception(
                "receipt adapter raised unexpectedly (treating as untrusted)",
                extra={"adapter_name": adapter.name, "exc_type": type(e).__name__},
            )
            return ReceiptVerification(
                adapter_name=adapter.name,
                trusted=False,
                reason=f"adapter raised {type(e).__name__}: {e}",
                policy_violations=[f"adapter raised {type(e).__name__}"],
            )

    async def ascan(
        self,
        text: str,
        *,
        tool_name: str | None = None,
        tool_type: str | None = None,
        source_url: str | None = None,
        parent_scan_id: str | None = None,
        is_indirect: bool | None = None,
        receipt: bytes | str | dict[str, object] | None = None,
        receipt_adapter: ReceiptAdapter | None = None,
        arg_hash: str | None = None,
    ) -> ScanReport:
        """Async variant. Runs the sync scan on the default executor."""
        return await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: self.scan(
                text,
                tool_name=tool_name,
                tool_type=tool_type,
                source_url=source_url,
                parent_scan_id=parent_scan_id,
                is_indirect=is_indirect,
                receipt=receipt,
                receipt_adapter=receipt_adapter,
                arg_hash=arg_hash,
            ),
        )

    def _enforce(self, report: ScanReport, tool_name: str | None) -> None:
        if not report.detections:
            return
        ctx = report.scan_context
        families = [f.value for f in (ctx.attack_families if ctx else [])]
        source_desc = f"tool_result[{tool_name or '?'}]"
        if self.mode == "block":
            raise ValueError(
                f"prompt-shield BLOCKED {source_desc} "
                f"(scan_id={report.scan_id}, families={families})"
            )
        if self.mode == "flag":
            logger.warning(
                "prompt-shield FLAGGED %s (scan_id=%s, families=%s)",
                source_desc,
                report.scan_id,
                families,
            )

    def _enforce_untrusted_origin(self, report: ScanReport, tool_name: str | None) -> None:
        """Enforce mode for a receipt-failure signal.

        Separate from ``_enforce`` because a receipt failure fires even
        when no content detections are present — a missing / invalid
        upstream capability is a first-class policy signal that must
        surface regardless of what the detectors said about content.
        """
        ctx = report.scan_context
        families = [f.value for f in (ctx.attack_families if ctx else [])]
        verification = ctx.receipt_verification if ctx else None
        reason = verification.reason if verification else "receipt failed to verify"
        source_desc = f"tool_result[{tool_name or '?'}]"
        if self.mode == "block":
            raise ValueError(
                f"prompt-shield BLOCKED {source_desc} — untrusted origin "
                f"(scan_id={report.scan_id}, families={families}, reason={reason!r})"
            )
        if self.mode == "flag":
            logger.warning(
                "prompt-shield FLAGGED %s untrusted origin (scan_id=%s, families=%s, reason=%s)",
                source_desc,
                report.scan_id,
                families,
                reason,
            )
        # In log/sanitize modes: run the standard enforce for any content
        # detections that happened alongside the receipt failure.
        if self.mode not in ("block", "flag"):
            self._enforce(report, tool_name=tool_name)

    def _cache_key(self, text: str, tool_name: str | None, tool_type: str | None) -> str | None:
        if self.cache_size == 0:
            return None
        h = hashlib.sha256()
        h.update(text.encode("utf-8", errors="replace"))
        h.update(b"|")
        h.update((tool_name or "").encode("utf-8"))
        h.update(b"|")
        h.update((tool_type or "").encode("utf-8"))
        return h.hexdigest()


def scan_tool_result(
    text: str,
    *,
    tool_name: str | None = None,
    tool_type: str | None = None,
    source_url: str | None = None,
    parent_scan_id: str | None = None,
    is_indirect: bool | None = None,
    engine: PromptShieldEngine | None = None,
    mode: str = "flag",
) -> ScanReport:
    """One-liner: scan a single tool result using a fresh ``ToolResultGuard``.

    For repeated scans, prefer instantiating ``ToolResultGuard`` yourself
    to benefit from the content-hash cache.
    """
    guard = ToolResultGuard(engine=engine, mode=mode, cache_size=0)
    return guard.scan(
        text,
        tool_name=tool_name,
        tool_type=tool_type,
        source_url=source_url,
        parent_scan_id=parent_scan_id,
        is_indirect=is_indirect,
    )


__all__: list[str] = [
    "Action",
    "ScanContext",
    "ScanReport",
    "ToolProvenance",
    "ToolResultAttackFamily",
    "ToolResultGuard",
    "scan_tool_result",
]

_ = Any  # kept for future typed hooks; silences vulture
