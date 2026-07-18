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
from collections import OrderedDict
from typing import Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import (
    Action,
    ScanContext,
    ScanReport,
    ToolProvenance,
    ToolResultAttackFamily,
)
from prompt_shield.tool_guard._sanitize import sanitize_text
from prompt_shield.tool_guard._taxonomy import build_mitigation, classify

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

    @property
    def engine(self) -> PromptShieldEngine:
        if self._engine is None:
            self._engine = PromptShieldEngine()
        return self._engine

    def scan(
        self,
        text: str,
        *,
        tool_name: str | None = None,
        tool_type: str | None = None,
        source_url: str | None = None,
        parent_scan_id: str | None = None,
        is_indirect: bool | None = None,
    ) -> ScanReport:
        """Scan ``text`` and return a ``ScanReport`` with ``scan_context`` populated."""
        cache_key = self._cache_key(text, tool_name, tool_type)
        if cache_key and cache_key in self._cache:
            self._cache.move_to_end(cache_key)
            cached = self._cache[cache_key]
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
        )

        if cache_key:
            self._cache[cache_key] = report
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)

        self._enforce(report, tool_name=tool_name)
        return report

    async def ascan(
        self,
        text: str,
        *,
        tool_name: str | None = None,
        tool_type: str | None = None,
        source_url: str | None = None,
        parent_scan_id: str | None = None,
        is_indirect: bool | None = None,
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
