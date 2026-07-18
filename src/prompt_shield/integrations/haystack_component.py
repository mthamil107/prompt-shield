"""Haystack v2 pipeline component for prompt-shield.

Drops a prompt-shield scan into any Haystack pipeline as a first-class
component. Follows the standard `@component` decorator pattern from
`haystack-ai` 2.x.

Three common wiring patterns:

1. **Input gate** — scan user query before it reaches downstream:

       pipeline.add_component("shield", PromptShieldGuard())
       pipeline.connect("shield.query", "retriever.query")

2. **Tool-result / RAG gate** — scan each retrieved document for
   indirect injection (d015 RAG poisoning fires here):

       pipeline.add_component("doc_shield", PromptShieldGuard())
       pipeline.connect("retriever.documents", "doc_shield.documents")

3. **Output gate** — scan the generator's answer for PII, prompt
   leakage, toxicity (9 output scanners fire here):

       pipeline.add_component("out_shield", PromptShieldOutputGuard())
       pipeline.connect("llm.replies", "out_shield.text")

All three raise ``ValueError`` on ``mode="block"`` (default). Change to
``mode="flag"`` to log-and-pass, or ``mode="log"`` for silent observation.

Lazy import: ``haystack-ai`` is an optional dependency. If not
installed, importing this module still works, but instantiating any
class raises ``ImportError`` with the pip install hint.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

try:
    from haystack import component

    _HAYSTACK_AVAILABLE = True
except ImportError:
    component = None  # type: ignore[assignment]
    _HAYSTACK_AVAILABLE = False

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action
from prompt_shield.tool_guard.guard import ToolResultGuard

if TYPE_CHECKING:
    from prompt_shield.models import ScanReport
    from prompt_shield.output_scanners.models import OutputScanResult

logger = logging.getLogger("prompt_shield.haystack")

_MISSING_MSG = (
    "haystack-ai is required for the Haystack integration. "
    "Install with: pip install prompt-shield-ai[haystack]"
)


def _summarize(report: ScanReport) -> dict[str, Any]:
    return {
        "scan_id": report.scan_id,
        "action": report.action.value,
        "detection_count": len(report.detections),
        "detector_ids": [d.detector_id for d in report.detections],
    }


def _make_guard_class():
    """Real Haystack-decorated class; only built when haystack-ai is installed."""

    @component
    class PromptShieldGuard:
        def __init__(
            self,
            engine: PromptShieldEngine | None = None,
            mode: str = "block",
        ) -> None:
            if mode not in ("block", "flag", "log"):
                raise ValueError(f"mode must be block/flag/log, got {mode!r}")
            self.engine = engine or PromptShieldEngine()
            self.mode = mode
            # Delegate retrieved-document scanning to the first-class primitive.
            # This also normalizes the gate string from "retrieved_document"
            # (Haystack-specific, v0.6.x) to "tool_result" with tool_type=retrieval.
            self._tool_guard = ToolResultGuard(engine=self.engine, mode="log")

        @component.output_types(query=str, documents=list, report=dict)
        def run(
            self,
            query: str | None = None,
            documents: list[Any] | None = None,
        ) -> dict[str, Any]:
            reports: list[dict[str, Any]] = []

            if query is not None:
                report = self.engine.scan(
                    query,
                    context={"gate": "input", "source": "haystack"},
                )
                self._enforce(report, source_desc=f"query: {query[:80]}")
                reports.append(_summarize(report))

            if documents:
                for i, doc in enumerate(documents):
                    content = getattr(doc, "content", None)
                    if not isinstance(content, str):
                        continue
                    doc_id = getattr(doc, "id", None)
                    report = self._tool_guard.scan(
                        content,
                        tool_name=f"haystack_doc[{i}]",
                        tool_type="retrieval",
                        source_url=doc_id,
                    )
                    self._enforce(
                        report,
                        source_desc=f"document[{i}] id={doc_id or '?'}",
                    )
                    reports.append(_summarize(report))

            return {
                "query": query,
                "documents": documents or [],
                "report": {"scan_count": len(reports), "reports": reports},
            }

        def _enforce(self, report: ScanReport, source_desc: str) -> None:
            if report.action == Action.BLOCK:
                msg = (
                    f"prompt-shield BLOCKED {source_desc!r} "
                    f"(scan_id={report.scan_id}, "
                    f"detections={len(report.detections)})"
                )
                if self.mode == "block":
                    raise ValueError(msg)
                logger.warning(msg)
            elif report.action == Action.FLAG and self.mode != "log":
                logger.warning(
                    "prompt-shield FLAGGED %s (scan_id=%s)",
                    source_desc,
                    report.scan_id,
                )

    return PromptShieldGuard


def _make_output_guard_class():
    @component
    class PromptShieldOutputGuard:
        def __init__(
            self,
            engine: PromptShieldEngine | None = None,
            mode: str = "block",
        ) -> None:
            if mode not in ("block", "flag", "log"):
                raise ValueError(f"mode must be block/flag/log, got {mode!r}")
            self.engine = engine or PromptShieldEngine()
            self.mode = mode

        @component.output_types(text=list, results=list)
        def run(
            self,
            text: str | list[str],
        ) -> dict[str, Any]:
            texts = [text] if isinstance(text, str) else list(text)
            results: list[list[dict[str, Any]]] = []

            for i, t in enumerate(texts):
                per_text: list[dict[str, Any]] = []
                for scanner in getattr(self.engine, "output_scanners", []) or []:
                    try:
                        r = scanner.scan(
                            t,
                            context={"index": i, "source": "haystack"},
                        )
                    except Exception as e:
                        logger.warning(
                            "output scanner %s crashed: %s",
                            getattr(scanner, "scanner_id", "?"),
                            e,
                        )
                        continue
                    per_text.append(
                        {
                            "scanner_id": r.scanner_id,
                            "flagged": r.flagged,
                            "confidence": r.confidence,
                            "categories": list(r.categories or []),
                        }
                    )
                    if r.flagged:
                        self._enforce(r, i)
                results.append(per_text)

            return {"text": texts, "results": results}

        def _enforce(self, r: OutputScanResult, i: int) -> None:
            msg = (
                f"prompt-shield output scanner {r.scanner_id!r} FLAGGED "
                f"text[{i}] (categories={list(r.categories or [])}, "
                f"confidence={r.confidence:.2f})"
            )
            if self.mode == "block":
                raise ValueError(msg)
            if self.mode == "flag":
                logger.warning(msg)
            else:
                logger.info(msg)

    return PromptShieldOutputGuard


class _MissingComponent:
    """Raised-on-instantiation stub used when haystack-ai is not installed."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise ImportError(_MISSING_MSG)


if _HAYSTACK_AVAILABLE:
    PromptShieldGuard: type = _make_guard_class()
    PromptShieldOutputGuard: type = _make_output_guard_class()
else:
    PromptShieldGuard = _MissingComponent  # type: ignore[misc,assignment]
    PromptShieldOutputGuard = _MissingComponent  # type: ignore[misc,assignment]


__all__ = ["PromptShieldGuard", "PromptShieldOutputGuard"]
