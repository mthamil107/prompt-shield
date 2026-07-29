"""Aggregator for all output scanners.

Provides :class:`OutputScanEngine`, a single entry point that runs the
nine bundled output scanners against an LLM response and returns a
combined :class:`OutputScanReport`. Callers can either scan with every
scanner or select a subset by name (short alias) or ``scanner_id``.

Example
-------
>>> from prompt_shield.output_scanners import OutputScanEngine
>>> engine = OutputScanEngine()
>>> report = engine.scan("Sure! Here's how to hack a server: Step 1...")
>>> report.flagged
True
>>> for flag in report.flags:
...     print(flag.scanner_id, flag.categories)
"""

from __future__ import annotations

import logging
import time
from typing import Any

from prompt_shield.output_scanners.base import (
    BaseOutputScanner,  # noqa: TC001  (runtime import: registry dict entries subclass this)
)
from prompt_shield.output_scanners.bias_fairness import BiasFairnessOutputScanner
from prompt_shield.output_scanners.code_injection import CodeInjectionScanner
from prompt_shield.output_scanners.hallucination import HallucinationOutputScanner
from prompt_shield.output_scanners.models import OutputScanReport, OutputScanResult
from prompt_shield.output_scanners.output_pii import OutputPIIScanner
from prompt_shield.output_scanners.prompt_leakage import PromptLeakageScanner
from prompt_shield.output_scanners.relevance import RelevanceScanner
from prompt_shield.output_scanners.schema_validation import SchemaValidationScanner
from prompt_shield.output_scanners.sentiment import SentimentOutputScanner
from prompt_shield.output_scanners.toxicity import ToxicityScanner

logger = logging.getLogger(__name__)


# Short-name registry used by the CLI/REST layers. Maps a friendly key
# (used on the command line and in JSON bodies) to the concrete scanner
# class. The order defines the canonical iteration order for `scan(...)`
# so listings and reports are stable across runs.
_SCANNER_REGISTRY: list[tuple[str, type[BaseOutputScanner]]] = [
    ("toxicity", ToxicityScanner),
    ("code_injection", CodeInjectionScanner),
    ("prompt_leakage", PromptLeakageScanner),
    ("pii", OutputPIIScanner),
    ("schema_validation", SchemaValidationScanner),
    ("bias_fairness", BiasFairnessOutputScanner),
    ("sentiment", SentimentOutputScanner),
    ("hallucination", HallucinationOutputScanner),
    ("relevance", RelevanceScanner),
]


def available_scanners() -> list[dict[str, str]]:
    """Return the catalogue of scanner names / IDs / descriptions."""
    catalog: list[dict[str, str]] = []
    for short, cls in _SCANNER_REGISTRY:
        # Instantiate lazily so we don't pay the cost of building
        # every scanner just to describe them. The class attributes are
        # populated at class definition, so no instance is required.
        catalog.append(
            {
                "name": short,
                "scanner_id": getattr(cls, "scanner_id", short),
                "description": getattr(cls, "description", "") or "",
            }
        )
    return catalog


class OutputScanEngine:
    """Run every bundled output scanner against LLM-generated text.

    Parameters
    ----------
    config:
        Optional per-scanner configuration dictionary. Keys are short
        scanner names (``toxicity``, ``pii``, ``bias_fairness``,  …) and
        values are the config dict passed to each scanner's
        :meth:`BaseOutputScanner.setup`. Scanners that don't override
        ``setup`` silently ignore their entry.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config: dict[str, Any] = dict(config or {})
        self._scanners: dict[str, BaseOutputScanner] = {}
        self._id_to_name: dict[str, str] = {}

        for short, cls in _SCANNER_REGISTRY:
            instance = cls()
            # Give every scanner a chance to load its config. Base impl
            # is a no-op, so this is safe even for scanners with no
            # meaningful configuration.
            try:
                instance.setup(self._config.get(short, {}))
            except Exception:  # pragma: no cover - never let one bad config brick the engine
                logger.exception("Failed to configure output scanner %s", short)
            self._scanners[short] = instance
            self._id_to_name[getattr(instance, "scanner_id", short)] = short

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_scanners(self) -> list[dict[str, str]]:
        """Return the catalog of scanners this engine knows about."""
        return available_scanners()

    def scan(
        self,
        text: str,
        scanners: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> OutputScanReport:
        """Scan *text* with every scanner, or only the named subset.

        Parameters
        ----------
        text:
            The LLM-generated text to inspect.
        scanners:
            Optional list of scanner names to run. Each entry may be a
            short name (``toxicity``, ``pii``) or a full ``scanner_id``
            (``output_pii``, ``output_code_injection``). Unknown entries
            are ignored with a warning so the caller doesn't have to
            defend against typos.
        context:
            Optional context dict forwarded to every scanner.  Some
            scanners (``hallucination``, ``schema_validation``) rely on
            it — the rest ignore it.
        """
        chosen = self._resolve(scanners)
        start = time.perf_counter()

        flags: list[OutputScanResult] = []
        for name in chosen:
            scanner = self._scanners[name]
            try:
                result = scanner.scan(text, context=context)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Scanner %s raised %r — treating as no-detection", name, exc)
                continue
            flags.append(result)

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        detected = [f for f in flags if f.flagged]
        overall_flagged = bool(detected)
        # Overall risk score = max confidence across flagged scanners.
        # Matches the intuition of ``max`` used by the input engine and
        # keeps the score in [0, 1].
        risk_score = max((f.confidence for f in detected), default=0.0)

        return OutputScanReport(
            output_text=text,
            total_scanners_run=len(chosen),
            flagged=overall_flagged,
            flags=flags,
            scan_duration_ms=elapsed_ms,
            overall_risk_score=risk_score,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve(self, scanners: list[str] | None) -> list[str]:
        """Translate a user-facing list into canonical short names."""
        if not scanners:
            return list(self._scanners.keys())

        resolved: list[str] = []
        seen: set[str] = set()
        for raw in scanners:
            key = str(raw).strip().lower()
            if not key:
                continue
            if key in self._scanners:
                short = key
            elif key in self._id_to_name:
                short = self._id_to_name[key]
            else:
                logger.warning("Unknown output scanner %r — skipping", raw)
                continue
            if short in seen:
                continue
            seen.add(short)
            resolved.append(short)
        return resolved
