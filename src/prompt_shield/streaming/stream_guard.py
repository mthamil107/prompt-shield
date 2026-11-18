"""``StreamGuard`` — hold-back buffer that scans a sliding window.

The guard sits between a streaming LLM response and the caller. It
accumulates deltas into a bounded hold-back window, scans that window
with the standard :class:`OutputScanEngine` (and, if canary tokens are
configured, with :class:`LeakDetector`), and releases text to the caller
chunk-by-chunk so a detection has a chance to fire *before* the full
response is emitted.

Mode semantics mid-stream:

- ``block`` — on the first finding during :meth:`feed` or :meth:`finish`,
  raise :class:`PromptShieldStreamBlocked`. The guard transitions to a
  terminal blocked state; subsequent :meth:`feed` / :meth:`finish` calls
  raise ``RuntimeError``. ``block`` stops **future** chunks. It cannot
  retract chunks already returned by prior :meth:`feed` calls — the caller
  must assume anything already yielded has been seen.
- ``flag`` — append the finding and keep releasing text; findings
  surface through :meth:`finish`.
- ``log`` — same as ``flag`` but emit ``logger.warning`` on each
  finding (the matched text itself is never logged).
- ``sanitize`` — not supported. Released text cannot be recalled, so a
  stream-time sanitizer would be a lie. Rejected in ``__init__``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from prompt_shield.canary.leak_detector import LeakDetector
from prompt_shield.output_scanners import OutputScanEngine
from prompt_shield.output_scanners.engine import available_scanners

if TYPE_CHECKING:
    from collections.abc import Sequence

    from prompt_shield.output_scanners.models import OutputScanResult

logger = logging.getLogger("prompt_shield.streaming")

_VALID_MODES: tuple[str, ...] = ("block", "flag", "log")

# Output scanners that only make sense on a whole response, not on a
# sliding fragment of one. ``sentiment`` reads tone; ``relevance`` and
# ``hallucination`` compare against the input question / context;
# ``schema_validation`` expects a complete JSON document. Each would
# fire spuriously on sub-complete fragments, so the stream-safe default
# set excludes them. Callers who want them can still pass ``scanners=``
# with these names explicitly.
_STREAM_UNSAFE_SCANNERS: frozenset[str] = frozenset(
    {"sentiment", "relevance", "hallucination", "schema_validation"}
)


@dataclass(frozen=True)
class StreamFinding:
    """One detection surfaced by :class:`StreamGuard` on a scanned window."""

    source: str
    scanner_id: str
    confidence: float
    categories: tuple[str, ...]
    explanation: str
    window_offset: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamReport:
    """Summary returned by :meth:`StreamGuard.finish`.

    Attributes
    ----------
    remaining_text:
        The held tail that was still buffered when :meth:`finish` ran.
        Callers MUST emit this after the feed loop to receive the
        complete stream — ``feed()`` only returns the safe-to-release
        prefix on each call, and the final ``hold_back + overlap`` chars
        stay buffered until ``finish()`` clears them for release.
    """

    mode: str
    released_chars: int
    total_chars: int
    blocked: bool
    findings: list[StreamFinding]
    scan_passes: int
    remaining_text: str = ""

    @property
    def was_blocked(self) -> bool:
        """Alias for :attr:`blocked` — reads naturally at call sites."""
        return self.blocked


class PromptShieldStreamBlocked(Exception):  # noqa: N818  (public API name, not an *Error)
    """Raised by :meth:`StreamGuard.feed` or :meth:`StreamGuard.finish`
    when ``mode="block"`` triggers.
    """

    def __init__(self, finding: StreamFinding, released_chars: int) -> None:
        super().__init__(
            f"stream blocked by {finding.scanner_id} (released_chars={released_chars})"
        )
        self.finding = finding
        self.released_chars = released_chars


class StreamGuard:
    """Hold-back buffer + sliding-window scanner for streaming LLM output.

    Parameters
    ----------
    mode:
        One of ``"block"``, ``"flag"``, ``"log"``. ``"sanitize"`` is
        rejected — released text cannot be recalled.
    hold_back:
        Minimum chars kept buffered before release. Payloads of length
        up to ``hold_back + overlap`` are guaranteed to appear fully
        inside at least one scan window.
    overlap:
        Extra chars kept in the sliding window on top of ``hold_back``.
        Carries context forward across feed boundaries so a payload
        split across two deltas is still seen whole by a single scan.
    engine:
        Optional :class:`OutputScanEngine`. Lazily constructed on first
        scan if ``None``.
    leak_detector:
        Optional :class:`LeakDetector`. Only used when ``canary_tokens``
        is non-empty; lazily constructed on first canary scan.
    canary_tokens:
        Iterable of hex canary tokens to check for in the sliding
        window. Each token fires at most once per stream (dedup is kept
        per instance).
    scanners:
        Scanner names forwarded to the engine on each scan. Three cases:

        - ``None`` (default) — use the stream-safe default set: every
          registered output scanner EXCEPT ``sentiment``, ``relevance``,
          ``hallucination`` and ``schema_validation``. Those four read
          whole-response context (tone, relatedness to the question,
          completeness of a JSON document) and fire spuriously on
          sub-complete fragments.
        - A non-empty list — use exactly the named scanners. Unknown
          names raise :class:`ValueError`.
        - An empty list — raises :class:`ValueError`. Pass ``None`` to
          mean the default set; passing ``[]`` to mean "disable all
          scanning" was a v1 footgun and is now an error.
    context:
        Optional context dict forwarded to the engine on each scan.

    Call contract
    -------------
    :meth:`feed` returns only the slice safe to release *so far*. The
    final ``hold_back + overlap`` chars stay buffered until
    :meth:`finish` runs — callers **MUST** emit
    :attr:`StreamReport.remaining_text` after the feed loop to receive
    the complete stream. Typical use::

        guard = StreamGuard(mode="flag")
        for chunk in stream:
            out = guard.feed(chunk.delta)
            yield out
        report = guard.finish()
        yield report.remaining_text

    Notes
    -----
    The guard is **sync-only**. :meth:`feed` and :meth:`finish` are
    CPU-bound; async callers can invoke them directly from inside an
    ``async for`` loop — the hold-back window is small enough that a
    scan does not block the event loop meaningfully.
    """

    def __init__(
        self,
        *,
        mode: str = "flag",
        hold_back: int = 256,
        overlap: int = 64,
        engine: OutputScanEngine | None = None,
        leak_detector: LeakDetector | None = None,
        canary_tokens: Sequence[str] = (),
        scanners: Sequence[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        if mode == "sanitize":
            raise ValueError(
                "sanitize mode is not supported on streams; released text cannot be recalled"
            )
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")
        if hold_back < 0:
            raise ValueError(f"hold_back must be >= 0, got {hold_back}")
        if overlap < 0:
            raise ValueError(f"overlap must be >= 0, got {overlap}")

        resolved_scanners = self._resolve_scanner_set(scanners)

        self.mode = mode
        self.hold_back = hold_back
        self.overlap = overlap
        self._engine: OutputScanEngine | None = engine
        self._leak_detector: LeakDetector | None = leak_detector
        self._canary_tokens: tuple[str, ...] = tuple(canary_tokens)
        self._scanners: list[str] = resolved_scanners
        self._context: dict[str, Any] | None = dict(context) if context else None

        # Buffer state — two plain strings plus counters, no deque/ring buffer.
        # Invariant: ``_window_start == _released_chars`` always. The slice
        # ``_held`` contains the absolute range ``[_window_start, _total_chars)``.
        self._held: str = ""
        self._total_chars: int = 0
        self._released_chars: int = 0
        self._window_start: int = 0
        # Absolute end offset of the last scan — used by finish() to
        # decide whether the held tail still needs its own scan pass.
        # (With the hold-back + overlap invariant, feed()'s scan usually
        # already covers the tail, so finish() can skip the extra pass.)
        self._last_scan_end: int = 0

        # Finding + state tracking.
        self._findings: list[StreamFinding] = []
        self._fired_canaries: set[str] = set()
        # Dedup key for non-canary scanner findings:
        # (scanner_id, rule_or_pattern, absolute_offset). A payload at
        # stream offset X that keeps sitting in the sliding window across
        # multiple rescans must fire only once.
        self._fired_findings: set[tuple[str, str, int]] = set()
        # Scanners that flagged without positional matches on the previous
        # pass; they fire only on the rising edge (see _scan_window).
        self._positionless_active: set[str] = set()
        self._scan_passes: int = 0
        self._finalized: bool = False
        self._blocked: bool = False
        self._final_report: StreamReport | None = None

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def released_chars(self) -> int:
        """Total chars that have been handed back from :meth:`feed`."""
        return self._released_chars

    @property
    def total_chars(self) -> int:
        """Total chars fed into :meth:`feed` so far."""
        return self._total_chars

    @property
    def engine(self) -> OutputScanEngine:
        """The output-scan engine, lazily constructed on initial access."""
        if self._engine is None:
            self._engine = OutputScanEngine()
        return self._engine

    @property
    def leak_detector(self) -> LeakDetector:
        """The canary leak detector, lazily constructed on initial access."""
        if self._leak_detector is None:
            self._leak_detector = LeakDetector()
        return self._leak_detector

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, delta: str) -> str:
        """Feed a chunk of streamed text; return the slice safe to release.

        Each call scans a region of length
        ``<= hold_back + overlap + len(delta)``. Total work for a stream
        of N chars is ``O(N * (hold_back + overlap) / d)`` where ``d`` is
        the typical delta size — linear in N, never quadratic.

        ``feed("")`` is a no-op and returns ``""``.
        """
        if self._blocked:
            raise RuntimeError("StreamGuard is blocked; no further chunks accepted")
        if self._finalized:
            raise RuntimeError("StreamGuard is finalized")
        if not isinstance(delta, str):
            raise TypeError(f"delta must be str, got {type(delta).__name__}")
        if not delta:
            return ""

        # Grow the scan region by the new delta. ``scan_region`` is the
        # full sliding window: everything we currently hold plus the
        # fresh delta. It starts at absolute offset ``_window_start``.
        scan_region = self._held + delta
        new_total = self._total_chars + len(delta)

        # Scan before release, so a finding can veto the chunk when
        # ``mode="block"`` — we must raise before handing bytes back.
        scan_findings = self._scan_window(scan_region, self._window_start)
        self._last_scan_end = self._window_start + len(scan_region)
        for finding in scan_findings:
            self._record_finding(finding)
            if self.mode == "block":
                self._blocked = True
                # Build the final report so finish() stays idempotent
                # and returns a consistent view even after block fired.
                self._total_chars = new_total
                self._final_report = StreamReport(
                    mode=self.mode,
                    released_chars=self._released_chars,
                    total_chars=self._total_chars,
                    blocked=True,
                    findings=list(self._findings),
                    scan_passes=self._scan_passes,
                    remaining_text="",
                )
                self._finalized = True
                raise PromptShieldStreamBlocked(
                    finding=finding, released_chars=self._released_chars
                )

        # Release prefix of ``scan_region`` whose end lies at or before
        # ``release_up_to``. Keep the suffix as the new ``_held`` so
        # subsequent feeds re-scan an overlap window — the invariant
        # ``len(_held) <= hold_back + overlap`` after release gives the
        # linear-time guarantee at the top of this method.
        keep_min = self.hold_back + self.overlap
        release_up_to = max(0, new_total - keep_min)
        release_count = max(0, release_up_to - self._window_start)
        released = scan_region[:release_count]
        self._held = scan_region[release_count:]
        self._released_chars += release_count
        self._total_chars = new_total
        self._window_start = self._released_chars
        return released

    def finish(self) -> StreamReport:
        """Flush the hold-back tail, run a final scan, and return the report.

        Sets :attr:`StreamReport.remaining_text` to whatever text was
        still held when the stream ended — callers MUST emit this after
        their feed loop to receive the complete stream (see the class
        docstring's call contract).

        In ``mode="block"``, if a new finding fires on the tail (after
        dedup), raises :class:`PromptShieldStreamBlocked` instead of
        returning. After a block raise from this method, subsequent
        :meth:`finish` calls raise ``RuntimeError``; after a clean
        finish, this method is idempotent and returns the same report.
        """
        if self._blocked:
            # Terminal blocked state reached via either feed() or a
            # prior finish() call. If feed() raised, a cached pre-block
            # report is available and this call is idempotent. If a
            # prior finish() raised, no report was cached and subsequent
            # finish() calls raise RuntimeError.
            if self._final_report is not None:
                return self._final_report
            raise RuntimeError("StreamGuard is blocked; finish() already raised")
        if self._finalized:
            # Clean finish; same report object every time.
            assert self._final_report is not None  # for mypy; set together with _finalized
            return self._final_report

        # Scan the tail only if the last feed() scan did not already
        # cover it. By the hold-back + overlap invariant, ``_held`` is
        # always a suffix of the last scanned region, so this normally
        # skips. The guard runs here anyway for safety: if a future
        # change breaks the invariant, or if the stream ended with no
        # feed() calls at all, we still get one scan over the tail.
        tail_end = self._total_chars
        if self._held and tail_end > self._last_scan_end:
            tail_window_start = self._total_chars - len(self._held)
            tail_findings = self._scan_window(self._held, tail_window_start)
            self._last_scan_end = tail_end
            for finding in tail_findings:
                self._record_finding(finding)
                if self.mode == "block":
                    # Fail closed: transition to the blocked terminal
                    # state and raise. The tail stays buffered; the
                    # caller MUST NOT emit it. No cached report —
                    # subsequent finish() calls raise RuntimeError.
                    self._blocked = True
                    raise PromptShieldStreamBlocked(
                        finding=finding, released_chars=self._released_chars
                    )

        # Clean finish: surface the tail through the report.
        remaining = self._held
        self._released_chars = self._total_chars
        self._held = ""
        self._window_start = self._total_chars

        report = StreamReport(
            mode=self.mode,
            released_chars=self._released_chars,
            total_chars=self._total_chars,
            blocked=self._blocked,
            findings=list(self._findings),
            scan_passes=self._scan_passes,
            remaining_text=remaining,
        )
        self._final_report = report
        self._finalized = True
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_scanner_set(scanners: Sequence[str] | None) -> list[str]:
        """Validate ``scanners`` and expand ``None`` to the stream-safe default.

        - ``None`` -> every registered scanner except the four in
          :data:`_STREAM_UNSAFE_SCANNERS`.
        - Empty sequence -> ``ValueError`` (v1 footgun; was silently
          "run every scanner").
        - Non-empty sequence -> the sequence itself, after verifying
          each name resolves to a known scanner (short name OR
          ``scanner_id``).
        """
        catalog = available_scanners()
        short_to_id = {entry["name"]: entry["scanner_id"] for entry in catalog}
        id_to_short = {entry["scanner_id"]: entry["name"] for entry in catalog}

        if scanners is None:
            # Default: every short name except the unsafe four.
            return [name for name in short_to_id if name not in _STREAM_UNSAFE_SCANNERS]

        requested = list(scanners)
        if not requested:
            raise ValueError(
                "empty scanners list disables scanning entirely - pass None "
                "for default set or name explicit scanners"
            )

        resolved: list[str] = []
        unknown: list[str] = []
        for raw in requested:
            key = str(raw).strip().lower()
            if key in short_to_id:
                resolved.append(key)
            elif key in id_to_short:
                resolved.append(id_to_short[key])
            else:
                unknown.append(raw)
        if unknown:
            known = sorted(short_to_id.keys())
            raise ValueError(f"unknown scanner names: {unknown!r}; known short names: {known}")
        return resolved

    def _scan_window(self, window_text: str, window_absolute_start: int) -> list[StreamFinding]:
        """Scan ``window_text`` with the engine + canary detector.

        Returns the list of :class:`StreamFinding` objects that fired on
        this window. Non-canary scanner findings are deduped across
        rescans on ``(scanner_id, pattern_or_empty, absolute_offset)``;
        canaries are deduped per token via ``_fired_canaries``. Does NOT
        mutate :attr:`_findings` — ``feed`` and ``finish`` decide what
        to do with each returned finding.
        """
        findings: list[StreamFinding] = []
        if not window_text:
            return findings

        # Output-scan engine pass. One scan per window; the engine is
        # stateless across ``scan()`` calls so this is safe.
        report = self.engine.scan(window_text, scanners=self._scanners, context=self._context)
        self._scan_passes += 1
        positionless_now: set[str] = set()
        for result in report.flags:
            if not result.flagged:
                continue
            finding = self._finding_from_scanner(result, window_absolute_start)
            if not any(m.position is not None for m in result.matches):
                # No positional match: the offset would be the moving
                # window start, so a positional key never repeats. Fire
                # only on the rising edge (scanner not flagged last pass).
                positionless_now.add(result.scanner_id)
                if result.scanner_id in self._positionless_active:
                    continue
                findings.append(finding)
                continue
            key = self._finding_dedup_key(result, finding)
            if key in self._fired_findings:
                # Same payload seen on an earlier rescan - swallow the
                # duplicate so flag/log mode does not multiply findings
                # proportional to window overlap.
                continue
            self._fired_findings.add(key)
            findings.append(finding)
        # Scanners that did not flag position-less this pass may fire
        # again for a later, separate occurrence.
        self._positionless_active = positionless_now

        # Canary leak pass. Each token fires at most once per stream to
        # keep ``finish().findings`` from blowing up on long leaks.
        for token in self._canary_tokens:
            if token in self._fired_canaries:
                continue
            if self.leak_detector.check(window_text, token):
                self._fired_canaries.add(token)
                match_offset = self._canary_match_offset(window_text, token)
                findings.append(
                    StreamFinding(
                        source="canary",
                        scanner_id="canary_leak",
                        confidence=1.0,
                        categories=("canary_leak",),
                        explanation="canary token (or a significant fragment) "
                        "appeared in the streamed response",
                        window_offset=window_absolute_start + match_offset,
                        metadata={"token_length": len(token)},
                    )
                )

        return findings

    def _finding_from_scanner(
        self, result: OutputScanResult, window_absolute_start: int
    ) -> StreamFinding:
        """Translate an :class:`OutputScanResult` to a :class:`StreamFinding`.

        Offsets reported by scanners are relative to the window; add
        ``window_absolute_start`` to recover an absolute stream offset.
        If the result carries no positional match, fall back to the
        window start — the caller still gets a correct lower bound.
        """
        match_offset = 0
        for match in result.matches:
            if match.position is not None:
                match_offset = int(match.position[0])
                break

        return StreamFinding(
            source="output_scanner",
            scanner_id=result.scanner_id,
            confidence=result.confidence,
            categories=tuple(result.categories),
            explanation=result.explanation,
            window_offset=window_absolute_start + match_offset,
            metadata=dict(result.metadata),
        )

    @staticmethod
    def _finding_dedup_key(
        result: OutputScanResult, finding: StreamFinding
    ) -> tuple[str, str, int]:
        """Build the dedup key for a scanner finding.

        Key shape: ``(scanner_id, rule_or_pattern, absolute_offset)``.
        ``OutputScanResult`` has no ``rule_id`` field, so the first
        match's ``pattern`` (or ``""`` if the scanner returned no
        positional matches) stands in — distinct rules at the same
        offset stay distinct.
        """
        pattern = ""
        for match in result.matches:
            if match.pattern:
                pattern = match.pattern
                break
        return (result.scanner_id, pattern, finding.window_offset)

    @staticmethod
    def _canary_match_offset(window_text: str, token: str) -> int:
        """Return the position of the canary token (or fragment) in the window.

        Mirrors :meth:`LeakDetector.check`'s detection order so the
        reported offset matches what actually tripped the detector.
        Returns 0 if neither the full token nor any fragment ≥ 9 chars
        is found (the caller will then report the window start as the
        offset — a correct lower bound, not a lie).
        """
        window_lower = window_text.lower()
        token_lower = token.lower()
        idx = window_lower.find(token_lower)
        if idx >= 0:
            return idx
        # Partial match — same sliding window as LeakDetector.
        token_len = len(token_lower)
        for length in range(token_len - 1, 8, -1):
            for start in range(token_len - length + 1):
                fragment = token_lower[start : start + length]
                frag_idx = window_lower.find(fragment)
                if frag_idx >= 0:
                    return frag_idx
        return 0

    def _record_finding(self, finding: StreamFinding) -> None:
        """Append ``finding`` to the running list and emit mode-specific side effects."""
        self._findings.append(finding)
        if self.mode == "log":
            logger.warning(
                "stream finding: scanner=%s confidence=%.2f categories=%s",
                finding.scanner_id,
                finding.confidence,
                finding.categories,
            )
