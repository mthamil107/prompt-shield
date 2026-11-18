"""Streaming guard primitives for incremental LLM output.

Public surface:

- :class:`StreamGuard` — hold-back buffer that scans a sliding window and
  releases text chunk-by-chunk.
- :class:`StreamReport` — summary returned by :meth:`StreamGuard.finish`.
- :class:`StreamFinding` — one detection surfaced by the guard.
- :class:`PromptShieldStreamBlocked` — raised in ``mode="block"`` on the
  first finding.

The streaming module delegates all detection logic to the existing output
scanners and canary leak detector — no detection rules live here.
"""

from __future__ import annotations

from prompt_shield.streaming.stream_guard import (
    PromptShieldStreamBlocked,
    StreamFinding,
    StreamGuard,
    StreamReport,
)

__all__ = [
    "PromptShieldStreamBlocked",
    "StreamFinding",
    "StreamGuard",
    "StreamReport",
]
