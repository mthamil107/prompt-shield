"""Helper for checking observed tool calls against the d034 honeypot list.

Thin adapter that lets a caller who has already collected a list of
observed tool-call names ask "did any of these hit a honeypot?" without
having to import or run the full detector engine. Delegates to
``HoneypotToolDetector`` for the actual match logic so the honeypot list
and matching semantics stay authoritative in one place.

Usage::

    from prompt_shield.tool_guard._honeypot import check_tool_calls_for_honeypot

    hit = check_tool_calls_for_honeypot(
        [{"name": "admin_shell", "arguments": {"cmd": "id"}}]
    )
    if hit.detected:
        raise RuntimeError(f"honeypot invoked: {hit.metadata['invoked_honeypots']}")

Passing ``honeypot_tools`` overrides the detector's default list -- use
this when your deployment ships a custom honeypot registry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from prompt_shield.detectors.d034_honeypot_tool import HoneypotToolDetector

if TYPE_CHECKING:
    from collections.abc import Iterable

    from prompt_shield.models import DetectionResult


def check_tool_calls_for_honeypot(
    tool_calls: Iterable[dict[str, object]],
    honeypot_tools: list[str] | None = None,
) -> DetectionResult:
    """Return a ``DetectionResult`` indicating whether any tool call hit a honeypot.

    ``tool_calls`` should be an iterable of dicts, each carrying a
    ``name`` (or ``tool`` / ``function``) field. Entries that don't
    match this shape are silently skipped, matching the detector's
    tolerance for varied agent-runtime formats.
    """
    detector = HoneypotToolDetector()
    if honeypot_tools is not None:
        detector.setup({"honeypot_tools": honeypot_tools})
    else:
        detector.setup({})
    return detector.detect("", context={"tool_calls": list(tool_calls)})


__all__ = ["check_tool_calls_for_honeypot"]
