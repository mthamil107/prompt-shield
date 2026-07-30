"""Honeypot tool-definitions detector (d034).

Fires when input text mentions -- or a tool-call context invokes -- one
of a set of *honeypot* tools that the operator has registered alongside
their real tools. A honeypot is a fake tool with an obviously-attractive
name (``admin_shell``, ``internal_debug_console``, ...) that no legitimate
agent workflow would ever use. Any mention or invocation is therefore
high-confidence evidence of a prompt-injection payload having reached
the model.

The technique is described in the prompt-shield paper (v4, section 4.3
"Honeypot Tool Definitions") as a *proposed* defense; this module is the
implementation. It complements d014 (tool/function abuse patterns) with
a zero-false-positive signal derived purely from deployment-specific
tool naming conventions.

Two firing modes
----------------

1. **Text-mention mode** (confidence 0.95). ``input_text`` contains one
   of the honeypot names as a word-bounded token. Handles payloads that
   *name* the honeypot -- e.g. ``"call admin_shell with args {...}"``.

2. **Context-invocation mode** (confidence 1.0). ``context["tool_calls"]``
   is a list of dicts and at least one entry's ``name`` field matches a
   honeypot. This is the paper's headline signal: the model was actually
   coerced into invoking a fake tool.

Configuration (``d034_honeypot_tool`` block in default.yaml)
------------------------------------------------------------

.. code-block:: yaml

    d034_honeypot_tool:
      enabled: true
      severity: critical
      honeypot_tools:
        - admin_shell
        - internal_debug_console
        - system_key_dump
        - sudo_execute_raw
        - priv_esc_helper

Operators SHOULD register these names as real (but no-op / trap)
tools in the agent's tool schema so a well-behaved model has zero
reason to reference them. Any hit is a canary.
"""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger(__name__)

DEFAULT_HONEYPOT_TOOLS: tuple[str, ...] = (
    "admin_shell",
    "internal_debug_console",
    "system_key_dump",
    "sudo_execute_raw",
    "priv_esc_helper",
)


class HoneypotToolDetector(BaseDetector):
    """Detect mentions or invocations of registered honeypot tools."""

    detector_id: str = "d034_honeypot_tool"
    name: str = "Honeypot Tool Definitions"
    description: str = (
        "Flag any reference to or invocation of a registered honeypot tool. "
        "Honeypots are fake tools with attractive names that a legitimate "
        "workflow would never use; a hit is high-confidence evidence of "
        "injection regardless of payload content."
    )
    severity: Severity = Severity.CRITICAL
    tags: ClassVar[list[str]] = ["indirect_injection", "tool_misuse", "honeypot"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _TEXT_CONFIDENCE: ClassVar[float] = 0.95
    _INVOCATION_CONFIDENCE: ClassVar[float] = 1.0

    def __init__(self) -> None:
        self._honeypots: tuple[str, ...] = DEFAULT_HONEYPOT_TOOLS
        self._honeypot_lookup: frozenset[str] = frozenset(n.lower() for n in DEFAULT_HONEYPOT_TOOLS)
        self._compiled: re.Pattern[str] | None = self._compile(DEFAULT_HONEYPOT_TOOLS)

    def setup(self, config: dict[str, object]) -> None:
        raw = config.get("honeypot_tools")
        names: list[str] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, str) and item.strip():
                    names.append(item.strip())
        if not names:
            # Missing/empty config keeps the built-in defaults so an
            # operator that only sets ``enabled: true`` still gets the
            # baseline behavior described in the paper.
            names = list(DEFAULT_HONEYPOT_TOOLS)

        # Deduplicate while preserving first-seen order.
        seen: set[str] = set()
        unique: list[str] = []
        for n in names:
            low = n.lower()
            if low in seen:
                continue
            seen.add(low)
            unique.append(n)

        self._honeypots = tuple(unique)
        self._honeypot_lookup = frozenset(n.lower() for n in unique)
        self._compiled = self._compile(unique)
        logger.info(
            "d034_honeypot_tool: registered %d honeypot tool name(s)",
            len(self._honeypots),
        )

    @staticmethod
    def _compile(names: tuple[str, ...] | list[str]) -> re.Pattern[str] | None:
        if not names:
            return None
        # ``\b`` word boundaries prevent ``admin_shell`` from matching
        # ``admin_shellish``. Underscore is a word character in Python
        # regex, so the boundary is well-defined at both ends.
        alternation = "|".join(re.escape(n) for n in names)
        return re.compile(rf"\b(?:{alternation})\b", re.IGNORECASE)

    def _iter_context_tool_calls(
        self,
        context: dict[str, object] | None,
    ) -> list[str]:
        """Extract honeypot names invoked in ``context['tool_calls']``.

        Accepts a list of dicts each with a ``name`` (or ``tool``,
        ``function``) field. Silently ignores anything else so a caller
        passing a novel structure never crashes the scan.
        """
        if not context:
            return []
        tool_calls = context.get("tool_calls")
        if not isinstance(tool_calls, list):
            return []
        hits: list[str] = []
        for call in tool_calls:
            if not isinstance(call, dict):
                continue
            name = self._extract_call_name(call)
            if name and name.lower() in self._honeypot_lookup:
                hits.append(name)
        return hits

    @staticmethod
    def _extract_call_name(call: dict[str, object]) -> str | None:
        """Extract the tool-call name across the shapes real frameworks use.

        Accepts:
          - flat string:            ``{"name": "admin_shell"}``
          - alternate flat keys:    ``{"tool": "..."}``, ``{"function": "..."}``,
                                    ``{"tool_name": "..."}``, ``{"function_name": "..."}``
          - OpenAI nested function: ``{"type": "function", "function": {"name": "admin_shell", ...}}``
          - Anthropic tool_use:     ``{"type": "tool_use", "name": "admin_shell", ...}`` (flat, covered above)
          - Nested under ``tool``:  ``{"tool": {"name": "admin_shell"}}``

        Returns the first string-typed name found, or None.
        """
        # Try flat keys first (Anthropic / bare-dict shape).
        for key in ("name", "tool_name", "function_name"):
            value = call.get(key)
            if isinstance(value, str):
                return value
        # Then nested-dict shapes (OpenAI / structured tool-call).
        for wrapper_key in ("function", "tool"):
            wrapper = call.get(wrapper_key)
            if isinstance(wrapper, str):
                return wrapper
            if isinstance(wrapper, dict):
                nested_name = wrapper.get("name")
                if isinstance(nested_name, str):
                    return nested_name
        return None

    def detect(
        self,
        input_text: str,
        context: dict[str, object] | None = None,
    ) -> DetectionResult:
        # (b) Context-invocation mode -- strongest signal, checked first.
        invoked = self._iter_context_tool_calls(context)
        if invoked:
            names = ", ".join(sorted({n.lower() for n in invoked}))
            return DetectionResult(
                detector_id=self.detector_id,
                detected=True,
                confidence=self._INVOCATION_CONFIDENCE,
                severity=self.severity,
                matches=[
                    MatchDetail(
                        pattern=f"honeypot_invocation:{n.lower()}",
                        matched_text=n,
                        position=None,
                        description=f"Honeypot tool '{n}' was invoked via tool_calls context",
                    )
                    for n in invoked
                ],
                explanation=(
                    f"Honeypot tool invocation detected via tool_calls context: {names}. "
                    "No legitimate workflow should ever call these names."
                ),
                metadata={
                    "mode": "context_invocation",
                    "invoked_honeypots": sorted({n.lower() for n in invoked}),
                    "honeypot_count": len(self._honeypots),
                },
            )

        # (a) Text-mention mode.
        if self._compiled is None or not input_text:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    "No honeypot tools registered" if self._compiled is None else "Empty input"
                ),
            )

        matches: list[MatchDetail] = []
        seen_names: set[str] = set()
        for m in self._compiled.finditer(input_text):
            matched = m.group(0)
            key = matched.lower()
            if key in seen_names:
                continue
            seen_names.add(key)
            matches.append(
                MatchDetail(
                    pattern=f"honeypot_mention:{key}",
                    matched_text=matched,
                    position=(m.start(), m.end()),
                    description=f"Honeypot tool name '{matched}' mentioned in input",
                )
            )

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No honeypot tool names present in input",
            )

        names = ", ".join(sorted(seen_names))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=self._TEXT_CONFIDENCE,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Honeypot tool name(s) mentioned in input: {names}. "
                "Legitimate prompts should not reference these names."
            ),
            metadata={
                "mode": "text_mention",
                "mentioned_honeypots": sorted(seen_names),
                "honeypot_count": len(self._honeypots),
            },
        )
