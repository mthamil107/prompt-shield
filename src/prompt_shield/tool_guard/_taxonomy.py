"""Attack-family projection over ``DetectionResult.detector_id``.

Every detector ID maps to at most one ``ToolResultAttackFamily`` via the
``DETECTOR_TO_FAMILY`` dict below. The taxonomy is intentionally a
projection (not a parallel regex layer) so classification accuracy tracks
detector accuracy — no drift between confidence scores and family labels.

Only two gap-filling regex checks live here, both for signals that no
detector currently covers:

- ``CONTEXT_TERMINATION`` — fake prompt-boundary markers a la
  ``</context>``, ``---END---``, ``[END SYSTEM]``
- ``EXFILTRATION_COMMAND`` phrasing — imperative "send/post/email X to Y"
  augmenting ``d013_data_exfiltration``.
"""

from __future__ import annotations

import re

from prompt_shield.models import ScanReport, ToolResultAttackFamily

_FAMILY = ToolResultAttackFamily

DETECTOR_TO_FAMILY: dict[str, ToolResultAttackFamily] = {
    "d001_system_prompt_extraction": _FAMILY.EXFILTRATION_COMMAND,
    "d002_role_hijack": _FAMILY.ROLE_HIJACK,
    "d003_instruction_override": _FAMILY.IMPERATIVE_INJECTION,
    "d004_prompt_leaking": _FAMILY.EXFILTRATION_COMMAND,
    "d005_context_manipulation": _FAMILY.DELIMITER_INJECTION,
    "d007_task_deflection": _FAMILY.ROLE_HIJACK,
    "d008_base64_payload": _FAMILY.ENCODED_PAYLOAD,
    "d009_rot13_substitution": _FAMILY.ENCODED_PAYLOAD,
    "d010_unicode_homoglyph": _FAMILY.ENCODED_PAYLOAD,
    "d011_whitespace_injection": _FAMILY.ENCODED_PAYLOAD,
    "d012_markdown_html_injection": _FAMILY.RENDERED_EXFIL,
    "d013_data_exfiltration": _FAMILY.EXFILTRATION_COMMAND,
    "d014_tool_function_abuse": _FAMILY.TOOL_MISUSE,
    "d015_rag_poisoning": _FAMILY.IMPERATIVE_INJECTION,
    "d016_url_injection": _FAMILY.RENDERED_EXFIL,
    "d017_hypothetical_framing": _FAMILY.ROLE_HIJACK,
    "d018_academic_pretext": _FAMILY.ROLE_HIJACK,
    "d019_dual_persona": _FAMILY.ROLE_HIJACK,
    "d020_token_smuggling": _FAMILY.ENCODED_PAYLOAD,
    "d024_multilingual_injection": _FAMILY.IMPERATIVE_INJECTION,
    "d025_multi_encoding": _FAMILY.ENCODED_PAYLOAD,
    "d029_many_shot_structural": _FAMILY.IMPERATIVE_INJECTION,
    # Detectors that are policy / statistical / meta and do not project onto
    # a specific attack family are intentionally omitted here. If they fire
    # alone, the classifier returns [UNCLASSIFIED].
}

_CONTEXT_TERMINATION_RE = re.compile(
    r"(</\s*(?:context|system|user|instructions?)\s*>"
    r"|---+\s*END\s*---+"
    r"|\[\s*END\s+(?:SYSTEM|CONTEXT|PROMPT|INSTRUCTIONS?)\s*\])",
    re.IGNORECASE,
)

_EXFIL_COMMAND_RE = re.compile(
    r"\b(?:send|post|email|upload|forward|leak|transmit|exfiltrate|deliver|report)\b"
    r"[^.\n]{0,80}\b(?:to|at|toward|via)\b"
    r"[^.\n]{0,80}(?:https?://|www\.|@|[a-zA-Z0-9.-]+\.[a-z]{2,})",
    re.IGNORECASE,
)


def classify(scan_report: ScanReport, text: str) -> tuple[list[ToolResultAttackFamily], float]:
    """Project detections → attack families and return (families, mean_confidence).

    Mean confidence is computed over detections that mapped to a family;
    detections without a mapping do not lower the score. If any detector
    fired but none mapped, returns ``[UNCLASSIFIED]`` with the mean
    confidence of the unmapped detectors so the caller still sees a
    non-zero confidence.
    """
    families: list[ToolResultAttackFamily] = []
    mapped_confidences: list[float] = []
    seen: set[ToolResultAttackFamily] = set()

    for det in scan_report.detections:
        family = DETECTOR_TO_FAMILY.get(det.detector_id)
        if family is None:
            continue
        if family not in seen:
            families.append(family)
            seen.add(family)
        mapped_confidences.append(det.confidence)

    if _CONTEXT_TERMINATION_RE.search(text) and _FAMILY.CONTEXT_TERMINATION not in seen:
        families.append(_FAMILY.CONTEXT_TERMINATION)
        seen.add(_FAMILY.CONTEXT_TERMINATION)
        mapped_confidences.append(0.85)

    if _EXFIL_COMMAND_RE.search(text) and _FAMILY.EXFILTRATION_COMMAND not in seen:
        families.append(_FAMILY.EXFILTRATION_COMMAND)
        seen.add(_FAMILY.EXFILTRATION_COMMAND)
        mapped_confidences.append(0.75)

    if not families and scan_report.detections:
        families.append(_FAMILY.UNCLASSIFIED)
        mapped_confidences = [d.confidence for d in scan_report.detections]

    if not mapped_confidences:
        return families, 0.0
    mean = sum(mapped_confidences) / len(mapped_confidences)
    return families, min(1.0, max(0.0, mean))


def build_mitigation(families: list[ToolResultAttackFamily]) -> str:
    """Human-readable mitigation recommendation for the flagged families."""
    if not families:
        return "No mitigation required — content passed all detectors."

    hints: dict[ToolResultAttackFamily, str] = {
        _FAMILY.IMPERATIVE_INJECTION: (
            "drop the tool result before it enters the LLM context, or wrap "
            "it in a delimiter the model treats as untrusted data"
        ),
        _FAMILY.DELIMITER_INJECTION: (
            "escape or strip prompt-boundary tokens (system/user/context markers)"
        ),
        _FAMILY.CONTEXT_TERMINATION: (
            "strip fake end-of-context markers before concatenating with the trusted prompt"
        ),
        _FAMILY.EXFILTRATION_COMMAND: (
            "block; do NOT let this content instruct the agent — treat as adversarial"
        ),
        _FAMILY.ROLE_HIJACK: (
            "block or discard; do not permit tool content to redefine the agent's persona"
        ),
        _FAMILY.TOOL_MISUSE: (
            "block; verify no downstream tool calls were queued as a result of this content"
        ),
        _FAMILY.ENCODED_PAYLOAD: (
            "reject or normalize the encoding (base64/rot13/homoglyph/etc.) and rescan before use"
        ),
        _FAMILY.RENDERED_EXFIL: (
            "strip or CSP-sandbox markdown/links; disable image auto-fetch "
            "in the client that renders the response"
        ),
        _FAMILY.UNCLASSIFIED: (
            "review the detections list for the specific detectors that fired and decide by policy"
        ),
    }
    parts = [hints[f] for f in families if f in hints]
    return "; ".join(parts) if parts else "review detections and decide by policy"


__all__ = ["DETECTOR_TO_FAMILY", "build_mitigation", "classify"]
