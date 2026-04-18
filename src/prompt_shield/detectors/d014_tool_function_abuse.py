"""Detector for tool and function abuse attempts."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class ToolFunctionAbuseDetector(BaseDetector):
    """Detects attempts to trick the AI into misusing its tools or API access.

    Adversaries craft instructions that coerce the model into calling
    destructive functions, executing commands, or accessing resources
    it should not touch.
    """

    detector_id: str = "d014_tool_function_abuse"
    name: str = "Tool / Function Abuse"
    description: str = "Detects attempts to trick the AI into misusing its tools or API access"
    severity: Severity = Severity.CRITICAL
    tags: ClassVar[list[str]] = ["indirect_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.8

    _patterns: ClassVar[list[tuple[str, str]]] = [
        (r"call\s+the\s+delete\s+function", "Delete function call"),
        (r"execute\s+\w+\s*\(", "Function execution attempt"),
        (r"run\s+the\s+following\s+command", "Command execution"),
        (r"use\s+your\s+\w+\s+to", "Tool usage instruction"),
        (r"invoke\s+\w+", "Invocation attempt"),
        (r"trigger\s+the\s+webhook", "Webhook trigger"),
        (r"access\s+the\s+database", "Database access"),
        (r"modify\s+the\s+file\s*system", "Filesystem modification"),
        (r"send\s+an?\s+API\s+request", "API request"),
        (r"use\s+your\s+code\s+interpreter", "Code interpreter abuse"),
        (r"rm\s+-rf", "Destructive command"),
        (r"DROP\s+TABLE", "SQL destructive command"),
        # JSON / tool-call / MCP injection patterns
        (
            r'"(?:function|tool|action|command)"\s*:\s*"[^"]*(?:execute|delete|remove|drop|shutdown|override|bypass)"',
            "JSON with dangerous function names",
        ),
        (
            r'"result"\s*:\s*"[^"]*(?:ignore\s+(?:all\s+)?(?:previous\s+)?instructions|you\s+are\s+now|new\s+instructions|system\s+prompt|override)',
            "Injection in tool result field",
        ),
        (
            r'"content"\s*:\s*"[^"]*(?:SYSTEM\s+OVERRIDE|IMPORTANT|IGNORE|NEW\s+INSTRUCTION|ADMIN|BYPASS)"',
            "Injection in content field with shouty keywords",
        ),
        (
            r"(?:tool|api|function|mcp)\s*(?:response|result|output|return)\s*:\s*\{",
            "Fake tool response structure",
        ),
        (
            r'"jsonrpc"\s*:\s*"2\.0".*"result".*(?:ignore|override|bypass|new\s+instruction|system\s+prompt)',
            "MCP/JSON-RPC injection",
        ),
        (
            r'\{\s*"(?:api_response|tool_response|server_response|mcp_response)"\s*:',
            "Fake API response wrapper",
        ),
        (
            r"(?:SYSTEM\s+OVERRIDE|NEW\s+DIRECTIVE|ADMIN\s+COMMAND|PRIORITY\s+INSTRUCTION)\s*:",
            "Authority-claiming keywords in structured data",
        ),
        (
            r'"arguments"\s*:\s*\{[^}]*(?:rm\s+-rf|drop\s+table|delete\s+from|os\.system|exec\(|eval\()',
            "Dangerous commands in function arguments",
        ),
    ]

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        matches: list[MatchDetail] = []

        for pattern_str, description in self._patterns:
            pattern = regex.compile(pattern_str, regex.IGNORECASE)
            for m in pattern.finditer(input_text):
                matches.append(
                    MatchDetail(
                        pattern=pattern_str,
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        description=description,
                    )
                )

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No suspicious patterns found",
            )

        confidence = min(1.0, self._base_confidence + 0.1 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(f"Detected {len(matches)} pattern(s) indicating {self.name.lower()}"),
        )
