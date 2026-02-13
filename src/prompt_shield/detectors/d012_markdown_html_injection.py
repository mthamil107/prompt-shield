"""Detector for Markdown and HTML injection attacks."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class MarkdownHtmlInjectionDetector(BaseDetector):
    """Detects injection of formatting or markup that could alter rendering or behavior.

    Attackers inject HTML tags, JavaScript URIs, or template syntax into
    prompts to exploit downstream rendering or trigger unintended actions.
    """

    detector_id: str = "d012_markdown_html_injection"
    name: str = "Markdown / HTML Injection"
    description: str = (
        "Detects injection of formatting or markup that could alter "
        "rendering or behavior"
    )
    severity: Severity = Severity.MEDIUM
    tags: list[str] = ["indirect_injection", "obfuscation"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _base_confidence: float = 0.75

    _patterns: list[tuple[str, str]] = [
        (r"<script[\s>]", "Script tag injection"),
        (r"<img\s[^>]*onerror", "Image tag with error handler"),
        (r"<iframe[\s>]", "Iframe injection"),
        (r"<object[\s>]", "Object tag injection"),
        (r"<embed[\s>]", "Embed tag injection"),
        (r"<link\s[^>]*href", "Link tag injection"),
        (r"on\w+\s*=", "HTML event handler"),
        (r"javascript:", "JavaScript URI"),
        (r"data:\s*text/html", "Data URI with HTML"),
        (r"\{\{.*\}\}", "Template injection (double braces)"),
        (r"\{%.*%\}", "Template injection (block tags)"),
        (r"!\[.*?\]\(https?://\S+\)", "Markdown image with external URL"),
    ]

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
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
            explanation=(
                f"Detected {len(matches)} pattern(s) indicating "
                f"{self.name.lower()}"
            ),
        )
