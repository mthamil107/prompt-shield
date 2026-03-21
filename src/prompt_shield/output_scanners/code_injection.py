"""Output scanner for dangerous code injection patterns in LLM responses."""

from __future__ import annotations

from typing import ClassVar

import regex

from prompt_shield.models import MatchDetail, Severity
from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.models import OutputScanResult

# ---------------------------------------------------------------------------
# Pattern categories
# ---------------------------------------------------------------------------

_PATTERN_CATEGORIES: dict[str, list[tuple[str, str]]] = {
    "sql_injection": [
        (
            r"(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE|ALTER\s+TABLE|UPDATE\s+\w+\s+SET)\s+\w+",
            "Destructive SQL statement",
        ),
        (
            r"(?:UNION\s+(?:ALL\s+)?SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'\s*=\s*'|;\s*DROP|;\s*DELETE|;\s*INSERT)",
            "SQL injection pattern",
        ),
        (
            r"(?:xp_cmdshell|EXEC\s+sp_|INTO\s+OUTFILE|LOAD_FILE|BENCHMARK\s*\()",
            "Dangerous SQL function",
        ),
    ],
    "shell_injection": [
        (
            r"(?:;\s*(?:rm\s+-rf|chmod\s+777|curl\s+.*\|\s*(?:sh|bash)|wget\s+.*\|\s*(?:sh|bash)))",
            "Chained shell command",
        ),
        (
            r"(?:os\.system|subprocess\.(?:call|run|Popen)|exec\s*\(|eval\s*\()\s*\(?\s*['\x22f]",
            "Python code execution",
        ),
        (
            r"(?:\$\(|`)\s*(?:rm|wget|curl|nc|ncat|bash|sh|python|perl|ruby)",
            "Command substitution",
        ),
        (
            r"(?:import\s+os|import\s+subprocess|from\s+os\s+import|__import__).*(?:system|popen|exec|eval)",
            "Dangerous Python import with execution",
        ),
        (
            r"""(?:require\s*\(\s*['"]child_process['"]\)|child_process\.exec)""",
            "Node.js command execution",
        ),
        (
            r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)",
            "Java command execution",
        ),
    ],
    "xss": [
        (
            r"<script[^>]*>.*?</script>",
            "Script tag",
        ),
        (
            r"(?:on(?:load|error|click|mouseover|submit|focus|blur)\s*=\s*['\x22]\s*(?:javascript|alert|confirm|prompt|eval|fetch|XMLHttpRequest))",
            "Event handler with script execution",
        ),
        (
            r"(?:javascript\s*:|data\s*:text/html)",
            "JavaScript or data URI",
        ),
        (
            r"(?:document\.(?:cookie|location|write)|window\.(?:location|open)|innerHTML\s*=)",
            "DOM manipulation",
        ),
    ],
    "path_traversal": [
        (
            r"(?:\.\./){2,}",
            "Multiple directory traversals",
        ),
        (
            r"(?:/etc/(?:passwd|shadow|hosts)|/proc/self|C:\\Windows\\System32)",
            "Sensitive file path",
        ),
        (
            r"(?:file://|php://|data://|expect://|zip://)",
            "Dangerous protocol handler",
        ),
    ],
    "ssrf": [
        (
            r"(?:http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+))",
            "Internal network URL",
        ),
        (
            r"(?:169\.254\.169\.254|metadata\.google\.internal)",
            "Cloud metadata endpoint",
        ),
    ],
    "deserialization": [
        (
            r"(?:pickle\.loads|yaml\.(?:load|unsafe_load)|unserialize|ObjectInputStream|eval\s*\(\s*atob)",
            "Unsafe deserialization",
        ),
    ],
}

_CATEGORY_SEVERITY: dict[str, Severity] = {
    "sql_injection": Severity.HIGH,
    "shell_injection": Severity.CRITICAL,
    "xss": Severity.HIGH,
    "path_traversal": Severity.MEDIUM,
    "ssrf": Severity.HIGH,
    "deserialization": Severity.CRITICAL,
}

# ---------------------------------------------------------------------------
# Pre-compile all patterns once at module load
# ---------------------------------------------------------------------------

_COMPILED_PATTERNS: dict[str, list[tuple[regex.Pattern[str], str]]] = {}

for _cat, _pats in _PATTERN_CATEGORIES.items():
    _COMPILED_PATTERNS[_cat] = [
        (regex.compile(pat, regex.IGNORECASE | regex.DOTALL), desc)
        for pat, desc in _pats
    ]


class CodeInjectionScanner(BaseOutputScanner):
    """Detects SQL injection, shell command injection, XSS, path traversal,
    SSRF, and deserialization attacks in LLM-generated code and text."""

    scanner_id: str = "output_code_injection"
    name: str = "Code Injection Scanner"
    description: str = (
        "Detects dangerous code injection patterns (SQL injection, shell "
        "injection, XSS, path traversal, SSRF, deserialization) in LLM outputs"
    )

    _base_confidence: ClassVar[float] = 0.90
    _category_boost: ClassVar[float] = 0.03

    def scan(
        self, output_text: str, context: dict[str, object] | None = None
    ) -> OutputScanResult:
        all_matches: list[MatchDetail] = []
        matched_categories: set[str] = set()

        for category, compiled in _COMPILED_PATTERNS.items():
            for pattern, description in compiled:
                for m in pattern.finditer(output_text):
                    matched_categories.add(category)
                    all_matches.append(
                        MatchDetail(
                            pattern=m.re.pattern,
                            matched_text=m.group(),
                            position=(m.start(), m.end()),
                            description=f"[{category}] {description}",
                        )
                    )

        if not all_matches:
            return OutputScanResult(
                scanner_id=self.scanner_id,
                flagged=False,
                confidence=0.0,
                explanation="No code injection patterns detected",
            )

        # Determine the highest severity across matched categories
        max_severity = max(
            (_CATEGORY_SEVERITY[c] for c in matched_categories),
            key=lambda s: list(Severity).index(s),
        )

        confidence = min(
            1.0,
            self._base_confidence
            + self._category_boost * (len(matched_categories) - 1),
        )

        sorted_categories = sorted(matched_categories)

        return OutputScanResult(
            scanner_id=self.scanner_id,
            flagged=True,
            confidence=confidence,
            categories=sorted_categories,
            matches=all_matches,
            explanation=(
                f"Detected {len(all_matches)} code injection pattern(s) "
                f"across categories: {', '.join(sorted_categories)}"
            ),
            metadata={
                "severity": max_severity.value,
                "category_count": len(matched_categories),
            },
        )
