"""Pre-commit hook entry points for prompt injection and PII scanning."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ANSI color codes
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

# Binary file detection: read first 8KB and look for null bytes
_BINARY_CHECK_SIZE = 8192


def _is_binary(filepath: Path) -> bool:
    """Return True if the file appears to be binary."""
    try:
        chunk = filepath.read_bytes()[:_BINARY_CHECK_SIZE]
        return b"\x00" in chunk
    except OSError:
        return True


def _read_file_text(filepath: Path) -> str | None:
    """Read file as UTF-8 text, returning None on encoding errors."""
    try:
        return filepath.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        # Try with replacement to be lenient
        try:
            return filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    except OSError:
        return None


def _build_injection_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan files for prompt injection patterns."
    )
    parser.add_argument(
        "filenames",
        nargs="*",
        help="Files to check (passed by pre-commit).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.7,
        help="Minimum confidence threshold for detections (default: 0.7).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob patterns to exclude (may be repeated).",
    )
    return parser


def _build_pii_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan files for PII (personally identifiable information)."
    )
    parser.add_argument(
        "filenames",
        nargs="*",
        help="Files to check (passed by pre-commit).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob patterns to exclude (may be repeated).",
    )
    return parser


def _should_exclude(filepath: Path, exclude_patterns: list[str]) -> bool:
    """Check if a file matches any exclusion pattern."""
    for pattern in exclude_patterns:
        if filepath.match(pattern):
            return True
    return False


def _find_line_number(text: str, position: int) -> int:
    """Return the 1-based line number for a character position in text."""
    return text[:position].count("\n") + 1


def prompt_shield_hook() -> int:
    """Pre-commit hook entry point for prompt injection scanning.

    Scans each staged file with PromptShieldEngine using a lightweight
    configuration (vault, feedback, and semantic classifier disabled for speed).

    Returns 0 if all files are clean, 1 if any detections are found.
    """
    parser = _build_injection_parser()
    args = parser.parse_args()

    if not args.filenames:
        return 0

    # Lazy import to keep startup fast when no files to scan
    from prompt_shield.engine import PromptShieldEngine

    # Lightweight config: disable heavy subsystems for speed
    engine = PromptShieldEngine(
        config_dict={
            "prompt_shield": {
                "threshold": args.threshold,
                "vault": {"enabled": False},
                "feedback": {"enabled": False},
                "canary": {"enabled": False},
                "history": {"enabled": False},
                "detectors": {
                    "d022_semantic_classifier": {"enabled": False},
                },
            }
        }
    )

    found_issues = False

    for filename in args.filenames:
        filepath = Path(filename)

        if not filepath.exists():
            continue

        if _should_exclude(filepath, args.exclude):
            continue

        if _is_binary(filepath):
            continue

        content = _read_file_text(filepath)
        if content is None:
            continue

        # Skip empty files
        if not content.strip():
            continue

        report = engine.scan(content)

        if report.detections:
            found_issues = True
            print(
                f"{_RED}{_BOLD}FAIL{_RESET} {filepath} "
                f"— {len(report.detections)} detection(s), "
                f"risk score {report.overall_risk_score:.2f}"
            )
            for detection in report.detections:
                severity_color = _RED if detection.severity.value in ("high", "critical") else _YELLOW
                print(
                    f"  {severity_color}[{detection.severity.value.upper()}]{_RESET} "
                    f"{detection.detector_id} "
                    f"(confidence: {detection.confidence:.2f})"
                )
                if detection.explanation:
                    print(f"    {detection.explanation}")
                for match in detection.matches:
                    if match.position:
                        line_no = _find_line_number(content, match.position[0])
                        print(f"    Line {line_no}: {match.description or match.matched_text!r}")
                    elif match.description:
                        print(f"    {match.description}")
        else:
            print(f"{_GREEN}PASS{_RESET} {filepath}")

    return 1 if found_issues else 0


def prompt_shield_pii_hook() -> int:
    """Pre-commit hook entry point for PII scanning.

    Scans each staged file with PIIRedactor to detect personally identifiable
    information (emails, phone numbers, SSNs, credit card numbers, etc.).

    Returns 0 if all files are clean, 1 if any PII is found.
    """
    parser = _build_pii_parser()
    args = parser.parse_args()

    if not args.filenames:
        return 0

    from prompt_shield.pii.redactor import PIIRedactor

    redactor = PIIRedactor()
    found_issues = False

    for filename in args.filenames:
        filepath = Path(filename)

        if not filepath.exists():
            continue

        if _should_exclude(filepath, args.exclude):
            continue

        if _is_binary(filepath):
            continue

        content = _read_file_text(filepath)
        if content is None:
            continue

        if not content.strip():
            continue

        result = redactor.redact(content)

        if result.redaction_count > 0:
            found_issues = True
            print(
                f"{_RED}{_BOLD}FAIL{_RESET} {filepath} "
                f"— {result.redaction_count} PII detection(s)"
            )
            for entity in result.redacted_entities:
                entity_type = entity.get("entity_type", "unknown")
                original = entity.get("original", "")
                # Find line number for this PII occurrence
                pos = content.find(original)
                if pos >= 0:
                    line_no = _find_line_number(content, pos)
                    # Mask the value for display
                    masked = original[:2] + "***" + original[-2:] if len(original) > 4 else "***"
                    print(
                        f"  {_RED}[{entity_type.upper()}]{_RESET} "
                        f"Line {line_no}: {masked}"
                    )
                else:
                    print(f"  {_RED}[{entity_type.upper()}]{_RESET} detected")
        else:
            print(f"{_GREEN}PASS{_RESET} {filepath}")

    return 1 if found_issues else 0


# Allow direct invocation: python -m prompt_shield.hooks
if __name__ == "__main__":
    sys.exit(prompt_shield_hook())
