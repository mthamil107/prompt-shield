"""Prompt Shield CI scanner for GitHub Actions.

Scans files for prompt injection and optionally PII, producing structured
JSON results and a Markdown summary suitable for PR comments.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileResult:
    """Scan result for a single file."""

    path: str
    risk_score: float = 0.0
    action: str = "pass"
    detections: list[dict] = field(default_factory=list)
    pii_findings: list[dict] = field(default_factory=list)
    pii_count: int = 0
    error: str | None = None
    scan_duration_ms: float = 0.0


def create_engine():
    """Create a PromptShieldEngine optimized for CI scanning speed."""
    from prompt_shield.engine import PromptShieldEngine

    config = {
        "prompt_shield": {
            "vault": {"enabled": False},
            "feedback": {"enabled": False},
            "canary": {"enabled": False},
            "history": {"enabled": False},
            "mode": "block",
        }
    }
    return PromptShieldEngine(config_dict=config)


def create_pii_redactor():
    """Create a PIIRedactor instance."""
    from prompt_shield.pii.redactor import PIIRedactor

    return PIIRedactor()


def read_file_safe(file_path: str) -> str | None:
    """Read a file with graceful encoding fallback.

    Tries UTF-8 first, then falls back to latin-1 which never fails.
    Returns None for binary files or unreadable files.
    """
    path = Path(file_path)
    if not path.exists():
        return None
    if not path.is_file():
        return None

    # Skip very large files (> 1 MB) to keep CI fast
    try:
        size = path.stat().st_size
        if size > 1_048_576:
            return None
        if size == 0:
            return ""
    except OSError:
        return None

    for encoding in ("utf-8", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except (UnicodeDecodeError, ValueError):
            continue
        except OSError:
            return None

    return None


def scan_file(
    engine,
    file_path: str,
    threshold: float,
    pii_redactor=None,
) -> FileResult:
    """Scan a single file for prompt injection and optionally PII."""
    result = FileResult(path=file_path)
    start = time.perf_counter()

    content = read_file_safe(file_path)
    if content is None:
        result.error = "Could not read file (binary, too large, or missing)"
        result.scan_duration_ms = (time.perf_counter() - start) * 1000
        return result

    if not content.strip():
        result.scan_duration_ms = (time.perf_counter() - start) * 1000
        return result

    # Run prompt injection scan
    try:
        report = engine.scan(content)
        result.risk_score = report.overall_risk_score
        result.action = report.action.value

        for detection in report.detections:
            if detection.confidence >= threshold:
                result.detections.append(
                    {
                        "detector_id": detection.detector_id,
                        "confidence": round(detection.confidence, 4),
                        "severity": detection.severity.value,
                        "explanation": detection.explanation,
                        "match_count": len(detection.matches),
                    }
                )
    except Exception as exc:
        result.error = f"Scan error: {exc}"

    # Run PII scan if enabled
    if pii_redactor is not None:
        try:
            pii_result = pii_redactor.redact(content)
            if pii_result.redaction_count > 0:
                result.pii_count = pii_result.redaction_count
                for entity in pii_result.redacted_entities:
                    result.pii_findings.append(
                        {
                            "entity_type": entity.get("entity_type", "unknown"),
                            # Do not include the actual PII value in CI output
                        }
                    )
        except Exception as exc:
            if result.error:
                result.error += f"; PII error: {exc}"
            else:
                result.error = f"PII error: {exc}"

    result.scan_duration_ms = round((time.perf_counter() - start) * 1000, 2)
    return result


def generate_markdown_summary(
    results: list[FileResult],
    threshold: float,
    mode: str,
    total_duration_ms: float,
) -> str:
    """Generate a Markdown summary of scan results for PR comment."""
    injection_files = [r for r in results if r.detections]
    pii_files = [r for r in results if r.pii_count > 0]
    error_files = [r for r in results if r.error]
    clean_files = [
        r
        for r in results
        if not r.detections and r.pii_count == 0 and not r.error
    ]

    # Header with status
    has_issues = len(injection_files) > 0 or len(pii_files) > 0
    if has_issues and mode == "block":
        status_icon = ":x:"
        status_text = "Issues Detected"
    elif has_issues:
        status_icon = ":warning:"
        status_text = "Issues Found (non-blocking)"
    else:
        status_icon = ":white_check_mark:"
        status_text = "All Clear"

    lines = [
        f"## {status_icon} Prompt Shield Scan &mdash; {status_text}",
        "",
        f"**Files scanned:** {len(results)} | "
        f"**Threshold:** {threshold} | "
        f"**Mode:** {mode} | "
        f"**Duration:** {total_duration_ms:.0f}ms",
        "",
    ]

    # Prompt injection findings
    if injection_files:
        lines.append("### Prompt Injection Detections")
        lines.append("")
        lines.append("| File | Risk Score | Severity | Detectors | Details |")
        lines.append("|------|-----------|----------|-----------|---------|")

        for r in injection_files:
            severities = set()
            detector_ids = []
            explanations = []
            for d in r.detections:
                severities.add(d["severity"])
                detector_ids.append(d["detector_id"])
                if d["explanation"]:
                    explanations.append(d["explanation"])

            worst_severity = "critical" if "critical" in severities else (
                "high" if "high" in severities else (
                    "medium" if "medium" in severities else "low"
                )
            )
            sev_badge = {
                "critical": ":red_circle:",
                "high": ":orange_circle:",
                "medium": ":yellow_circle:",
                "low": ":white_circle:",
            }.get(worst_severity, ":white_circle:")

            detail = "; ".join(explanations[:2])
            if len(detail) > 120:
                detail = detail[:117] + "..."

            lines.append(
                f"| `{r.path}` | {r.risk_score:.2f} | {sev_badge} {worst_severity} "
                f"| {', '.join(detector_ids[:3])} | {detail} |"
            )
        lines.append("")

    # PII findings
    if pii_files:
        lines.append("### PII Detections")
        lines.append("")
        lines.append("| File | PII Count | Entity Types |")
        lines.append("|------|-----------|-------------|")

        for r in pii_files:
            entity_types = set()
            for finding in r.pii_findings:
                entity_types.add(finding.get("entity_type", "unknown"))
            lines.append(
                f"| `{r.path}` | {r.pii_count} | {', '.join(sorted(entity_types))} |"
            )
        lines.append("")

    # Errors
    if error_files:
        lines.append(
            f"<details><summary>:information_source: {len(error_files)} file(s) "
            f"had scan errors</summary>\n"
        )
        for r in error_files:
            lines.append(f"- `{r.path}`: {r.error}")
        lines.append("\n</details>")
        lines.append("")

    # Clean summary
    if clean_files and not injection_files and not pii_files:
        lines.append(
            f"All {len(clean_files)} scanned file(s) passed with no findings."
        )
        lines.append("")

    lines.append("---")
    lines.append(
        "*Scanned by [prompt-shield-ai](https://github.com/prompt-shield/prompt-shield)*"
    )

    return "\n".join(lines)


def set_github_output(name: str, value: str) -> None:
    """Write a key=value pair to the GitHub Actions output file."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as f:
            # Use delimiter for multiline values
            if "\n" in value:
                import uuid as _uuid

                delimiter = f"ghadelimiter_{_uuid.uuid4()}"
                f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
            else:
                f.write(f"{name}={value}\n")
    else:
        # Fallback for local testing
        print(f"::set-output name={name}::{value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prompt Shield CI Scanner")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.7,
        help="Risk score threshold",
    )
    parser.add_argument(
        "--mode",
        choices=["block", "flag", "monitor"],
        default="block",
        help="Scan mode",
    )
    parser.add_argument(
        "--pii-scan",
        default="true",
        help="Enable PII scanning (true/false)",
    )
    parser.add_argument(
        "--fail-on-detection",
        default="true",
        help="Fail on detection (true/false)",
    )
    parser.add_argument(
        "--files",
        nargs="*",
        default=[],
        help="Files to scan",
    )
    parser.add_argument(
        "--ignore-patterns",
        default="",
        help=(
            "Comma-separated glob patterns of files to skip (e.g. "
            "'tests/fixtures/**,docs/attack-research/**'). Repo-local "
            "'.prompt-shield-ignore' file is also read if present — one "
            "pattern per line, '#' comments supported."
        ),
    )
    args = parser.parse_args()

    pii_enabled = args.pii_scan.lower() == "true"

    # Build ignore pattern list: CLI flag first, then .prompt-shield-ignore lines.
    ignore_patterns: list[str] = []
    if args.ignore_patterns:
        ignore_patterns.extend(
            p.strip() for p in args.ignore_patterns.split(",") if p.strip()
        )
    ignore_file = Path(".prompt-shield-ignore")
    if ignore_file.is_file():
        for raw in ignore_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                ignore_patterns.append(line)

    if ignore_patterns:
        import fnmatch

        filtered = [
            f
            for f in args.files
            if not any(fnmatch.fnmatch(f, pat) for pat in ignore_patterns)
        ]
        skipped = len(args.files) - len(filtered)
        if skipped:
            print(f"Skipping {skipped} file(s) via ignore patterns.")
        args.files = filtered

    if not args.files:
        print("No files to scan.")
        set_github_output("results", "{}")
        set_github_output("detection_count", "0")
        set_github_output("pii_count", "0")
        set_github_output("has_detections", "false")
        set_github_output("summary", "")
        return

    print(f"Prompt Shield scanning {len(args.files)} file(s)...")
    print(f"  Threshold: {args.threshold}")
    print(f"  Mode: {args.mode}")
    print(f"  PII scan: {pii_enabled}")

    # Initialize engine and optional PII redactor
    total_start = time.perf_counter()

    try:
        engine = create_engine()
    except Exception as exc:
        print(f"::error::Failed to initialize Prompt Shield engine: {exc}")
        sys.exit(1)

    pii_redactor = None
    if pii_enabled:
        try:
            pii_redactor = create_pii_redactor()
        except Exception as exc:
            print(f"::warning::Failed to initialize PII scanner: {exc}")

    # Scan each file
    results: list[FileResult] = []
    for file_path in args.files:
        print(f"  Scanning: {file_path}")
        result = scan_file(engine, file_path, args.threshold, pii_redactor)
        results.append(result)

        if result.detections:
            print(f"    -> {len(result.detections)} detection(s), risk={result.risk_score:.2f}")
        if result.pii_count > 0:
            print(f"    -> {result.pii_count} PII finding(s)")
        if result.error:
            print(f"    -> Error: {result.error}")

    total_duration_ms = (time.perf_counter() - total_start) * 1000

    # Compute aggregates
    detection_count = sum(1 for r in results if r.detections)
    pii_count = sum(1 for r in results if r.pii_count > 0)
    has_detections = detection_count > 0

    # Build JSON results
    json_results = {
        "threshold": args.threshold,
        "mode": args.mode,
        "total_files": len(results),
        "detection_count": detection_count,
        "pii_file_count": pii_count,
        "total_duration_ms": round(total_duration_ms, 2),
        "files": [],
    }
    for r in results:
        file_entry = {
            "path": r.path,
            "risk_score": r.risk_score,
            "action": r.action,
            "detections": r.detections,
            "pii_count": r.pii_count,
            "pii_findings": r.pii_findings,
            "scan_duration_ms": r.scan_duration_ms,
        }
        if r.error:
            file_entry["error"] = r.error
        json_results["files"].append(file_entry)

    # Generate Markdown summary
    summary = generate_markdown_summary(
        results, args.threshold, args.mode, total_duration_ms
    )

    # Set outputs
    set_github_output("results", json.dumps(json_results))
    set_github_output("detection_count", str(detection_count))
    set_github_output("pii_count", str(pii_count))
    set_github_output("has_detections", str(has_detections).lower())
    set_github_output("summary", summary)

    # Print summary to workflow log
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Files scanned:     {len(results)}")
    print(f"Injection findings:{detection_count}")
    print(f"PII findings:      {pii_count}")
    print(f"Duration:          {total_duration_ms:.0f}ms")
    print("=" * 60)

    if has_detections:
        for r in results:
            if r.detections:
                print(f"\n  {r.path}:")
                for d in r.detections:
                    print(f"    - [{d['severity']}] {d['detector_id']} "
                          f"(confidence: {d['confidence']:.2f})")
                    if d.get("explanation"):
                        print(f"      {d['explanation']}")


if __name__ == "__main__":
    main()
