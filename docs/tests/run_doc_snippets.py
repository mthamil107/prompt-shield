"""Extract and execute Python fenced code blocks from documentation files.

This script guards against docs-vs-code drift by actually running every
```python ... ``` block in the given files. Each block is executed in a
fresh Python subprocess with a per-block timeout, and non-zero exits are
reported.

A block is skipped if its first non-blank line matches the exact marker
``# doctest: +SKIP`` (compatible with the stdlib doctest convention).
Skip markers are intended for illustrative snippets that need external
services, network access, or undefined variables; do NOT skip a block
that could actually catch a docs-vs-code drift bug (missing symbol,
renamed class, etc.). If you must skip, include a brief reason on the
same line, e.g. ``# doctest: +SKIP  (needs live LangChain LLM)``.

Usage:
    python docs/tests/run_doc_snippets.py README.md docs/index.md

Exit code 0 = all executed blocks passed. Exit code 1 = at least one
block failed. Skipped blocks are reported but do not affect exit status.
"""

from __future__ import annotations

import argparse
import contextlib
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Matches an opening ```python fence (optionally with attributes after
# "python") through the closing ``` on its own line.
FENCE_RE = re.compile(
    r"^```python\b[^\n]*\n(?P<body>.*?)^```\s*$",
    re.MULTILINE | re.DOTALL,
)

SKIP_MARKER = "# doctest: +SKIP"


@dataclass
class Snippet:
    """A single fenced Python block extracted from a doc file."""

    source_file: Path
    line_number: int  # 1-based line where the block starts (the opening fence)
    body: str

    @property
    def first_meaningful_line(self) -> str:
        """First non-blank stripped line, used to detect the skip marker."""
        for line in self.body.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
        return ""

    @property
    def should_skip(self) -> bool:
        return self.first_meaningful_line.startswith(SKIP_MARKER)


def extract_snippets(path: Path) -> list[Snippet]:
    """Return every ```python fenced block in `path`."""
    text = path.read_text(encoding="utf-8")
    snippets: list[Snippet] = []
    for match in FENCE_RE.finditer(text):
        # Line number of the opening fence (1-based).
        line_number = text.count("\n", 0, match.start()) + 1
        snippets.append(
            Snippet(source_file=path, line_number=line_number, body=match.group("body"))
        )
    return snippets


def run_snippet(snippet: Snippet, *, timeout: float, python: str) -> tuple[bool, str]:
    """Execute a snippet in a fresh subprocess.

    Returns (passed, message). `passed` is True on exit code 0 and no
    exception; message contains stderr on failure or the timeout hint.
    """
    # Write the body to a real .py tempfile so tracebacks show line numbers.
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".py",
        prefix="doc_snippet_",
        encoding="utf-8",
        delete=False,
    ) as tmp:
        tmp.write(snippet.body)
        tmp_path = Path(tmp.name)

    try:
        proc = subprocess.run(
            [python, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"TIMEOUT after {timeout}s"
    finally:
        with contextlib.suppress(OSError):
            tmp_path.unlink()

    if proc.returncode == 0:
        return True, ""
    # Fold in stdout too — some errors print there before exit.
    combined = proc.stderr or ""
    if proc.stdout:
        combined += "\n--- stdout ---\n" + proc.stdout
    return False, combined.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path, help="Markdown files to scan")
    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="Per-snippet subprocess timeout in seconds (default: 90)",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter used to run snippets (default: current interpreter)",
    )
    args = parser.parse_args(argv)

    total = 0
    skipped = 0
    failed: list[tuple[Snippet, str]] = []

    for path in args.files:
        if not path.exists():
            print(f"ERROR: {path} does not exist", file=sys.stderr)
            return 2

        snippets = extract_snippets(path)
        print(f"\n=== {path} — {len(snippets)} python fenced block(s) ===")
        for i, snippet in enumerate(snippets, start=1):
            total += 1
            label = f"[{path}:{snippet.line_number}] block {i}/{len(snippets)}"
            if snippet.should_skip:
                skipped += 1
                first_line = snippet.first_meaningful_line
                print(f"  SKIP  {label}  {first_line}")
                continue

            passed, message = run_snippet(snippet, timeout=args.timeout, python=args.python)
            if passed:
                print(f"  PASS  {label}")
            else:
                print(f"  FAIL  {label}")
                if message:
                    # Indent the failure body for readability
                    for line in message.splitlines():
                        print(f"        {line}")
                failed.append((snippet, message))

    executed = total - skipped
    print(
        f"\nSummary: {total} block(s), {executed} executed, "
        f"{skipped} skipped, {len(failed)} failed."
    )

    if failed:
        print("\nFailures:")
        for snippet, _message in failed:
            print(f"  - {snippet.source_file}:{snippet.line_number}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
