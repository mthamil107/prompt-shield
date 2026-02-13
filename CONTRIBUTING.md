# Contributing to prompt-shield

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/prompt-shield/prompt-shield.git
cd prompt-shield

# Install in development mode with all extras
pip install -e ".[dev,all]"

# Install pre-commit hooks
pre-commit install
```

## Running Tests

```bash
# Run all tests
make test

# Run with verbose output
make test-verbose

# Run a specific test file
pytest tests/test_engine.py -v

# Run a specific test
pytest tests/detectors/test_d001_system_prompt_extraction.py::TestSystemPromptExtraction::test_classic_extraction -v
```

## Code Quality

```bash
# Lint
make lint

# Auto-format
make format

# Type check
make typecheck

# Run all checks (lint + typecheck + test)
make ci
```

## Adding a New Detector

This is the most common contribution. Follow these steps:

### 1. Choose a Detector ID

Use the next available number: `dXXX_descriptive_name.py`

Check existing detectors:
```bash
ls src/prompt_shield/detectors/d*.py
```

### 2. Create the Detector File

Copy the template from `docs/writing-detectors.md` or use this minimal example:

```python
"""Detector: My New Detector"""
from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class MyNewDetector(BaseDetector):
    detector_id = "d022_my_new_detector"
    name = "My New Detector"
    description = "Detects [what it detects]"
    severity = Severity.MEDIUM
    tags = ["category"]
    version = "1.0.0"
    author = "your_github_handle"

    def __init__(self) -> None:
        self._base_confidence = 0.75
        self._patterns: list[tuple[str, str]] = [
            (r"pattern_one", "Description of pattern one"),
            (r"pattern_two", "Description of pattern two"),
            # Add at least 10 patterns
        ]

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        matches: list[MatchDetail] = []
        for pattern_str, description in self._patterns:
            pattern = regex.compile(pattern_str, regex.IGNORECASE)
            for m in pattern.finditer(input_text):
                matches.append(MatchDetail(
                    pattern=pattern_str,
                    matched_text=m.group(),
                    position=(m.start(), m.end()),
                    description=description,
                ))

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
            explanation=f"Detected {len(matches)} suspicious pattern(s)",
        )
```

### 3. Add Tests

Create `tests/detectors/test_dXXX_my_new_detector.py` with:
- At least 10 positive test cases (should detect)
- At least 5 negative test cases (should NOT detect)

### 4. Add Test Fixtures

Create `tests/fixtures/injections/my_new_detector.json` following the fixture schema:

```json
{
  "detector_id": "d022_my_new_detector",
  "test_cases": [
    {
      "id": "d022_pos_001",
      "input": "malicious input here",
      "expected_detected": true,
      "min_confidence": 0.7,
      "description": "Description of test case"
    }
  ]
}
```

### 5. Update Documentation

Add your detector to `docs/detectors.md`.

### 6. Submit PR

- Ensure all tests pass: `make ci`
- Add a changelog entry
- Submit PR with the "new-detector" label

## Code Style

- Enforced by `ruff` (config in `pyproject.toml`)
- Type-checked by `mypy --strict`
- Use `from __future__ import annotations` in all files
- Use `regex` instead of stdlib `re` for Unicode support

## PR Requirements

- All tests pass
- No mypy errors
- No ruff errors
- Documentation updated if applicable
- Changelog entry added
- Minimum 90% test coverage for new detectors

## Reporting Issues

Use the GitHub issue templates:
- **Bug Report**: For bugs in existing functionality
- **Feature Request**: For new features
- **New Detector Proposal**: For proposing new detectors

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
