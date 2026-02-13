# Writing Custom Detectors

This example shows how to create and register a custom prompt injection detector.

## Steps

1. Subclass `BaseDetector` from `prompt_shield.detectors.base`
2. Set the required class attributes: `detector_id`, `name`, `description`, `severity`, `tags`, `version`, `author`
3. Implement the `detect()` method returning a `DetectionResult`
4. Register with `engine.register_detector(MyDetector())`

## Run

```bash
python examples/custom_detector/my_detector.py
```

## Entry Point Registration

For distributing a detector as a package, add an entry point to your `pyproject.toml`:

```toml
[project.entry-points."prompt_shield.detectors"]
my_detector = "my_package.detector:PleaseHackDetector"
```

The engine will auto-discover it on startup.

## Detector Interface

```python
class BaseDetector(ABC):
    detector_id: str       # Unique ID (e.g., "custom_please_hack")
    name: str              # Human-readable name
    description: str       # What it detects
    severity: Severity     # LOW, MEDIUM, HIGH, or CRITICAL
    tags: list[str]        # Category tags
    version: str           # Semver version
    author: str            # Author name

    def detect(self, input_text: str, context: dict | None = None) -> DetectionResult: ...
    def setup(self, config: dict) -> None: ...    # Optional
    def teardown(self) -> None: ...               # Optional
```
