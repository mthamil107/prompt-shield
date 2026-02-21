"""Dataset loading for prompt-shield benchmarks."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import NamedTuple

from prompt_shield.exceptions import BenchmarkError


class BenchmarkSample(NamedTuple):
    """A single benchmark sample."""

    text: str
    is_injection: bool
    source: str


# Path to the bundled sample dataset
_SAMPLE_DATA_PATH = Path(__file__).parent / "sample_data.json"

# Registry of known datasets
_DATASET_REGISTRY: dict[str, dict[str, str]] = {
    "sample": {
        "name": "prompt-shield built-in sample",
        "description": "Bundled 50-sample dataset (25 injection + 25 benign)",
        "source": "local",
    },
    "deepset/prompt-injections": {
        "name": "Deepset Prompt Injections",
        "description": "Community prompt injection dataset from HuggingFace",
        "source": "huggingface",
    },
}


def list_datasets() -> list[dict[str, str]]:
    """Return information about available datasets.

    Returns:
        List of dicts with 'id', 'name', 'description', and 'source'.
    """
    return [{"id": k, **v} for k, v in _DATASET_REGISTRY.items()]


def load_dataset(
    name: str,
    data_dir: str | None = None,
) -> list[BenchmarkSample]:
    """Load a dataset by its registry name.

    Args:
        name: Dataset identifier (e.g. 'sample', 'deepset/prompt-injections').
        data_dir: Optional directory for cached downloads.

    Returns:
        List of BenchmarkSample.

    Raises:
        BenchmarkError: If the dataset is unknown or cannot be loaded.
    """
    if name == "sample":
        return _load_bundled_sample()
    elif name == "deepset/prompt-injections":
        return load_huggingface_dataset(
            "deepset/prompt-injections",
            cache_dir=data_dir,
        )
    elif name not in _DATASET_REGISTRY:
        available = ", ".join(_DATASET_REGISTRY.keys())
        raise BenchmarkError(f"Unknown dataset '{name}'. Available: {available}")
    raise BenchmarkError(f"Dataset '{name}' is registered but has no loader")


def _load_bundled_sample() -> list[BenchmarkSample]:
    """Load the bundled sample_data.json."""
    if not _SAMPLE_DATA_PATH.exists():
        raise BenchmarkError(f"Bundled sample data not found at {_SAMPLE_DATA_PATH}")
    return load_json_dataset(_SAMPLE_DATA_PATH)


def load_json_dataset(path: str | Path) -> list[BenchmarkSample]:
    """Load a dataset from prompt-shield JSON format.

    Expected format:
        {"samples": [{"text": "...", "is_injection": true/false, "source": "..."}, ...]}

    Args:
        path: Path to the JSON file.

    Returns:
        List of BenchmarkSample.
    """
    path = Path(path)
    if not path.exists():
        raise BenchmarkError(f"Dataset file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise BenchmarkError(f"Failed to load JSON dataset: {exc}") from exc

    samples_raw = data.get("samples", [])
    if not samples_raw:
        raise BenchmarkError(f"No samples found in {path}")

    return [
        BenchmarkSample(
            text=s["text"],
            is_injection=bool(s["is_injection"]),
            source=s.get("source", str(path.name)),
        )
        for s in samples_raw
    ]


def load_csv_dataset(
    path: str | Path,
    text_col: str = "text",
    label_col: str = "label",
) -> list[BenchmarkSample]:
    """Load a dataset from a CSV file.

    Args:
        path: Path to the CSV file.
        text_col: Column name for the input text.
        label_col: Column name for the label (1 = injection, 0 = benign).

    Returns:
        List of BenchmarkSample.
    """
    path = Path(path)
    if not path.exists():
        raise BenchmarkError(f"CSV file not found: {path}")

    samples: list[BenchmarkSample] = []
    try:
        with open(path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if text_col not in row or label_col not in row:
                    raise BenchmarkError(
                        f"CSV missing required columns: '{text_col}', '{label_col}'"
                    )
                samples.append(
                    BenchmarkSample(
                        text=row[text_col],
                        is_injection=row[label_col] in ("1", "true", "True", "injection"),
                        source=str(path.name),
                    )
                )
    except (OSError, csv.Error) as exc:
        raise BenchmarkError(f"Failed to load CSV dataset: {exc}") from exc

    if not samples:
        raise BenchmarkError(f"No samples found in {path}")
    return samples


def load_huggingface_dataset(
    repo_id: str,
    cache_dir: str | None = None,
) -> list[BenchmarkSample]:
    """Download and load a dataset from HuggingFace Hub.

    Uses urllib to download the dataset JSON/CSV without requiring the `datasets` library.

    Args:
        repo_id: HuggingFace repository ID (e.g. 'deepset/prompt-injections').
        cache_dir: Optional directory to cache downloaded files.

    Returns:
        List of BenchmarkSample.
    """
    import urllib.request
    import urllib.error

    url = f"https://datasets-server.huggingface.co/rows?dataset={repo_id}&config=default&split=train&offset=0&length=1000"

    cache_path = None
    if cache_dir:
        cache_path = Path(cache_dir) / f"hf_{repo_id.replace('/', '_')}.json"
        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                return _parse_hf_rows(data, repo_id)
            except (json.JSONDecodeError, KeyError):
                pass  # Re-download on cache corruption

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "prompt-shield"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"Failed to download dataset from HuggingFace: {exc}") from exc

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data), encoding="utf-8")

    return _parse_hf_rows(data, repo_id)


def _parse_hf_rows(data: dict, repo_id: str) -> list[BenchmarkSample]:
    """Parse rows from the HuggingFace datasets server API response."""
    rows = data.get("rows", [])
    if not rows:
        raise BenchmarkError(f"No rows returned from HuggingFace for {repo_id}")

    samples: list[BenchmarkSample] = []
    for entry in rows:
        row = entry.get("row", {})
        text = row.get("text", row.get("prompt", ""))
        label = row.get("label", row.get("is_injection", 0))
        if text:
            samples.append(
                BenchmarkSample(
                    text=str(text),
                    is_injection=label in (1, True, "1", "injection"),
                    source=repo_id,
                )
            )
    return samples
