"""Dataset loading for prompt-shield benchmarks."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, NamedTuple

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
    "jailbreakbench": {
        "name": "JailbreakBench (Chao et al., NeurIPS 2024)",
        "description": (
            "100 harmful + 100 benign behaviors across 10 categories. "
            "Jailbreak / harmful-behavior benchmark, NOT a prompt-injection "
            "benchmark; loader is provided for scope-completeness eval."
        ),
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
    elif name == "jailbreakbench":
        return load_jailbreakbench(cache_dir=data_dir)
    elif name not in _DATASET_REGISTRY:
        available = ", ".join(_DATASET_REGISTRY.keys())
        raise BenchmarkError(f"Unknown dataset '{name}'. Available: {available}")
    raise BenchmarkError(f"Dataset '{name}' is registered but has no loader")


def load_jailbreakbench(cache_dir: str | None = None) -> list[BenchmarkSample]:
    """Load JailbreakBench (100 harmful + 100 benign behaviors).

    Fetches both splits from the ``JailbreakBench/JBB-Behaviors`` HuggingFace
    dataset (config ``behaviors``) via the stdlib datasets-server API — no
    ``datasets`` dependency required. Harmful goals are labelled
    ``is_injection=True``, benign goals ``False``, mirroring the shape the
    rest of the benchmark harness expects.

    Note: JailbreakBench is a jailbreak (harmful-behavior) benchmark, not a
    prompt-injection benchmark. See ``tests/benchmark_jailbreakbench.py`` for
    a runner that reports harmful-recall AND benign-FPR side by side, which
    is the honest way to consume this dataset for an injection defender.
    """
    import urllib.error
    import urllib.request

    base = (
        "https://datasets-server.huggingface.co/rows?"
        "dataset=JailbreakBench/JBB-Behaviors&config=behaviors&split={split}&"
        "offset=0&length=100"
    )
    cache_path = None
    if cache_dir:
        cache_path = Path(cache_dir) / "hf_JailbreakBench_JBB-Behaviors.json"
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                return _samples_from_jbb_payload(cached)
            except (json.JSONDecodeError, KeyError):
                pass

    combined: dict[str, list[dict]] = {}
    for split in ("harmful", "benign"):
        try:
            req = urllib.request.Request(
                base.format(split=split), headers={"User-Agent": "prompt-shield"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise BenchmarkError(
                f"Failed to fetch JailbreakBench '{split}' split: {exc}"
            ) from exc
        combined[split] = data.get("rows", [])

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(combined), encoding="utf-8")

    return _samples_from_jbb_payload(combined)


def _samples_from_jbb_payload(payload: dict[str, list[dict]]) -> list[BenchmarkSample]:
    samples: list[BenchmarkSample] = []
    for split, rows in payload.items():
        is_injection = split == "harmful"
        for entry in rows:
            row = entry.get("row", {})
            goal = row.get("Goal", "")
            if goal:
                samples.append(
                    BenchmarkSample(
                        text=str(goal),
                        is_injection=is_injection,
                        source=f"jailbreakbench:{split}",
                    )
                )
    if not samples:
        raise BenchmarkError("JailbreakBench payload contained no rows")
    return samples


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
    import urllib.error
    import urllib.request

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
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"Failed to download dataset from HuggingFace: {exc}") from exc

    if cache_path:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data), encoding="utf-8")

    return _parse_hf_rows(data, repo_id)


def _parse_hf_rows(data: dict[str, Any], repo_id: str) -> list[BenchmarkSample]:
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
