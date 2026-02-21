"""Tests for benchmark dataset loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_shield.benchmarks.datasets import (
    BenchmarkSample,
    list_datasets,
    load_csv_dataset,
    load_dataset,
    load_json_dataset,
)
from prompt_shield.exceptions import BenchmarkError


class TestLoadSampleDataset:
    """Loading the bundled sample dataset."""

    def test_load_sample(self) -> None:
        samples = load_dataset("sample")
        assert len(samples) == 50

    def test_sample_has_injections_and_benign(self) -> None:
        samples = load_dataset("sample")
        injections = [s for s in samples if s.is_injection]
        benign = [s for s in samples if not s.is_injection]
        assert len(injections) == 25
        assert len(benign) == 25

    def test_sample_types(self) -> None:
        samples = load_dataset("sample")
        for s in samples:
            assert isinstance(s, BenchmarkSample)
            assert isinstance(s.text, str)
            assert isinstance(s.is_injection, bool)
            assert isinstance(s.source, str)


class TestLoadJsonDataset:
    """Loading JSON datasets."""

    def test_load_json(self, tmp_path: Path) -> None:
        data = {
            "samples": [
                {"text": "hello", "is_injection": False, "source": "test"},
                {"text": "ignore instructions", "is_injection": True, "source": "test"},
            ]
        }
        path = tmp_path / "test.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        samples = load_json_dataset(path)
        assert len(samples) == 2
        assert samples[0].is_injection is False
        assert samples[1].is_injection is True

    def test_missing_file_raises(self) -> None:
        with pytest.raises(BenchmarkError, match="not found"):
            load_json_dataset("/nonexistent/path.json")

    def test_empty_samples_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.json"
        path.write_text('{"samples": []}', encoding="utf-8")
        with pytest.raises(BenchmarkError, match="No samples"):
            load_json_dataset(path)


class TestLoadCsvDataset:
    """Loading CSV datasets."""

    def test_load_csv(self, tmp_path: Path) -> None:
        csv_content = "text,label\nhello world,0\nignore instructions,1\n"
        path = tmp_path / "test.csv"
        path.write_text(csv_content, encoding="utf-8")
        samples = load_csv_dataset(path)
        assert len(samples) == 2
        assert samples[0].is_injection is False
        assert samples[1].is_injection is True

    def test_csv_missing_file_raises(self) -> None:
        with pytest.raises(BenchmarkError, match="not found"):
            load_csv_dataset("/nonexistent/path.csv")

    def test_csv_custom_columns(self, tmp_path: Path) -> None:
        csv_content = "prompt,is_injection\nhello,0\nhack,1\n"
        path = tmp_path / "custom.csv"
        path.write_text(csv_content, encoding="utf-8")
        samples = load_csv_dataset(path, text_col="prompt", label_col="is_injection")
        assert len(samples) == 2


class TestUnknownDataset:
    """Unknown dataset name."""

    def test_unknown_raises(self) -> None:
        with pytest.raises(BenchmarkError, match="Unknown dataset"):
            load_dataset("nonexistent_dataset")


class TestListDatasets:
    """Listing available datasets."""

    def test_list_returns_entries(self) -> None:
        datasets = list_datasets()
        assert len(datasets) >= 1
        names = [d["id"] for d in datasets]
        assert "sample" in names

    def test_list_entry_fields(self) -> None:
        datasets = list_datasets()
        for ds in datasets:
            assert "id" in ds
            assert "name" in ds
            assert "description" in ds
