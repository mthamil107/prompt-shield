"""Tests for the DetectorRegistry."""
from __future__ import annotations

import pytest

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.exceptions import RegistryError
from prompt_shield.models import DetectionResult, Severity
from prompt_shield.registry import DetectorRegistry


def _make_mock_detector(detector_id: str = "mock_detector") -> BaseDetector:
    """Create a minimal concrete detector for registry testing."""

    class MockDetector(BaseDetector):
        detector_id = "placeholder"
        name = "Mock Detector"
        description = "A mock detector for testing"
        severity = Severity.LOW
        tags = ["test"]
        version = "0.0.1"
        author = "test"

        def detect(
            self, input_text: str, context: dict[str, object] | None = None
        ) -> DetectionResult:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
            )

    MockDetector.detector_id = detector_id
    return MockDetector()


class TestRegistryRegister:
    """Tests for registering detectors."""

    def test_registry_register(self) -> None:
        """Registering a detector should add it to the registry."""
        registry = DetectorRegistry()
        detector = _make_mock_detector("test_001")
        registry.register(detector)
        assert "test_001" in registry

    def test_registry_unregister(self) -> None:
        """Unregistering a detector should remove it from the registry."""
        registry = DetectorRegistry()
        detector = _make_mock_detector("test_002")
        registry.register(detector)
        assert "test_002" in registry

        registry.unregister("test_002")
        assert "test_002" not in registry


class TestRegistryGet:
    """Tests for retrieving detectors."""

    def test_registry_get(self) -> None:
        """get() should return the registered detector by ID."""
        registry = DetectorRegistry()
        detector = _make_mock_detector("test_003")
        registry.register(detector)

        retrieved = registry.get("test_003")
        assert retrieved is detector
        assert retrieved.detector_id == "test_003"

    def test_registry_get_missing(self) -> None:
        """get() should raise RegistryError for non-existent detector ID."""
        registry = DetectorRegistry()
        with pytest.raises(RegistryError, match="Detector not found"):
            registry.get("nonexistent_detector")


class TestRegistryList:
    """Tests for listing detectors."""

    def test_registry_list_all(self) -> None:
        """list_all should return all registered detectors."""
        registry = DetectorRegistry()
        d1 = _make_mock_detector("list_001")
        d2 = _make_mock_detector("list_002")
        d3 = _make_mock_detector("list_003")
        registry.register(d1)
        registry.register(d2)
        registry.register(d3)

        all_detectors = registry.list_all()
        assert len(all_detectors) == 3
        ids = {d.detector_id for d in all_detectors}
        assert ids == {"list_001", "list_002", "list_003"}

    def test_registry_list_metadata(self) -> None:
        """list_metadata should return dicts with expected keys."""
        registry = DetectorRegistry()
        detector = _make_mock_detector("meta_001")
        registry.register(detector)

        metadata = registry.list_metadata()
        assert len(metadata) == 1
        entry = metadata[0]
        expected_keys = {"detector_id", "name", "description", "severity", "tags", "version", "author"}
        assert expected_keys == set(entry.keys())
        assert entry["detector_id"] == "meta_001"
        assert entry["name"] == "Mock Detector"


class TestRegistryAutoDiscover:
    """Tests for auto-discovery of built-in detectors."""

    def test_registry_auto_discover(self) -> None:
        """auto_discover should find built-in detectors (count > 0)."""
        registry = DetectorRegistry()
        count = registry.auto_discover()
        assert count > 0
        assert len(registry) == count


class TestRegistryDunder:
    """Tests for __len__ and __contains__."""

    def test_registry_len(self) -> None:
        """__len__ should reflect the number of registered detectors."""
        registry = DetectorRegistry()
        assert len(registry) == 0

        registry.register(_make_mock_detector("len_001"))
        assert len(registry) == 1

        registry.register(_make_mock_detector("len_002"))
        assert len(registry) == 2

    def test_registry_contains(self) -> None:
        """__contains__ should return True for registered IDs and False otherwise."""
        registry = DetectorRegistry()
        registry.register(_make_mock_detector("contains_001"))

        assert "contains_001" in registry
        assert "not_registered" not in registry
