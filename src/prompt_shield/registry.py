"""Detector plugin registry with auto-discovery, entry points, and manual registration."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from typing import TYPE_CHECKING

from prompt_shield.exceptions import RegistryError

if TYPE_CHECKING:
    from prompt_shield.detectors.base import BaseDetector

logger = logging.getLogger("prompt_shield.registry")


class DetectorRegistry:
    """Registry for prompt injection detectors.

    Supports three registration methods:
    1. Auto-discovery: scans prompt_shield.detectors package
    2. Entry points: third-party packages via prompt_shield.detectors group
    3. Manual: engine.register_detector() at runtime
    """

    def __init__(self) -> None:
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        """Register a detector instance."""
        if not hasattr(detector, "detector_id"):
            raise RegistryError(
                f"Detector {type(detector).__name__} missing required 'detector_id' attribute"
            )
        detector_id = detector.detector_id
        if detector_id in self._detectors:
            logger.warning("Overwriting existing detector: %s", detector_id)
        self._detectors[detector_id] = detector
        logger.debug("Registered detector: %s", detector_id)

    def unregister(self, detector_id: str) -> None:
        """Remove a detector by ID."""
        if detector_id not in self._detectors:
            raise RegistryError(f"Detector not found: {detector_id}")
        del self._detectors[detector_id]
        logger.debug("Unregistered detector: %s", detector_id)

    def get(self, detector_id: str) -> BaseDetector:
        """Get a detector by ID."""
        if detector_id not in self._detectors:
            raise RegistryError(f"Detector not found: {detector_id}")
        return self._detectors[detector_id]

    def list_all(self) -> list[BaseDetector]:
        """Return all registered detectors."""
        return list(self._detectors.values())

    def list_metadata(self) -> list[dict[str, object]]:
        """Return metadata dicts for all registered detectors."""
        result = []
        for d in self._detectors.values():
            result.append({
                "detector_id": d.detector_id,
                "name": d.name,
                "description": d.description,
                "severity": d.severity.value if hasattr(d.severity, "value") else str(d.severity),
                "tags": d.tags,
                "version": d.version,
                "author": d.author,
            })
        return result

    def auto_discover(self) -> int:
        """Discover and register all detectors in prompt_shield.detectors package.

        Returns the number of detectors discovered.
        """
        from prompt_shield.detectors import base as _base_module

        count = 0
        try:
            import prompt_shield.detectors as detectors_pkg
        except ImportError:
            logger.warning("Could not import prompt_shield.detectors package")
            return 0

        base_cls = _get_base_class()

        for importer, modname, ispkg in pkgutil.iter_modules(
            detectors_pkg.__path__, prefix="prompt_shield.detectors."
        ):
            if modname.endswith(".base"):
                continue
            try:
                module = importlib.import_module(modname)
                for _name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, base_cls)
                        and obj is not base_cls
                        and hasattr(obj, "detector_id")
                        and not inspect.isabstract(obj)
                    ):
                        try:
                            instance = obj()
                            self.register(instance)
                            count += 1
                        except Exception as exc:
                            logger.warning(
                                "Failed to instantiate detector %s from %s: %s",
                                _name, modname, exc,
                            )
            except Exception as exc:
                logger.warning("Failed to import detector module %s: %s", modname, exc)

        return count

    def discover_entry_points(self) -> int:
        """Discover detectors registered via entry points.

        Third-party packages register via pyproject.toml:
            [project.entry-points."prompt_shield.detectors"]
            my_detector = "my_package.detector:MyDetector"

        Returns the number of detectors discovered.
        """
        count = 0
        try:
            from importlib.metadata import entry_points

            eps = entry_points()
            # Python 3.12+ returns a SelectableGroups, older returns dict
            if hasattr(eps, "select"):
                detector_eps = eps.select(group="prompt_shield.detectors")
            else:
                detector_eps = eps.get("prompt_shield.detectors", [])

            base_cls = _get_base_class()

            for ep in detector_eps:
                try:
                    cls = ep.load()
                    if isinstance(cls, type) and issubclass(cls, base_cls):
                        instance = cls()
                        self.register(instance)
                        count += 1
                except Exception as exc:
                    logger.warning(
                        "Failed to load entry point %s: %s", ep.name, exc
                    )
        except Exception as exc:
            logger.warning("Failed to discover entry points: %s", exc)

        return count

    def __len__(self) -> int:
        return len(self._detectors)

    def __contains__(self, detector_id: str) -> bool:
        return detector_id in self._detectors


def _get_base_class() -> type:
    """Import and return BaseDetector class."""
    from prompt_shield.detectors.base import BaseDetector

    return BaseDetector
