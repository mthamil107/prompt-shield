"""Tests for configuration loading and validation."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from prompt_shield.config import (
    get_action_for_severity,
    get_detector_config,
    load_config,
    resolve_data_dir,
    validate_config,
)
from prompt_shield.models import Severity


class TestLoadConfig:
    """Tests for load_config."""

    def test_load_default_config(self) -> None:
        """Loading with no args should return a config with prompt_shield key."""
        config = load_config()
        assert "prompt_shield" in config
        ps = config["prompt_shield"]
        assert "mode" in ps
        assert "threshold" in ps

    def test_load_config_with_dict(self) -> None:
        """Loading with a config_dict override should merge values."""
        override = {
            "prompt_shield": {
                "mode": "monitor",
                "threshold": 0.9,
            }
        }
        config = load_config(config_dict=override)
        ps = config["prompt_shield"]
        assert ps["mode"] == "monitor"
        assert ps["threshold"] == 0.9


class TestEnvOverride:
    """Tests for environment variable overrides."""

    def test_config_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Setting PROMPT_SHIELD_MODE env var should override config mode."""
        monkeypatch.setenv("PROMPT_SHIELD_MODE", "monitor")
        config = load_config()
        ps = config["prompt_shield"]
        assert ps["mode"] == "monitor"


class TestResolveDataDir:
    """Tests for data directory resolution."""

    def test_resolve_data_dir_default(self) -> None:
        """Without explicit data_dir, should return ~/.prompt_shield."""
        config = {"prompt_shield": {"data_dir": None}}
        result = resolve_data_dir(config)
        assert result == Path.home() / ".prompt_shield"

    def test_resolve_data_dir_explicit(self, tmp_path: Path) -> None:
        """Explicit data_dir in config should be used directly."""
        explicit = str(tmp_path / "custom_data")
        config = {"prompt_shield": {"data_dir": explicit}}
        result = resolve_data_dir(config)
        assert result == Path(explicit)


class TestDetectorConfig:
    """Tests for get_detector_config."""

    def test_get_detector_config(self) -> None:
        """Should return enabled, threshold, and severity for a detector."""
        config = {
            "prompt_shield": {
                "threshold": 0.7,
                "detectors": {
                    "d001_system_prompt_extraction": {
                        "enabled": True,
                        "severity": "critical",
                        "threshold": 0.6,
                    }
                },
            }
        }
        det_cfg = get_detector_config(config, "d001_system_prompt_extraction")
        assert det_cfg["enabled"] is True
        assert det_cfg["severity"] == "critical"
        assert det_cfg["threshold"] == 0.6

    def test_get_detector_config_defaults(self) -> None:
        """Missing per-detector config should fall back to global defaults."""
        config = {
            "prompt_shield": {
                "threshold": 0.7,
                "detectors": {},
            }
        }
        det_cfg = get_detector_config(config, "nonexistent_detector")
        assert det_cfg["enabled"] is True
        assert det_cfg["severity"] is None
        assert det_cfg["threshold"] == 0.7


class TestGetActionForSeverity:
    """Tests for get_action_for_severity."""

    def test_get_action_for_severity(self) -> None:
        """Should correctly map severity levels to configured actions."""
        config = {
            "prompt_shield": {
                "mode": "block",
                "actions": {
                    "critical": "block",
                    "high": "block",
                    "medium": "flag",
                    "low": "log",
                },
            }
        }
        assert get_action_for_severity(config, Severity.CRITICAL) == "block"
        assert get_action_for_severity(config, Severity.HIGH) == "block"
        assert get_action_for_severity(config, Severity.MEDIUM) == "flag"
        assert get_action_for_severity(config, Severity.LOW) == "log"


class TestValidateConfig:
    """Tests for validate_config."""

    def test_validate_config_valid(self) -> None:
        """A valid config should return an empty errors list."""
        config = {
            "prompt_shield": {
                "mode": "block",
                "threshold": 0.7,
                "vault": {"similarity_threshold": 0.85},
            }
        }
        errors = validate_config(config)
        assert errors == []

    def test_validate_config_invalid_mode(self) -> None:
        """An invalid mode value should produce a validation error."""
        config = {
            "prompt_shield": {
                "mode": "invalid_mode",
                "threshold": 0.7,
            }
        }
        errors = validate_config(config)
        assert len(errors) > 0
        assert any("Invalid mode" in e for e in errors)
