"""Shared test fixtures for prompt-shield."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Generator

import pytest


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    """Create a temporary data directory for tests."""
    data_dir = tmp_path / "prompt_shield_test"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def sample_config(tmp_data_dir: Path) -> dict[str, Any]:
    """Minimal config dict for testing — vault/feedback disabled to avoid heavy deps."""
    return {
        "prompt_shield": {
            "mode": "block",
            "threshold": 0.7,
            "data_dir": str(tmp_data_dir),
            "vault": {"enabled": False},
            "feedback": {"enabled": False},
            "canary": {"enabled": True, "token_length": 16},
            "history": {"enabled": True, "retention_days": 90},
            "threat_feed": {"enabled": False},
            "actions": {"critical": "block", "high": "block", "medium": "flag", "low": "log"},
            "detectors": {},
            "allowlist": {"patterns": []},
            "blocklist": {"patterns": []},
        }
    }


@pytest.fixture
def engine(sample_config: dict[str, Any], tmp_data_dir: Path):
    """Create a PromptShieldEngine for testing (vault disabled for speed)."""
    from prompt_shield.engine import PromptShieldEngine
    return PromptShieldEngine(config_dict=sample_config, data_dir=str(tmp_data_dir))


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


def load_fixture(fixture_path: Path) -> dict[str, Any]:
    """Load a JSON fixture file."""
    return json.loads(fixture_path.read_text(encoding="utf-8"))
