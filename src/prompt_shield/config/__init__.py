"""Configuration loader for prompt-shield (YAML + env vars + defaults)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from prompt_shield.exceptions import ConfigError
from prompt_shield.models import Severity

_DEFAULT_CONFIG_PATH = Path(__file__).parent / "default.yaml"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(config: dict[str, Any]) -> dict[str, Any]:
    """Apply environment variable overrides.

    Convention: PROMPT_SHIELD_<SECTION>_<KEY> in uppercase.
    """
    prefix = "PROMPT_SHIELD_"
    ps = config.get("prompt_shield", config)

    env_map: dict[str, tuple[str, ...]] = {
        f"{prefix}MODE": ("mode",),
        f"{prefix}THRESHOLD": ("threshold",),
        f"{prefix}DATA_DIR": ("data_dir",),
        f"{prefix}VAULT_ENABLED": ("vault", "enabled"),
        f"{prefix}VAULT_SIMILARITY_THRESHOLD": ("vault", "similarity_threshold"),
        f"{prefix}FEEDBACK_ENABLED": ("feedback", "enabled"),
        f"{prefix}CANARY_ENABLED": ("canary", "enabled"),
        f"{prefix}LOGGING_LEVEL": ("logging", "level"),
    }

    for env_key, path in env_map.items():
        value = os.environ.get(env_key)
        if value is None:
            continue

        if value.lower() in ("true", "false"):
            coerced: Any = value.lower() == "true"
        else:
            try:
                coerced = float(value)
            except ValueError:
                coerced = value

        target = ps
        for part in path[:-1]:
            target = target.setdefault(part, {})
        target[path[-1]] = coerced

    return config


def load_config(
    config_path: str | None = None,
    config_dict: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Load configuration from YAML file, dict override, and env vars.

    Priority (highest to lowest):
    1. Environment variables
    2. config_dict parameter
    3. config_path YAML file
    4. Default config
    """
    try:
        with open(_DEFAULT_CONFIG_PATH) as f:
            config = yaml.safe_load(f)
    except Exception as exc:
        raise ConfigError(f"Failed to load default config: {exc}") from exc

    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"Config file not found: {config_path}")
        try:
            with open(path) as f:
                user_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, user_config)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {config_path}: {exc}") from exc

    if config_dict:
        if "prompt_shield" in config_dict:
            config = _deep_merge(config, config_dict)
        else:
            config = _deep_merge(config, {"prompt_shield": config_dict})

    config = _apply_env_overrides(config)

    return config


def resolve_data_dir(config: dict[str, Any]) -> Path:
    """Resolve the data directory path."""
    ps = config.get("prompt_shield", config)
    explicit = ps.get("data_dir")

    if explicit:
        return Path(explicit)

    if Path(".prompt-shield.yaml").exists():
        return Path(".prompt_shield")

    return Path.home() / ".prompt_shield"


def get_detector_config(config: dict[str, Any], detector_id: str) -> dict[str, Any]:
    """Get per-detector config, falling back to global defaults.

    Returns all detector-specific keys plus ``enabled`` and ``threshold``
    with sensible defaults so that custom detectors (e.g. d022) can
    receive extra settings like ``model_name`` or ``device``.
    """
    ps = config.get("prompt_shield", config)
    detectors = ps.get("detectors", {})
    detector_cfg = dict(detectors.get(detector_id, {}))

    detector_cfg.setdefault("enabled", True)
    detector_cfg.setdefault("severity", None)
    detector_cfg.setdefault("threshold", ps.get("threshold", 0.7))
    return detector_cfg


def get_action_for_severity(config: dict[str, Any], severity: Severity) -> str:
    """Get the configured action for a given severity level."""
    ps = config.get("prompt_shield", config)
    actions = ps.get("actions", {})
    return actions.get(severity.value, ps.get("mode", "block"))


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate configuration, returning a list of error messages (empty = valid)."""
    errors: list[str] = []
    ps = config.get("prompt_shield")
    if not ps:
        errors.append("Missing top-level 'prompt_shield' key")
        return errors

    mode = ps.get("mode", "block")
    if mode not in ("block", "monitor", "flag"):
        errors.append(f"Invalid mode: {mode}. Must be block, monitor, or flag")

    threshold = ps.get("threshold", 0.7)
    if not isinstance(threshold, (int, float)) or not 0.0 <= threshold <= 1.0:
        errors.append(f"Invalid threshold: {threshold}. Must be 0.0-1.0")

    vault = ps.get("vault", {})
    sim_thresh = vault.get("similarity_threshold", 0.85)
    if not isinstance(sim_thresh, (int, float)) or not 0.0 <= sim_thresh <= 1.0:
        errors.append(f"Invalid vault similarity_threshold: {sim_thresh}")

    return errors
