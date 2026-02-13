"""Custom exceptions for prompt-shield."""

from __future__ import annotations


class PromptShieldError(Exception):
    """Base exception for all prompt-shield errors."""


class ConfigError(PromptShieldError):
    """Raised when configuration is invalid or cannot be loaded."""


class DetectorError(PromptShieldError):
    """Raised when a detector fails during scanning."""


class RegistryError(PromptShieldError):
    """Raised when detector registration or discovery fails."""


class VaultError(PromptShieldError):
    """Raised when the attack vault encounters an error."""


class EmbedderError(PromptShieldError):
    """Raised when embedding generation fails."""


class PersistenceError(PromptShieldError):
    """Raised when database operations fail."""


class FeedbackError(PromptShieldError):
    """Raised when feedback recording or processing fails."""


class ThreatFeedError(PromptShieldError):
    """Raised when threat feed import/export/sync fails."""


class ScanError(PromptShieldError):
    """Raised when a scan operation fails."""
