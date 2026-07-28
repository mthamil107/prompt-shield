"""Bridge between the signed federated feed and a live ``PromptShieldEngine``.

The federated feed (see :mod:`prompt_shield.signatures.client`) publishes
regex / substring signatures ready to drop into the ``d030_custom_rules``
detector. This module wires those two ends together so callers don't have
to reach into detector internals themselves.

Verification is **mandatory**: the feed is only ever consumed after its
detached minisign signature has been validated against the caller-supplied
public key. If verification fails, :class:`SignatureVerificationError` is
raised and the engine's state is left untouched.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import regex

from prompt_shield.models import Severity
from prompt_shield.signatures.client import (
    DEFAULT_SIG_URL,
    SignaturesClient,
    SignatureVerificationError,
)

if TYPE_CHECKING:
    from prompt_shield.engine import PromptShieldEngine

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _derive_sig_url(feed_url: str) -> str:
    """Guess the .minisig URL from the feed URL.

    The published feed pairs ``<name>.json`` with ``<name>.json.minisig``.
    If the caller passed a URL that already ends in ``.minisig`` we return
    it verbatim; if they passed the canonical CDN feed URL we return the
    canonical signature URL.
    """
    if feed_url.endswith(".minisig"):
        return feed_url
    if not feed_url:
        return DEFAULT_SIG_URL
    return feed_url + ".minisig"


def apply_to_engine(
    engine: PromptShieldEngine,
    feed_url: str,
    public_key: str,
    *,
    cache_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Fetch, verify, and load federated signatures into a live engine.

    Parameters
    ----------
    engine:
        A :class:`prompt_shield.engine.PromptShieldEngine` instance. Its
        ``d030_custom_rules`` detector (if registered) will receive one
        :class:`prompt_shield.detectors.d030_custom_rules.CustomRule` per
        verified signature.
    feed_url:
        URL of the signatures.json feed. The corresponding ``.minisig``
        URL is derived automatically.
    public_key:
        Base64-encoded minisign ed25519 public key. Signatures that do not
        verify against this key are rejected.
    cache_dir:
        Optional directory in which to cache the verified feed. When ``None``
        the client's default cache location is used.

    Returns
    -------
    dict
        ``{"signature_count": int, "verified": bool, "source_url": str,
        "loaded_rules": int}``. ``verified`` is only ``True`` when the
        detached minisign signature passed verification.

    Raises
    ------
    SignatureVerificationError
        If the feed cannot be fetched or its signature cannot be verified
        against ``public_key``.
    """
    cache_file: Path | None = None
    if cache_dir is not None:
        cache_file = Path(cache_dir) / "signatures.json"

    client = SignaturesClient(
        feed_url=feed_url,
        sig_url=_derive_sig_url(feed_url),
        public_key=public_key,
        cache_file=cache_file,
        # Callers control refresh cadence; the throttle is only useful for
        # long-lived clients that would otherwise hammer the CDN.
        min_fetch_interval_seconds=0,
    )
    update = client.fetch(force=True)
    if not update.success:
        raise SignatureVerificationError(
            update.error or "feed fetch or signature verification failed"
        )

    loaded_rules = _install_signatures(engine, update.signatures)

    return {
        "signature_count": update.signature_count,
        "verified": True,
        "source_url": feed_url,
        "loaded_rules": loaded_rules,
    }


def _install_signatures(engine: PromptShieldEngine, signatures: list[dict[str, Any]]) -> int:
    """Convert verified signature dicts to CustomRule objects and load them.

    Silently no-ops if the engine has no ``d030_custom_rules`` detector.
    """
    if not signatures:
        return 0

    try:
        registry = engine._registry
    except AttributeError:
        return 0

    if "d030_custom_rules" not in registry:
        logger.warning(
            "apply_to_engine: engine has no d030_custom_rules detector; "
            "%d verified signatures will not be applied",
            len(signatures),
        )
        return 0

    from prompt_shield.detectors.d030_custom_rules import CustomRule

    d030 = registry.get("d030_custom_rules")
    if not hasattr(d030, "_rules"):
        return 0

    installed: list[CustomRule] = []
    for sig in signatures:
        rule = _to_custom_rule(sig)
        if rule is not None:
            installed.append(rule)

    d030._rules.extend(installed)
    return len(installed)


def _to_custom_rule(sig: dict[str, Any]) -> Any | None:
    """Convert a single signature dict to a CustomRule, or return None."""
    from prompt_shield.detectors.d030_custom_rules import CustomRule

    sig_id = sig.get("id")
    pattern_str = sig.get("pattern")
    if not isinstance(sig_id, str) or not isinstance(pattern_str, str) or not pattern_str:
        return None

    sig_type = str(sig.get("type", "regex")).lower()
    if sig_type == "substring":
        pattern_str = regex.escape(pattern_str)

    severity = _SEVERITY_MAP.get(str(sig.get("severity", "medium")).lower(), Severity.MEDIUM)
    description = str(sig.get("description", "") or sig.get("category", ""))

    try:
        compiled = regex.compile(pattern_str, regex.IGNORECASE | regex.UNICODE)
    except regex.error as exc:
        logger.warning("apply_to_engine: skipping signature %s (bad pattern): %s", sig_id, exc)
        return None

    return CustomRule(
        id=sig_id,
        pattern=compiled,
        severity=severity,
        action="block",
        description=description,
    )
