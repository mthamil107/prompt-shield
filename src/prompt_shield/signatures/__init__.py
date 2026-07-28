"""Federated threat-intel feed client for prompt-shield.

Fetches and verifies signed signature data from prompt-shield-signatures
(https://github.com/mthamil107/prompt-shield-signatures) — a public
ed25519-signed feed of known prompt-injection attack patterns published
under CC0.

Quick start (verify only)::

    from prompt_shield.signatures import SignaturesClient

    client = SignaturesClient()
    update = client.fetch()
    print(update)  # SignaturesUpdate(success=True, signature_count=56, ...)

End-to-end (verify + apply to a live engine)::

    from prompt_shield import PromptShieldEngine
    from prompt_shield.signatures import MAINTAINER_PUBLIC_KEY, apply_to_engine

    engine = PromptShieldEngine()
    result = apply_to_engine(
        engine,
        feed_url="https://cdn.jsdelivr.net/gh/mthamil107/prompt-shield-signatures@main/v1/signatures.json",
        public_key=MAINTAINER_PUBLIC_KEY,
    )
    # {'signature_count': 56, 'verified': True, 'source_url': ..., 'loaded_rules': 56}

``apply_to_engine`` is a thin bridge that runs ``SignaturesClient.fetch()``
(which verifies the detached minisign signature) and then loads the
verified regex signatures into the engine's ``d030_custom_rules`` detector.
It never writes to the engine unless verification succeeds.
"""

from prompt_shield.signatures.apply_to_engine import apply_to_engine
from prompt_shield.signatures.client import (
    DEFAULT_FEED_URL,
    DEFAULT_SIG_URL,
    MAINTAINER_PUBLIC_KEY,
    SignaturesClient,
    SignaturesUpdate,
    SignatureVerificationError,
)

__all__ = [
    "DEFAULT_FEED_URL",
    "DEFAULT_SIG_URL",
    "MAINTAINER_PUBLIC_KEY",
    "SignatureVerificationError",
    "SignaturesClient",
    "SignaturesUpdate",
    "apply_to_engine",
]
