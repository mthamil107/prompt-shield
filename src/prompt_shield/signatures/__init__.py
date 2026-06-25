"""Federated threat-intel feed client for prompt-shield.

Fetches and verifies signed signature data from prompt-shield-signatures
(https://github.com/mthamil107/prompt-shield-signatures) — a public
ed25519-signed feed of known prompt-injection attack patterns published
under CC0.

Quick start:

    from prompt_shield.signatures import SignaturesClient

    client = SignaturesClient()
    update = client.fetch()
    print(update)  # SignaturesUpdate(success=True, signature_count=56, ...)

The fetched signatures are returned as plain dicts ready to drop into
the d030 custom-rules detector. See ``SignaturesClient.fetch`` and
``apply_to_engine`` for end-to-end usage.
"""

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
]
