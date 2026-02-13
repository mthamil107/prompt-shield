"""Canary token generation and injection into prompt templates."""

from __future__ import annotations

import secrets


class CanaryTokenGenerator:
    """Generates random canary tokens and injects them into prompt text.

    A canary token is a unique hex string that is silently embedded in a
    prompt before it is sent to a model.  If the token (or a significant
    fragment) later appears in the model's response, it indicates that the
    model is leaking prompt content.

    Parameters
    ----------
    token_length:
        Number of hex characters in the generated token.  Defaults to ``16``.
    header_format:
        Format string used when injecting the token.  Must contain a
        ``{canary}`` placeholder.  Defaults to
        ``"<-@!-- {canary} --@!->"``.
    """

    def __init__(
        self,
        token_length: int = 16,
        header_format: str = "<-@!-- {canary} --@!->",
    ) -> None:
        self._token_length = token_length
        self._header_format = header_format

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> str:
        """Generate a cryptographically random hex canary token.

        Returns
        -------
        str
            A lowercase hex string of length ``token_length``.
        """
        return secrets.token_hex(self._token_length // 2)

    def inject(self, prompt_template: str) -> tuple[str, str]:
        """Inject a new canary token into *prompt_template*.

        The token is formatted using :attr:`header_format` and prepended
        to the prompt with a newline separator.

        Parameters
        ----------
        prompt_template:
            The original prompt text.

        Returns
        -------
        tuple[str, str]
            ``(modified_prompt, token)`` where *modified_prompt* has the
            canary header prepended and *token* is the raw hex string.
        """
        token = self.generate()
        header = self._header_format.format(canary=token)
        modified_prompt = header + "\n" + prompt_template
        return modified_prompt, token
