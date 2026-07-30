"""Tests for the ThreatFeedManager.sync_feed() download path.

Covers the v0.7.3 hardening of the legacy remote-sync path: HTTPS-only
URL-scheme allowlist and explicit connect/read timeout. The signed-feed
path (``apply_to_engine``) is exercised in tests/signatures/, not here.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from prompt_shield.exceptions import ThreatFeedError
from prompt_shield.vault.threat_feed import ThreatFeedManager


@pytest.fixture
def manager(tmp_path) -> ThreatFeedManager:
    """A ThreatFeedManager wired to a mock vault and a scratch data_dir.

    The vault mock never has its methods called by the tests below — every
    test either short-circuits before the download (scheme-rejection tests)
    or intercepts urlopen (timeout test).
    """
    vault = MagicMock()
    vault.embedder.model_name = "all-MiniLM-L6-v2"
    return ThreatFeedManager(vault=vault, data_dir=str(tmp_path))


class TestSchemeAllowlist:
    """Only https:// URLs are accepted by sync_feed()."""

    @pytest.mark.parametrize(
        "bad_url",
        [
            "file:///etc/passwd",
            "file:///C:/Windows/System32/config/SAM",
            "http://example.com/feed.json",
            "ftp://mirror.example.com/feed.json",
            "javascript:alert(1)",
            "data:application/json,{}",
            # empty / malformed
            "",
            "example.com/feed.json",  # missing scheme
        ],
    )
    def test_sync_feed_rejects_non_https_scheme(
        self, manager: ThreatFeedManager, bad_url: str
    ) -> None:
        with pytest.raises(ValueError, match="requires an https:// URL"):
            manager.sync_feed(bad_url)

    def test_error_message_names_the_bad_url(self, manager: ThreatFeedManager) -> None:
        """The ValueError includes the offending URL for actionable logs."""
        with pytest.raises(ValueError) as exc_info:
            manager.sync_feed("http://example.com/x.json")
        assert "http://example.com/x.json" in str(exc_info.value)

    def test_https_url_passes_scheme_gate(self, manager: ThreatFeedManager) -> None:
        """An https:// URL clears the gate and then fails at the network call.

        We patch urlopen to raise a URLError so the test doesn't actually
        touch the network — we're only asserting the scheme check didn't
        short-circuit first (which would raise ValueError, not
        ThreatFeedError).
        """
        with (
            patch(
                "prompt_shield.vault.threat_feed.urllib.request.urlopen",
                side_effect=OSError("simulated network down"),
            ),
            pytest.raises(ThreatFeedError, match="Failed to download"),
        ):
            manager.sync_feed("https://example.com/feed.json")


class TestTimeout:
    """sync_feed() must pass an explicit timeout to urlopen so a hung
    feed server can't wedge the sync worker forever."""

    def test_sync_feed_passes_timeout_kwarg(self, manager: ThreatFeedManager) -> None:
        """Assert the timeout kwarg is set on the urlopen call.

        We can't check what timeout the socket layer *actually* enforced
        without a real slow server; the contract we verify here is that
        the caller code passed a positive numeric timeout. Everything
        below the urllib boundary is CPython's problem.
        """
        with (
            patch(
                "prompt_shield.vault.threat_feed.urllib.request.urlopen",
                side_effect=OSError("intercepted"),
            ) as mock_urlopen,
            pytest.raises(ThreatFeedError),
        ):
            manager.sync_feed("https://example.com/feed.json")

        assert mock_urlopen.called, "urlopen was never invoked"
        _args, kwargs = mock_urlopen.call_args
        assert "timeout" in kwargs, (
            "sync_feed() must pass an explicit timeout to urlopen; without "
            "one CPython uses socket.getdefaulttimeout() which is typically "
            "None (block forever)"
        )
        assert isinstance(kwargs["timeout"], (int, float))
        assert kwargs["timeout"] > 0
        # Sanity: not something absurdly high like 3600s — that would
        # defeat the purpose of having a timeout at all.
        assert kwargs["timeout"] <= 120, (
            f"timeout={kwargs['timeout']}s is too high to protect against "
            f"a hung feed server; the module default is 30s"
        )

    def test_timeout_error_wrapped_as_threatfeederror(self, manager: ThreatFeedManager) -> None:
        """A socket TimeoutError should surface as ThreatFeedError, not
        as a bare TimeoutError bubbling up through the call site."""
        with (
            patch(
                "prompt_shield.vault.threat_feed.urllib.request.urlopen",
                side_effect=TimeoutError("read timed out"),
            ),
            pytest.raises(ThreatFeedError, match="Failed to download"),
        ):
            manager.sync_feed("https://example.com/feed.json")
