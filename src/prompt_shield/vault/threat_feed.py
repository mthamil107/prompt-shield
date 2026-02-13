"""Threat feed manager for importing, exporting, and syncing community feeds."""

from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone

from prompt_shield.exceptions import ThreatFeedError
from prompt_shield.models import ThreatEntry, ThreatFeed
from prompt_shield.vault.attack_vault import AttackVault


class ThreatFeedManager:
    """Orchestrates threat intelligence exchange via JSON feed files.

    Parameters
    ----------
    vault:
        The :class:`AttackVault` that stores and queries threat embeddings.
    data_dir:
        Root data directory.  Downloaded feeds are cached under
        ``<data_dir>/threats/``.
    """

    def __init__(self, vault: AttackVault, data_dir: str) -> None:
        self._vault = vault
        self._data_dir = data_dir

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_feed(
        self,
        output_path: str,
        since: str | None = None,
    ) -> ThreatFeed:
        """Export local threats as a :class:`ThreatFeed` JSON file.

        Parameters
        ----------
        output_path:
            Destination file path for the JSON output.
        since:
            Optional ISO-8601 timestamp.  Only threats first seen after this
            date are included.

        Returns
        -------
        ThreatFeed
            The validated feed model that was written to disk.
        """
        try:
            threats: list[ThreatEntry] = self._vault.export_threats(since=since)

            feed = ThreatFeed(
                version="1.0",
                generated_at=datetime.now(timezone.utc),
                generator="prompt-shield",
                embedding_model=self._vault.embedder.model_name,
                embedding_dim=self._vault.embedder.dimension,
                total_threats=len(threats),
                threats=threats,
            )

            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(feed.model_dump_json(indent=2))

            return feed
        except ThreatFeedError:
            raise
        except Exception as exc:
            raise ThreatFeedError(f"Failed to export feed: {exc}") from exc

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def import_feed(self, source_path: str) -> dict:
        """Import a threat feed from a local JSON file.

        The file is validated against the :class:`ThreatFeed` schema.  If the
        feed's ``embedding_model`` does not match the vault's embedder model
        the import is rejected.

        Returns
        -------
        dict
            ``{"imported": int, "duplicates_skipped": int, "errors": int}``
        """
        errors = 0
        try:
            with open(source_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)

            feed = ThreatFeed.model_validate(raw)

            if feed.embedding_model != self._vault.embedder.model_name:
                raise ThreatFeedError(
                    f"Embedding model mismatch: feed uses "
                    f"'{feed.embedding_model}' but vault uses "
                    f"'{self._vault.embedder.model_name}'"
                )

            result = self._vault.import_threats(feed.threats)
        except ThreatFeedError:
            raise
        except Exception as exc:
            raise ThreatFeedError(f"Failed to import feed: {exc}") from exc

        return {
            "imported": result["imported"],
            "duplicates_skipped": result["duplicates_skipped"],
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Remote sync
    # ------------------------------------------------------------------

    def sync_feed(self, feed_url: str) -> dict:
        """Download a remote threat feed and import it.

        The feed is saved to ``<data_dir>/threats/`` before importing so that
        a local copy is available for auditing.

        Returns
        -------
        dict
            Same keys as :meth:`import_feed` plus ``"feed_url"``.
        """
        threats_dir = os.path.join(self._data_dir, "threats")
        os.makedirs(threats_dir, exist_ok=True)

        # Derive a safe local filename from the URL.
        safe_name = (
            feed_url
            .rsplit("/", 1)[-1]
            .replace("?", "_")
            .replace("&", "_")
        ) or "feed.json"
        if not safe_name.endswith(".json"):
            safe_name += ".json"

        local_path = os.path.join(threats_dir, safe_name)

        try:
            req = urllib.request.Request(feed_url, method="GET")
            with urllib.request.urlopen(req) as resp:  # noqa: S310
                data = resp.read()

            with open(local_path, "wb") as fh:
                fh.write(data)
        except Exception as exc:
            raise ThreatFeedError(
                f"Failed to download feed from '{feed_url}': {exc}"
            ) from exc

        result = self.import_feed(local_path)
        result["feed_url"] = feed_url
        return result
