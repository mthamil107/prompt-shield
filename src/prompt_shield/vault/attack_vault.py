"""ChromaDB-backed attack intelligence vault for similarity search."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field

import chromadb
from chromadb import EmbeddingFunction, Embeddings

from prompt_shield.exceptions import VaultError
from prompt_shield.models import ThreatEntry
from prompt_shield.utils import sha256_hash
from prompt_shield.vault.embedder import Embedder


# ------------------------------------------------------------------
# Helper dataclass
# ------------------------------------------------------------------


@dataclass
class VaultMatch:
    """A single similarity match returned from the vault."""

    id: str
    similarity_score: float
    metadata: dict = field(default_factory=dict)


# ------------------------------------------------------------------
# Bridging ChromaDB's EmbeddingFunction protocol
# ------------------------------------------------------------------


class _EmbedderBridge(EmbeddingFunction[list[str]]):
    """Adapts :class:`Embedder` to the ChromaDB ``EmbeddingFunction`` interface."""

    def __init__(self, embedder: Embedder) -> None:
        self._embedder = embedder

    def __call__(self, input: list[str]) -> Embeddings:  # noqa: A002
        return self._embedder.encode_batch(input)


# ------------------------------------------------------------------
# Main vault class
# ------------------------------------------------------------------


class AttackVault:
    """Self-learning vector similarity store backed by ChromaDB.

    Parameters
    ----------
    data_dir:
        Root directory for persistent storage.  ChromaDB files are kept under
        ``<data_dir>/vault`` and model weights under ``<data_dir>/models``.
    embedding_model:
        HuggingFace model identifier forwarded to :class:`Embedder`.
    similarity_threshold:
        Default minimum similarity score (1 - cosine distance) for a match
        to be considered relevant.  Used as metadata; filtering is left to
        callers.
    """

    _COLLECTION_NAME = "attack_vault"

    def __init__(
        self,
        data_dir: str,
        embedding_model: str = "all-MiniLM-L6-v2",
        similarity_threshold: float = 0.85,
    ) -> None:
        self._data_dir = data_dir
        self._similarity_threshold = similarity_threshold

        vault_path = os.path.join(data_dir, "vault")
        models_path = os.path.join(data_dir, "models")

        self.embedder = Embedder(model_name=embedding_model, cache_dir=models_path)

        try:
            self._client = chromadb.PersistentClient(path=vault_path)
            self._collection = self._client.get_or_create_collection(
                name=self._COLLECTION_NAME,
                embedding_function=_EmbedderBridge(self.embedder),
                metadata={"hnsw:space": "cosine"},
            )
        except Exception as exc:
            raise VaultError(f"Failed to initialise ChromaDB: {exc}") from exc

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(self, input_text: str, n_results: int = 5) -> list[VaultMatch]:
        """Find the closest stored entries to *input_text*.

        Returns a list of :class:`VaultMatch` objects sorted by descending
        similarity score (``1 - distance``).
        """
        try:
            embedding = self.embedder.encode(input_text)
            results = self._collection.query(
                query_embeddings=[embedding],
                n_results=n_results,
                include=["distances", "metadatas"],
            )

            matches: list[VaultMatch] = []
            ids = results.get("ids", [[]])[0]
            distances = results.get("distances", [[]])[0]
            metadatas = results.get("metadatas", [[]])[0]

            for entry_id, distance, meta in zip(ids, distances, metadatas):
                similarity = 1.0 - distance
                matches.append(
                    VaultMatch(
                        id=entry_id,
                        similarity_score=similarity,
                        metadata=meta or {},
                    )
                )

            matches.sort(key=lambda m: m.similarity_score, reverse=True)
            return matches
        except VaultError:
            raise
        except Exception as exc:
            raise VaultError(f"Vault query failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Store / Remove
    # ------------------------------------------------------------------

    def store(self, input_text: str, metadata: dict) -> str:
        """Store a new entry in the vault.

        The raw text is **never** persisted — only its SHA-256 hash is kept as
        the ChromaDB document.  Returns the generated UUID.
        """
        try:
            entry_id = str(uuid.uuid4())
            text_hash = sha256_hash(input_text)
            embedding = self.embedder.encode(input_text)

            self._collection.add(
                ids=[entry_id],
                documents=[text_hash],
                embeddings=[embedding],
                metadatas=[metadata],
            )
            return entry_id
        except VaultError:
            raise
        except Exception as exc:
            raise VaultError(f"Failed to store entry: {exc}") from exc

    def remove(self, entry_id: str) -> None:
        """Delete an entry by its id."""
        try:
            self._collection.delete(ids=[entry_id])
        except Exception as exc:
            raise VaultError(f"Failed to remove entry '{entry_id}': {exc}") from exc

    # ------------------------------------------------------------------
    # Threat feed helpers
    # ------------------------------------------------------------------

    def import_threats(self, threats: list[ThreatEntry]) -> dict:
        """Bulk-import a list of :class:`ThreatEntry` objects.

        Entries whose ``pattern_hash`` already exists in the collection are
        silently skipped (deduplication).

        Returns
        -------
        dict
            ``{"imported": int, "duplicates_skipped": int}``
        """
        imported = 0
        duplicates_skipped = 0

        try:
            # Fetch all existing pattern hashes in one call so we can
            # deduplicate without N+1 queries.
            existing_meta = self._collection.get(include=["metadatas"])
            existing_hashes: set[str] = set()
            for meta in existing_meta.get("metadatas") or []:
                if meta and "pattern_hash" in meta:
                    existing_hashes.add(meta["pattern_hash"])

            for threat in threats:
                if threat.pattern_hash in existing_hashes:
                    duplicates_skipped += 1
                    continue

                metadata: dict[str, object] = {
                    "pattern_hash": threat.pattern_hash,
                    "detector_id": threat.detector_id,
                    "severity": threat.severity.value,
                    "confidence": threat.confidence,
                    "first_seen": threat.first_seen,
                    "report_count": threat.report_count,
                    "tags": ",".join(threat.tags),
                    "source": "feed",
                }

                self._collection.add(
                    ids=[threat.id],
                    documents=[threat.pattern_hash],
                    embeddings=[threat.embedding],
                    metadatas=[metadata],  # type: ignore[arg-type]
                )
                existing_hashes.add(threat.pattern_hash)
                imported += 1

        except VaultError:
            raise
        except Exception as exc:
            raise VaultError(f"Threat import failed: {exc}") from exc

        return {"imported": imported, "duplicates_skipped": duplicates_skipped}

    def export_threats(self, since: str | None = None) -> list[ThreatEntry]:
        """Export locally-sourced entries as :class:`ThreatEntry` objects.

        Only entries with ``source == "local"`` are included.  If *since* is
        given it is compared against the ``first_seen`` metadata field (ISO-8601
        string comparison).
        """
        try:
            where_filter: dict[str, object] = {"source": "local"}
            data = self._collection.get(
                where=where_filter,
                include=["embeddings", "metadatas"],
            )

            entries: list[ThreatEntry] = []
            ids = data.get("ids") or []
            embeddings = data.get("embeddings") or []
            metadatas = data.get("metadatas") or []

            for entry_id, embedding, meta in zip(ids, embeddings, metadatas):
                if meta is None:
                    continue

                first_seen = str(meta.get("first_seen", ""))
                if since and first_seen < since:
                    continue

                tags_raw = meta.get("tags", "")
                tags = [t for t in str(tags_raw).split(",") if t] if tags_raw else []

                entries.append(
                    ThreatEntry(
                        id=entry_id,
                        pattern_hash=str(meta.get("pattern_hash", "")),
                        embedding=list(embedding),
                        detector_id=str(meta.get("detector_id", "")),
                        severity=str(meta.get("severity", "medium")),
                        confidence=float(meta.get("confidence", 0.0)),
                        first_seen=first_seen,
                        report_count=int(meta.get("report_count", 1)),
                        tags=tags,
                    )
                )

            return entries
        except VaultError:
            raise
        except Exception as exc:
            raise VaultError(f"Threat export failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return summary statistics for the vault.

        Returns
        -------
        dict
            ``{"total": int, "by_source": {<source>: int, ...}}``
        """
        try:
            data = self._collection.get(include=["metadatas"])
            metadatas = data.get("metadatas") or []

            by_source: dict[str, int] = {}
            for meta in metadatas:
                source = str((meta or {}).get("source", "unknown"))
                by_source[source] = by_source.get(source, 0) + 1

            return {
                "total": len(metadatas),
                "by_source": by_source,
            }
        except Exception as exc:
            raise VaultError(f"Failed to compute vault stats: {exc}") from exc

    def clear(self) -> None:
        """Delete **all** entries and recreate an empty collection."""
        try:
            self._client.delete_collection(name=self._COLLECTION_NAME)
            self._collection = self._client.get_or_create_collection(
                name=self._COLLECTION_NAME,
                embedding_function=_EmbedderBridge(self.embedder),
                metadata={"hnsw:space": "cosine"},
            )
        except Exception as exc:
            raise VaultError(f"Failed to clear vault: {exc}") from exc
