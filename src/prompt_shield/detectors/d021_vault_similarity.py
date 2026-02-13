"""Detector that matches inputs against known attack embeddings using vector similarity."""

from __future__ import annotations

import regex  # noqa: F401 – required by detector contract

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class VaultSimilarityDetector(BaseDetector):
    """Matches inputs against known attack embeddings using vector similarity.

    This detector queries the :class:`AttackVault` for stored attack
    patterns that are semantically similar to the incoming input.  The
    vault is injected by the engine after construction; if no vault is
    available, the detector is a no-op.
    """

    detector_id: str = "d021_vault_similarity"
    name: str = "Vault Similarity"
    description: str = (
        "Matches inputs against known attack embeddings using vector similarity"
    )
    severity: Severity = Severity.HIGH
    tags: list[str] = ["self_learning", "vector_similarity"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        self.vault = None  # Will be injected by the engine

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        if self.vault is None:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="Vault not available; skipping similarity check",
            )

        vault_matches = self.vault.query(input_text)

        if not vault_matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No matches found in vault",
            )

        threshold = getattr(self.vault, "_similarity_threshold", 0.85)

        matches_above_threshold = [
            vm for vm in vault_matches if vm.similarity_score >= threshold
        ]

        if not matches_above_threshold:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=(
                    f"Vault matches found but none above threshold "
                    f"({threshold})"
                ),
            )

        # Determine severity from top match metadata if available
        top_match = matches_above_threshold[0]
        severity = self.severity
        if top_match.metadata and "severity" in top_match.metadata:
            try:
                severity = Severity(top_match.metadata["severity"])
            except ValueError:
                pass

        # Build MatchDetail list
        detail_matches: list[MatchDetail] = []
        for vm in matches_above_threshold:
            detail_matches.append(
                MatchDetail(
                    pattern="vault_similarity",
                    matched_text=input_text[:120] + ("..." if len(input_text) > 120 else ""),
                    position=(0, len(input_text)),
                    description=(
                        f"Vault entry '{vm.id}' matched with "
                        f"similarity score {vm.similarity_score:.4f}"
                    ),
                )
            )

        confidence = top_match.similarity_score
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=severity,
            matches=detail_matches,
            explanation=(
                f"Input matched {len(matches_above_threshold)} known attack "
                f"pattern(s) in the vault (top similarity: "
                f"{top_match.similarity_score:.4f})"
            ),
        )
