"""Core scanning engine — orchestrates detectors, vault, feedback, and canary systems."""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import regex

from prompt_shield.canary.leak_detector import LeakDetector
from prompt_shield.canary.token_generator import CanaryTokenGenerator
from prompt_shield.config import (
    get_action_for_severity,
    get_detector_config,
    load_config,
    resolve_data_dir,
)
from prompt_shield.exceptions import ScanError
from prompt_shield.models import (
    Action,
    DetectionResult,
    ScanReport,
    Severity,
    ThreatFeed,
)
from prompt_shield.persistence.database import DatabaseManager
from prompt_shield.registry import DetectorRegistry
from prompt_shield.utils import sha256_hash

if TYPE_CHECKING:
    from prompt_shield.detectors.base import BaseDetector
    from prompt_shield.feedback.auto_tuner import AutoTuner
    from prompt_shield.feedback.feedback_store import FeedbackStore
    from prompt_shield.vault.attack_vault import AttackVault
    from prompt_shield.vault.threat_feed import ThreatFeedManager

logger = logging.getLogger("prompt_shield.engine")


class PromptShieldEngine:
    """Core scanning engine. Loads detectors, runs them, aggregates results.

    Integrates with vault, feedback, and canary systems.
    """

    def __init__(
        self,
        config_path: str | None = None,
        config_dict: dict[str, Any] | None = None,
        data_dir: str | None = None,
    ) -> None:
        self._config = load_config(config_path=config_path, config_dict=config_dict)
        self._ps_config: dict[str, Any] = self._config.get("prompt_shield", self._config)

        # Resolve data directory
        if data_dir:
            self._data_dir = Path(data_dir)
        else:
            self._data_dir = resolve_data_dir(self._config)
        self._data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize persistence
        db_dir = self._data_dir / "db"
        db_dir.mkdir(parents=True, exist_ok=True)
        self._db = DatabaseManager(str(db_dir / "prompt_shield.db"))

        # Initialize vault (if enabled)
        self._vault: AttackVault | None = None
        vault_cfg = self._ps_config.get("vault", {})
        if vault_cfg.get("enabled", True):
            self._init_vault(vault_cfg)

        # Initialize feedback (if enabled)
        self._feedback_store: FeedbackStore | None = None
        self._auto_tuner: AutoTuner | None = None
        feedback_cfg = self._ps_config.get("feedback", {})
        if feedback_cfg.get("enabled", True):
            self._init_feedback(feedback_cfg)

        # Initialize canary (if enabled)
        self._canary_generator: CanaryTokenGenerator | None = None
        self._leak_detector: LeakDetector | None = None
        canary_cfg = self._ps_config.get("canary", {})
        if canary_cfg.get("enabled", True):
            self._canary_generator = CanaryTokenGenerator(
                token_length=canary_cfg.get("token_length", 16),
                header_format=canary_cfg.get("header_format", "<-@!-- {canary} --@!->"),
            )
            self._leak_detector = LeakDetector()

        # Initialize threat feed manager
        self._threat_feed: ThreatFeedManager | None = None
        if self._vault is not None:
            from prompt_shield.vault.threat_feed import ThreatFeedManager

            self._threat_feed = ThreatFeedManager(
                vault=self._vault, data_dir=str(self._data_dir)
            )

        # Initialize detector registry
        self._registry = DetectorRegistry()
        self._init_detectors()

        # Compile allowlist/blocklist patterns
        self._allowlist_patterns = self._compile_patterns(
            self._ps_config.get("allowlist", {}).get("patterns", [])
        )
        self._blocklist_patterns = self._compile_patterns(
            self._ps_config.get("blocklist", {}).get("patterns", [])
        )

        # Track scan count for auto-tune interval
        self._scan_count = 0
        self._tune_interval = feedback_cfg.get("tune_interval", 100)

    def _init_vault(self, vault_cfg: dict[str, Any]) -> None:
        """Initialize the attack vault."""
        from prompt_shield.vault.attack_vault import AttackVault

        vault_dir = self._data_dir / "vault"
        vault_dir.mkdir(parents=True, exist_ok=True)
        self._vault = AttackVault(
            data_dir=str(self._data_dir),
            embedding_model=vault_cfg.get("embedding_model", "all-MiniLM-L6-v2"),
            similarity_threshold=vault_cfg.get("similarity_threshold", 0.85),
        )

    def _init_feedback(self, feedback_cfg: dict[str, Any]) -> None:
        """Initialize feedback store and auto-tuner."""
        from prompt_shield.feedback.auto_tuner import AutoTuner
        from prompt_shield.feedback.feedback_store import FeedbackStore

        db_path = str(self._data_dir / "db" / "prompt_shield.db")
        self._feedback_store = FeedbackStore(db_path)
        if feedback_cfg.get("auto_tune", True):
            self._auto_tuner = AutoTuner(
                db_path=db_path,
                max_adjustment=feedback_cfg.get("max_threshold_adjustment", 0.15),
            )

    def _init_detectors(self) -> None:
        """Auto-discover and register built-in + entry point detectors."""
        # Pass vault to d021 if it needs it
        count = self._registry.auto_discover()
        logger.info("Auto-discovered %d detectors", count)

        ep_count = self._registry.discover_entry_points()
        if ep_count:
            logger.info("Discovered %d entry point detectors", ep_count)

        # Wire vault into d021 if present
        if self._vault is not None and "d021_vault_similarity" in self._registry:
            d021 = self._registry.get("d021_vault_similarity")
            if hasattr(d021, "vault"):
                d021.vault = self._vault

        # Run setup on each detector with its config
        for detector in self._registry.list_all():
            det_cfg = get_detector_config(self._config, detector.detector_id)
            try:
                detector.setup(det_cfg)
            except Exception as exc:
                logger.warning("Failed to setup detector %s: %s", detector.detector_id, exc)

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[regex.Pattern[str]]:
        """Compile regex patterns for allowlist/blocklist."""
        compiled = []
        for p in patterns:
            try:
                compiled.append(regex.compile(p, regex.IGNORECASE))
            except regex.error as exc:
                logger.warning("Invalid pattern '%s': %s", p, exc)
        return compiled

    def scan(self, input_text: str, context: dict[str, object] | None = None) -> ScanReport:
        """Run all enabled detectors against input. Returns aggregated report."""
        start = time.perf_counter()
        scan_id = str(uuid.uuid4())
        ctx = dict(context) if context else {}

        # Check allowlist
        for pattern in self._allowlist_patterns:
            if pattern.search(input_text):
                return self._build_report(
                    scan_id=scan_id,
                    input_text=input_text,
                    action=Action.PASS,
                    detections=[],
                    total_run=0,
                    start_time=start,
                )

        # Check blocklist
        for pattern in self._blocklist_patterns:
            if pattern.search(input_text):
                return self._build_report(
                    scan_id=scan_id,
                    input_text=input_text,
                    action=Action.BLOCK,
                    detections=[],
                    total_run=0,
                    start_time=start,
                    risk_score=1.0,
                )

        # Run all enabled detectors
        detections: list[DetectionResult] = []
        total_run = 0

        for detector in self._registry.list_all():
            det_cfg = get_detector_config(self._config, detector.detector_id)
            if not det_cfg.get("enabled", True):
                continue

            # Get effective threshold (may be auto-tuned)
            threshold = det_cfg.get("threshold", self._ps_config.get("threshold", 0.7))
            if self._auto_tuner:
                threshold = self._auto_tuner.get_effective_threshold(
                    detector.detector_id, threshold
                )

            total_run += 1
            try:
                result = detector.detect(input_text, context=ctx)

                # Apply severity override from config
                cfg_severity = det_cfg.get("severity")
                if cfg_severity:
                    try:
                        result.severity = Severity(cfg_severity)
                    except ValueError:
                        pass

                if result.detected and result.confidence >= threshold:
                    detections.append(result)
            except Exception as exc:
                logger.warning(
                    "Detector %s failed: %s", detector.detector_id, exc
                )

        # Aggregate risk score
        if detections:
            risk_score = max(d.confidence for d in detections)
        else:
            risk_score = 0.0

        # Determine action based on highest severity detection
        action = self._determine_action(detections, risk_score)

        # Check vault match
        vault_matched = any(
            d.detector_id == "d021_vault_similarity" for d in detections
        )

        report = self._build_report(
            scan_id=scan_id,
            input_text=input_text,
            action=action,
            detections=detections,
            total_run=total_run,
            start_time=start,
            risk_score=risk_score,
            vault_matched=vault_matched,
        )

        # Store in history
        self._log_scan(report)

        # Auto-store in vault if detected
        if detections and self._vault is not None:
            vault_cfg = self._ps_config.get("vault", {})
            if vault_cfg.get("auto_store_detections", True):
                min_conf = vault_cfg.get("min_confidence_to_store", 0.7)
                if risk_score >= min_conf:
                    try:
                        top_detection = max(detections, key=lambda d: d.confidence)
                        self._vault.store(input_text, {
                            "detector_id": top_detection.detector_id,
                            "severity": top_detection.severity.value,
                            "confidence": top_detection.confidence,
                            "source": "local",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })
                    except Exception as exc:
                        logger.warning("Failed to store detection in vault: %s", exc)

        # Auto-tune check
        self._scan_count += 1
        if (
            self._auto_tuner
            and self._scan_count % self._tune_interval == 0
        ):
            try:
                self._auto_tuner.tune()
            except Exception as exc:
                logger.warning("Auto-tune failed: %s", exc)

        return report

    def scan_batch(self, inputs: list[str]) -> list[ScanReport]:
        """Scan multiple inputs."""
        return [self.scan(text) for text in inputs]

    def feedback(self, scan_id: str, is_correct: bool, notes: str = "") -> None:
        """Record user feedback on a scan result."""
        if not self._feedback_store:
            logger.warning("Feedback is disabled in config")
            return

        # Look up scan in history to get detector info
        try:
            with self._db.connection() as conn:
                row = conn.execute(
                    "SELECT detectors_fired, input_hash FROM scan_history WHERE id = ?",
                    (scan_id,),
                ).fetchone()
        except Exception:
            row = None

        if row:
            fired = json.loads(row["detectors_fired"]) if row["detectors_fired"] else []
            for det in fired:
                det_id = det.get("detector_id", "unknown")
                self._feedback_store.record(
                    scan_id=scan_id,
                    detector_id=det_id,
                    is_correct=is_correct,
                    notes=notes,
                )

            # If false positive and vault enabled: try to remove from vault
            if not is_correct and self._vault is not None:
                input_hash = row["input_hash"]
                try:
                    # Query vault for entries with matching hash
                    results = self._vault._collection.get(
                        where={"attack_hash": input_hash}
                    )
                    if results and results["ids"]:
                        for vid in results["ids"]:
                            self._vault.remove(vid)
                        logger.info(
                            "Removed %d vault entries for false positive scan %s",
                            len(results["ids"]),
                            scan_id,
                        )
                except Exception as exc:
                    logger.warning("Failed to remove vault entry: %s", exc)
        else:
            # No scan found — still record feedback with generic detector
            self._feedback_store.record(
                scan_id=scan_id,
                detector_id="unknown",
                is_correct=is_correct,
                notes=notes,
            )

    def register_detector(self, detector: BaseDetector) -> None:
        """Manually register a custom detector at runtime."""
        self._registry.register(detector)
        det_cfg = get_detector_config(self._config, detector.detector_id)
        try:
            detector.setup(det_cfg)
        except Exception as exc:
            logger.warning("Failed to setup detector %s: %s", detector.detector_id, exc)

    def unregister_detector(self, detector_id: str) -> None:
        """Remove a detector by ID."""
        detector = self._registry.get(detector_id)
        try:
            detector.teardown()
        except Exception:
            pass
        self._registry.unregister(detector_id)

    def list_detectors(self) -> list[dict[str, object]]:
        """List all registered detectors with metadata."""
        return self._registry.list_metadata()

    def export_threats(self, output_path: str, since: str | None = None) -> ThreatFeed:
        """Export detected attacks as anonymized threat feed JSON."""
        if not self._threat_feed:
            raise ScanError("Threat feed is not available (vault disabled)")
        return self._threat_feed.export_feed(output_path, since=since)

    def import_threats(self, source_path: str) -> dict[str, int]:
        """Import threats from a JSON file into the local vault."""
        if not self._threat_feed:
            raise ScanError("Threat feed is not available (vault disabled)")
        return self._threat_feed.import_feed(source_path)

    def sync_threats(self, feed_url: str | None = None) -> dict[str, Any]:
        """Pull latest threats from community feed URL and merge into vault."""
        if not self._threat_feed:
            raise ScanError("Threat feed is not available (vault disabled)")
        url = feed_url or self._ps_config.get("threat_feed", {}).get("feed_url", "")
        return self._threat_feed.sync_feed(url)

    def add_canary(self, prompt_template: str) -> tuple[str, str]:
        """Add a canary token to a prompt template."""
        if not self._canary_generator:
            raise ScanError("Canary system is disabled in config")
        return self._canary_generator.inject(prompt_template)

    def check_canary(
        self,
        llm_response: str,
        canary_token: str,
        original_input: str | None = None,
    ) -> bool:
        """Check if canary token leaked in LLM response."""
        if not self._leak_detector:
            raise ScanError("Canary system is disabled in config")

        leaked = self._leak_detector.check(llm_response, canary_token)

        if leaked and original_input and self._vault:
            try:
                self._vault.store(original_input, {
                    "detector_id": "canary_leak",
                    "severity": "critical",
                    "confidence": 1.0,
                    "source": "local",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            except Exception as exc:
                logger.warning("Failed to store canary leak in vault: %s", exc)

        return leaked

    @property
    def vault(self) -> AttackVault | None:
        """Access the attack vault (may be None if disabled)."""
        return self._vault

    @property
    def config(self) -> dict[str, Any]:
        """Access the loaded configuration."""
        return self._config

    def _determine_action(
        self, detections: list[DetectionResult], risk_score: float
    ) -> Action:
        """Determine action based on detections and config."""
        if not detections:
            return Action.PASS

        mode = self._ps_config.get("mode", "block")
        if mode == "monitor":
            return Action.LOG

        # Use highest severity detection to determine action
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in severity_order:
            for d in detections:
                if d.severity == sev:
                    action_str = get_action_for_severity(self._config, sev)
                    try:
                        return Action(action_str)
                    except ValueError:
                        return Action.BLOCK

        return Action.FLAG

    def _build_report(
        self,
        scan_id: str,
        input_text: str,
        action: Action,
        detections: list[DetectionResult],
        total_run: int,
        start_time: float,
        risk_score: float = 0.0,
        vault_matched: bool = False,
    ) -> ScanReport:
        """Build a ScanReport."""
        elapsed = (time.perf_counter() - start_time) * 1000
        return ScanReport(
            scan_id=scan_id,
            input_text=input_text,
            input_hash=sha256_hash(input_text),
            timestamp=datetime.now(timezone.utc),
            overall_risk_score=risk_score,
            action=action,
            detections=detections,
            total_detectors_run=total_run,
            scan_duration_ms=round(elapsed, 2),
            vault_matched=vault_matched,
            config_snapshot={"mode": self._ps_config.get("mode", "block")},
        )

    def _log_scan(self, report: ScanReport) -> None:
        """Log scan to SQLite history."""
        history_cfg = self._ps_config.get("history", {})
        if not history_cfg.get("enabled", True):
            return

        fired = [
            {
                "detector_id": d.detector_id,
                "confidence": d.confidence,
                "severity": d.severity.value,
            }
            for d in report.detections
        ]

        try:
            with self._db.connection() as conn:
                conn.execute(
                    """INSERT INTO scan_history
                       (id, timestamp, input_hash, input_length, overall_score,
                        action_taken, detectors_fired, vault_matched, scan_duration_ms, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        report.scan_id,
                        report.timestamp.isoformat(),
                        report.input_hash,
                        len(report.input_text),
                        report.overall_risk_score,
                        report.action.value,
                        json.dumps(fired),
                        1 if report.vault_matched else 0,
                        report.scan_duration_ms,
                        "direct",
                    ),
                )
                conn.commit()
        except Exception as exc:
            logger.warning("Failed to log scan: %s", exc)

        # Auto-prune
        retention = history_cfg.get("retention_days", 90)
        try:
            self._db.prune_scan_history(retention)
        except Exception:
            pass
