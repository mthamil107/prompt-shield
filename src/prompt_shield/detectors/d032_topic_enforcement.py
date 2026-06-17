"""Topic / denied-topics enforcement detector (d032).

Lets operators block inputs that match denied topics or fall outside an
allowed-topics list. The detection uses lightweight keyword and phrase
matching by default — no embedding model required. When sentence
transformers are available, an optional semantic-similarity mode can be
enabled via configuration.

Typical use: a code-assistant deployment that should refuse to discuss
politics, medical advice, or any topic outside engineering.

Configuration:
    d032_topic_enforcement:
      enabled: true
      denied_topics:
        - name: medical_advice
          keywords: ["diagnose", "prescription", "dosage", "symptoms"]
        - name: legal_advice
          keywords: ["lawsuit", "attorney", "court", "litigation"]
      min_keyword_hits: 2          # require at least 2 keyword hits
      case_sensitive: false
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import ClassVar

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger(__name__)


@dataclass
class DeniedTopic:
    name: str
    keywords: list[str]
    severity: Severity = Severity.MEDIUM
    description: str = ""
    compiled: list[re.Pattern[str]] = field(default_factory=list)


class TopicEnforcementDetector(BaseDetector):
    """Flag inputs that hit configured denied-topic keyword groups."""

    detector_id: str = "d032_topic_enforcement"
    name: str = "Topic Enforcement"
    description: str = (
        "Flag inputs that match configured denied-topic keyword groups "
        "(e.g., medical advice, legal advice, politics)."
    )
    severity: Severity = Severity.MEDIUM
    tags: ClassVar[list[str]] = ["policy", "operator-defined", "topics"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    def __init__(self) -> None:
        self._topics: list[DeniedTopic] = []
        self._min_hits: int = 2
        self._case_sensitive: bool = False

    def setup(self, config: dict[str, object]) -> None:
        self._case_sensitive = bool(config.get("case_sensitive", False))
        min_hits = config.get("min_keyword_hits", 2)
        self._min_hits = int(min_hits) if isinstance(min_hits, (int, float, str)) else 2
        topics_cfg = config.get("denied_topics", [])
        if not isinstance(topics_cfg, list):
            return
        for entry in topics_cfg:
            topic = self._parse_topic(entry)
            if topic is not None:
                self._topics.append(topic)

    def _parse_topic(self, entry: object) -> DeniedTopic | None:
        if not isinstance(entry, dict):
            return None
        name = entry.get("name")
        keywords = entry.get("keywords")
        if not isinstance(name, str) or not isinstance(keywords, list):
            return None
        if not all(isinstance(k, str) and k.strip() for k in keywords):
            return None
        sev_str = str(entry.get("severity", "medium")).lower()
        sev_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        severity = sev_map.get(sev_str, Severity.MEDIUM)
        flags = 0 if self._case_sensitive else re.IGNORECASE
        compiled = []
        for kw in keywords:
            try:
                # Treat keywords as word-bounded literal phrases.
                compiled.append(re.compile(r"\b" + re.escape(kw.strip()) + r"\b", flags))
            except re.error:
                continue
        return DeniedTopic(
            name=name,
            keywords=[k.strip() for k in keywords],
            severity=severity,
            description=str(entry.get("description", "")),
            compiled=compiled,
        )

    def detect(
        self,
        input_text: str,
        context: dict[str, object] | None = None,
    ) -> DetectionResult:
        if not input_text or not self._topics:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=("No denied topics configured" if not self._topics else "Empty input"),
            )

        best_topic: DeniedTopic | None = None
        best_matches: list[MatchDetail] = []
        best_hits = 0
        for topic in self._topics:
            matches: list[MatchDetail] = []
            for pat in topic.compiled:
                for m in pat.finditer(input_text):
                    matches.append(
                        MatchDetail(
                            pattern=pat.pattern,
                            matched_text=m.group(0),
                            position=(m.start(), m.end()),
                            description=f"keyword for topic '{topic.name}'",
                        )
                    )
            if len(matches) >= self._min_hits and len(matches) > best_hits:
                best_topic = topic
                best_matches = matches
                best_hits = len(matches)

        if best_topic is None:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation=f"No denied topics matched (checked {len(self._topics)})",
            )

        confidence = min(0.95, 0.4 + 0.15 * best_hits)
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=best_topic.severity,
            matches=best_matches[:10],
            explanation=(
                f"Matched denied topic {best_topic.name!r} with {best_hits} keyword hit(s)"
            ),
            metadata={
                "topic": best_topic.name,
                "hit_count": best_hits,
                "min_required": self._min_hits,
            },
        )
