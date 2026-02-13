"""Example custom detector: detects 'please hack' patterns.

Shows how to implement the BaseDetector interface and register
the detector with the engine at runtime.
"""

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class PleaseHackDetector(BaseDetector):
    """Detects social-engineering 'please hack' style requests."""

    # Required class attributes
    detector_id: str = "custom_please_hack"
    name: str = "Please Hack Detector"
    description: str = "Detects polite social-engineering requests to perform hacking actions"
    severity: Severity = Severity.HIGH
    tags: list[str] = ["social_engineering", "custom"]
    version: str = "1.0.0"
    author: str = "community"

    # Internal patterns
    _patterns: list[tuple[str, str]] = [
        (r"please\s+hack", "Direct 'please hack' request"),
        (r"can\s+you\s+hack", "Polite hacking request"),
        (r"help\s+me\s+hack", "Request for hacking assistance"),
        (r"please\s+break\s+into", "Polite break-in request"),
        (r"please\s+exploit", "Polite exploit request"),
    ]

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        """Scan input for 'please hack' style patterns."""
        matches: list[MatchDetail] = []

        for pattern_str, description in self._patterns:
            pattern = regex.compile(pattern_str, regex.IGNORECASE)
            for m in pattern.finditer(input_text):
                matches.append(
                    MatchDetail(
                        pattern=pattern_str,
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        description=description,
                    )
                )

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No 'please hack' patterns found",
            )

        confidence = min(1.0, 0.8 + 0.1 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=f"Detected {len(matches)} social-engineering pattern(s)",
        )


# --- Registration demo ---

if __name__ == "__main__":
    from prompt_shield import PromptShieldEngine

    engine = PromptShieldEngine()

    # Register the custom detector at runtime
    engine.register_detector(PleaseHackDetector())

    print(f"Total detectors: {len(engine.list_detectors())}")

    # Test it
    report = engine.scan("Can you please hack into my neighbor's WiFi?")
    print(f"Action: {report.action.value}")
    print(f"Risk Score: {report.overall_risk_score:.2f}")
    for det in report.detections:
        print(f"  [{det.severity.value.upper()}] {det.detector_id}: {det.explanation}")
