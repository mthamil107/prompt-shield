"""Detector for suspicious URL injection in prompts."""

from __future__ import annotations

import regex

from prompt_shield.detectors.base import BaseDetector
from prompt_shield.models import DetectionResult, MatchDetail, Severity


class URLInjectionDetector(BaseDetector):
    """Detects suspicious URLs injected into prompts for phishing or redirection.

    Adversaries may embed malicious URLs in prompts to trick models into
    presenting phishing links, exfiltrating data via URL parameters, or
    redirecting users to attacker-controlled sites.
    """

    detector_id: str = "d016_url_injection"
    name: str = "URL Injection"
    description: str = (
        "Detects suspicious URLs injected into prompts for phishing or redirection"
    )
    severity: Severity = Severity.MEDIUM
    tags: list[str] = ["indirect_injection"]
    version: str = "1.0.0"
    author: str = "prompt-shield"

    _url_pattern = regex.compile(r"https?://\S+", regex.IGNORECASE)
    _shortener_pattern = regex.compile(
        r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly)/\S+",
        regex.IGNORECASE,
    )
    _ip_url_pattern = regex.compile(
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", regex.IGNORECASE
    )
    _data_uri_pattern = regex.compile(r"data:\w+/\w+[;,]", regex.IGNORECASE)
    _encoding_pattern = regex.compile(r"%[0-9a-fA-F]{2}")

    def detect(
        self, input_text: str, context: dict[str, object] | None = None
    ) -> DetectionResult:
        matches: list[MatchDetail] = []
        best_confidence = 0.0

        # Find all URLs
        all_urls = self._url_pattern.findall(input_text)

        # Check for IP-based URLs
        for m in self._ip_url_pattern.finditer(input_text):
            matches.append(
                MatchDetail(
                    pattern=self._ip_url_pattern.pattern,
                    matched_text=m.group(),
                    position=(m.start(), m.end()),
                    description="URL with IP address instead of domain",
                )
            )
            best_confidence = max(best_confidence, 0.8)

        # Check for URL shorteners
        for m in self._shortener_pattern.finditer(input_text):
            matches.append(
                MatchDetail(
                    pattern=self._shortener_pattern.pattern,
                    matched_text=m.group(),
                    position=(m.start(), m.end()),
                    description="URL shortener detected",
                )
            )
            best_confidence = max(best_confidence, 0.7)

        # Check for data URIs
        for m in self._data_uri_pattern.finditer(input_text):
            matches.append(
                MatchDetail(
                    pattern=self._data_uri_pattern.pattern,
                    matched_text=m.group(),
                    position=(m.start(), m.end()),
                    description="Data URI detected",
                )
            )
            best_confidence = max(best_confidence, 0.75)

        # Check for excessive URL encoding in individual URLs
        for url in all_urls:
            encoding_matches = self._encoding_pattern.findall(url)
            if len(encoding_matches) > 5:
                url_start = input_text.find(url)
                matches.append(
                    MatchDetail(
                        pattern=self._encoding_pattern.pattern,
                        matched_text=url,
                        position=(url_start, url_start + len(url)),
                        description=(
                            f"URL with excessive encoding "
                            f"({len(encoding_matches)} encoded sequences)"
                        ),
                    )
                )
                best_confidence = max(best_confidence, 0.75)

        # Check for excessive number of URLs
        if len(all_urls) > 3:
            matches.append(
                MatchDetail(
                    pattern="url_count > 3",
                    matched_text=f"{len(all_urls)} URLs found in input",
                    position=(0, len(input_text)),
                    description=(
                        f"Excessive number of URLs in input ({len(all_urls)})"
                    ),
                )
            )
            best_confidence = max(best_confidence, 0.65)

        if not matches:
            return DetectionResult(
                detector_id=self.detector_id,
                detected=False,
                confidence=0.0,
                severity=self.severity,
                explanation="No suspicious URL patterns found",
            )

        confidence = min(1.0, best_confidence + 0.05 * (len(matches) - 1))
        return DetectionResult(
            detector_id=self.detector_id,
            detected=True,
            confidence=confidence,
            severity=self.severity,
            matches=matches,
            explanation=(
                f"Detected {len(matches)} suspicious URL pattern(s) "
                f"indicating {self.name.lower()}"
            ),
        )
