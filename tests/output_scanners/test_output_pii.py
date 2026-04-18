"""Tests for the OutputPIIScanner output scanner."""

from __future__ import annotations

from prompt_shield.output_scanners.output_pii import OutputPIIScanner


class TestOutputPIIScanner:
    """Test suite for OutputPIIScanner."""

    def setup_method(self) -> None:
        self.scanner = OutputPIIScanner()

    # ------------------------------------------------------------------ #
    # Detection tests
    # ------------------------------------------------------------------ #

    def test_email_in_output(self) -> None:
        text = "You can reach the account owner at john.doe@example.com for support."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "email" in result.categories

    def test_ssn_in_output(self) -> None:
        text = "The customer's social security number is 123-45-6789."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "ssn" in result.categories

    def test_credit_card_in_output(self) -> None:
        text = "Payment was processed with card number 4111-1111-1111-1111."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "credit_card" in result.categories

    def test_multiple_pii_types(self) -> None:
        text = "Customer record: email alice@corp.com, SSN 987-65-4321, card 4111 1111 1111 1111."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert len(result.categories) >= 2
        assert result.confidence > 0.90  # multiple types increase confidence

    def test_clean_output_passes(self) -> None:
        text = (
            "The weather forecast for tomorrow shows partly cloudy skies "
            "with a high of 72 degrees Fahrenheit."
        )
        result = self.scanner.scan(text)
        assert result.flagged is False
        assert result.confidence == 0.0

    def test_redacted_text_in_metadata(self) -> None:
        text = "Contact support at help@example.com or call 555-123-4567."
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "redacted_text" in result.metadata
        redacted = result.metadata["redacted_text"]
        assert "help@example.com" not in redacted
        assert "[EMAIL_REDACTED]" in redacted

    def test_entity_counts_in_metadata(self) -> None:
        text = "Email: a@b.com, another: c@d.com"
        result = self.scanner.scan(text)
        assert result.flagged is True
        assert "entity_counts" in result.metadata
        counts = result.metadata["entity_counts"]
        assert counts.get("email", 0) >= 2

    def test_scanner_metadata(self) -> None:
        assert self.scanner.scanner_id == "output_pii"
        assert self.scanner.name == "Output PII Scanner"
