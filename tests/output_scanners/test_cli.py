"""Tests for the `prompt-shield output` CLI commands."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from prompt_shield.cli import main


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_output_scan_cli_command_benign(runner: CliRunner) -> None:
    """A clean input exits 0 and reports no flags."""
    result = runner.invoke(main, ["output", "scan", "The weather is nice today."])
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_output_scan_cli_command_flagged(runner: CliRunner) -> None:
    """A clearly toxic input exits non-zero and reports a flag."""
    result = runner.invoke(
        main, ["output", "scan", "You should kill yourself, nobody cares."]
    )
    assert result.exit_code == 1
    assert "FLAGGED" in result.output


def test_output_scan_cli_command_subset(runner: CliRunner) -> None:
    """--scanners restricts the run to the named scanners."""
    result = runner.invoke(
        main,
        ["output", "scan", "--scanners", "toxicity,pii", "Hello there."],
    )
    assert result.exit_code == 0
    # With only two scanners, "Scanners run: 2" should appear in output.
    assert "Scanners run: 2" in result.output


def test_output_scan_cli_command_json(runner: CliRunner) -> None:
    """Global --json-output prints valid JSON."""
    result = runner.invoke(
        main,
        ["--json-output", "output", "scan", "Hello there."],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "flagged" in payload
    assert "overall_risk_score" in payload
    assert "flags" in payload


def test_output_scanners_list_command(runner: CliRunner) -> None:
    """`prompt-shield output scanners` lists all nine scanners."""
    result = runner.invoke(main, ["output", "scanners"])
    assert result.exit_code == 0
    for name in (
        "toxicity",
        "code_injection",
        "prompt_leakage",
        "pii",
        "schema_validation",
        "bias_fairness",
        "sentiment",
        "hallucination",
        "relevance",
    ):
        assert name in result.output


def test_output_scanners_list_command_json(runner: CliRunner) -> None:
    """The JSON variant returns a nine-entry list."""
    result = runner.invoke(main, ["--json-output", "output", "scanners"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 9
