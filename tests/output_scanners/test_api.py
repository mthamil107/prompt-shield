"""Tests for the /scan/output REST endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from prompt_shield.api import app


@pytest.fixture()
def client() -> TestClient:
    # TestClient handles lifespan startup/shutdown when used as a context.
    with TestClient(app) as tc:
        yield tc


def test_scan_output_endpoint_benign(client: TestClient) -> None:
    response = client.post("/scan/output", json={"text": "The weather is nice today."})
    assert response.status_code == 200
    body = response.json()
    assert body["flagged"] is False
    assert body["overall_risk_score"] == 0.0
    assert body["total_scanners_run"] == 9
    assert len(body["flags"]) == 9


def test_scan_output_endpoint_flagged(client: TestClient) -> None:
    response = client.post(
        "/scan/output",
        json={"text": "You should kill yourself, nobody cares."},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["flagged"] is True
    assert body["overall_risk_score"] > 0.0
    assert any(f["scanner_id"] == "toxicity" and f["flagged"] for f in body["flags"])


def test_scan_output_endpoint_subset(client: TestClient) -> None:
    response = client.post(
        "/scan/output",
        json={"text": "Hello world", "scanners": ["toxicity", "pii"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_scanners_run"] == 2
    scanner_ids = {f["scanner_id"] for f in body["flags"]}
    assert scanner_ids == {"toxicity", "output_pii"}


def test_scan_output_endpoint_rejects_empty(client: TestClient) -> None:
    response = client.post("/scan/output", json={"text": ""})
    # Pydantic min_length=1 → 422 unprocessable entity.
    assert response.status_code == 422
