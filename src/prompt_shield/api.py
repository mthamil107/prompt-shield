"""Lightweight FastAPI REST API server for prompt-shield.

Run directly:
    python -m prompt_shield.api
    uvicorn prompt_shield.api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from prompt_shield import __version__
from prompt_shield.engine import PromptShieldEngine
from prompt_shield.pii.redactor import PIIRedactor

logger = logging.getLogger("prompt_shield.api")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
_MODE = os.environ.get("PROMPT_SHIELD_MODE", "block")
_THRESHOLD = float(os.environ.get("PROMPT_SHIELD_THRESHOLD", "0.7"))
_HOST = os.environ.get("PROMPT_SHIELD_HOST", "0.0.0.0")
_PORT = int(os.environ.get("PROMPT_SHIELD_PORT", "8000"))
_RATE_LIMIT = int(os.environ.get("PROMPT_SHIELD_RATE_LIMIT", "100"))  # reqs/min
_CORS_ORIGINS = os.environ.get("PROMPT_SHIELD_CORS_ORIGINS", "*")

# ---------------------------------------------------------------------------
# In-memory rate limiter (no external deps)
# ---------------------------------------------------------------------------
_rate_buckets: dict[str, list[float]] = defaultdict(list)
_RATE_WINDOW = 60.0  # seconds


def _check_rate_limit(client_ip: str) -> bool:
    """Return True if the request should be allowed, False if rate-limited."""
    now = time.monotonic()
    bucket = _rate_buckets[client_ip]
    # Prune expired entries
    _rate_buckets[client_ip] = bucket = [t for t in bucket if now - t < _RATE_WINDOW]
    if len(bucket) >= _RATE_LIMIT:
        return False
    bucket.append(now)
    return True


# ---------------------------------------------------------------------------
# Shared state (engine + PII redactor)
# ---------------------------------------------------------------------------
_state: dict[str, Any] = {}


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Create engine and redactor once at startup; clean up on shutdown."""
    logger.info("Starting prompt-shield API (mode=%s, threshold=%s)", _MODE, _THRESHOLD)
    _state["engine"] = PromptShieldEngine(
        config_dict={
            "prompt_shield": {
                "mode": _MODE,
                "threshold": _THRESHOLD,
                # Disable heavy optional subsystems in API mode by default
                "vault": {"enabled": False},
                "canary": {"enabled": False},
            }
        }
    )
    _state["pii"] = PIIRedactor()
    yield
    _state.clear()


# ---------------------------------------------------------------------------
# App creation
# ---------------------------------------------------------------------------
app = FastAPI(
    title="prompt-shield",
    description="Self-learning prompt injection detection engine — REST API",
    version=__version__,
    lifespan=_lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Rate-limit middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return Response(
            content='{"detail":"Rate limit exceeded. Try again later."}',
            status_code=429,
            media_type="application/json",
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    """Body for the /scan endpoint."""

    text: str = Field(..., min_length=1, max_length=100_000, description="Text to scan")
    context: dict[str, Any] | None = Field(
        default=None, description="Optional context dict passed to detectors"
    )


class ScanResponse(BaseModel):
    """Serialised scan report returned by /scan."""

    scan_id: str
    input_hash: str
    timestamp: str
    overall_risk_score: float
    action: str
    detections: list[dict[str, Any]]
    total_detectors_run: int
    scan_duration_ms: float
    vault_matched: bool


class PIIRequest(BaseModel):
    """Body for PII endpoints."""

    text: str = Field(..., min_length=1, max_length=100_000, description="Text to scan for PII")


class PIIScanEntity(BaseModel):
    """A single PII entity found in text."""

    entity_type: str
    original: str


class PIIScanResponse(BaseModel):
    """Response from /pii/scan."""

    entities: list[PIIScanEntity]
    entity_counts: dict[str, int]
    total_found: int


class PIIRedactResponse(BaseModel):
    """Response from /pii/redact."""

    original_text: str
    redacted_text: str
    redaction_count: int
    entity_counts: dict[str, int]
    redacted_entities: list[dict[str, str]]


class HealthResponse(BaseModel):
    """Response from /health."""

    status: str
    version: str


class VersionResponse(BaseModel):
    """Response from /version."""

    name: str
    version: str
    mode: str
    threshold: float


class DetectorInfo(BaseModel):
    """Metadata about a single detector."""

    detector_id: str
    name: str
    description: str
    version: str
    severity: str
    enabled: bool


class ErrorResponse(BaseModel):
    """Standard error envelope."""

    detail: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
    summary="Health check",
)
async def health():
    """Return service health status."""
    return HealthResponse(status="ok", version=__version__)


@app.get(
    "/version",
    response_model=VersionResponse,
    tags=["system"],
    summary="Version information",
)
async def version():
    """Return version and configuration info."""
    return VersionResponse(
        name="prompt-shield",
        version=__version__,
        mode=_MODE,
        threshold=_THRESHOLD,
    )


@app.post(
    "/scan",
    response_model=ScanResponse,
    responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    tags=["scanning"],
    summary="Scan text for prompt injection",
)
async def scan(req: ScanRequest):
    """Scan the provided text for prompt injection attacks.

    Returns a full scan report with risk score, action recommendation,
    and individual detector results.
    """
    engine: PromptShieldEngine = _state["engine"]
    try:
        report = engine.scan(req.text, context=req.context)
    except Exception as exc:
        logger.exception("Scan failed")
        raise HTTPException(status_code=500, detail=f"Scan error: {exc}") from exc

    return ScanResponse(
        scan_id=report.scan_id,
        input_hash=report.input_hash,
        timestamp=report.timestamp.isoformat(),
        overall_risk_score=report.overall_risk_score,
        action=report.action.value,
        detections=[
            {
                "detector_id": d.detector_id,
                "detected": d.detected,
                "confidence": d.confidence,
                "severity": d.severity.value,
                "explanation": d.explanation,
                "matches": [m.model_dump() for m in d.matches],
            }
            for d in report.detections
        ],
        total_detectors_run=report.total_detectors_run,
        scan_duration_ms=report.scan_duration_ms,
        vault_matched=report.vault_matched,
    )


@app.post(
    "/pii/scan",
    response_model=PIIScanResponse,
    responses={422: {"model": ErrorResponse}},
    tags=["pii"],
    summary="Scan text for PII entities",
)
async def pii_scan(req: PIIRequest):
    """Detect PII entities (emails, phone numbers, SSNs, etc.) in the text."""
    redactor: PIIRedactor = _state["pii"]
    result = redactor.redact(req.text)
    entities = [
        PIIScanEntity(entity_type=e["entity_type"], original=e["original"])
        for e in result.redacted_entities
    ]
    return PIIScanResponse(
        entities=entities,
        entity_counts=result.entity_counts,
        total_found=result.redaction_count,
    )


@app.post(
    "/pii/redact",
    response_model=PIIRedactResponse,
    responses={422: {"model": ErrorResponse}},
    tags=["pii"],
    summary="Redact PII from text",
)
async def pii_redact(req: PIIRequest):
    """Detect and replace PII with type-aware placeholders."""
    redactor: PIIRedactor = _state["pii"]
    result = redactor.redact(req.text)
    return PIIRedactResponse(
        original_text=result.original_text,
        redacted_text=result.redacted_text,
        redaction_count=result.redaction_count,
        entity_counts=result.entity_counts,
        redacted_entities=result.redacted_entities,
    )


@app.get(
    "/detectors",
    response_model=list[DetectorInfo],
    tags=["scanning"],
    summary="List all registered detectors",
)
async def list_detectors():
    """Return metadata for every registered detector."""
    engine: PromptShieldEngine = _state["engine"]
    raw = engine.list_detectors()
    return [
        DetectorInfo(
            detector_id=str(d.get("detector_id", "")),
            name=str(d.get("name", "")),
            description=str(d.get("description", "")),
            version=str(d.get("version", "0.0.0")),
            severity=str(d.get("severity", "medium")),
            enabled=bool(d.get("enabled", True)),
        )
        for d in raw
    ]


# ---------------------------------------------------------------------------
# Main entry-point (python -m prompt_shield.api)
# ---------------------------------------------------------------------------
def _main() -> None:
    """Run the API server via uvicorn."""
    import uvicorn

    log_level = os.environ.get("PROMPT_SHIELD_LOG_LEVEL", "info").lower()
    uvicorn.run(
        "prompt_shield.api:app",
        host=_HOST,
        port=_PORT,
        log_level=log_level,
        access_log=True,
    )


if __name__ == "__main__":
    _main()
