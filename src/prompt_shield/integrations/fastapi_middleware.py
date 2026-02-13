"""FastAPI middleware for prompt-shield HTTP request scanning."""

from __future__ import annotations
import json
from typing import Any, Callable, Awaitable

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except ImportError:
    raise ImportError("Install fastapi extras: pip install prompt-shield[fastapi]")

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action


class PromptShieldMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that scans request bodies for prompt injection."""

    def __init__(
        self,
        app: Any,
        config_path: str | None = None,
        mode: str = "block",
        scan_fields: list[str] | None = None,
        on_detection: Callable[..., Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(app)
        self.engine = PromptShieldEngine(config_path=config_path, config_dict={"mode": mode} if mode != "block" else None)
        self.scan_fields = scan_fields or ["body.prompt", "body.messages.*.content"]
        self.on_detection = on_detection

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        try:
            body = await request.json()
        except Exception:
            return await call_next(request)

        texts_to_scan = self._extract_fields(body)
        for text in texts_to_scan:
            if not text or not isinstance(text, str):
                continue
            report = self.engine.scan(text, context={"gate": "http", "source": "fastapi"})
            if report.action == Action.BLOCK:
                if self.on_detection:
                    await self.on_detection(request, report)
                return JSONResponse(
                    status_code=400,
                    content={"error": "Prompt injection detected", "scan_id": report.scan_id, "risk_score": report.overall_risk_score},
                )
        return await call_next(request)

    def _extract_fields(self, body: Any) -> list[str]:
        """Extract text fields from request body based on scan_fields config."""
        texts: list[str] = []
        for field_path in self.scan_fields:
            parts = field_path.replace("body.", "", 1).split(".")
            texts.extend(self._resolve_path(body, parts))
        return texts

    def _resolve_path(self, obj: Any, parts: list[str]) -> list[str]:
        if not parts:
            return [str(obj)] if obj else []
        key = parts[0]
        rest = parts[1:]
        if key == "*" and isinstance(obj, list):
            results: list[str] = []
            for item in obj:
                results.extend(self._resolve_path(item, rest))
            return results
        if isinstance(obj, dict) and key in obj:
            return self._resolve_path(obj[key], rest)
        return []
