"""Flask middleware for prompt-shield HTTP request scanning."""

from __future__ import annotations
import json
from typing import Any

from prompt_shield.engine import PromptShieldEngine
from prompt_shield.models import Action


class PromptShieldMiddleware:
    """Flask WSGI middleware that scans request bodies for prompt injection."""

    def __init__(
        self,
        app: Any,
        config_path: str | None = None,
        scan_fields: list[str] | None = None,
    ) -> None:
        self.app = app
        self.engine = PromptShieldEngine(config_path=config_path)
        self.scan_fields = scan_fields or ["prompt", "messages.*.content"]

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Any:
        method = environ.get("REQUEST_METHOD", "GET")
        if method not in ("POST", "PUT", "PATCH"):
            return self.app(environ, start_response)

        try:
            content_length = int(environ.get("CONTENT_LENGTH", 0))
            body_bytes = environ["wsgi.input"].read(content_length)
            # Reset input stream for downstream
            import io
            environ["wsgi.input"] = io.BytesIO(body_bytes)
            body = json.loads(body_bytes)
        except Exception:
            return self.app(environ, start_response)

        texts = self._extract_fields(body)
        for text in texts:
            if not text or not isinstance(text, str):
                continue
            report = self.engine.scan(text, context={"gate": "http", "source": "flask"})
            if report.action == Action.BLOCK:
                response_body = json.dumps({"error": "Prompt injection detected", "scan_id": report.scan_id}).encode()
                start_response("400 Bad Request", [("Content-Type", "application/json"), ("Content-Length", str(len(response_body)))])
                return [response_body]

        return self.app(environ, start_response)

    def _extract_fields(self, body: Any) -> list[str]:
        texts: list[str] = []
        for field_path in self.scan_fields:
            parts = field_path.split(".")
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
