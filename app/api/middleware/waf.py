"""
ShieldFlow — WAF Middleware
============================
Web Application Firewall implemented as a Starlette middleware.

Flow:
  1. Read and buffer the request body (necessary for inspection).
  2. Pass the request through the WAF inspector.
  3. If a threat is detected → return HTTP 403 + log the event.
  4. If clean → reconstruct the request with the buffered body and pass through.

Design Notes:
  - Body is read once and stored in request.state for downstream handlers.
  - WAF is bypassed for whitelisted IPs (e.g., internal health checkers).
  - Threat logging is non-blocking (fire-and-forget).
"""

from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.core.config import get_settings
from app.rules.inspector import inspect_request
from app.services.threat_logger import fire_and_forget_log, log_threat_event

settings = get_settings()
logger = structlog.get_logger(__name__)

# Paths exempt from WAF inspection (e.g., health checks, metrics)
_EXEMPT_PATHS = frozenset({"/health", "/metrics", "/docs", "/openapi.json", "/redoc"})

# Maximum body size to read for inspection (10 MB)
_MAX_BODY_SIZE = 10 * 1024 * 1024


class WAFMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that inspects every incoming HTTP request for
    SQL Injection and XSS attack patterns.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # ── Skip WAF for exempt paths ─────────────────────────────────────────
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        # ── Skip WAF if disabled ──────────────────────────────────────────────
        if not settings.WAF_ENABLED:
            return await call_next(request)

        # ── Generate a request correlation ID ─────────────────────────────────
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # ── Check IP whitelist ────────────────────────────────────────────────
        client_ip = _get_client_ip(request)
        if client_ip in settings.waf_whitelist_list:
            return await call_next(request)

        # ── Buffer the request body ───────────────────────────────────────────
        # We must read the body here because Starlette's request body stream
        # can only be consumed once. We store it in request.state for reuse.
        try:
            body_bytes = await request.body()
            if len(body_bytes) > _MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large."},
                )
        except Exception:
            body_bytes = b""

        # Store the buffered body so downstream routes can still read it
        request.state.body = body_bytes

        # ── Inspect the request ───────────────────────────────────────────────
        start = time.perf_counter()
        result = await inspect_request(request, body_bytes)
        inspection_ms = (time.perf_counter() - start) * 1000

        # ── Block if threat detected ──────────────────────────────────────────
        if result.is_threat:
            primary = result.threats[0]

            logger.warning(
                "waf_blocked",
                request_id=request_id,
                client_ip=result.client_ip,
                path=result.request_path,
                attack_type=primary.attack_type,
                pattern=primary.matched_pattern,
                location=primary.location,
                inspection_ms=round(inspection_ms, 2),
            )

            # Log to DB asynchronously — never block the response
            if settings.WAF_LOG_BLOCKED:
                fire_and_forget_log(
                    log_threat_event(result, primary.attack_type, request_id)
                )

            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "detail": f"Request blocked by ShieldFlow WAF: {primary.matched_pattern}",
                    "attack_type": primary.attack_type,
                    "request_id": request_id,
                },
                headers={"X-Request-Id": request_id, "X-Blocked-By": "ShieldFlow-WAF"},
            )

        # ── Clean request — pass through ──────────────────────────────────────
        response = await call_next(request)

        # Add security headers to all responses
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-WAF-Inspection-Ms"] = str(round(inspection_ms, 2))

        return response


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, honoring proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
