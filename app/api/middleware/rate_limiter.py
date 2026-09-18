"""
ShieldFlow — Rate Limiter Middleware
======================================
Starlette middleware implementing the Token Bucket algorithm via Redis.

Flow:
  1. Extract client identifier (IP or API-Key header).
  2. Consult Redis Token Bucket for the identifier.
  3. If bucket is full (allowed) → pass through, add rate-limit headers.
  4. If bucket is empty → return HTTP 429 Too Many Requests.

Headers added to all responses:
  X-RateLimit-Limit:      Max requests per window
  X-RateLimit-Remaining:  Tokens left in the current window
  X-RateLimit-Reset:      Seconds until bucket refills (when rate-limited)
  Retry-After:            Standard header for 429 responses
"""

from __future__ import annotations

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.core.config import get_settings
from app.services.redis_service import TokenBucketRateLimiter, get_redis_client
from app.services.threat_logger import fire_and_forget_log, log_rate_limit_event

settings = get_settings()
logger = structlog.get_logger(__name__)

# Paths that bypass rate limiting entirely
_EXEMPT_PATHS = frozenset({"/health", "/metrics", "/docs", "/openapi.json", "/redoc"})


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    Token Bucket rate limiting middleware backed by Redis.

    The client identifier is resolved in priority order:
      1. X-API-Key header (for authenticated API consumers)
      2. Authorization: Bearer sub claim (if already decoded upstream)
      3. Client IP address (fallback)
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._limiter: TokenBucketRateLimiter | None = None

    async def _get_limiter(self) -> TokenBucketRateLimiter:
        """Lazily initialize the rate limiter with a shared Redis connection."""
        if self._limiter is None:
            redis = await get_redis_client()
            self._limiter = TokenBucketRateLimiter(
                redis=redis,
                max_tokens=settings.RATE_LIMIT_REQUESTS,
                window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
            )
        return self._limiter

    @staticmethod
    def _get_client_identifier(request: Request) -> str:
        """
        Resolve a unique, stable identifier for the requesting client.
        Priority: API Key > Authorization subject > IP address.
        """
        # Check for explicit API key header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # Hash the key to avoid storing raw credentials in Redis keys
            import hashlib
            return f"apikey:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"

        # Fallback to IP address
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"

        if request.client:
            return f"ip:{request.client.host}"

        return "ip:unknown"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # ── Skip exempt paths ─────────────────────────────────────────────────
        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        identifier = self._get_client_identifier(request)
        limiter = await self._get_limiter()

        try:
            result = await limiter.check(identifier)
        except Exception as exc:
            # Redis failure — fail open (allow request) to preserve availability
            logger.error("rate_limiter_error", error=str(exc), identifier=identifier)
            return await call_next(request)

        if not result.allowed:
            client_ip = request.client.host if request.client else "unknown"

            logger.warning(
                "rate_limit_exceeded",
                identifier=identifier,
                path=request.url.path,
                retry_after=result.retry_after,
            )

            fire_and_forget_log(
                log_rate_limit_event(
                    client_ip=client_ip,
                    request_path=request.url.path,
                    request_method=request.method,
                    retry_after=result.retry_after,
                )
            )

            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": "You have exceeded your request limit. Please slow down.",
                    "retry_after": result.retry_after,
                },
                headers={
                    "X-RateLimit-Limit": str(settings.RATE_LIMIT_REQUESTS),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(result.retry_after),
                    "Retry-After": str(result.retry_after),
                },
            )

        # ── Allowed — pass through and annotate response ─────────────────────
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
        response.headers["X-RateLimit-Reset"] = str(settings.RATE_LIMIT_WINDOW_SECONDS)
        return response
