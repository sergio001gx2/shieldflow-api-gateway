"""
ShieldFlow — FastAPI Application Factory
==========================================
Creates and configures the FastAPI application with:
  - Middleware stack (WAF → Rate Limiter → CORS → Logging)
  - Route registration
  - Lifespan events (startup/shutdown)
  - OpenAPI documentation customization
  - Structured JSON logging
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from app.api.middleware.rate_limiter import RateLimiterMiddleware
from app.api.middleware.waf import WAFMiddleware
from app.api.routes import auth, gateway, health
from app.core.config import get_settings
from app.services.database import close_db, create_tables, init_db
from app.services.redis_service import close_redis_client

settings = get_settings()

# ── Configure structured logging ──────────────────────────────────────────────
import logging as _logging

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
        if settings.LOG_FORMAT == "json"
        else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        _logging.getLevelName(settings.LOG_LEVEL.upper())
    ),
    logger_factory=structlog.PrintLoggerFactory(),
)

logger = structlog.get_logger(__name__)


# ── Application Lifespan ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage application startup and shutdown.
    - Startup: Initialize DB engine, create tables (if needed), verify Redis.
    - Shutdown: Gracefully close DB pool and Redis connections.
    """
    logger.info("shieldflow_starting", env=settings.APP_ENV, version="1.0.0")

    # Initialize database
    init_db()
    try:
        await create_tables()
        logger.info("database_ready")
    except Exception as exc:
        logger.warning("database_init_warning", error=str(exc))

    logger.info("shieldflow_ready", host=settings.APP_HOST, port=settings.APP_PORT)

    yield  # ← Application is running here

    logger.info("shieldflow_stopping")
    await close_db()
    await close_redis_client()
    logger.info("shieldflow_stopped")


# ── App Factory ───────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="ShieldFlow",
        description=(
            "🛡️ **ShieldFlow** — Zero-Trust API Gateway & Threat Detector\n\n"
            "A production-ready API security layer featuring:\n"
            "- **WAF**: SQL Injection & XSS detection\n"
            "- **Rate Limiting**: Token Bucket algorithm (Redis-backed)\n"
            "- **JWT Auth**: Stateless token verification with rotation\n"
            "- **Threat Logging**: Persistent event records in PostgreSQL\n\n"
            "**Demo Credentials:** `admin` / `supersecret`"
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS Middleware ───────────────────────────────────────────────────────
    # Must be added BEFORE WAF/Rate Limiter so preflight OPTIONS pass through
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Security Middleware (innermost = first to process request) ────────────
    # Order matters! Middleware is applied last-added = outermost wrapper.
    # Execution order for a request: RateLimiter → WAF → Routes
    app.add_middleware(WAFMiddleware)
    app.add_middleware(RateLimiterMiddleware)

    # ── Prometheus Metrics ────────────────────────────────────────────────────
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/health", "/live", "/ready"],
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    # ── Request Logging Middleware ────────────────────────────────────────────
    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        """Log every request with timing and correlation ID."""
        request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
        start = time.perf_counter()

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000

        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            client_ip=request.client.host if request.client else "unknown",
        )
        return response

    # ── Global Exception Handler ──────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(
            "unhandled_exception",
            error=str(exc),
            path=request.url.path,
            method=request.method,
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred. Please try again later.",
            },
        )

    # ── Route Registration ────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(gateway.router, prefix="/api/v1")

    # ── Root Redirect ─────────────────────────────────────────────────────────
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "name": "ShieldFlow",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/health",
        }

    return app


# ── ASGI Application Instance ─────────────────────────────────────────────────
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=False,  # Handled by our custom middleware
    )
