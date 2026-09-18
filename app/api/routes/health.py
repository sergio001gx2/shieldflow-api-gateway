"""
ShieldFlow — Health & Readiness Routes
=========================================
Endpoints for monitoring, liveness, and readiness probes.

GET /health   — Full system health check (Redis + DB)
GET /ready    — Kubernetes-style readiness probe
GET /live     — Kubernetes-style liveness probe (lightweight)
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.models.schemas import HealthResponse
from app.services.database import get_async_session
from app.services.redis_service import get_redis_client

settings = get_settings()
router = APIRouter(tags=["Health"])

# Track application start time for uptime calculation
_START_TIME = time.time()
_VERSION = "1.0.0"


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health Check",
    description="Returns the health status of all system components.",
)
async def health_check() -> HealthResponse:
    """
    Comprehensive health check endpoint.
    Verifies connectivity to Redis and PostgreSQL.
    Returns 200 if healthy, 503 if any dependency is unhealthy.
    """
    redis_status = "unknown"
    db_status = "unknown"
    http_status = status.HTTP_200_OK

    # ── Redis health ──────────────────────────────────────────────────────────
    try:
        redis_client: aioredis.Redis = await get_redis_client()
        pong = await redis_client.ping()
        redis_status = "healthy" if pong else "unhealthy"
    except Exception as exc:
        redis_status = f"unhealthy: {str(exc)[:50]}"
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE

    # ── Database health ───────────────────────────────────────────────────────
    try:
        async for session in get_async_session():
            await session.execute(text("SELECT 1"))
            db_status = "healthy"
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)[:50]}"
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE

    overall = "healthy" if http_status == 200 else "degraded"

    response = HealthResponse(
        status=overall,
        version=_VERSION,
        redis=redis_status,
        database=db_status,
        uptime_seconds=round(time.time() - _START_TIME, 2),
    )

    return JSONResponse(content=response.model_dump(), status_code=http_status)


@router.get(
    "/ready",
    summary="Readiness Probe",
    description="Kubernetes readiness probe. Returns 200 when all dependencies are available.",
)
async def readiness() -> dict:
    """
    Readiness probe — returns 200 only when the service is ready to accept traffic.
    """
    try:
        redis_client = await get_redis_client()
        await redis_client.ping()

        async for session in get_async_session():
            await session.execute(text("SELECT 1"))

        return {"status": "ready", "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "error": str(exc)[:100]},
        )


@router.get(
    "/live",
    summary="Liveness Probe",
    description="Lightweight liveness probe. Returns 200 if the process is alive.",
)
async def liveness() -> dict:
    """
    Liveness probe — returns 200 immediately (no I/O).
    If this endpoint is unreachable, the process is dead and should be restarted.
    """
    return {
        "status": "alive",
        "uptime_seconds": round(time.time() - _START_TIME, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
