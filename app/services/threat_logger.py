"""
ShieldFlow — Threat Logger Service
=====================================
Asynchronously persists blocked request events to PostgreSQL (Supabase).
Runs database writes in a non-blocking fire-and-forget manner so that
WAF/rate-limiter responses are not delayed by I/O.
"""

from __future__ import annotations

import asyncio
import structlog
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_event import ThreatEvent
from app.rules.inspector import InspectionResult
from app.services.database import get_async_session

logger = structlog.get_logger(__name__)


async def log_threat_event(
    inspection: InspectionResult,
    block_reason: str,
    request_id: Optional[str] = None,
) -> None:
    """
    Persist a blocked request event to the database.

    This function is designed to be called with asyncio.create_task() so it
    does not block the response pipeline.

    Args:
        inspection:   The InspectionResult from the WAF inspector.
        block_reason: Human-readable reason for blocking ("sqli", "xss", "rate_limit").
        request_id:   Optional correlation ID for tracing.
    """
    try:
        async for session in get_async_session():
            primary_threat = inspection.threats[0] if inspection.threats else None

            event = ThreatEvent(
                client_ip=inspection.client_ip,
                request_path=inspection.request_path,
                request_method=inspection.request_method,
                attack_type=block_reason,
                matched_pattern=primary_threat.matched_pattern if primary_threat else block_reason,
                payload_location=primary_threat.location if primary_threat else "unknown",
                payload_snippet=primary_threat.payload_snippet if primary_threat else "",
                all_threats_count=len(inspection.threats),
                request_id=request_id,
                detected_at=datetime.now(timezone.utc),
            )
            session.add(event)
            # Session commit happens automatically in get_async_session()

        logger.info(
            "threat_logged",
            client_ip=inspection.client_ip,
            attack_type=block_reason,
            path=inspection.request_path,
            patterns=[t.matched_pattern for t in inspection.threats],
        )

    except Exception as exc:
        # Never let logging failure affect the security response
        logger.error(
            "threat_log_failed",
            error=str(exc),
            client_ip=inspection.client_ip,
        )


async def log_rate_limit_event(
    client_ip: str,
    request_path: str,
    request_method: str,
    retry_after: int,
) -> None:
    """
    Log a rate-limit block event (no WAF inspection result available).
    """
    try:
        async for session in get_async_session():
            event = ThreatEvent(
                client_ip=client_ip,
                request_path=request_path,
                request_method=request_method,
                attack_type="rate_limit",
                matched_pattern="token_bucket_exhausted",
                payload_location="metadata",
                payload_snippet=f"retry_after={retry_after}s",
                all_threats_count=0,
                detected_at=datetime.now(timezone.utc),
            )
            session.add(event)

        logger.warning(
            "rate_limit_logged",
            client_ip=client_ip,
            path=request_path,
            retry_after=retry_after,
        )

    except Exception as exc:
        logger.error("rate_limit_log_failed", error=str(exc))


def fire_and_forget_log(coro) -> None:
    """
    Schedule a coroutine as a background task.
    Safe to call from synchronous contexts via asyncio.get_event_loop().
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(coro)
        else:
            loop.run_until_complete(coro)
    except RuntimeError:
        # No event loop available; skip logging (test environments)
        pass
