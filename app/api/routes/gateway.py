"""
ShieldFlow — Gateway Routes (Protected Endpoints)
====================================================
Demonstrates the full security pipeline:
  WAF → Rate Limiter → JWT Auth → Business Logic

Endpoints:
  GET  /gateway/echo         — Public endpoint (WAF-protected only)
  POST /gateway/echo         — Echoes a sanitized request body
  GET  /gateway/profile      — Requires valid JWT
  GET  /gateway/threats      — Returns recent threat log (admin only)
  GET  /gateway/stats        — Rate limiter stats for current client
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select

from app.core.dependencies import CurrentUser, DBSession
from app.models.schemas import (
    EchoRequest,
    EchoResponse,
    MetricsSummary,
    ThreatEventList,
    ThreatEventOut,
    UserProfileResponse,
)
from app.models.threat_event import ThreatEvent

router = APIRouter(prefix="/gateway", tags=["Gateway"])


@router.get(
    "/echo",
    summary="Public Echo",
    description="Public endpoint protected only by WAF and Rate Limiter. Try injecting payloads here!",
)
async def echo_get(
    request: Request,
    message: str = Query("Hello, ShieldFlow!", max_length=500),
) -> dict:
    """
    Public GET endpoint. Passes through WAF inspection.
    Any SQLi or XSS in the `message` query parameter will be blocked.
    """
    return {
        "echo": message,
        "method": "GET",
        "gateway": "ShieldFlow v1",
        "request_id": getattr(request.state, "request_id", None),
    }


@router.post(
    "/echo",
    response_model=EchoResponse,
    summary="Protected Echo",
    description="Authenticated POST endpoint. Body is WAF-inspected before reaching this handler.",
)
async def echo_post(
    body: EchoRequest,
    current_user: CurrentUser,
    request: Request,
) -> EchoResponse:
    """
    Authenticated POST endpoint. Requires valid Bearer JWT token.
    The request body has already passed WAF inspection before reaching here.
    """
    return EchoResponse(
        message=body.message,
        metadata={
            **(body.metadata or {}),
            "processed_by_user": current_user.get("username"),
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@router.get(
    "/profile",
    response_model=UserProfileResponse,
    summary="User Profile",
    description="Returns the current user's profile from their JWT claims.",
)
async def get_profile(current_user: CurrentUser) -> UserProfileResponse:
    """Protected endpoint — requires a valid access token."""
    from datetime import datetime, timezone
    issued_at = datetime.fromtimestamp(current_user["iat"], tz=timezone.utc)
    return UserProfileResponse(
        user_id=current_user["sub"],
        username=current_user.get("username", "unknown"),
        role=current_user.get("role", "user"),
        issued_at=issued_at,
    )


@router.get(
    "/threats",
    response_model=ThreatEventList,
    summary="Threat Event Log",
    description="Paginated list of recent threat events. Requires admin role.",
)
async def list_threats(
    current_user: CurrentUser,
    db: DBSession,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    attack_type: Optional[str] = Query(None, description="Filter by attack type: sqli, xss, rate_limit"),
) -> ThreatEventList:
    """Returns the threat event log (admin only)."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Admin role required.",
        )

    stmt = select(ThreatEvent).order_by(desc(ThreatEvent.detected_at))
    count_stmt = select(func.count()).select_from(ThreatEvent)

    if attack_type:
        stmt = stmt.where(ThreatEvent.attack_type == attack_type)
        count_stmt = count_stmt.where(ThreatEvent.attack_type == attack_type)

    # Pagination
    offset = (page - 1) * page_size
    stmt = stmt.offset(offset).limit(page_size)

    result = await db.execute(stmt)
    events = result.scalars().all()

    count_result = await db.execute(count_stmt)
    total = count_result.scalar_one()

    return ThreatEventList(
        items=[ThreatEventOut.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/stats",
    response_model=MetricsSummary,
    summary="Threat Metrics Summary",
    description="Aggregated security metrics. Requires admin role.",
)
async def get_stats(
    current_user: CurrentUser,
    db: DBSession,
) -> MetricsSummary:
    """Return aggregated threat metrics for the dashboard."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Admin role required.",
        )

    from datetime import datetime, timedelta, timezone
    from sqlalchemy import and_

    # Total blocked
    total = (await db.execute(select(func.count()).select_from(ThreatEvent))).scalar_one()

    # By type
    sqli = (await db.execute(
        select(func.count()).select_from(ThreatEvent).where(ThreatEvent.attack_type == "sqli")
    )).scalar_one()

    xss = (await db.execute(
        select(func.count()).select_from(ThreatEvent).where(ThreatEvent.attack_type == "xss")
    )).scalar_one()

    rl = (await db.execute(
        select(func.count()).select_from(ThreatEvent).where(ThreatEvent.attack_type == "rate_limit")
    )).scalar_one()

    # Last 24h
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24h = (await db.execute(
        select(func.count()).select_from(ThreatEvent).where(ThreatEvent.detected_at >= since)
    )).scalar_one()

    # Top offenders (by IP)
    top_stmt = (
        select(ThreatEvent.client_ip, func.count().label("count"))
        .group_by(ThreatEvent.client_ip)
        .order_by(desc("count"))
        .limit(5)
    )
    top_result = await db.execute(top_stmt)
    top_offenders = [{"ip": row.client_ip, "count": row.count} for row in top_result]

    return MetricsSummary(
        total_blocked=total,
        sqli_count=sqli,
        xss_count=xss,
        rate_limit_count=rl,
        top_offenders=top_offenders,
        last_24h_events=last_24h,
    )
