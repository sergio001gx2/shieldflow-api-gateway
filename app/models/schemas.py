"""
ShieldFlow — Pydantic Schemas
================================
Request/response schemas for all API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ─── Auth Schemas ─────────────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    """Credentials for obtaining a JWT token pair."""
    username: str = Field(..., min_length=3, max_length=64, examples=["admin"])
    password: str = Field(..., min_length=6, examples=["supersecret"])


class TokenResponse(BaseModel):
    """JWT token pair returned after successful authentication."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token TTL in seconds")


class RefreshRequest(BaseModel):
    """Body for token rotation endpoint."""
    refresh_token: str


# ─── Threat Event Schemas ─────────────────────────────────────────────────────

class ThreatEventOut(BaseModel):
    """Serialized threat event for API responses."""
    id: int
    client_ip: str
    request_path: str
    request_method: str
    attack_type: str
    matched_pattern: str
    payload_location: str
    payload_snippet: str
    all_threats_count: int
    request_id: Optional[str]
    detected_at: datetime

    model_config = {"from_attributes": True}


class ThreatEventList(BaseModel):
    """Paginated list of threat events."""
    items: List[ThreatEventOut]
    total: int
    page: int
    page_size: int


# ─── Health / Metrics Schemas ─────────────────────────────────────────────────

class HealthResponse(BaseModel):
    """System health check response."""
    status: str = "healthy"
    version: str
    redis: str
    database: str
    uptime_seconds: float


class MetricsSummary(BaseModel):
    """Aggregated threat detection metrics."""
    total_blocked: int
    sqli_count: int
    xss_count: int
    rate_limit_count: int
    top_offenders: List[dict]
    last_24h_events: int


# ─── Gateway Schemas ─────────────────────────────────────────────────────────

class EchoRequest(BaseModel):
    """Echo endpoint — returns the sanitized request back."""
    message: str = Field(..., max_length=1000)
    metadata: Optional[dict] = None


class EchoResponse(BaseModel):
    message: str
    metadata: Optional[dict]
    processed_by: str = "ShieldFlow Gateway"


class UserProfileResponse(BaseModel):
    """Demo protected endpoint response."""
    user_id: str
    username: str
    role: str
    issued_at: datetime
    gateway: str = "ShieldFlow v1"
