"""
ShieldFlow — Threat Event ORM Model
======================================
SQLAlchemy model for persisting blocked/detected threat events.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.services.database import Base


class ThreatEvent(Base):
    """
    Records every request that was blocked by the WAF or Rate Limiter.

    Columns:
        id              — Auto-incrementing primary key.
        client_ip       — Source IP of the request.
        request_path    — URL path of the blocked request.
        request_method  — HTTP method (GET, POST, etc.).
        attack_type     — Category: "sqli", "xss", "rate_limit".
        matched_pattern — Human-readable label of the triggered pattern.
        payload_location — Where the payload was found (header/query/body).
        payload_snippet — Truncated suspicious content (max 512 chars).
        all_threats_count — Total number of threats found in the request.
        request_id      — Optional correlation/trace ID.
        detected_at     — UTC timestamp of detection.
    """

    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    client_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    request_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    request_method: Mapped[str] = mapped_column(String(10), nullable=False)

    attack_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    matched_pattern: Mapped[str] = mapped_column(String(256), nullable=False)
    payload_location: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_snippet: Mapped[str] = mapped_column(Text, nullable=False, default="")

    all_threats_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # ── Composite indexes for common dashboard queries ────────────────────────
    __table_args__ = (
        Index("ix_threat_events_ip_time", "client_ip", "detected_at"),
        Index("ix_threat_events_type_time", "attack_type", "detected_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatEvent id={self.id} type={self.attack_type!r} "
            f"ip={self.client_ip!r} at={self.detected_at}>"
        )
