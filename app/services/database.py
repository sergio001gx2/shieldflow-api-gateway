"""
ShieldFlow — Async Database Service
=====================================
SQLAlchemy async engine and session factory for PostgreSQL (Supabase).
Provides a lifespan-managed engine and per-request session dependency.
"""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# ── Declarative base for all ORM models ──────────────────────────────────────
class Base(DeclarativeBase):
    """SQLAlchemy declarative base class shared by all models."""
    pass


# ── Engine (created once at startup) ─────────────────────────────────────────
def create_engine() -> AsyncEngine:
    """
    Create the async SQLAlchemy engine.
    Pool settings are tuned for free-tier constraints:
      - pool_size=5 keeps Supabase connection count within free limits.
      - pool_pre_ping ensures stale connections are recycled.
    """
    return create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,  # Recycle connections every 30 min
    )


# Module-level engine and session factory (initialized at app startup)
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_db(engine: AsyncEngine | None = None) -> None:
    """Initialize the database engine and session factory."""
    global _engine, _session_factory
    _engine = engine or create_engine()
    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


async def close_db() -> None:
    """Dispose of the database engine connection pool."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None


async def create_tables() -> None:
    """Create all tables defined in ORM models (dev/test use; use Alembic in prod)."""
    global _engine
    if _engine is None:
        init_db()
    async with _engine.begin() as conn:  # type: ignore[union-attr]
        from app.models.threat_event import ThreatEvent  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async generator that yields a database session.
    Commits on success, rolls back on exception, always closes.
    """
    if _session_factory is None:
        init_db()

    async with _session_factory() as session:  # type: ignore[misc]
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
