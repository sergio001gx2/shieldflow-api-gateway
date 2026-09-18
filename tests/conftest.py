"""
ShieldFlow — pytest Configuration & Fixtures
=============================================
Shared fixtures for all test modules.
Uses fakeredis for in-memory Redis and SQLite (async) for in-memory DB.
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.core.security import create_access_token, create_refresh_token
from app.main import create_app
from app.models.threat_event import ThreatEvent
from app.services import database as db_service
from app.services import redis_service

settings = get_settings()

# ── Event loop ────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def event_loop():
    """Use a single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Fake Redis fixture ────────────────────────────────────────────────────────
@pytest_asyncio.fixture(scope="function")
async def fake_redis():
    """In-memory Redis replacement using fakeredis."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=False)
    # Patch the global Redis client
    redis_service._redis_client = client
    yield client
    await client.aclose()
    redis_service._redis_client = None


# ── In-memory SQLite DB fixture ───────────────────────────────────────────────
@pytest_asyncio.fixture(scope="function")
async def test_db_engine():
    """Create a fresh SQLite in-memory database for each test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(db_service.Base.metadata.create_all)

    db_service.init_db(engine)
    yield engine

    await engine.dispose()
    db_service._engine = None
    db_service._session_factory = None


# ── FastAPI test client fixture ───────────────────────────────────────────────
@pytest_asyncio.fixture(scope="function")
async def client(fake_redis, test_db_engine) -> AsyncGenerator[AsyncClient, None]:
    """
    HTTPX async test client bound to the FastAPI app.
    Uses fake Redis and in-memory SQLite — no external services required.
    """
    app: FastAPI = create_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
        headers={"X-Forwarded-For": "192.168.1.100"},
    ) as ac:
        yield ac


# ── Auth token fixtures ───────────────────────────────────────────────────────
@pytest.fixture
def admin_token() -> str:
    """Pre-signed admin access token."""
    return create_access_token(
        subject="usr_001",
        extra_claims={"username": "admin", "role": "admin"},
    )


@pytest.fixture
def user_token() -> str:
    """Pre-signed developer access token."""
    return create_access_token(
        subject="usr_002",
        extra_claims={"username": "developer", "role": "developer"},
    )


@pytest.fixture
def refresh_token_fixture() -> str:
    """Pre-signed refresh token."""
    return create_refresh_token(subject="usr_001")


@pytest.fixture
def auth_headers(admin_token: str) -> dict:
    """Authorization headers for admin user."""
    return {"Authorization": f"Bearer {admin_token}"}
