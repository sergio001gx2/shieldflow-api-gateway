"""
ShieldFlow — FastAPI Dependencies
===================================
Reusable dependency-injection functions for routes and middleware.
"""

from __future__ import annotations

from typing import Annotated, AsyncGenerator

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decode_token
from app.services.database import get_async_session
from app.services.redis_service import get_redis_client

settings = get_settings()

# ── HTTP Bearer extractor ─────────────────────────────────────────────────────
_bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(_bearer_scheme)],
) -> dict:
    """
    FastAPI dependency that extracts and validates the JWT Bearer token.

    Returns:
        The decoded JWT payload (sub, iat, exp, jti, type + any extra claims).

    Raises:
        HTTP 401 if the token is missing, malformed, or expired.
    """
    payload = decode_token(credentials.credentials, expected_type="access")
    return payload


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async SQLAlchemy session, ensuring it is closed after use."""
    async for session in get_async_session():
        yield session


async def get_redis() -> aioredis.Redis:
    """Return the shared async Redis client."""
    return await get_redis_client()


# ── Type aliases for cleaner route signatures ────────────────────────────────
CurrentUser = Annotated[dict, Depends(get_current_user)]
DBSession = Annotated[AsyncSession, Depends(get_db)]
RedisClient = Annotated[aioredis.Redis, Depends(get_redis)]
