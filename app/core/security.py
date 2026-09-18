"""
ShieldFlow — JWT Security Module
==================================
Handles JWT token creation, validation, and refresh rotation.
Stateless design — no server-side session storage required.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from fastapi import HTTPException, status
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

# ── Password hashing context (bcrypt) ────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ─── Token Payload Types ─────────────────────────────────────────────────────
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def _create_token(
    subject: str,
    token_type: str,
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Internal helper to build and sign a JWT.

    Args:
        subject:      Unique identifier (user ID / API Key ID).
        token_type:   "access" or "refresh".
        extra_claims: Additional payload fields to embed.
        expires_delta: Override the default expiry.

    Returns:
        Signed JWT string.
    """
    now = datetime.now(timezone.utc)

    if expires_delta is None:
        if token_type == ACCESS_TOKEN_TYPE:
            expires_delta = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        else:
            expires_delta = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + expires_delta,
        "jti": str(uuid.uuid4()),     # Unique token ID for revocation tracking
        "type": token_type,
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(subject: str, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    """Create a short-lived access token."""
    return _create_token(subject, ACCESS_TOKEN_TYPE, extra_claims)


def create_refresh_token(subject: str) -> str:
    """Create a long-lived refresh token for rotation."""
    return _create_token(subject, REFRESH_TOKEN_TYPE)


def decode_token(token: str, expected_type: str = ACCESS_TOKEN_TYPE) -> Dict[str, Any]:
    """
    Decode and validate a JWT token.

    Raises:
        HTTPException 401: If the token is invalid, expired, or wrong type.

    Returns:
        The decoded payload dictionary.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub", "type"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please refresh or re-authenticate.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Expected '{expected_type}' token, got '{payload.get('type')}'.",
        )

    return payload


def rotate_tokens(refresh_token: str) -> Dict[str, str]:
    """
    Token rotation: validate the refresh token and issue a new pair.
    This invalidates the old refresh token (stateless via short TTL).

    Returns:
        Dict with 'access_token' and 'refresh_token'.
    """
    payload = decode_token(refresh_token, expected_type=REFRESH_TOKEN_TYPE)
    subject = payload["sub"]

    return {
        "access_token": create_access_token(subject),
        "refresh_token": create_refresh_token(subject),
        "token_type": "bearer",
    }
