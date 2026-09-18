"""
ShieldFlow — Authentication Routes
=====================================
Endpoints for token issuance and rotation.

POST /auth/token    — Issue access + refresh token pair (login)
POST /auth/refresh  — Rotate tokens using a valid refresh token
GET  /auth/me       — Return the current user's token claims

Note: In a real deployment, replace the in-memory user store with a
database lookup against a users table. The demo users below are intentional
for local development and testing.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from app.core.config import get_settings
from app.core.dependencies import CurrentUser
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    rotate_tokens,
    verify_password,
)
from app.models.schemas import (
    RefreshRequest,
    TokenRequest,
    TokenResponse,
    UserProfileResponse,
)

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["Authentication"])

# ── Demo user store (replace with DB lookup in production) ────────────────────
# Passwords are pre-hashed with bcrypt.
_DEMO_USERS: dict[str, dict] = {
    "admin": {
        "user_id": "usr_001",
        "password_hash": hash_password("supersecret"),
        "role": "admin",
    },
    "developer": {
        "user_id": "usr_002",
        "password_hash": hash_password("devpassword"),
        "role": "developer",
    },
    "readonly": {
        "user_id": "usr_003",
        "password_hash": hash_password("readonlypass"),
        "role": "viewer",
    },
}


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Issue JWT Token Pair",
    description="Authenticate with username and password to receive an access + refresh token pair.",
    status_code=status.HTTP_200_OK,
)
async def login(credentials: TokenRequest) -> TokenResponse:
    """
    Authenticate a user and return a JWT token pair.

    - **username**: The user's username.
    - **password**: The user's plaintext password.

    Returns a short-lived `access_token` and a long-lived `refresh_token`.
    """
    user = _DEMO_USERS.get(credentials.username)

    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        subject=user["user_id"],
        extra_claims={"username": credentials.username, "role": user["role"]},
    )
    refresh_token = create_refresh_token(subject=user["user_id"])

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate JWT Tokens",
    description="Exchange a valid refresh token for a new access + refresh token pair.",
    status_code=status.HTTP_200_OK,
)
async def refresh(body: RefreshRequest) -> TokenResponse:
    """
    Rotate tokens using a valid refresh token.
    The old refresh token is implicitly invalidated (stateless via short TTL).
    """
    tokens = rotate_tokens(body.refresh_token)
    return TokenResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Current User Profile",
    description="Returns the claims of the currently authenticated user.",
    status_code=status.HTTP_200_OK,
)
async def get_me(current_user: CurrentUser) -> UserProfileResponse:
    """
    Returns the authenticated user's profile extracted from their JWT.
    Requires a valid Bearer access token.
    """
    issued_at = datetime.fromtimestamp(current_user["iat"], tz=timezone.utc)
    return UserProfileResponse(
        user_id=current_user["sub"],
        username=current_user.get("username", "unknown"),
        role=current_user.get("role", "user"),
        issued_at=issued_at,
    )
