"""
ShieldFlow — JWT Authentication Tests
========================================
Tests for the authentication flow:
  - Login with valid/invalid credentials
  - Token verification and protected endpoint access
  - Token rotation (refresh)
  - Edge cases: expired, malformed, wrong-type tokens
"""

from __future__ import annotations

import time
from datetime import timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient

from app.core.security import (
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    _create_token,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


# ═════════════════════════════════════════════════════════════════════════════
# PASSWORD HASHING TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = hash_password("mysecretpassword")
        assert verify_password("mysecretpassword", hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("correctpassword")
        assert verify_password("wrongpassword", hashed) is False

    def test_hash_is_not_plaintext(self):
        hashed = hash_password("plaintext")
        assert hashed != "plaintext"
        assert hashed.startswith("$2b$")


# ═════════════════════════════════════════════════════════════════════════════
# TOKEN CREATION & DECODING TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestTokenCreation:
    def test_create_access_token(self):
        token = create_access_token("user_123")
        payload = decode_token(token, expected_type=ACCESS_TOKEN_TYPE)
        assert payload["sub"] == "user_123"
        assert payload["type"] == "access"

    def test_create_refresh_token(self):
        token = create_refresh_token("user_123")
        payload = decode_token(token, expected_type=REFRESH_TOKEN_TYPE)
        assert payload["sub"] == "user_123"
        assert payload["type"] == "refresh"

    def test_extra_claims_embedded(self):
        token = create_access_token(
            "user_123",
            extra_claims={"role": "admin", "username": "john"},
        )
        payload = decode_token(token)
        assert payload["role"] == "admin"
        assert payload["username"] == "john"

    def test_jti_is_unique(self):
        t1 = create_access_token("user_1")
        t2 = create_access_token("user_1")
        p1 = decode_token(t1)
        p2 = decode_token(t2)
        assert p1["jti"] != p2["jti"]

    def test_expired_token_raises(self):
        from fastapi import HTTPException
        expired_token = _create_token(
            "user_123",
            ACCESS_TOKEN_TYPE,
            expires_delta=timedelta(seconds=-1),  # Already expired
        )
        with pytest.raises(HTTPException) as exc_info:
            decode_token(expired_token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_wrong_token_type_raises(self):
        from fastapi import HTTPException
        refresh = create_refresh_token("user_123")
        with pytest.raises(HTTPException) as exc_info:
            decode_token(refresh, expected_type=ACCESS_TOKEN_TYPE)
        assert exc_info.value.status_code == 401
        assert "access" in exc_info.value.detail

    def test_malformed_token_raises(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            decode_token("this.is.not.a.jwt")
        assert exc_info.value.status_code == 401

    def test_tampered_token_raises(self):
        from fastapi import HTTPException
        token = create_access_token("user_123")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(HTTPException):
            decode_token(tampered)


# ═════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINT TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestAuthEndpoints:
    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/token",
            json={"username": "admin", "password": "supersecret"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/token",
            json={"username": "admin", "password": "wrongpassword"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_unknown_user(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/token",
            json={"username": "nonexistent", "password": "anypassword"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_endpoint_requires_token(self, client: AsyncClient):
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 403  # No auth header

    @pytest.mark.asyncio
    async def test_protected_endpoint_with_valid_token(
        self, client: AsyncClient, auth_headers: dict
    ):
        response = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "usr_001"
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    @pytest.mark.asyncio
    async def test_protected_endpoint_with_invalid_token(self, client: AsyncClient):
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalidtoken123"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_token_rotation(self, client: AsyncClient, refresh_token_fixture: str):
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token_fixture},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        # New tokens should be different from the originals
        assert data["refresh_token"] != refresh_token_fixture

    @pytest.mark.asyncio
    async def test_access_token_cannot_refresh(self, client: AsyncClient, admin_token: str):
        """Using an access token as a refresh token should fail."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": admin_token},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_full_auth_flow(self, client: AsyncClient):
        """Complete flow: login → use token → refresh → use new token."""
        # Step 1: Login
        login_response = await client.post(
            "/api/v1/auth/token",
            json={"username": "developer", "password": "devpassword"},
        )
        assert login_response.status_code == 200
        tokens = login_response.json()

        # Step 2: Access protected endpoint
        me_response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert me_response.status_code == 200

        # Step 3: Rotate tokens
        refresh_response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
        assert refresh_response.status_code == 200
        new_tokens = refresh_response.json()

        # Step 4: Access with new token
        me_response2 = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {new_tokens['access_token']}"},
        )
        assert me_response2.status_code == 200
        assert me_response2.json()["username"] == "developer"
