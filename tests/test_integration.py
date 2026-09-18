"""
ShieldFlow — Integration Tests
=================================
End-to-end tests that exercise the complete request pipeline:
  WAF → Rate Limiter → JWT Auth → Business Logic → DB Logging

These tests simulate realistic attack and usage scenarios.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestFullSecurityPipeline:
    """Complete pipeline integration tests."""

    @pytest.mark.asyncio
    async def test_clean_public_request(self, client: AsyncClient):
        """Clean public request passes all middleware."""
        response = await client.get(
            "/api/v1/gateway/echo",
            params={"message": "Hello ShieldFlow!"},
        )
        assert response.status_code == 200
        assert response.json()["echo"] == "Hello ShieldFlow!"
        # Security headers must be present
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        # Rate limit headers must be present
        assert "X-RateLimit-Remaining" in response.headers

    @pytest.mark.asyncio
    async def test_attack_blocked_before_reaching_auth(self, client: AsyncClient):
        """SQLi is blocked at WAF layer — JWT is never checked."""
        response = await client.get(
            "/api/v1/gateway/echo",
            params={"message": "' OR '1'='1"},
            # No Authorization header on purpose
        )
        # WAF should block BEFORE auth check
        assert response.status_code == 403
        assert response.json()["attack_type"] == "sqli"

    @pytest.mark.asyncio
    async def test_authenticated_echo_flow(self, client: AsyncClient):
        """Full flow: login → use token → echo endpoint."""
        # Login
        login = await client.post(
            "/api/v1/auth/token",
            json={"username": "admin", "password": "supersecret"},
        )
        assert login.status_code == 200
        access_token = login.json()["access_token"]

        # Use protected endpoint
        echo = await client.post(
            "/api/v1/gateway/echo",
            json={"message": "Test payload", "metadata": {"env": "test"}},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert echo.status_code == 200
        data = echo.json()
        assert data["message"] == "Test payload"
        assert data["metadata"]["processed_by_user"] == "admin"

    @pytest.mark.asyncio
    async def test_multiple_attack_types_in_one_request(self, client: AsyncClient, auth_headers: dict):
        """A request containing both SQLi and XSS is blocked at first detection."""
        response = await client.post(
            "/api/v1/gateway/echo",
            json={
                "message": "safe",
                "metadata": {
                    "q": "' UNION SELECT * FROM users--",  # SQLi
                    "html": "<script>alert('xss')</script>",  # XSS
                },
            },
            headers=auth_headers,
        )
        assert response.status_code == 403
        # First detected attack type is returned
        assert response.json()["attack_type"] in ("sqli", "xss")

    @pytest.mark.asyncio
    async def test_health_endpoint_always_accessible(self, client: AsyncClient):
        """Health endpoint bypasses WAF and rate limiting."""
        response = await client.get("/health")
        assert response.status_code in (200, 503)  # Not 403, not 429

    @pytest.mark.asyncio
    async def test_openapi_docs_accessible(self, client: AsyncClient):
        """OpenAPI docs should be accessible without auth."""
        response = await client.get("/docs")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_liveness_probe(self, client: AsyncClient):
        """Liveness probe must always return 200."""
        response = await client.get("/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"
        assert data["uptime_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_admin_can_access_threat_log(self, client: AsyncClient, auth_headers: dict):
        """Admin user can query the threat event log."""
        response = await client.get("/api/v1/gateway/threats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    @pytest.mark.asyncio
    async def test_non_admin_cannot_access_threat_log(
        self, client: AsyncClient, user_token: str
    ):
        """Developer role cannot access the admin threat log."""
        response = await client.get(
            "/api/v1/gateway/threats",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 403
        assert "Admin role required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_request_id_correlation(self, client: AsyncClient):
        """Every response (clean or blocked) should carry a traceable request ID."""
        # Clean response
        clean = await client.get(
            "/api/v1/gateway/echo", params={"message": "clean"}
        )
        assert "X-Request-Id" in clean.headers
        assert len(clean.headers["X-Request-Id"]) == 36  # UUID

        # Blocked response
        blocked = await client.get(
            "/api/v1/gateway/echo",
            params={"message": "<script>xss</script>"},
        )
        assert blocked.status_code == 403
        assert "request_id" in blocked.json()

    @pytest.mark.asyncio
    async def test_profile_endpoint_returns_correct_role(
        self, client: AsyncClient, user_token: str
    ):
        """Profile endpoint returns role from JWT claims."""
        response = await client.get(
            "/api/v1/gateway/profile",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "developer"
        assert data["gateway"] == "ShieldFlow v1"
