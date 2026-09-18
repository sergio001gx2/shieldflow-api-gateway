"""
ShieldFlow — WAF Detection Tests
====================================
Tests SQL Injection and XSS pattern detection across all request surfaces:
  - Query parameters
  - Request headers
  - JSON body
  - URL-encoded form body
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient


# ═════════════════════════════════════════════════════════════════════════════
# SQL INJECTION DETECTION TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestSQLInjectionDetection:
    """Tests for SQL Injection WAF rules."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload", [
        # Classic UNION-based
        "' UNION SELECT username, password FROM users--",
        "1 UNION SELECT null, null, null--",
        # OR tautology
        "' OR '1'='1",
        "admin' OR 1=1--",
        # Stacked queries
        "1; DROP TABLE users;",
        "1; SELECT * FROM information_schema.tables",
        # Time-based blind
        "1' AND SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'",
        # Error-based
        "1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))",
        # Hex encoding
        "0x53454c454354202a2046524f4d207573657273",
        # Information schema
        "' AND 1=1 UNION SELECT table_name FROM information_schema.tables--",
    ])
    async def test_sqli_blocked_in_query_param(self, client: AsyncClient, payload: str):
        """SQLi payloads in query params should return HTTP 403."""
        response = await client.get("/api/v1/gateway/echo", params={"message": payload})
        assert response.status_code == 403, (
            f"Expected 403 for SQLi payload: {payload!r}, got {response.status_code}"
        )
        data = response.json()
        assert data["attack_type"] == "sqli"
        assert "ShieldFlow WAF" in data["detail"]

    @pytest.mark.asyncio
    async def test_sqli_blocked_in_header(self, client: AsyncClient):
        """SQLi in a custom header should be blocked."""
        response = await client.get(
            "/api/v1/gateway/echo",
            headers={"X-Custom-Header": "' OR '1'='1'; DROP TABLE users;--"},
        )
        assert response.status_code == 403
        assert response.json()["attack_type"] == "sqli"

    @pytest.mark.asyncio
    async def test_sqli_blocked_in_json_body(self, client: AsyncClient, auth_headers: dict):
        """SQLi in nested JSON body fields should be blocked."""
        response = await client.post(
            "/api/v1/gateway/echo",
            json={"message": "safe message", "metadata": {"filter": "' UNION SELECT * FROM users--"}},
            headers=auth_headers,
        )
        assert response.status_code == 403
        assert response.json()["attack_type"] == "sqli"

    @pytest.mark.asyncio
    async def test_sqli_blocked_encoded_payload(self, client: AsyncClient):
        """URL-encoded SQLi payloads should be decoded and blocked."""
        # %27 = ', %20 = space
        response = await client.get(
            "/api/v1/gateway/echo?message=%27%20UNION%20SELECT%20*%20FROM%20users--"
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_clean_request_passes(self, client: AsyncClient):
        """Legitimate request must not be blocked."""
        response = await client.get(
            "/api/v1/gateway/echo",
            params={"message": "Hello, World! This is a normal message."},
        )
        assert response.status_code == 200
        assert response.json()["echo"] == "Hello, World! This is a normal message."


# ═════════════════════════════════════════════════════════════════════════════
# XSS DETECTION TESTS
# ═════════════════════════════════════════════════════════════════════════════

class TestXSSDetection:
    """Tests for XSS WAF rules."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload", [
        # Classic script tags
        "<script>alert('xss')</script>",
        "<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>",
        # Event handlers
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('xss')>",
        # JavaScript protocol
        "javascript:alert(document.cookie)",
        "<a href='javascript:void(0)' onclick='steal()'>",
        # Template injection
        "{{7*7}}",
        "${alert(1)}",
        # Data URI
        "<object data='data:text/html,<script>alert(1)</script>'>",
        # DOM manipulation
        "<img src=x onerror=document.write('<h1>XSS</h1>')>",
        # SVG
        "<svg onload=alert(1)>",
        # eval
        "eval(atob('YWxlcnQoJ1hTUycpOw=='))",
    ])
    async def test_xss_blocked_in_query_param(self, client: AsyncClient, payload: str):
        """XSS payloads in query params should return HTTP 403."""
        response = await client.get("/api/v1/gateway/echo", params={"message": payload})
        assert response.status_code == 403, (
            f"Expected 403 for XSS payload: {payload!r}, got {response.status_code}"
        )
        data = response.json()
        assert data["attack_type"] == "xss"

    @pytest.mark.asyncio
    async def test_xss_blocked_in_json_body(self, client: AsyncClient, auth_headers: dict):
        """XSS in JSON body should be detected and blocked."""
        response = await client.post(
            "/api/v1/gateway/echo",
            json={"message": "<script>document.cookie</script>"},
            headers=auth_headers,
        )
        assert response.status_code == 403
        assert response.json()["attack_type"] == "xss"

    @pytest.mark.asyncio
    async def test_xss_in_user_agent_header(self, client: AsyncClient):
        """XSS in User-Agent header should be blocked."""
        response = await client.get(
            "/api/v1/gateway/echo",
            params={"message": "normal"},
            headers={"User-Agent": "<script>alert(1)</script>"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_html_entities_pass_through(self, client: AsyncClient):
        """
        Escaped HTML entities in non-harmful context should not be blocked.
        e.g., '&lt;b&gt;bold&lt;/b&gt;' is safe as-is.
        """
        response = await client.get(
            "/api/v1/gateway/echo",
            params={"message": "Price: 5 &lt; 10 &amp; tax &gt; 0"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_security_headers_present(self, client: AsyncClient):
        """All security response headers should be present on clean responses."""
        response = await client.get(
            "/api/v1/gateway/echo", params={"message": "clean"}
        )
        assert response.status_code == 200
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"

    @pytest.mark.asyncio
    async def test_waf_returns_request_id(self, client: AsyncClient):
        """Blocked responses should include a traceable request ID."""
        response = await client.get(
            "/api/v1/gateway/echo",
            params={"message": "<script>alert(1)</script>"},
        )
        assert response.status_code == 403
        data = response.json()
        assert "request_id" in data
        assert len(data["request_id"]) == 36  # UUID format


# ═════════════════════════════════════════════════════════════════════════════
# UNIT TESTS FOR DETECTION FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

class TestDetectionFunctions:
    """Unit tests for the detection functions without HTTP overhead."""

    def test_detect_sqli_positive(self):
        from app.rules.sqli_patterns import detect_sqli
        detected, label = detect_sqli("' UNION SELECT password FROM users--")
        assert detected is True
        assert "UNION" in label or "union" in label.lower() or label

    def test_detect_sqli_negative(self):
        from app.rules.sqli_patterns import detect_sqli
        detected, label = detect_sqli("The quick brown fox jumps over the lazy dog.")
        assert detected is False
        assert label == ""

    def test_detect_xss_positive(self):
        from app.rules.xss_patterns import detect_xss
        detected, label = detect_xss("<script>alert('xss')</script>")
        assert detected is True
        assert label  # Should have a non-empty label

    def test_detect_xss_negative(self):
        from app.rules.xss_patterns import detect_xss
        detected, label = detect_xss("Hello World! This is normal text.")
        assert detected is False
        assert label == ""

    def test_pattern_labels_count(self):
        """Ensure pattern and label lists are aligned."""
        from app.rules.sqli_patterns import SQLI_COMPILED_PATTERNS, SQLI_PATTERN_LABELS
        from app.rules.xss_patterns import XSS_COMPILED_PATTERNS, XSS_PATTERN_LABELS
        assert len(SQLI_COMPILED_PATTERNS) == len(SQLI_PATTERN_LABELS)
        assert len(XSS_COMPILED_PATTERNS) == len(XSS_PATTERN_LABELS)
