"""
ShieldFlow — Redis Service & Token Bucket Rate Limiter
=======================================================
Implements the Token Bucket algorithm using a Lua script for atomic
operations in Redis. This ensures no race conditions under high concurrency.

Token Bucket Algorithm:
  - Each client (IP or API Key) has a bucket with a max capacity.
  - Tokens refill at a constant rate over the configured window.
  - Each request consumes one token. If the bucket is empty → HTTP 429.

Why Lua?
  - Lua scripts in Redis execute atomically, eliminating TOCTOU race conditions
    that would occur with a GET + SET approach.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import get_settings

settings = get_settings()

# ── Singleton Redis client ────────────────────────────────────────────────────
_redis_client: Optional[aioredis.Redis] = None


async def get_redis_client() -> aioredis.Redis:
    """Return (or create) the singleton async Redis client."""
    global _redis_client
    if _redis_client is None:
        kwargs = {
            "decode_responses": False,  # We handle decoding manually
            "socket_timeout": 5.0,
            "socket_connect_timeout": 5.0,
            "retry_on_timeout": True,
            "health_check_interval": 30,
        }
        if settings.REDIS_PASSWORD:
            kwargs["password"] = settings.REDIS_PASSWORD

        _redis_client = aioredis.from_url(settings.REDIS_URL, **kwargs)
    return _redis_client


async def close_redis_client() -> None:
    """Gracefully close the Redis connection pool."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


# ── Token Bucket Lua Script ───────────────────────────────────────────────────
# KEYS[1] = bucket key (e.g., "ratelimit:ip:192.168.1.1")
# ARGV[1] = max_tokens (bucket capacity)
# ARGV[2] = refill_rate (tokens per second)
# ARGV[3] = current timestamp (float seconds)
# ARGV[4] = cost (tokens consumed per request, usually 1)
#
# Returns: [allowed (0/1), remaining_tokens, retry_after_seconds]
_TOKEN_BUCKET_LUA = """
local key          = KEYS[1]
local max_tokens   = tonumber(ARGV[1])
local refill_rate  = tonumber(ARGV[2])
local now          = tonumber(ARGV[3])
local cost         = tonumber(ARGV[4])

-- Load existing bucket state
local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens      = tonumber(data[1]) or max_tokens
local last_refill = tonumber(data[2]) or now

-- Calculate tokens to add since last request
local elapsed = math.max(0, now - last_refill)
local new_tokens = math.min(max_tokens, tokens + elapsed * refill_rate)

-- Try to consume tokens
if new_tokens >= cost then
    new_tokens = new_tokens - cost
    redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
    -- TTL = 2x the refill window to auto-clean idle buckets
    redis.call('EXPIRE', key, math.ceil(max_tokens / refill_rate) * 2)
    return {1, math.floor(new_tokens), 0}
else
    -- Calculate seconds until enough tokens are available
    local retry_after = math.ceil((cost - new_tokens) / refill_rate)
    redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(max_tokens / refill_rate) * 2)
    return {0, 0, retry_after}
end
"""


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    remaining: int
    retry_after: int  # Seconds until the client can retry (0 if allowed)


class TokenBucketRateLimiter:
    """
    Token Bucket rate limiter backed by Redis.

    Each unique key (IP address or API key) gets its own bucket.
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        max_tokens: int = settings.RATE_LIMIT_REQUESTS,
        window_seconds: int = settings.RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self._redis = redis
        self._max_tokens = max_tokens
        # Refill rate: tokens per second
        self._refill_rate = max_tokens / window_seconds
        # Register the Lua script for efficient re-use
        self._script = self._redis.register_script(_TOKEN_BUCKET_LUA)

    async def check(self, identifier: str, cost: int = 1) -> RateLimitResult:
        """
        Perform a rate limit check for the given identifier.

        Args:
            identifier: Unique client identifier (IP, API key hash, etc.)
            cost:       Number of tokens this request consumes.

        Returns:
            RateLimitResult indicating whether the request is allowed.
        """
        key = f"shieldflow:ratelimit:{identifier}"
        now = time.time()

        result = await self._script(
            keys=[key],
            args=[self._max_tokens, self._refill_rate, now, cost],
        )

        allowed, remaining, retry_after = result
        return RateLimitResult(
            allowed=bool(allowed),
            remaining=int(remaining),
            retry_after=int(retry_after),
        )

    async def reset(self, identifier: str) -> None:
        """Reset a client's bucket (useful for testing)."""
        key = f"shieldflow:ratelimit:{identifier}"
        await self._redis.delete(key)

    async def get_remaining(self, identifier: str) -> int:
        """Get remaining tokens without consuming any."""
        key = f"shieldflow:ratelimit:{identifier}"
        data = await self._redis.hget(key, "tokens")
        return int(float(data)) if data else self._max_tokens
