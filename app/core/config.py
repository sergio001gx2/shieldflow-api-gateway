"""
ShieldFlow — Core Configuration
================================
Centralized settings management using pydantic-settings.
All values are loaded from environment variables / .env file.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings loaded from the environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────
    APP_NAME: str = "ShieldFlow"
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    DEBUG: bool = False

    # ── Security / JWT ───────────────────────────────────────────────
    JWT_SECRET_KEY: str = secrets.token_hex(32)  # Override in production!
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Redis ────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_PASSWORD: str = ""

    # ── Rate Limiting ────────────────────────────────────────────────
    RATE_LIMIT_REQUESTS: int = 100      # Max tokens in the bucket
    RATE_LIMIT_WINDOW_SECONDS: int = 60  # Refill window
    RATE_LIMIT_BURST: int = 20          # Additional burst capacity

    # ── Database ─────────────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/shieldflow"
    )

    # ── WAF ──────────────────────────────────────────────────────────
    WAF_ENABLED: bool = True
    WAF_LOG_BLOCKED: bool = True
    WAF_WHITELIST_IPS: str = "127.0.0.1,::1"

    # ── CORS ─────────────────────────────────────────────────────────
    CORS_ORIGINS: str = "http://localhost:3000"

    # ── Logging ──────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # ── Derived properties ───────────────────────────────────────────
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def waf_whitelist_list(self) -> List[str]:
        """Parse comma-separated whitelisted IPs into a list."""
        return [ip.strip() for ip in self.WAF_WHITELIST_IPS.split(",") if ip.strip()]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return cached application settings.
    Using lru_cache ensures settings are loaded once and reused across the app.
    """
    return Settings()
