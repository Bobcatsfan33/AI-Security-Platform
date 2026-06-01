"""Application configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process-wide settings.

    Loaded once at startup. Never mutate. Treat as immutable.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    environment: Literal["development", "staging", "production", "test"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    api_v1_prefix: str = "/v1"
    cors_origins: str = "http://localhost:3000"

    # PostgreSQL — operational data (source of truth for "what is configured")
    database_url: str = "postgresql+asyncpg://platform:platform@localhost:5432/platform"

    # ClickHouse — telemetry (source of truth for "what happened")
    # NEVER queried in policy enforcement hot path.
    clickhouse_url: str = "http://localhost:8123"
    clickhouse_database: str = "telemetry"

    # Redis — cache, policy pub/sub, JWT revocation list
    redis_url: str = "redis://localhost:6379/0"

    # Redpanda — telemetry streaming spine (Kafka-compatible)
    redpanda_brokers: str = "localhost:9092"
    # When false, the ingest dual-write skips the broker entirely (ClickHouse
    # only). Lets dev / CI run without Redpanda; production sets it true.
    streaming_enabled: bool = False
    runtime_events_topic: str = "runtime.events"

    # JWT signing
    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: Literal["HS256", "HS384", "HS512", "RS256"] = "HS256"
    jwt_access_ttl_seconds: int = 900       # 15 minutes
    jwt_refresh_ttl_seconds: int = 604800   # 7 days

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
