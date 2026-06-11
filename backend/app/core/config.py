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
    # When jwt_private_key (PEM) is set, access tokens are RS256-signed and
    # verified via the public key (published at /v1/auth/.well-known/jwks.json),
    # so verifiers never need the symmetric secret. Otherwise HS256 with
    # jwt_secret (dev/test fallback). jwt_secret stays required: it still backs
    # refresh-token bookkeeping and the HS256 fallback.
    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: Literal["HS256", "HS384", "HS512", "RS256"] = "HS256"
    jwt_private_key: str | None = None  # PEM RS256 private key; enables asymmetric signing
    jwt_key_id: str = "default"  # kid stamped on RS256 tokens + published in JWKS
    # kid -> PEM public key for keys rotated OUT but whose tokens may still be
    # in flight. Verification accepts the active key + all of these.
    jwt_additional_public_keys: dict[str, str] = Field(default_factory=dict)
    jwt_access_ttl_seconds: int = 900  # 15 minutes
    jwt_refresh_ttl_seconds: int = 604800  # 7 days

    # Stage-3 LLM judge (optional second opinion on uncertain content).
    # Enabled when judge_api_key_ref resolves (key present) — otherwise the
    # judge reports "disabled" and computes nothing (Phase 0.5 honesty). Backs
    # POST /v1/aiguard/judge, which the runtime agent's Stage 3
    # (STAGE3_JUDGE_ENDPOINT) can target. Use a small, cheap model.
    judge_api_key_ref: str = "env:ANTHROPIC_API_KEY"
    judge_model: str = "claude-haiku-4-5"
    judge_max_tokens: int = 256

    # Stage-2 ONNX model (optional real ML classifier). Provisioned at startup
    # from a checksum-pinned release artifact (Phase 1A); unset → the heuristic
    # Stage 2 runs instead (honest fallback). Backs POST /v1/aiguard/classify,
    # which the runtime agent's STAGE2_ONNX_ENDPOINT can target.
    stage2_onnx_model_url: str = ""  # file:// or http(s):// to the .onnx
    stage2_onnx_model_sha256: str = ""
    stage2_onnx_tokenizer_url: str = ""  # file:// or http(s):// to tokenizer.json
    stage2_onnx_tokenizer_sha256: str = ""
    model_cache_dir: str = "/var/cache/aisp/models"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
