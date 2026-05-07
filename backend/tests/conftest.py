"""Pytest configuration — minimal fixtures for unit tests that don't need
live infrastructure. Integration tests use additional fixtures defined below.
"""

from __future__ import annotations

import os

# Set required env vars BEFORE any app imports load Settings.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-must-be-at-least-32-chars-long-for-pydantic-validation",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://platform:platform@localhost:5432/platform_test"
)
