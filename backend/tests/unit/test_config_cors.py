"""Production CORS guardrails."""

import pytest

from app.core.config import Settings


def _settings(**overrides):
    base = {
        "jwt_secret": "x" * 40,
        "environment": "production",
        "deployment_region": "us-east-1",
        "runtime_events_topic": "runtime.events.us-east-1",
    }
    base.update(overrides)
    return Settings(**base)


@pytest.mark.unit
def test_production_rejects_wildcard_cors() -> None:
    with pytest.raises(ValueError, match="wildcard CORS"):
        _settings(cors_origins="https://app.example.com,*")


@pytest.mark.unit
def test_production_rejects_empty_cors() -> None:
    with pytest.raises(ValueError, match="explicitly configured"):
        _settings(cors_origins="")


@pytest.mark.unit
def test_production_accepts_explicit_cors_origins() -> None:
    settings = _settings(cors_origins="https://app.example.com, https://admin.example.com")

    assert settings.cors_origins_list == [
        "https://app.example.com",
        "https://admin.example.com",
    ]


@pytest.mark.unit
def test_development_keeps_localhost_default() -> None:
    settings = Settings(jwt_secret="x" * 40, environment="development")

    assert settings.cors_origins_list == ["http://localhost:3000"]


@pytest.mark.unit
def test_production_requires_explicit_deployment_region() -> None:
    with pytest.raises(ValueError, match="explicit deployment region"):
        _settings(deployment_region="local", runtime_events_topic="runtime.events.local")


@pytest.mark.unit
def test_production_requires_region_scoped_runtime_topic() -> None:
    with pytest.raises(ValueError, match="suffixed with the deployment region"):
        _settings(runtime_events_topic="runtime.events.eu-west-1")
