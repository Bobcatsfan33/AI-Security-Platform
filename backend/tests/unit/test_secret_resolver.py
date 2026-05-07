"""Tests for the secret reference resolver."""

from __future__ import annotations

import pytest

from app.identity.secret_resolver import EnvVarResolver


@pytest.mark.unit
class TestEnvVarResolver:
    def test_resolves_existing_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OIDC_SECRET_OKTA", "topsecret")
        assert EnvVarResolver().resolve("env:OIDC_SECRET_OKTA") == "topsecret"

    def test_missing_env_var_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OIDC_SECRET_MISSING", raising=False)
        with pytest.raises(KeyError, match="OIDC_SECRET_MISSING"):
            EnvVarResolver().resolve("env:OIDC_SECRET_MISSING")

    def test_unsupported_prefix_raises(self) -> None:
        with pytest.raises(ValueError, match="env:"):
            EnvVarResolver().resolve("vault:secret/path")
