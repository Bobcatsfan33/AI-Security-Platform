"""Tests for the secret reference resolver — multi-backend dispatch.

Covers EnvVarResolver, the CompositeResolver dispatcher, and the production
secret_gate. AWS and Vault backends are not exercised here (require live
boto3 / Vault); their unit tests live in the integration suite when the
optional deps are installed.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from app.security import secret_gate
from app.security.secrets import (
    AwsSecretsManagerResolver,
    CompositeResolver,
    EnvVarResolver,
    SecretResolutionError,
    VaultResolver,
    get_resolver,
    invalidate_cache,
    set_resolver,
)


# --------------------------------------------------------- EnvVarResolver


@pytest.mark.unit
class TestEnvVarResolver:
    def test_resolves_existing_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OIDC_SECRET_OKTA", "topsecret")
        assert EnvVarResolver().resolve("env:OIDC_SECRET_OKTA") == "topsecret"

    def test_missing_env_var_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OIDC_SECRET_MISSING", raising=False)
        with pytest.raises(SecretResolutionError, match="OIDC_SECRET_MISSING"):
            EnvVarResolver().resolve("env:OIDC_SECRET_MISSING")

    def test_unsupported_prefix_raises(self) -> None:
        with pytest.raises(SecretResolutionError, match="env:"):
            EnvVarResolver().resolve("vault:secret/path")


# --------------------------------------------------------- CompositeResolver


@pytest.mark.unit
class TestCompositeResolver:
    def test_dispatches_to_matching_backend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MY_VAR", "from-env")

        class FakeVault:
            prefix = "vault:"

            def resolve(self, reference: str) -> str:
                return "from-vault"

        composite = CompositeResolver(EnvVarResolver(), FakeVault())
        assert composite.resolve("env:MY_VAR") == "from-env"
        assert composite.resolve("vault:any/path") == "from-vault"

    def test_unknown_prefix_raises(self) -> None:
        composite = CompositeResolver(EnvVarResolver())
        with pytest.raises(SecretResolutionError, match="No backend"):
            composite.resolve("gcp:my-secret")


# --------------------------------------------------------- module-level resolver + cache


@pytest.mark.unit
class TestModuleResolver:
    def test_set_resolver_overrides(self) -> None:
        class StaticResolver:
            prefix = "static:"

            def resolve(self, reference: str) -> str:
                return "STATIC_VALUE"

        original = get_resolver()
        try:
            set_resolver(StaticResolver())
            assert get_resolver().resolve("static:anything") == "STATIC_VALUE"
        finally:
            set_resolver(original)

    def test_invalidate_cache_clears(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.security.secrets import get_secret

        monkeypatch.setenv("MY_KEY", "first")
        # Ensure cache is clean for this test, then prime it
        invalidate_cache()
        assert get_secret("env:MY_KEY") == "first"

        monkeypatch.setenv("MY_KEY", "second")
        # Cached — still returns "first"
        assert get_secret("env:MY_KEY") == "first"

        invalidate_cache()
        assert get_secret("env:MY_KEY") == "second"


# --------------------------------------------------------- AwsSecretsManagerResolver


@pytest.mark.unit
class TestAwsSecretsManagerResolver:
    def test_rejects_non_matching_prefix(self) -> None:
        with pytest.raises(SecretResolutionError):
            AwsSecretsManagerResolver().resolve("env:VAR")

    def test_missing_boto3_raises_clear_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Force ImportError for boto3 by intercepting __import__
        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "boto3":
                raise ImportError("boto3 not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(SecretResolutionError, match="boto3"):
            AwsSecretsManagerResolver().resolve("awssm:my-secret")


# --------------------------------------------------------- VaultResolver


@pytest.mark.unit
class TestVaultResolver:
    def test_rejects_non_matching_prefix(self) -> None:
        with pytest.raises(SecretResolutionError):
            VaultResolver().resolve("env:VAR")


# --------------------------------------------------------- secret_gate


@pytest.mark.unit
class TestSecretGate:
    def test_no_op_outside_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Outside production the gate is a no-op even if a required secret
        # would otherwise fail validation.
        monkeypatch.setattr(secret_gate, "is_production", lambda: False)
        monkeypatch.delenv("JWT_SECRET", raising=False)
        secret_gate.assert_production_secrets()  # must not raise

    def test_rejects_missing_required_secret_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ENVIRONMENT", "production")
        # Settings cache binds to original env — bypass via direct check
        # by patching is_production:
        monkeypatch.setattr(secret_gate, "is_production", lambda: True)
        monkeypatch.delenv("JWT_SECRET", raising=False)
        with pytest.raises(secret_gate.ConfigurationError, match="JWT_SECRET"):
            secret_gate.assert_production_secrets()

    def test_rejects_known_dev_default_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(secret_gate, "is_production", lambda: True)
        monkeypatch.setenv("JWT_SECRET", secret_gate.KNOWN_DEV_DEFAULTS["JWT_SECRET"])
        with pytest.raises(secret_gate.ConfigurationError, match="dev default"):
            secret_gate.assert_production_secrets()

    def test_rejects_short_secret_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(secret_gate, "is_production", lambda: True)
        monkeypatch.setenv("JWT_SECRET", "tooshort")
        with pytest.raises(secret_gate.ConfigurationError, match="shorter than"):
            secret_gate.assert_production_secrets()

    def test_accepts_strong_secret_in_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(secret_gate, "is_production", lambda: True)
        monkeypatch.setenv(
            "JWT_SECRET",
            "x" * secret_gate.MIN_SECRET_BYTES + "-extra-padding-bytes",
        )
        secret_gate.assert_production_secrets()  # should not raise

    def test_report_summarizes_state(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JWT_SECRET", "abcdefghijklmnopqrstuvwxyz0123456789")
        rows = secret_gate.report()
        jwt_row = next(r for r in rows if r.env_var == "JWT_SECRET")
        assert jwt_row.present is True
        assert jwt_row.is_dev_default is False
        assert jwt_row.length_bytes >= secret_gate.MIN_SECRET_BYTES


# --------------------------------------------------------- backwards-compat shim


@pytest.mark.unit
class TestBackwardsCompatShim:
    def test_identity_secret_resolver_module_re_exports(self) -> None:
        from app.identity import secret_resolver as legacy

        assert legacy.EnvVarResolver is EnvVarResolver
        assert callable(legacy.get_resolver)
        assert callable(legacy.set_resolver)
