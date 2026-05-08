"""Secret reference resolver — multi-backend.

NIST 800-53 Rev5: IA-5, SC-12, SC-28.

Design
------
Secrets are stored in the database as **references**, never plaintext. A
reference has a backend prefix:

    env:VAR_NAME        — process environment (dev/CI/non-secret-rotation paths)
    awssm:secret_name   — AWS Secrets Manager (production default)
    vault:secret/path   — HashiCorp Vault KV v2

Each reference resolves through its declared backend. Different secrets can
live in different backends within one deployment — useful when migrating
from env-vars to a managed secret store one secret at a time.

The SecretResolver Protocol exists so callers depend on the interface, not
the concrete backend. Tests inject a fake resolver via :func:`set_resolver`.

In production (ENVIRONMENT=production), every reference MUST resolve through
the secret_gate (see ``secret_gate.py``) which enforces minimum entropy and
rejects published dev-default values.

Origin: ported from TokenDNA ``modules/security/secrets.py`` and adapted to
the platform's per-reference backend dispatch.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Final, Protocol

import structlog

logger = structlog.get_logger("platform.secrets")


class SecretResolutionError(RuntimeError):
    """Raised when a reference cannot be resolved by the chosen backend."""


class SecretResolver(Protocol):
    """Interface every backend implements."""

    prefix: str

    def resolve(self, reference: str) -> str: ...


# --------------------------------------------------------- backends


class EnvVarResolver:
    """Resolve ``env:VAR_NAME`` against process env vars.

    Suitable for: dev, CI, internal services where rotation cadence is low
    and the orchestrator (Kubernetes, ECS) injects secrets as env vars from
    a managed source.
    """

    prefix: Final[str] = "env:"

    def resolve(self, reference: str) -> str:
        if not reference.startswith(self.prefix):
            raise SecretResolutionError(
                f"EnvVarResolver only handles {self.prefix!r} refs; got {reference!r}"
            )
        var_name = reference[len(self.prefix) :]
        try:
            return os.environ[var_name]
        except KeyError as exc:
            raise SecretResolutionError(
                f"Secret env var {var_name!r} is not set"
            ) from exc


class AwsSecretsManagerResolver:
    """Resolve ``awssm:name`` against AWS Secrets Manager.

    Uses FIPS endpoints when ``FIPS_MODE=true`` (FIPS 140-2 validated).
    Lazy-imports boto3 so it isn't a hard dependency.
    """

    prefix: Final[str] = "awssm:"

    def __init__(self, region: str | None = None, *, use_fips: bool = False) -> None:
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.use_fips = use_fips or os.getenv("FIPS_MODE", "false").lower() == "true"

    def resolve(self, reference: str) -> str:
        if not reference.startswith(self.prefix):
            raise SecretResolutionError(
                f"AwsSecretsManagerResolver only handles {self.prefix!r} refs"
            )
        name = reference[len(self.prefix) :]

        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            raise SecretResolutionError(
                "boto3 is required for awssm: references. Install boto3."
            ) from exc

        kwargs: dict[str, str] = {"region_name": self.region}
        if self.use_fips:
            kwargs["endpoint_url"] = (
                f"https://secretsmanager-fips.{self.region}.amazonaws.com"
            )

        try:
            client = boto3.client("secretsmanager", **kwargs)
            response = client.get_secret_value(SecretId=name)
        except Exception as exc:  # noqa: BLE001
            raise SecretResolutionError(
                f"AWS Secrets Manager fetch failed for {name!r}: {exc}"
            ) from exc

        secret = response.get("SecretString") or response.get(
            "SecretBinary", b""
        ).decode()
        if not secret:
            raise SecretResolutionError(f"AWS SM returned empty secret for {name!r}")
        return secret


class VaultResolver:
    """Resolve ``vault:path`` against HashiCorp Vault KV v2.

    Expects ``VAULT_ADDR`` and ``VAULT_TOKEN`` (or AppRole/Kubernetes auth
    handled at the deployment layer). The reference path is appended to
    ``VAULT_KV_MOUNT`` (default: ``secret``).
    """

    prefix: Final[str] = "vault:"

    def __init__(
        self,
        addr: str | None = None,
        token: str | None = None,
        mount: str | None = None,
    ) -> None:
        self.addr = addr or os.getenv("VAULT_ADDR", "http://localhost:8200")
        self.token = token or os.getenv("VAULT_TOKEN", "")
        self.mount = mount or os.getenv("VAULT_KV_MOUNT", "secret")

    def resolve(self, reference: str) -> str:
        if not reference.startswith(self.prefix):
            raise SecretResolutionError(
                f"VaultResolver only handles {self.prefix!r} refs"
            )
        path = reference[len(self.prefix) :]

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover — httpx is a hard dep
            raise SecretResolutionError("httpx required for vault: references") from exc

        url = f"{self.addr.rstrip('/')}/v1/{self.mount}/data/{path.lstrip('/')}"
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(url, headers={"X-Vault-Token": self.token})
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise SecretResolutionError(
                f"Vault fetch failed for {path!r}: {exc}"
            ) from exc

        # KV v2: data.data.value
        try:
            return payload["data"]["data"]["value"]
        except (KeyError, TypeError) as exc:
            raise SecretResolutionError(
                f"Vault payload missing data.data.value for {path!r}"
            ) from exc


# --------------------------------------------------------- composite + factory


class CompositeResolver:
    """Dispatch each reference to the backend whose prefix matches."""

    def __init__(self, *resolvers: SecretResolver) -> None:
        self._resolvers = resolvers

    def resolve(self, reference: str) -> str:
        for resolver in self._resolvers:
            if reference.startswith(resolver.prefix):
                return resolver.resolve(reference)
        raise SecretResolutionError(
            f"No backend registered for reference {reference!r}. "
            f"Known prefixes: {[r.prefix for r in self._resolvers]}"
        )


def _build_default_resolver() -> SecretResolver:
    """Construct a CompositeResolver with all known backends.

    All backends are registered unconditionally — the resolver only invokes
    the matching one. Boto3/Vault deps are imported lazily and only on use.
    """
    return CompositeResolver(
        EnvVarResolver(),
        AwsSecretsManagerResolver(),
        VaultResolver(),
    )


_resolver: SecretResolver = _build_default_resolver()


def get_resolver() -> SecretResolver:
    return _resolver


def set_resolver(resolver: SecretResolver) -> None:
    """Override the resolver. Used by tests and by callers wiring a custom
    secret backend (e.g. GCP Secret Manager) into the platform."""
    global _resolver
    _resolver = resolver


# --------------------------------------------------------- convenience


@lru_cache(maxsize=256)
def get_secret(reference: str) -> str:
    """Resolve and cache a reference. Cache is per-process; clear with
    :func:`invalidate_cache` after rotation."""
    return get_resolver().resolve(reference)


def invalidate_cache() -> None:
    """Drop all cached resolutions. Call after a rotation event."""
    get_secret.cache_clear()
    logger.info("secrets_cache_invalidated")
