"""Resolve secret references to plaintext values at the moment of use.

Secrets are stored as REFERENCES in the database (e.g. `env:OIDC_SECRET_OKTA`)
not as plaintext. The resolver looks up the reference and returns the actual
value. This keeps DB dumps and Alembic snapshots from leaking credentials.

Sprint 1 ships a single backend: env-var resolution. Production deployments
should plug in AWS Secrets Manager, Vault, GCP Secret Manager, etc. by
implementing the SecretResolver protocol.
"""

from __future__ import annotations

import os
from typing import Protocol


class SecretResolver(Protocol):
    def resolve(self, reference: str) -> str: ...


class EnvVarResolver:
    """Resolve `env:VAR_NAME` references against process env vars."""

    PREFIX = "env:"

    def resolve(self, reference: str) -> str:
        if not reference.startswith(self.PREFIX):
            raise ValueError(
                f"EnvVarResolver only supports references prefixed with {self.PREFIX!r}; "
                f"got {reference!r}"
            )
        var_name = reference[len(self.PREFIX) :]
        try:
            return os.environ[var_name]
        except KeyError as exc:
            raise KeyError(f"Secret env var {var_name!r} not set") from exc


_resolver: SecretResolver = EnvVarResolver()


def get_resolver() -> SecretResolver:
    return _resolver


def set_resolver(resolver: SecretResolver) -> None:
    """Override the resolver (e.g. for tests or production secret managers)."""
    global _resolver
    _resolver = resolver
