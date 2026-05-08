"""Production secret gate — refuses startup with weak / default secrets.

Origin: ported from TokenDNA ``modules/security/secret_gate.py``.

Adapted to the platform's :class:`Settings` model: production check uses
``ENVIRONMENT=production`` rather than TokenDNA's ``TOKENDNA_ENV``. The
canonical required-secrets list is the platform's, not TokenDNA's.

Call :func:`assert_production_secrets` once during application startup
(currently in ``app/main.py`` lifespan). It is a no-op outside production.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

import structlog

from app.core.config import get_settings

logger = structlog.get_logger("platform.secret_gate")


class ConfigurationError(RuntimeError):
    """Raised when a required production secret is missing or unsafe."""


MIN_SECRET_BYTES: int = 32

# Env vars that MUST be operator-supplied in production. Add new entries
# as additional security-critical config is added.
REQUIRED_PRODUCTION_SECRETS: tuple[str, ...] = (
    "JWT_SECRET",
)

# Dev fallback values that have been published in this repo. Anything
# matching these in production is rejected — an attacker reading the source
# can forge a JWT.
KNOWN_DEV_DEFAULTS: Mapping[str, str] = {
    "JWT_SECRET": "CHANGE_ME_TO_A_LONG_RANDOM_STRING_AT_LEAST_64_CHARS_FOR_DEV_ONLY",
}


def is_production() -> bool:
    return get_settings().environment == "production"


def assert_production_secrets() -> None:
    """Validate every entry in REQUIRED_PRODUCTION_SECRETS. No-op in non-prod."""
    if not is_production():
        return

    failures: list[str] = []
    for env_var in REQUIRED_PRODUCTION_SECRETS:
        try:
            _enforce_prod_secret(env_var, os.getenv(env_var))
        except ConfigurationError as exc:
            failures.append(str(exc))

    if failures:
        joined = "\n  - ".join(failures)
        raise ConfigurationError(
            "Production secret gate failed. Refusing to start.\n  - " + joined
        )


def _enforce_prod_secret(env_var: str, raw: str | None) -> None:
    if raw is None or raw == "":
        raise ConfigurationError(
            f"{env_var} is not set. Production deployments must supply this."
        )
    if raw == KNOWN_DEV_DEFAULTS.get(env_var):
        raise ConfigurationError(
            f"{env_var} is set to the published dev default. "
            "Generate a fresh 32+ byte random key (e.g. `openssl rand -hex 32`)."
        )
    if len(raw.encode("utf-8")) < MIN_SECRET_BYTES:
        raise ConfigurationError(
            f"{env_var} is shorter than {MIN_SECRET_BYTES} bytes. "
            "Use `openssl rand -hex 32` to generate one."
        )


@dataclass(frozen=True)
class SecretReport:
    env_var: str
    present: bool
    is_dev_default: bool
    length_bytes: int


def report() -> list[SecretReport]:
    """Non-sensitive summary suitable for preflight scripts and admin endpoints."""
    out: list[SecretReport] = []
    for env_var in REQUIRED_PRODUCTION_SECRETS:
        raw = os.getenv(env_var, "")
        out.append(
            SecretReport(
                env_var=env_var,
                present=bool(raw),
                is_dev_default=raw == KNOWN_DEV_DEFAULTS.get(env_var),
                length_bytes=len(raw.encode("utf-8")),
            )
        )
    return out
