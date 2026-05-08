"""Backwards-compatibility shim — secret resolution lives in app.security.secrets.

The OIDC adapter and IDP admin route used to import from this module. Keeping
it as a thin re-export means we can move the implementation without breaking
existing callers.
"""

from __future__ import annotations

from app.security.secrets import (
    EnvVarResolver,
    SecretResolutionError,
    SecretResolver,
    get_resolver,
    set_resolver,
)

__all__ = [
    "EnvVarResolver",
    "SecretResolutionError",
    "SecretResolver",
    "get_resolver",
    "set_resolver",
]
