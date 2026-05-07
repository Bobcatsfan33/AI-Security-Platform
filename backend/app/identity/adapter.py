"""IDP adapter interface — protocol-based, IDP-agnostic.

Every supported provider implements this protocol. The platform's auth code
calls the adapter; the adapter handles protocol-specific details (SAML
XMLDSig, OIDC JWKS, SCIM 2.0). New IDPs are added by writing a new adapter
without touching core auth logic.

Decision (Sprint 1): the OIDC adapter wraps `authlib`, the SAML adapter
wraps `python3-saml` (deferred — stub only this sprint), the SCIM adapter
is built in Sprint 5.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.identity.types import IdentityClaims


@runtime_checkable
class IdpAdapter(Protocol):
    """Behavior every IDP adapter must implement.

    Implementations are stateless after construction — they hold parsed
    config but no per-request state. The platform constructs one adapter
    per `idp_configs` row at use time.
    """

    provider_type: str

    async def begin_login(self, *, redirect_uri: str, state: str) -> str:
        """Return the URL the user should be redirected to in order to start login."""
        ...

    async def complete_login(
        self, *, callback_params: dict[str, str], expected_state: str | None
    ) -> IdentityClaims:
        """Validate the provider's callback (token exchange / assertion parse)
        and return canonical claims.

        Raises:
            IdentityAuthError on any validation failure.
        """
        ...


class IdentityAuthError(Exception):
    """Raised when an IDP-side login fails (bad token, replay, signature, etc.)."""
