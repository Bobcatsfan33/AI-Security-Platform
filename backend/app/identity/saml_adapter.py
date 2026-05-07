"""SAML 2.0 adapter — DEFERRED to follow-on session.

Per Sprint 1 scope, SAML is included in the schema and the adapter interface
but the actual implementation is deferred. When implemented, this adapter
will wrap `python3-saml` (OneLogin's audited library) for assertion parsing,
XMLDSig validation, and attribute mapping.

The blueprint's saml_config schema:
    {entity_id, sso_url, slo_url, certificate, name_id_format, attribute_mappings}

To enable: `pip install "python3-saml>=1.16"` and replace the NotImplementedError
in begin_login / complete_login with the real OneLogin flow. See:
    https://github.com/SAML-Toolkits/python3-saml
"""

from __future__ import annotations

from typing import Any

from app.identity.adapter import IdentityAuthError
from app.identity.types import IdentityClaims


class SamlAdapter:
    provider_type = "saml"

    def __init__(self, saml_config: dict[str, Any]) -> None:
        self.saml_config = saml_config

    async def begin_login(self, *, redirect_uri: str, state: str) -> str:
        raise IdentityAuthError(
            "saml_adapter_not_implemented: deferred to Sprint 1 follow-on. "
            "Install python3-saml and implement using OneLogin auth_request flow."
        )

    async def complete_login(
        self, *, callback_params: dict[str, str], expected_state: str | None
    ) -> IdentityClaims:
        raise IdentityAuthError(
            "saml_adapter_not_implemented: deferred to Sprint 1 follow-on."
        )
