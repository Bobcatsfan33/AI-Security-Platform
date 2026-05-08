"""SAML 2.0 adapter — production implementation via ``python3-saml``.

OneLogin's library handles the parts most likely to produce CVEs in
hand-rolled code:
- AuthnRequest construction with proper IDs and timestamps
- SAMLResponse XMLDSig signature verification
- Assertion conditions (NotBefore / NotOnOrAfter / Audience) enforcement
- Replay protection via ID tracking
- Encrypted-assertion decryption (when configured)

Origin: ported from TokenDNA ``modules/auth/saml.py``. TokenDNA's module
was function-based with single-org env-var config; this adapter is class-
based with per-org config drawn from ``idp_configs.saml_config`` JSONB so
multiple SAML IdPs can coexist in one deployment.

Config schema (matches the platform's IDP admin DTOs in
``app/api/v1/idp_admin.py``):

    {
        "entity_id":        "https://idp.example.com/entity",   # IdP entity ID
        "sso_url":          "https://idp.example.com/sso",      # IdP SingleSignOnService
        "slo_url":          "https://idp.example.com/slo",      # optional logout
        "certificate":      "<X.509 PEM>",                      # IdP signing cert
        "name_id_format":   "email",                            # email|persistent|transient
        "attribute_mappings": {                                  # SAML attr → canonical
            "subject":  "NameID",                                # special: the NameID
            "email":    "http://schemas.xmlsoap.org/.../emailaddress",
            "name":     "http://schemas.xmlsoap.org/.../name",
            "groups":   "groups",
        },
        # Optional SP overrides; defaults are derived from the request URL
        "sp_entity_id":     "https://platform.example.com/saml/sp",
        "sp_acs_url":       "https://platform.example.com/v1/auth/saml/acme/acs",
    }

The SAML adapter integrates with the existing :class:`IdpAdapter` Protocol
in :mod:`app.identity.adapter`. ``begin_login`` returns the IdP redirect
URL; ``complete_login`` accepts the POST body from the ACS callback.
"""

from __future__ import annotations

import base64
import logging
from typing import Any
from urllib.parse import urlparse

from app.identity.adapter import IdentityAuthError
from app.identity.types import IdentityClaims

logger = logging.getLogger("platform.saml")


# Map our short name_id_format codes to SAML 2.0 URN values.
_NAME_ID_FORMATS = {
    "email": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "persistent": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "transient": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "unspecified": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
}


class SamlAdapter:
    """Per-org SAML adapter. Construct from an :class:`IdpConfig.saml_config` dict.

    The constructor only validates structure — actual library imports are
    deferred to :meth:`begin_login` / :meth:`complete_login` so importing
    the adapter module never fails when ``python3-saml`` is missing.
    """

    provider_type = "saml"

    def __init__(self, saml_config: dict[str, Any]) -> None:
        self._cfg = dict(saml_config or {})

        for required in ("entity_id", "sso_url", "certificate"):
            if not self._cfg.get(required):
                raise ValueError(
                    f"Invalid SAML config: missing {required!r} "
                    f"(present keys: {sorted(self._cfg.keys())})"
                )

        self.idp_entity_id: str = self._cfg["entity_id"]
        self.idp_sso_url: str = self._cfg["sso_url"]
        self.idp_slo_url: str | None = self._cfg.get("slo_url") or None
        self.idp_certificate: str = self._cfg["certificate"]
        self.attribute_mappings: dict[str, str] = dict(
            self._cfg.get("attribute_mappings") or {}
        )

        name_id_short = self._cfg.get("name_id_format", "email")
        self.name_id_format = _NAME_ID_FORMATS.get(
            name_id_short, _NAME_ID_FORMATS["email"]
        )

        # SP entity_id and ACS URL can be overridden in config; otherwise
        # they're synthesized at runtime from the request URL we receive.
        self.sp_entity_id_override: str | None = self._cfg.get("sp_entity_id")
        self.sp_acs_url_override: str | None = self._cfg.get("sp_acs_url")

    # ─────────────────────────────────────────── public API

    async def begin_login(self, *, redirect_uri: str, state: str) -> str:
        """Build a SAML AuthnRequest and return the IdP redirect URL.

        The ``redirect_uri`` argument is treated as the platform's ACS URL —
        SAML will POST to this URL on completion. The ``state`` is passed as
        RelayState so the ACS handler can correlate it with cached state.
        """
        auth = self._build_auth(
            request_data=_synthetic_request_data(redirect_uri),
            sp_acs_url=redirect_uri,
        )
        # OneLogin returns the full IdP URL with SAMLRequest + RelayState
        return auth.login(return_to=state, set_nameid_policy=True)

    async def complete_login(
        self, *, callback_params: dict[str, str], expected_state: str | None
    ) -> IdentityClaims:
        """Validate the SAMLResponse and return canonical IdentityClaims.

        ``callback_params`` is a dict of POST form fields from the ACS
        endpoint, plus ``_redirect_uri`` and ``_host`` injected by the route
        handler so we can reconstruct the request_data for python3-saml.
        """
        saml_response = callback_params.get("SAMLResponse")
        if not saml_response:
            raise IdentityAuthError("saml_missing_response")

        relay_state = callback_params.get("RelayState")
        if expected_state is not None and relay_state != expected_state:
            raise IdentityAuthError("saml_relay_state_mismatch")

        sp_acs_url = callback_params.get("_redirect_uri")
        if not sp_acs_url:
            raise IdentityAuthError("saml_missing_redirect_uri_in_callback_params")

        # Build OneLogin's request_data from the actual HTTP context.
        # The library uses these fields to validate Destination/Recipient.
        host = callback_params.get("_host") or _extract_host(sp_acs_url)
        request_data = {
            "https": "on",  # we always assume TLS in front of the platform
            "http_host": host,
            "server_port": "443",
            "script_name": _extract_path(sp_acs_url),
            "get_data": {},
            "post_data": {
                "SAMLResponse": saml_response,
                "RelayState": relay_state or "",
            },
        }

        auth = self._build_auth(request_data=request_data, sp_acs_url=sp_acs_url)
        try:
            auth.process_response()
        except Exception as exc:  # noqa: BLE001 — onelogin wraps various errors
            raise IdentityAuthError(f"saml_process_response_failed: {exc}") from exc

        if not auth.is_authenticated():
            errors = auth.get_errors()
            reason = auth.get_last_error_reason() or "unauthenticated"
            raise IdentityAuthError(
                f"saml_assertion_invalid: {reason} (errors: {errors})"
            )

        return self._claims_from_auth(auth)

    # ─────────────────────────────────────────── internals

    def _build_auth(
        self, *, request_data: dict[str, Any], sp_acs_url: str
    ) -> Any:
        """Construct a OneLogin_Saml2_Auth instance from the per-call context."""
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover — listed as a hard dep
            raise IdentityAuthError(
                "python3-saml is not installed; cannot use SAML adapter"
            ) from exc

        sp_entity_id = self.sp_entity_id_override or sp_acs_url
        settings_dict: dict[str, Any] = {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": sp_entity_id,
                "assertionConsumerService": {
                    "url": self.sp_acs_url_override or sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "NameIDFormat": self.name_id_format,
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": self.idp_certificate,
            },
            "security": {
                # We require IdP-side signed assertions. We don't sign our
                # own AuthnRequests by default — most enterprise IdPs don't
                # require it, and signed AuthnRequest needs an SP signing
                # key which adds a key-management surface. Customers who
                # need it can flip these flags via a follow-on change.
                "wantAssertionsSigned": True,
                "wantMessagesSigned": False,
                "authnRequestsSigned": False,
                "wantNameIdEncrypted": False,
                "wantAssertionsEncrypted": False,
            },
        }
        if self.idp_slo_url:
            settings_dict["idp"]["singleLogoutService"] = {
                "url": self.idp_slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }

        return OneLogin_Saml2_Auth(request_data, old_settings=settings_dict)

    def _claims_from_auth(self, auth: Any) -> IdentityClaims:
        """Extract canonical IdentityClaims from a successfully-authenticated
        OneLogin_Saml2_Auth instance."""
        attributes: dict[str, list[str]] = auth.get_attributes() or {}
        name_id = auth.get_nameid() or ""

        m = self.attribute_mappings

        # Subject: usually the NameID, but a customer may map a custom attribute
        subject_key = m.get("subject", "NameID")
        if subject_key == "NameID":
            subject_id = name_id
        else:
            subject_id = _first(attributes.get(subject_key, []))

        email = _first(attributes.get(m.get("email", "email"), [])) or _first(
            attributes.get(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                [],
            )
        )
        # Fall back to NameID when the IdP uses email-format NameID and no
        # explicit email attribute is sent.
        if not email and "@" in name_id:
            email = name_id

        name = (
            _first(attributes.get(m.get("name", "name"), []))
            or _first(
                attributes.get(
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                    [],
                )
            )
            or email
        )

        groups_raw = attributes.get(m.get("groups", "groups"), [])
        groups = tuple(str(g) for g in groups_raw)

        if not subject_id:
            raise IdentityAuthError("saml_missing_subject")
        if not email:
            raise IdentityAuthError("saml_missing_email")

        return IdentityClaims(
            subject_id=subject_id,
            email=email,
            name=name,
            groups=groups,
            raw_claims={
                "name_id": name_id,
                "name_id_format": auth.get_nameid_format(),
                "session_index": auth.get_session_index(),
                "attributes": attributes,
            },
        )


# ─────────────────────────────────────────── helpers


def _first(values: list[Any]) -> str:
    return str(values[0]) if values else ""


def _extract_host(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc


def _extract_path(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def _synthetic_request_data(acs_url: str) -> dict[str, Any]:
    """Construct minimal request_data for begin_login when no real HTTP
    context is available (we're synthesizing the IdP redirect, not
    consuming an inbound request).
    """
    return {
        "https": "on",
        "http_host": _extract_host(acs_url),
        "server_port": "443",
        "script_name": _extract_path(acs_url),
        "get_data": {},
        "post_data": {},
    }


# ─────────────────────────────────────────── SP metadata


def generate_sp_metadata(*, sp_entity_id: str, sp_acs_url: str) -> str:
    """Return SP metadata XML for upload to the customer's IdP.

    Stand-alone helper so the metadata route doesn't need a configured IdP —
    it just needs to know what SP entity ID + ACS URL we expose for that
    org's SAML route.
    """
    return (
        '<?xml version="1.0"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"\n'
        f'                     entityID="{sp_entity_id}">\n'
        '  <md:SPSSODescriptor AuthnRequestsSigned="false"\n'
        '                      WantAssertionsSigned="true"\n'
        '                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        f'    <md:NameIDFormat>{_NAME_ID_FORMATS["email"]}</md:NameIDFormat>\n'
        '    <md:AssertionConsumerService\n'
        '        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"\n'
        f'        Location="{sp_acs_url}"\n'
        '        index="0"\n'
        '        isDefault="true"/>\n'
        "  </md:SPSSODescriptor>\n"
        "</md:EntityDescriptor>\n"
    )
