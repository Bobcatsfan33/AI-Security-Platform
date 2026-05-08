"""SAML adapter tests.

Real SAML round-trips require XML signing with real keypairs and a live
IdP — those belong in the integration suite with a docker-composed
SimpleSAMLphp. Here we test the parts we can isolate:

- Construction validation (rejects missing required fields)
- Claim extraction from a mocked OneLogin_Saml2_Auth instance
- SP metadata generation
- name_id_format mapping
- begin_login state propagation (via mock)
"""

from __future__ import annotations

from typing import Any

import pytest

from app.identity.adapter import IdentityAuthError
from app.identity.saml_adapter import (
    SamlAdapter,
    _NAME_ID_FORMATS,
    generate_sp_metadata,
)


# Minimal valid config — used as the base for adapter construction tests
_BASE_CFG: dict[str, Any] = {
    "entity_id": "https://idp.example.com/entity",
    "sso_url": "https://idp.example.com/sso",
    "certificate": "-----BEGIN CERTIFICATE-----\nDUMMY\n-----END CERTIFICATE-----",
}


def _cfg(**overrides: Any) -> dict[str, Any]:
    return {**_BASE_CFG, **overrides}


# ─────────────────────────────────────────── Construction


@pytest.mark.unit
class TestConstruction:
    def test_minimal_config_succeeds(self) -> None:
        adapter = SamlAdapter(_cfg())
        assert adapter.idp_entity_id == "https://idp.example.com/entity"
        assert adapter.idp_sso_url == "https://idp.example.com/sso"
        assert adapter.name_id_format == _NAME_ID_FORMATS["email"]

    def test_missing_entity_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="entity_id"):
            SamlAdapter({"sso_url": "x", "certificate": "y"})

    def test_missing_sso_url_rejected(self) -> None:
        with pytest.raises(ValueError, match="sso_url"):
            SamlAdapter({"entity_id": "x", "certificate": "y"})

    def test_missing_certificate_rejected(self) -> None:
        with pytest.raises(ValueError, match="certificate"):
            SamlAdapter({"entity_id": "x", "sso_url": "y"})

    def test_name_id_format_mapping(self) -> None:
        for short, urn in _NAME_ID_FORMATS.items():
            adapter = SamlAdapter(_cfg(name_id_format=short))
            assert adapter.name_id_format == urn

    def test_unknown_name_id_format_falls_back_to_email(self) -> None:
        adapter = SamlAdapter(_cfg(name_id_format="bogus"))
        assert adapter.name_id_format == _NAME_ID_FORMATS["email"]

    def test_empty_config_rejected(self) -> None:
        with pytest.raises(ValueError):
            SamlAdapter({})

    def test_attribute_mappings_preserved(self) -> None:
        adapter = SamlAdapter(
            _cfg(
                attribute_mappings={
                    "email": "urn:custom:email",
                    "groups": "urn:custom:groups",
                }
            )
        )
        assert adapter.attribute_mappings["email"] == "urn:custom:email"
        assert adapter.attribute_mappings["groups"] == "urn:custom:groups"


# ─────────────────────────────────────────── Claim extraction


class _MockAuth:
    """Stand-in for OneLogin_Saml2_Auth — only the methods we call."""

    def __init__(
        self,
        *,
        name_id: str,
        attributes: dict[str, list[Any]],
        nameid_format: str = _NAME_ID_FORMATS["email"],
        session_index: str | None = "sess-1",
    ) -> None:
        self._name_id = name_id
        self._attributes = attributes
        self._nameid_format = nameid_format
        self._session_index = session_index

    def get_attributes(self) -> dict[str, list[Any]]:
        return self._attributes

    def get_nameid(self) -> str:
        return self._name_id

    def get_nameid_format(self) -> str:
        return self._nameid_format

    def get_session_index(self) -> str | None:
        return self._session_index


@pytest.mark.unit
class TestClaimExtraction:
    def test_default_extraction_uses_name_id_as_subject(self) -> None:
        adapter = SamlAdapter(_cfg())
        auth = _MockAuth(
            name_id="alice@example.com",
            attributes={
                "email": ["alice@example.com"],
                "name": ["Alice"],
                "groups": ["Engineering", "Security"],
            },
        )
        claims = adapter._claims_from_auth(auth)
        assert claims.subject_id == "alice@example.com"
        assert claims.email == "alice@example.com"
        assert claims.name == "Alice"
        assert claims.groups == ("Engineering", "Security")

    def test_custom_attribute_mapping(self) -> None:
        adapter = SamlAdapter(
            _cfg(
                attribute_mappings={
                    "email": "urn:custom:mail",
                    "name": "urn:custom:displayName",
                    "groups": "urn:custom:memberOf",
                }
            )
        )
        auth = _MockAuth(
            name_id="user@example.com",
            attributes={
                "urn:custom:mail": ["bob@example.com"],
                "urn:custom:displayName": ["Bob"],
                "urn:custom:memberOf": ["Admins"],
            },
        )
        claims = adapter._claims_from_auth(auth)
        assert claims.email == "bob@example.com"
        assert claims.name == "Bob"
        assert claims.groups == ("Admins",)

    def test_falls_back_to_microsoft_claim_url_for_email(self) -> None:
        adapter = SamlAdapter(_cfg())
        auth = _MockAuth(
            name_id="opaque-id-not-an-email",
            attributes={
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
                    "cathy@example.com"
                ],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": ["Cathy"],
            },
        )
        claims = adapter._claims_from_auth(auth)
        assert claims.email == "cathy@example.com"
        assert claims.name == "Cathy"

    def test_email_falls_back_to_name_id_when_email_format(self) -> None:
        adapter = SamlAdapter(_cfg())
        auth = _MockAuth(
            name_id="dave@example.com",
            attributes={"name": ["Dave"]},  # no email attribute
        )
        claims = adapter._claims_from_auth(auth)
        assert claims.email == "dave@example.com"

    def test_subject_from_custom_attribute(self) -> None:
        adapter = SamlAdapter(
            _cfg(attribute_mappings={"subject": "uid", "email": "mail"})
        )
        auth = _MockAuth(
            name_id="ignored-name-id",
            attributes={"uid": ["azure-12345"], "mail": ["x@example.com"]},
        )
        claims = adapter._claims_from_auth(auth)
        assert claims.subject_id == "azure-12345"

    def test_missing_subject_raises(self) -> None:
        adapter = SamlAdapter(_cfg())
        auth = _MockAuth(
            name_id="",
            attributes={"email": ["x@y.com"]},
        )
        with pytest.raises(IdentityAuthError, match="saml_missing_subject"):
            adapter._claims_from_auth(auth)

    def test_missing_email_raises(self) -> None:
        adapter = SamlAdapter(_cfg())
        auth = _MockAuth(
            name_id="opaque-subject-no-at-sign",
            attributes={"name": ["NoEmail"]},
        )
        with pytest.raises(IdentityAuthError, match="saml_missing_email"):
            adapter._claims_from_auth(auth)

    def test_groups_normalized_to_strings(self) -> None:
        adapter = SamlAdapter(_cfg())
        auth = _MockAuth(
            name_id="x@y.com",
            attributes={"email": ["x@y.com"], "groups": [1, 2, "three"]},
        )
        claims = adapter._claims_from_auth(auth)
        assert claims.groups == ("1", "2", "three")

    def test_raw_claims_preserved(self) -> None:
        adapter = SamlAdapter(_cfg())
        attrs = {"email": ["x@y.com"], "name": ["X"]}
        auth = _MockAuth(name_id="x@y.com", attributes=attrs, session_index="s-99")
        claims = adapter._claims_from_auth(auth)
        assert claims.raw_claims["session_index"] == "s-99"
        assert claims.raw_claims["attributes"] == attrs


# ─────────────────────────────────────────── SP metadata


@pytest.mark.unit
class TestSpMetadata:
    def test_metadata_contains_entity_id(self) -> None:
        xml = generate_sp_metadata(
            sp_entity_id="https://platform.example.com/sp",
            sp_acs_url="https://platform.example.com/v1/auth/saml/acme/acs",
        )
        assert 'entityID="https://platform.example.com/sp"' in xml

    def test_metadata_contains_acs_url(self) -> None:
        xml = generate_sp_metadata(
            sp_entity_id="https://platform.example.com/sp",
            sp_acs_url="https://platform.example.com/v1/auth/saml/acme/acs",
        )
        assert (
            'Location="https://platform.example.com/v1/auth/saml/acme/acs"' in xml
        )

    def test_metadata_declares_http_post_binding(self) -> None:
        xml = generate_sp_metadata(
            sp_entity_id="https://platform.example.com/sp",
            sp_acs_url="https://platform.example.com/v1/auth/saml/acme/acs",
        )
        assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" in xml

    def test_metadata_requires_signed_assertions(self) -> None:
        xml = generate_sp_metadata(
            sp_entity_id="https://x", sp_acs_url="https://y/acs"
        )
        assert 'WantAssertionsSigned="true"' in xml


# ─────────────────────────────────────────── begin_login + complete_login


@pytest.mark.unit
@pytest.mark.asyncio
class TestBeginLogin:
    async def test_calls_onelogin_login_with_relay_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Patch the OneLogin import inside the adapter to a mock
        from app.identity import saml_adapter as mod

        captured: dict[str, Any] = {}

        class _StubAuth:
            def __init__(self, request_data: Any, old_settings: Any) -> None:
                captured["request_data"] = request_data
                captured["settings"] = old_settings

            def login(self, *, return_to: str, set_nameid_policy: bool) -> str:
                captured["return_to"] = return_to
                return f"https://idp.example.com/sso?SAMLRequest=...&RelayState={return_to}"

        # Replace the import-time symbol that _build_auth uses
        import sys
        import types

        fake_module = types.ModuleType("onelogin.saml2.auth")
        fake_module.OneLogin_Saml2_Auth = _StubAuth  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "onelogin.saml2.auth", fake_module)

        adapter = mod.SamlAdapter(_cfg())
        url = await adapter.begin_login(
            redirect_uri="https://platform.example.com/v1/auth/saml/acme/acs",
            state="state-abc",
        )
        assert "SAMLRequest" in url
        assert "RelayState=state-abc" in url
        assert captured["return_to"] == "state-abc"
        # Verify the settings dict shape
        s = captured["settings"]
        assert s["sp"]["assertionConsumerService"]["url"].endswith("/acs")
        assert s["idp"]["entityId"] == "https://idp.example.com/entity"
        assert s["security"]["wantAssertionsSigned"] is True
