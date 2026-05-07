"""Test claim-mapping logic on the OIDC adapter.

Network-touching parts (discovery, JWKS, token exchange) belong in integration
tests with a real or mocked IDP. Here we test the pure mapping function that
converts raw IDP claims into our canonical IdentityClaims.
"""

from __future__ import annotations

import pytest

from app.identity.adapter import IdentityAuthError
from app.identity.oidc_adapter import OidcAdapter


def _adapter(claim_mappings: dict[str, str] | None = None) -> OidcAdapter:
    return OidcAdapter(
        {
            "issuer_url": "https://issuer.example.com",
            "client_id": "abc",
            "client_secret_ref": "env:UNUSED",
            "scopes": ["openid", "profile", "email"],
            "audience": "abc",
            "claim_mappings": claim_mappings or {},
        }
    )


@pytest.mark.unit
class TestOidcClaimsMapping:
    def test_default_claim_names(self) -> None:
        adapter = _adapter()
        identity = adapter._claims_to_identity(
            {
                "sub": "okta|user-1",
                "email": "alice@example.com",
                "name": "Alice",
                "groups": ["Engineering", "Security"],
            }
        )
        assert identity.subject_id == "okta|user-1"
        assert identity.email == "alice@example.com"
        assert identity.name == "Alice"
        assert identity.groups == ("Engineering", "Security")

    def test_custom_claim_mapping(self) -> None:
        adapter = _adapter(
            {
                "subject": "uid",
                "email": "preferred_username",
                "name": "displayName",
                "groups": "memberOf",
            }
        )
        identity = adapter._claims_to_identity(
            {
                "uid": "azure-12345",
                "preferred_username": "bob@example.com",
                "displayName": "Bob",
                "memberOf": ["Admins"],
            }
        )
        assert identity.subject_id == "azure-12345"
        assert identity.email == "bob@example.com"
        assert identity.name == "Bob"
        assert identity.groups == ("Admins",)

    def test_groups_can_be_string_or_list(self) -> None:
        adapter = _adapter()
        single = adapter._claims_to_identity(
            {"sub": "u", "email": "e@x.com", "groups": "Engineering"}
        )
        assert single.groups == ("Engineering",)

        listed = adapter._claims_to_identity(
            {"sub": "u", "email": "e@x.com", "groups": ["A", "B"]}
        )
        assert listed.groups == ("A", "B")

    def test_name_falls_back_to_email_when_missing(self) -> None:
        adapter = _adapter()
        identity = adapter._claims_to_identity(
            {"sub": "u", "email": "no-name@example.com"}
        )
        assert identity.name == "no-name@example.com"

    def test_missing_subject_raises(self) -> None:
        adapter = _adapter()
        with pytest.raises(IdentityAuthError, match="oidc_missing_subject_claim"):
            adapter._claims_to_identity({"email": "a@b.com"})

    def test_missing_email_raises(self) -> None:
        adapter = _adapter()
        with pytest.raises(IdentityAuthError, match="oidc_missing_email_claim"):
            adapter._claims_to_identity({"sub": "u"})

    def test_invalid_config_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing"):
            OidcAdapter({"issuer_url": "https://x"})  # missing client_id, etc.
