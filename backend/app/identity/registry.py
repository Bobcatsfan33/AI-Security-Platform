"""Adapter factory: build the right adapter for a given idp_configs row."""

from __future__ import annotations

from typing import Any

from app.db.models.idp_config import IdpConfig
from app.identity.adapter import IdpAdapter
from app.identity.oidc_adapter import OidcAdapter
from app.identity.saml_adapter import SamlAdapter


def build_adapter(idp: IdpConfig) -> IdpAdapter:
    if idp.provider_type == "oidc":
        return OidcAdapter(idp.oidc_config)
    if idp.provider_type == "saml":
        return SamlAdapter(idp.saml_config)
    raise ValueError(f"Unsupported provider_type: {idp.provider_type}")


def map_groups_to_role(
    idp_groups: list[str] | tuple[str, ...],
    directory_sync: dict[str, Any],
) -> str:
    """Resolve an IDP user's groups to a platform role.

    Precedence: first matching group in the IDP list wins. Falls back to
    `default_role` if no group maps. If no default is configured, returns
    "viewer" (least-privilege fallback).
    """
    mapping: dict[str, str] = directory_sync.get("group_to_role_mapping") or {}
    default_role: str = directory_sync.get("default_role") or "viewer"

    for group in idp_groups:
        if group in mapping:
            return mapping[group]
    return default_role
