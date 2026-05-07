"""Domain types shared by identity adapters."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class IdentityClaims:
    """Claims extracted from an IDP token / SAML assertion / SCIM payload.

    Provider-specific fields have been mapped to canonical names by the adapter.
    This is the shape the platform's user provisioning logic depends on — not the
    raw IDP payload.
    """

    subject_id: str  # IDP-side unique identifier (sub, NameID, externalId)
    email: str
    name: str
    groups: tuple[str, ...] = field(default_factory=tuple)
    raw_claims: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class IdentityContext:
    """Authenticated principal for the duration of one request.

    Attached to request.state by auth dependencies. Routes consume this to enforce
    org isolation and RBAC. Frozen so handlers cannot accidentally mutate it.
    """

    org_id: uuid.UUID
    user_id: Optional[uuid.UUID]            # None when authenticated via API key
    role: str                                # owner | admin | analyst | viewer | api_only
    auth_method: str                         # oidc | saml | api_key | refresh
    scopes: tuple[str, ...] = field(default_factory=tuple)
    idp_subject_id: Optional[str] = None
    api_key_id: Optional[uuid.UUID] = None
    jwt_id: Optional[str] = None             # JTI claim, for revocation
