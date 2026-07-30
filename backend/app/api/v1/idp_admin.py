"""IDP configuration admin routes — `admin` role required.

Sprint 1 supports OIDC end-to-end. SAML rows can be created (schema is here)
but begin_login/complete_login will raise the deferred-implementation error.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.scim.auth import generate_scim_token
from app.security.audit_log import AuditEventType, AuditOutcome, log_event
from app.security.field_crypto import FieldCryptoError
from app.security.field_crypto import encrypt as fc_encrypt
from app.security.outbound_url import (
    OutboundURLPolicyError,
    pinned_async_transport,
    validate_public_https_url,
)
from app.security.rate_limit import IDP_ADMIN, rate_limit_principal

_idp_admin_rl = rate_limit_principal(bucket="idp-admin", **IDP_ADMIN)
router = APIRouter(tags=["admin", "idp"], dependencies=[Depends(_idp_admin_rl)])
_ACTIVE_SCIM_INDEX = "uq_idp_configs_active_scim_per_org"


class OidcConfig(BaseModel):
    issuer_url: HttpUrl
    client_id: str = Field(min_length=1, max_length=255)
    client_secret_ref: str = Field(
        min_length=1,
        description="Reference to a secret store entry, e.g. 'env:OIDC_SECRET_OKTA'.",
    )
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    audience: str | None = None
    claim_mappings: dict[str, str] = Field(default_factory=dict)


class SamlConfig(BaseModel):
    entity_id: str = Field(min_length=1, max_length=2048)
    sso_url: HttpUrl
    slo_url: HttpUrl | None = None
    certificate: str = Field(min_length=1, max_length=131_072)
    name_id_format: Literal["email", "persistent", "transient"] = "email"
    attribute_mappings: dict[str, str] = Field(default_factory=dict)


class DirectorySyncConfig(BaseModel):
    enabled: bool = False
    frequency_minutes: int = Field(default=60, ge=5, le=10_080)
    group_to_role_mapping: dict[str, str] = Field(default_factory=dict)
    default_role: Literal["admin", "analyst", "viewer"] = "viewer"

    @field_validator("group_to_role_mapping")
    @classmethod
    def mapping_cannot_grant_owner(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {"admin", "analyst", "viewer"}
        invalid = sorted({role for role in value.values() if role not in allowed})
        if invalid:
            raise ValueError(
                f"group mappings may grant only admin, analyst, or viewer; invalid roles: {invalid}"
            )
        return value


class IdpConfigCreate(BaseModel):
    provider_type: Literal["saml", "oidc", "scim"]
    display_name: str = Field(min_length=1, max_length=255)
    oidc_config: OidcConfig | None = None
    saml_config: SamlConfig | None = None
    directory_sync: DirectorySyncConfig = Field(default_factory=DirectorySyncConfig)


class IdpConfigUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    status: Literal["active", "disabled", "pending_verification"] | None = None
    oidc_config: OidcConfig | None = None
    saml_config: SamlConfig | None = None
    directory_sync: DirectorySyncConfig | None = None


class IdpConfigResponse(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    provider_type: str
    display_name: str
    status: str
    oidc_config: dict[str, Any]
    saml_config: dict[str, Any]
    directory_sync: dict[str, Any]
    verification_status: dict[str, Any]
    created_at: datetime
    updated_at: datetime


ENC_PENDING_PREFIX = "enc-pending:"


def _maybe_encrypt_pending_secret(oidc_config: dict[str, Any]) -> dict[str, Any]:
    """If client_secret_ref starts with ``enc-pending:<plaintext>``, encrypt the
    plaintext via field_crypto and replace the ref with ``enc:vN:...``.

    This lets admins paste a raw secret in the UI without provisioning an
    AWS SM / Vault entry first. The stored reference is encrypted at rest
    with a key that lives in a separate secret store, so DB dumps cannot
    reveal it without also compromising the field_crypto key.
    """
    ref = oidc_config.get("client_secret_ref", "")
    if not isinstance(ref, str) or not ref.startswith(ENC_PENDING_PREFIX):
        return oidc_config
    plaintext = ref[len(ENC_PENDING_PREFIX) :]
    if not plaintext:
        raise HTTPException(status_code=400, detail="enc_pending_empty_plaintext")
    try:
        ciphertext = fc_encrypt(plaintext)
    except FieldCryptoError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"field_crypto_unavailable: {exc}",
        ) from exc
    return {**oidc_config, "client_secret_ref": f"enc:{ciphertext}"}


def _to_response(row: IdpConfig) -> IdpConfigResponse:
    return IdpConfigResponse(
        id=row.id,
        org_id=row.org_id,
        provider_type=row.provider_type,
        display_name=row.display_name,
        status=row.status,
        oidc_config=row.oidc_config or {},
        saml_config=row.saml_config or {},
        directory_sync=row.directory_sync or {},
        verification_status=row.verification_status or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("", response_model=list[IdpConfigResponse])
async def list_idp_configs(
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> list[IdpConfigResponse]:
    rows = (
        (await db.execute(select(IdpConfig).where(IdpConfig.org_id == identity.org_id)))
        .scalars()
        .all()
    )
    return [_to_response(r) for r in rows]


@router.post("", response_model=IdpConfigResponse, status_code=status.HTTP_201_CREATED)
async def create_idp_config(
    payload: IdpConfigCreate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> IdpConfigResponse:
    if payload.provider_type == "oidc" and payload.oidc_config is None:
        raise HTTPException(status_code=400, detail="oidc_config_required")
    if payload.provider_type == "saml" and payload.saml_config is None:
        raise HTTPException(status_code=400, detail="saml_config_required")

    if payload.oidc_config is not None:
        await _validate_oidc_discovery(str(payload.oidc_config.issuer_url))

    oidc_dict = (
        _maybe_encrypt_pending_secret(payload.oidc_config.model_dump(mode="json"))
        if payload.oidc_config
        else {}
    )

    row = IdpConfig(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        provider_type=payload.provider_type,
        display_name=payload.display_name,
        status="pending_verification",
        oidc_config=oidc_dict,
        saml_config=payload.saml_config.model_dump(mode="json") if payload.saml_config else {},
        scim_config={},
        directory_sync=payload.directory_sync.model_dump(mode="json"),
        verification_status={},
        created_by=identity.user_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    log_event(
        AuditEventType.IDP_CONFIG_CREATED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"idp_config:{row.id}",
        detail={"provider_type": row.provider_type, "display_name": row.display_name},
    )
    return _to_response(row)


@router.patch("/{idp_id}", response_model=IdpConfigResponse)
async def update_idp_config(
    idp_id: uuid.UUID,
    payload: IdpConfigUpdate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> IdpConfigResponse:
    row = await _load_owned(db, idp_id, identity.org_id)
    if payload.status == "active" and row.provider_type == "scim":
        if not (row.scim_config or {}).get("bearer_token_hash"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="scim_token_required_before_activation",
            )
        active_id = (
            await db.execute(
                select(IdpConfig.id).where(
                    IdpConfig.org_id == identity.org_id,
                    IdpConfig.provider_type == "scim",
                    IdpConfig.status == "active",
                    IdpConfig.id != row.id,
                )
            )
        ).scalar_one_or_none()
        if active_id is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="active_scim_idp_already_exists",
            )
    if payload.display_name is not None:
        row.display_name = payload.display_name
    if payload.status is not None:
        row.status = payload.status
    if payload.oidc_config is not None:
        await _validate_oidc_discovery(str(payload.oidc_config.issuer_url))
        row.oidc_config = _maybe_encrypt_pending_secret(payload.oidc_config.model_dump(mode="json"))
    if payload.saml_config is not None:
        row.saml_config = payload.saml_config.model_dump(mode="json")
    if payload.directory_sync is not None:
        row.directory_sync = payload.directory_sync.model_dump(mode="json")
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        if _constraint_name(exc) != _ACTIVE_SCIM_INDEX:
            raise
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="active_scim_idp_already_exists",
        ) from exc
    await db.refresh(row)
    log_event(
        AuditEventType.IDP_CONFIG_UPDATED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"idp_config:{row.id}",
        detail={
            "fields_changed": sorted(payload.model_dump(exclude_unset=True).keys()),
        },
    )
    return _to_response(row)


@router.post("/{idp_id}/scim-token")
async def mint_scim_token(
    idp_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Mint a fresh SCIM bearer token for a SCIM-type IDP config.

    The plaintext is returned exactly once; only the bcrypt hash is
    persisted to ``scim_config.bearer_token_hash``. Calling this endpoint
    invalidates any previous token for this IdP — the IdP must update its
    SCIM connection to use the new value.
    """
    row = await _load_owned(db, idp_id, identity.org_id)
    if row.provider_type != "scim":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="not_a_scim_idp_config",
        )

    plaintext, hashed = generate_scim_token()
    scim_cfg = dict(row.scim_config or {})
    scim_cfg["bearer_token_hash"] = hashed
    org_slug = (
        await db.execute(select(Organization.slug).where(Organization.id == identity.org_id))
    ).scalar_one()
    scim_cfg["endpoint_url"] = f"/v1/scim/v2/{org_slug}"
    row.scim_config = scim_cfg
    await db.commit()
    await db.refresh(row)

    log_event(
        AuditEventType.IDP_CONFIG_UPDATED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"idp_config:{row.id}",
        detail={"action": "scim_token_minted"},
    )
    return {
        "token": plaintext,
        "warning": "This token is shown exactly once. Store it securely; "
        "regenerating produces a new token and invalidates this one.",
    }


@router.delete("/{idp_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_idp_config(
    idp_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    row = await _load_owned(db, idp_id, identity.org_id)
    provider_type = row.provider_type
    display_name = row.display_name
    await db.delete(row)
    await db.commit()
    log_event(
        AuditEventType.IDP_CONFIG_DELETED,
        AuditOutcome.SUCCESS,
        tenant_id=str(identity.org_id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"idp_config:{idp_id}",
        detail={"provider_type": provider_type, "display_name": display_name},
    )


async def _load_owned(db: AsyncSession, idp_id: uuid.UUID, org_id: uuid.UUID) -> IdpConfig:
    row = (
        await db.execute(
            select(IdpConfig).where(IdpConfig.id == idp_id, IdpConfig.org_id == org_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return row


def _constraint_name(exc: IntegrityError) -> str | None:
    """Extract the PostgreSQL constraint through SQLAlchemy/asyncpg wrappers."""
    current: object | None = exc.orig
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        direct = getattr(current, "constraint_name", None)
        if isinstance(direct, str):
            return direct
        diagnostic = getattr(current, "diag", None)
        diagnosed = getattr(diagnostic, "constraint_name", None)
        if isinstance(diagnosed, str):
            return diagnosed
        current = getattr(current, "__cause__", None) or getattr(
            current,
            "__context__",
            None,
        )
    return None


async def _validate_oidc_discovery(issuer_url: str) -> None:
    """Hit the .well-known endpoint to confirm the issuer is reachable and serves
    a parseable OpenID-Connect discovery document. Performed at config time so
    a misconfigured IDP fails fast rather than at first user login."""
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        transport = await pinned_async_transport(url)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=10.0,
            follow_redirects=False,
            trust_env=False,
        ) as http:
            resp = await http.get(url)
            resp.raise_for_status()
            data = resp.json()
    except OutboundURLPolicyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"oidc_discovery_destination_blocked: {e}",
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="oidc_discovery_failed",
        ) from e

    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if required not in data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"oidc_discovery_missing_field: {required}",
            )
        if required.endswith("_endpoint") or required == "jwks_uri":
            try:
                await validate_public_https_url(str(data[required]))
            except OutboundURLPolicyError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"oidc_discovery_{required}_blocked: {e}",
                ) from e
