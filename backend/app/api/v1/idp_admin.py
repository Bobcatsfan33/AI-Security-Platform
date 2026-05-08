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
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.idp_config import IdpConfig
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.security.audit_log import AuditEventType, AuditOutcome, log_event
from app.security.field_crypto import FieldCryptoError, encrypt as fc_encrypt

router = APIRouter(tags=["admin", "idp"])


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
    entity_id: str
    sso_url: HttpUrl
    slo_url: HttpUrl | None = None
    certificate: str
    name_id_format: Literal["email", "persistent", "transient"] = "email"
    attribute_mappings: dict[str, str] = Field(default_factory=dict)


class DirectorySyncConfig(BaseModel):
    enabled: bool = False
    frequency_minutes: int = 60
    group_to_role_mapping: dict[str, str] = Field(default_factory=dict)
    default_role: str = "viewer"


class IdpConfigCreate(BaseModel):
    provider_type: Literal["saml", "oidc"]
    display_name: str
    oidc_config: OidcConfig | None = None
    saml_config: SamlConfig | None = None
    directory_sync: DirectorySyncConfig = Field(default_factory=DirectorySyncConfig)


class IdpConfigUpdate(BaseModel):
    display_name: str | None = None
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
        raise HTTPException(
            status_code=400, detail="enc_pending_empty_plaintext"
        )
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
        await db.execute(
            select(IdpConfig).where(IdpConfig.org_id == identity.org_id)
        )
    ).scalars().all()
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
    if payload.display_name is not None:
        row.display_name = payload.display_name
    if payload.status is not None:
        row.status = payload.status
    if payload.oidc_config is not None:
        await _validate_oidc_discovery(str(payload.oidc_config.issuer_url))
        row.oidc_config = _maybe_encrypt_pending_secret(
            payload.oidc_config.model_dump(mode="json")
        )
    if payload.saml_config is not None:
        row.saml_config = payload.saml_config.model_dump(mode="json")
    if payload.directory_sync is not None:
        row.directory_sync = payload.directory_sync.model_dump(mode="json")
    await db.commit()
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


async def _validate_oidc_discovery(issuer_url: str) -> None:
    """Hit the .well-known endpoint to confirm the issuer is reachable and serves
    a parseable OpenID-Connect discovery document. Performed at config time so
    a misconfigured IDP fails fast rather than at first user login."""
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            resp = await http.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"oidc_discovery_failed: {e}",
        ) from e

    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if required not in data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"oidc_discovery_missing_field: {required}",
            )
