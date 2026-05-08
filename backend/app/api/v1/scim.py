"""SCIM 2.0 endpoints — RFC 7644 subset.

Routes are mounted under ``/v1/scim/v2/{org_slug}/...`` and authenticated
via the per-org bearer token registered on the SCIM IdP config. All
endpoints return SCIM-formatted bodies even on errors so IdPs can parse
them deterministically.

Discovery endpoints (ServiceProviderConfig, ResourceTypes) live at
``/v1/scim/v2/{org_slug}/...`` rather than the global SCIM-spec
``/scim/v2/`` location because everything in this platform is org-
scoped.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.session import get_db
from app.scim import groups as scim_groups
from app.scim import users as scim_users
from app.scim.auth import scim_authenticated_idp
from app.scim.types import (
    SCHEMA_LIST_RESPONSE,
    SCHEMA_RESOURCE_TYPE,
    SCHEMA_SP_CONFIG,
    SCHEMA_USER as USER_SCHEMA,
    SCHEMA_GROUP as GROUP_SCHEMA,
    SCIMError,
)

router = APIRouter(tags=["scim"])

SCIM_MEDIA_TYPE = "application/scim+json"


def _scim_response(body: dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=body, status_code=status_code, media_type=SCIM_MEDIA_TYPE)


def _scim_error_response(exc: SCIMError) -> JSONResponse:
    return JSONResponse(
        content=exc.to_response(),
        status_code=exc.status,
        media_type=SCIM_MEDIA_TYPE,
    )


# ─────────────────────────────────────────────── Users


@router.post("/{org_slug}/Users")
async def create_user(
    org_slug: str,
    request: Request,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, idp = org_idp
    payload = await request.json()
    try:
        result = await scim_users.create_user(db, payload, org_id=org.id, idp=idp)
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result, status_code=201)


@router.get("/{org_slug}/Users/{user_id}")
async def get_user(
    org_slug: str,
    user_id: uuid.UUID,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, _ = org_idp
    try:
        result = await scim_users.get_user(db, user_id, org_id=org.id)
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result)


@router.put("/{org_slug}/Users/{user_id}")
async def replace_user(
    org_slug: str,
    user_id: uuid.UUID,
    request: Request,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, idp = org_idp
    payload = await request.json()
    try:
        result = await scim_users.replace_user(
            db, user_id, payload, org_id=org.id, idp=idp
        )
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result)


@router.patch("/{org_slug}/Users/{user_id}")
async def patch_user(
    org_slug: str,
    user_id: uuid.UUID,
    request: Request,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, idp = org_idp
    payload = await request.json()
    try:
        result = await scim_users.patch_user(
            db, user_id, payload, org_id=org.id, idp=idp
        )
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result)


@router.delete("/{org_slug}/Users/{user_id}")
async def delete_user(
    org_slug: str,
    user_id: uuid.UUID,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, _ = org_idp
    try:
        await scim_users.delete_user(db, user_id, org_id=org.id)
    except SCIMError as exc:
        return _scim_error_response(exc)
    return Response(status_code=204)


@router.get("/{org_slug}/Users")
async def list_users(
    org_slug: str,
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=0, le=200),
    filter: str | None = Query(None),
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, _ = org_idp
    try:
        result = await scim_users.list_users(
            db,
            org_id=org.id,
            start_index=startIndex,
            count=count,
            filter_expr=filter,
        )
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result)


# ─────────────────────────────────────────────── Groups


@router.post("/{org_slug}/Groups")
async def create_group(
    org_slug: str,
    request: Request,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, idp = org_idp
    payload = await request.json()
    try:
        result = await scim_groups.create_group(db, payload, org_id=org.id, idp=idp)
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result, status_code=201)


@router.get("/{org_slug}/Groups/{group_name}")
async def get_group(
    org_slug: str,
    group_name: str,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, _ = org_idp
    try:
        result = await scim_groups.get_group(db, group_name, org_id=org.id)
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result)


@router.get("/{org_slug}/Groups")
async def list_groups(
    org_slug: str,
    filter: str | None = Query(None),
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, _ = org_idp
    try:
        result = await scim_groups.list_groups(db, org_id=org.id, filter_expr=filter)
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result)


@router.patch("/{org_slug}/Groups/{group_name}")
async def patch_group(
    org_slug: str,
    group_name: str,
    request: Request,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, idp = org_idp
    payload = await request.json()
    try:
        result = await scim_groups.patch_group(
            db, group_name, payload, org_id=org.id, idp=idp
        )
    except SCIMError as exc:
        return _scim_error_response(exc)
    return _scim_response(result)


@router.delete("/{org_slug}/Groups/{group_name}")
async def delete_group(
    org_slug: str,
    group_name: str,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
    db: AsyncSession = Depends(get_db),
) -> Response:
    org, idp = org_idp
    try:
        await scim_groups.delete_group(db, group_name, org_id=org.id, idp=idp)
    except SCIMError as exc:
        return _scim_error_response(exc)
    return Response(status_code=204)


# ─────────────────────────────────────────────── Discovery


@router.get("/{org_slug}/ServiceProviderConfig")
async def service_provider_config(
    org_slug: str,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
) -> Response:
    body = {
        "schemas": [SCHEMA_SP_CONFIG],
        "documentationUri": "https://github.com/Bobcatsfan33/ai-security-platform",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Bearer token issued via the platform admin console",
                "specUri": "https://datatracker.ietf.org/doc/html/rfc6750",
                "primary": True,
            }
        ],
    }
    return _scim_response(body)


@router.get("/{org_slug}/ResourceTypes")
async def resource_types(
    org_slug: str,
    org_idp: tuple[Organization, IdpConfig] = Depends(scim_authenticated_idp),
) -> Response:
    body = {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": 2,
        "Resources": [
            {
                "schemas": [SCHEMA_RESOURCE_TYPE],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "Platform user",
                "schema": USER_SCHEMA,
            },
            {
                "schemas": [SCHEMA_RESOURCE_TYPE],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "description": "Platform group (derived from user idp_groups)",
                "schema": GROUP_SCHEMA,
            },
        ],
        "startIndex": 1,
        "itemsPerPage": 2,
    }
    return _scim_response(body)
