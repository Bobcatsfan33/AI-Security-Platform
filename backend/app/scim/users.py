"""SCIM Users service — DB-backed against the platform's ``users`` table.

The SCIM operations are translated to async SQLAlchemy queries scoped by
``org_id``. The IDP that authenticated the SCIM request determines the
org, and group→role mapping draws from that IDP's
``directory_sync.group_to_role_mapping`` so role updates flow naturally
on group membership changes pushed via SCIM.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.idp_config import IdpConfig
from app.db.models.user import User
from app.identity.registry import map_groups_to_role
from app.scim import filter as scim_filter
from app.scim.patch import PatchError, UnsupportedPatch, apply_patch
from app.scim.serializers import scim_to_user_fields, user_to_scim
from app.scim.types import (
    SCHEMA_LIST_RESPONSE,
    SCHEMA_USER,
    SCIMError,
)


# ─────────────────────────────────────────────── helpers


def _apply_role_from_groups(user: User, idp: IdpConfig) -> None:
    """Recompute the user's role from current idp_groups + the IdP mapping."""
    user.role = map_groups_to_role(user.idp_groups or [], idp.directory_sync or {})


# ─────────────────────────────────────────────── CRUD


async def create_user(
    db: AsyncSession,
    payload: dict[str, Any],
    *,
    org_id: uuid.UUID,
    idp: IdpConfig,
) -> dict[str, Any]:
    if SCHEMA_USER not in (payload.get("schemas") or []):
        raise SCIMError(400, "User schema missing", scimType="invalidValue")

    fields = scim_to_user_fields(payload)
    if "email" not in fields:
        raise SCIMError(400, "userName is required", scimType="invalidValue")

    # Enforce org-scoped uniqueness on email
    existing = (
        await db.execute(
            select(User).where(User.org_id == org_id, User.email == fields["email"])
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise SCIMError(409, "User already exists", scimType="uniqueness")

    user = User(
        id=uuid.uuid4(),
        org_id=org_id,
        email=fields["email"],
        name=fields.get("name") or fields["email"],
        idp_config_id=idp.id,
        idp_subject_id=fields.get("subject_id"),
        idp_groups=fields.get("idp_groups", []),
        is_active=fields.get("is_active", True),
    )
    _apply_role_from_groups(user, idp)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user_to_scim(user)


async def get_user(
    db: AsyncSession, user_id: uuid.UUID, *, org_id: uuid.UUID
) -> dict[str, Any]:
    user = await _load_owned(db, user_id, org_id)
    return user_to_scim(user)


async def replace_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    payload: dict[str, Any],
    *,
    org_id: uuid.UUID,
    idp: IdpConfig,
) -> dict[str, Any]:
    user = await _load_owned(db, user_id, org_id)
    fields = scim_to_user_fields(payload)
    for attr, value in fields.items():
        setattr(user, attr, value)
    _apply_role_from_groups(user, idp)
    await db.commit()
    await db.refresh(user)
    return user_to_scim(user)


async def patch_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    patch_doc: dict[str, Any],
    *,
    org_id: uuid.UUID,
    idp: IdpConfig,
) -> dict[str, Any]:
    user = await _load_owned(db, user_id, org_id)
    current = user_to_scim(user)
    try:
        patched = apply_patch(current, patch_doc)
    except UnsupportedPatch as exc:
        raise SCIMError(501, str(exc), scimType="invalidPath") from exc
    except PatchError as exc:
        raise SCIMError(400, str(exc), scimType="invalidValue") from exc

    fields = scim_to_user_fields(patched)
    for attr, value in fields.items():
        setattr(user, attr, value)
    _apply_role_from_groups(user, idp)
    await db.commit()
    await db.refresh(user)
    return user_to_scim(user)


async def delete_user(
    db: AsyncSession, user_id: uuid.UUID, *, org_id: uuid.UUID
) -> None:
    user = await _load_owned(db, user_id, org_id)
    # SCIM DELETE on a User typically means deactivate, not hard-delete.
    # We deactivate rather than DELETE so audit trail and historical
    # findings remain intact.
    user.is_active = False
    await db.commit()


async def list_users(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    start_index: int = 1,
    count: int = 100,
    filter_expr: str | None = None,
) -> dict[str, Any]:
    if start_index < 1 or count < 0:
        raise SCIMError(400, "Invalid startIndex/count", scimType="invalidValue")

    rows = (
        await db.execute(select(User).where(User.org_id == org_id))
    ).scalars().all()
    resources = [user_to_scim(u) for u in rows]

    if filter_expr:
        try:
            predicate = scim_filter.parse(filter_expr)
        except scim_filter.UnsupportedFilter as exc:
            raise SCIMError(501, str(exc), scimType="invalidFilter") from exc
        except scim_filter.FilterError as exc:
            raise SCIMError(400, str(exc), scimType="invalidFilter") from exc
        resources = [r for r in resources if predicate(r)]

    total = len(resources)
    page = resources[start_index - 1 : start_index - 1 + count]
    return {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": total,
        "Resources": page,
        "startIndex": start_index,
        "itemsPerPage": len(page),
    }


# ─────────────────────────────────────────────── helpers


async def _load_owned(
    db: AsyncSession, user_id: uuid.UUID, org_id: uuid.UUID
) -> User:
    user = (
        await db.execute(
            select(User).where(User.id == user_id, User.org_id == org_id)
        )
    ).scalar_one_or_none()
    if user is None:
        raise SCIMError(404, "User not found")
    return user
