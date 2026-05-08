"""SCIM Groups service — derived from ``user.idp_groups``.

The platform does not maintain a separate Groups table. Group membership
is stored on the User side as ``idp_groups`` (a JSONB array of group
names). When an IdP pushes group membership changes via SCIM, the
operations are applied to user records directly:

  POST   /Groups          → no-op (group is implicit; first user joining
                            creates it)
  GET    /Groups          → enumerate distinct group names from all users
  GET    /Groups/{name}   → list users with that name in idp_groups
  PATCH  /Groups/{name}   → add/remove members → mutates each user's
                            idp_groups
  DELETE /Groups/{name}   → remove the name from every user's idp_groups

This pragmatic shape handles the 95% case of Okta / Azure AD pushing
group membership without requiring a separate Groups table. Customers
who need first-class group resources (with descriptions, hierarchies,
etc.) get a clear "501 Not Implemented" rather than a quiet half-fit.
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
from app.scim.serializers import group_to_scim
from app.scim.types import SCHEMA_GROUP, SCHEMA_LIST_RESPONSE, SCIMError


# ─────────────────────────────────────────────── helpers


async def _users_in_group(
    db: AsyncSession, *, org_id: uuid.UUID, group_name: str
) -> list[User]:
    rows = (
        await db.execute(select(User).where(User.org_id == org_id))
    ).scalars().all()
    return [u for u in rows if group_name in (u.idp_groups or [])]


async def _all_users(db: AsyncSession, *, org_id: uuid.UUID) -> list[User]:
    rows = (
        await db.execute(select(User).where(User.org_id == org_id))
    ).scalars().all()
    return list(rows)


def _distinct_group_names(users: list[User]) -> list[str]:
    seen: set[str] = set()
    for u in users:
        for g in u.idp_groups or []:
            seen.add(g)
    return sorted(seen)


def _refresh_role(user: User, idp: IdpConfig) -> None:
    user.role = map_groups_to_role(user.idp_groups or [], idp.directory_sync or {})


# ─────────────────────────────────────────────── CRUD


async def create_group(
    db: AsyncSession,
    payload: dict[str, Any],
    *,
    org_id: uuid.UUID,
    idp: IdpConfig,
) -> dict[str, Any]:
    if SCHEMA_GROUP not in (payload.get("schemas") or []):
        raise SCIMError(400, "Group schema missing", scimType="invalidValue")
    display_name = payload.get("displayName")
    if not display_name:
        raise SCIMError(400, "displayName is required", scimType="invalidValue")

    members = payload.get("members") or []
    if not isinstance(members, list):
        raise SCIMError(400, "members must be a list", scimType="invalidValue")

    # Add the group name to each listed member's idp_groups
    for entry in members:
        if not isinstance(entry, dict):
            continue
        user_id_str = entry.get("value")
        if not user_id_str:
            continue
        user = (
            await db.execute(
                select(User).where(User.id == uuid.UUID(user_id_str), User.org_id == org_id)
            )
        ).scalar_one_or_none()
        if user is not None:
            user.idp_groups = sorted(set([*(user.idp_groups or []), display_name]))
            _refresh_role(user, idp)
    await db.commit()

    member_users = await _users_in_group(db, org_id=org_id, group_name=display_name)
    return group_to_scim(group_name=display_name, member_users=member_users)


async def get_group(
    db: AsyncSession, group_name: str, *, org_id: uuid.UUID
) -> dict[str, Any]:
    member_users = await _users_in_group(db, org_id=org_id, group_name=group_name)
    if not member_users:
        raise SCIMError(404, "Group not found")
    return group_to_scim(group_name=group_name, member_users=member_users)


async def list_groups(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    filter_expr: str | None = None,
) -> dict[str, Any]:
    users = await _all_users(db, org_id=org_id)
    groups: list[dict[str, Any]] = []
    for name in _distinct_group_names(users):
        members = [u for u in users if name in (u.idp_groups or [])]
        groups.append(group_to_scim(group_name=name, member_users=members))

    if filter_expr:
        try:
            predicate = scim_filter.parse(filter_expr)
        except scim_filter.UnsupportedFilter as exc:
            raise SCIMError(501, str(exc), scimType="invalidFilter") from exc
        except scim_filter.FilterError as exc:
            raise SCIMError(400, str(exc), scimType="invalidFilter") from exc
        groups = [g for g in groups if predicate(g)]

    return {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": len(groups),
        "Resources": groups,
        "startIndex": 1,
        "itemsPerPage": len(groups),
    }


async def patch_group(
    db: AsyncSession,
    group_name: str,
    patch_doc: dict[str, Any],
    *,
    org_id: uuid.UUID,
    idp: IdpConfig,
) -> dict[str, Any]:
    members = await _users_in_group(db, org_id=org_id, group_name=group_name)
    if not members and not patch_doc.get("Operations"):
        raise SCIMError(404, "Group not found")

    current = group_to_scim(group_name=group_name, member_users=members)
    try:
        patched = apply_patch(current, patch_doc)
    except UnsupportedPatch as exc:
        raise SCIMError(501, str(exc), scimType="invalidPath") from exc
    except PatchError as exc:
        raise SCIMError(400, str(exc), scimType="invalidValue") from exc

    new_members = patched.get("members") or []
    new_member_ids = {
        str(m.get("value"))
        for m in new_members
        if isinstance(m, dict) and m.get("value")
    }
    current_member_ids = {str(u.id) for u in members}

    to_add = new_member_ids - current_member_ids
    to_remove = current_member_ids - new_member_ids

    for user_id_str in to_add:
        try:
            uid = uuid.UUID(user_id_str)
        except ValueError:
            continue
        user = (
            await db.execute(
                select(User).where(User.id == uid, User.org_id == org_id)
            )
        ).scalar_one_or_none()
        if user is not None:
            user.idp_groups = sorted(set([*(user.idp_groups or []), group_name]))
            _refresh_role(user, idp)

    for user_id_str in to_remove:
        try:
            uid = uuid.UUID(user_id_str)
        except ValueError:
            continue
        user = (
            await db.execute(
                select(User).where(User.id == uid, User.org_id == org_id)
            )
        ).scalar_one_or_none()
        if user is not None:
            user.idp_groups = [g for g in (user.idp_groups or []) if g != group_name]
            _refresh_role(user, idp)

    await db.commit()
    refreshed = await _users_in_group(db, org_id=org_id, group_name=group_name)
    return group_to_scim(group_name=group_name, member_users=refreshed)


async def delete_group(
    db: AsyncSession,
    group_name: str,
    *,
    org_id: uuid.UUID,
    idp: IdpConfig,
) -> None:
    """Remove the group name from every user's idp_groups in the org."""
    users = await _all_users(db, org_id=org_id)
    affected = False
    for u in users:
        if group_name in (u.idp_groups or []):
            u.idp_groups = [g for g in u.idp_groups if g != group_name]
            _refresh_role(u, idp)
            affected = True
    if not affected:
        raise SCIMError(404, "Group not found")
    await db.commit()
