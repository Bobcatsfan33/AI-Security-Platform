"""Provision / look up users on IDP login.

On every successful IDP login we either:
    1. Match an existing user by (idp_config_id, idp_subject_id) — preferred,
       because it tolerates email changes upstream
    2. Match an existing user by (org_id, email) — useful on first login
       when we haven't recorded the IDP subject yet
    3. Create a new user (auto-provisioning is on for IDP users by default)

In all cases the user's role is recomputed from current IDP groups using the
group_to_role_mapping configured on idp_configs.directory_sync. This is what
makes group changes (in Okta / Azure AD) actually take effect on the platform.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.idp_config import IdpConfig
from app.db.models.user import User
from app.identity.registry import map_groups_to_role
from app.identity.types import IdentityClaims


async def upsert_user_from_claims(
    db: AsyncSession,
    *,
    idp: IdpConfig,
    claims: IdentityClaims,
) -> User:
    role = map_groups_to_role(claims.groups, idp.directory_sync or {})

    # 1. Match by (idp_config_id, idp_subject_id)
    stmt = select(User).where(
        User.idp_config_id == idp.id,
        User.idp_subject_id == claims.subject_id,
    )
    user = (await db.execute(stmt)).scalar_one_or_none()

    if user is None:
        # 2. Match by (org_id, email) — claim the existing user record
        stmt = select(User).where(
            User.org_id == idp.org_id,
            User.email == claims.email,
        )
        user = (await db.execute(stmt)).scalar_one_or_none()
        if user is not None:
            user.idp_config_id = idp.id
            user.idp_subject_id = claims.subject_id

    if user is None:
        # 3. Auto-provision
        user = User(
            id=uuid.uuid4(),
            org_id=idp.org_id,
            email=claims.email,
            name=claims.name,
            role=role,
            idp_config_id=idp.id,
            idp_subject_id=claims.subject_id,
            idp_groups=list(claims.groups),
            is_active=True,
        )
        db.add(user)
    else:
        user.email = claims.email
        user.name = claims.name
        user.idp_groups = list(claims.groups)
        user.role = role
        user.is_active = True

    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(user)
    return user
