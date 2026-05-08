"""SCIM ↔ database model serializers.

The SCIM User resource doesn't map 1:1 to our ``users`` table — SCIM
defines ``name.givenName`` / ``name.familyName`` and an ``emails`` array,
while we store a flat ``name`` string and a single ``email``. The
serializers here are the only place that translation happens.

Group resources are derived from each user's ``idp_groups`` JSONB field
rather than persisted separately — see ``app/scim/groups.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.db.models.user import User
from app.scim.types import SCHEMA_GROUP, SCHEMA_USER, make_meta


# ─────────────────────────────────────────────── User ↔ SCIM


def user_to_scim(user: User) -> dict[str, Any]:
    """Render a User row as a SCIM 2.0 User resource."""
    given, family = _split_name(user.name)
    created = (user.created_at or datetime.now(timezone.utc)).isoformat().replace(
        "+00:00", "Z"
    )
    last_modified = (
        user.updated_at or user.created_at or datetime.now(timezone.utc)
    ).isoformat().replace("+00:00", "Z")

    return {
        "schemas": [SCHEMA_USER],
        "id": str(user.id),
        "userName": user.email,
        "active": bool(user.is_active),
        "name": {
            "givenName": given,
            "familyName": family,
            "formatted": user.name,
        },
        "emails": [{"value": user.email, "primary": True, "type": "work"}],
        "groups": [{"value": g, "display": g} for g in (user.idp_groups or [])],
        "meta": make_meta(
            resource_id=str(user.id),
            resource_type="User",
            created=created,
            last_modified=last_modified,
        ),
    }


def scim_to_user_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate a SCIM User payload into kwargs for the User model.

    Only fields the platform actually persists are extracted. Unknown
    fields are silently dropped — SCIM provisioning is forgiving by design
    so different IdPs can push the same payload shape and we keep what
    we understand.
    """
    out: dict[str, Any] = {}
    if "userName" in payload:
        out["email"] = payload["userName"]
    if "active" in payload:
        out["is_active"] = bool(payload["active"])
    name_obj = payload.get("name") or {}
    if isinstance(name_obj, dict):
        formatted = name_obj.get("formatted")
        if formatted:
            out["name"] = str(formatted)
        elif "givenName" in name_obj or "familyName" in name_obj:
            given = str(name_obj.get("givenName") or "")
            family = str(name_obj.get("familyName") or "")
            combined = f"{given} {family}".strip()
            if combined:
                out["name"] = combined
    # SCIM emails: prefer the primary email if marked, else the first one.
    # If userName was already extracted, an explicit primary email overrides it.
    emails = payload.get("emails") or []
    if isinstance(emails, list) and emails:
        primary = next(
            (e for e in emails if isinstance(e, dict) and e.get("primary")),
            None,
        )
        chosen = primary or emails[0]
        if isinstance(chosen, dict) and chosen.get("value"):
            out["email"] = str(chosen["value"])
    # Groups arrive as [{"value": "<group_id_or_name>", "display": "..."}]
    groups = payload.get("groups")
    if isinstance(groups, list):
        out["idp_groups"] = [
            str(g.get("display") or g.get("value"))
            for g in groups
            if isinstance(g, dict) and (g.get("display") or g.get("value"))
        ]
    return out


def _split_name(full_name: str) -> tuple[str, str]:
    """Best-effort split for the SCIM givenName / familyName projection.

    SCIM consumers (Okta, Azure AD) want a structured name even though we
    store just a single string. We split on the first whitespace; users
    with multi-word given names get them collapsed into givenName.
    """
    if not full_name:
        return ("", "")
    parts = full_name.strip().split(maxsplit=1)
    if len(parts) == 1:
        return (parts[0], "")
    return (parts[0], parts[1])


# ─────────────────────────────────────────────── Group serializer


def group_to_scim(*, group_name: str, member_users: list[User]) -> dict[str, Any]:
    """Synthesize a SCIM Group resource from a group name + the users that
    list this group in their idp_groups."""
    return {
        "schemas": [SCHEMA_GROUP],
        # We use the group name as the ID since we don't have a Groups
        # table — SCIM treats id as opaque so this is permitted.
        "id": group_name,
        "displayName": group_name,
        "members": [
            {"value": str(u.id), "display": u.name, "type": "User"}
            for u in member_users
        ],
        "meta": {
            "resourceType": "Group",
            "location": f"/scim/v2/Groups/{group_name}",
        },
    }
