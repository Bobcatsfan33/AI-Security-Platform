"""Role-based access control.

Five roles, ordered by privilege (highest first):
    owner    — full control over the organization, including billing
    admin    — full control over assets, evaluations, policies; cannot transfer ownership
    analyst  — create/edit assets/policies, run evaluations, manage findings
    viewer   — read-only access to all org resources
    api_only — only allowed to authenticate via API key; never seen on UI sessions

The matrix below is intentionally simple: route handlers declare a minimum role
and any role at or above that level passes. Finer-grained permissions belong on
specific routes (e.g. only owner can delete the organization).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

ROLE_HIERARCHY: Final[tuple[str, ...]] = (
    "owner",
    "admin",
    "analyst",
    "viewer",
    "api_only",
)

_RANK = {role: idx for idx, role in enumerate(ROLE_HIERARCHY)}


def is_valid_role(role: str) -> bool:
    return role in _RANK


def has_role_at_least(actual_role: str, required_role: str) -> bool:
    """True iff actual_role is at least as privileged as required_role.

    `api_only` is a side-track — never satisfies any UI role requirement, but
    can satisfy explicit `api_only` checks if needed.
    """
    if actual_role == "api_only":
        return required_role == "api_only"
    if not (is_valid_role(actual_role) and is_valid_role(required_role)):
        return False
    return _RANK[actual_role] <= _RANK[required_role]


def is_in(actual_role: str, allowed_roles: Iterable[str]) -> bool:
    return actual_role in set(allowed_roles)
