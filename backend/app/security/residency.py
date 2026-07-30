"""Tenant-to-region residency enforcement.

The platform uses a cell architecture: one API/EPA deployment, PostgreSQL,
Redis, ClickHouse, Redpanda topic, audit sinks, and model cache per approved
region. ``Organization.data_region`` is the routing authority. A process bound
to any other ``Settings.deployment_region`` rejects the tenant before arming
ORM/RLS context or writing telemetry.

The rejection deliberately does not reveal the tenant's configured region or a
redirect target. A trusted global ingress may route from its own protected
tenant directory; the regional service remains fail closed.
"""

from __future__ import annotations

import hashlib

from app.core.config import get_settings
from app.db.models.organization import Organization
from app.security.audit_log import AuditEventType, AuditOutcome, log_event


class TenantRegionMismatchError(Exception):
    """The tenant is missing or is not resident in this deployment cell."""


def enforce_organization_region(org: Organization | None, *, surface: str) -> Organization:
    settings = get_settings()
    if org is not None and org.data_region == settings.deployment_region:
        return org

    # Do not persist the raw tenant identifier or configured target region in a
    # non-resident cell's denial audit. The stable digest supports correlation
    # during an incident without becoming a second customer-identity store.
    org_ref = (
        hashlib.sha256(str(org.id).encode()).hexdigest()[:16] if org is not None else "missing"
    )
    log_event(
        AuditEventType.RESIDENCY_ROUTE_DENIED,
        AuditOutcome.FAILURE,
        tenant_id="_global_",
        resource=surface,
        detail={
            "reason": "tenant_region_mismatch",
            "tenant_ref": org_ref,
            "deployment_region": settings.deployment_region,
        },
    )
    raise TenantRegionMismatchError("tenant is not available in this deployment region")
