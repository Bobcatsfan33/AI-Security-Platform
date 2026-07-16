"""SIEM exporter admin routes — list / create / update / delete.

Per-org SIEM configuration lives on ``Organization.settings.siem_exporters``
as a list of ``{type, name, config}`` entries. Secret material (HEC
tokens, shared keys, bearer tokens) MUST be passed as secret refs
(``env:NAME`` / ``vault:path`` / ``awssm:arn``) — raw secrets are
rejected at validation time so they never land in the JSONB column.

Updates invalidate the per-org exporter cache so the next batch picks
up the new configuration.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.auth.dependencies import require_role
from app.db.models.organization import Organization
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.security.audit_log import AuditEventType, AuditOutcome, log_event
from app.security.secrets import get_resolver
from app.siem.exporters import (
    TIER_B_EXPORTER_TYPES,
    TIER_C_EXPORTER_TYPES,
    exporter_type_allowed,
    exporter_type_known,
)
from app.siem.forwarder import get_forwarder

router = APIRouter(tags=["admin", "siem"])


ExporterType = Literal[
    "splunk_hec", "elastic", "sentinel", "datadog", "chronicle", "webhook"
]


class ExporterCreate(BaseModel):
    type: ExporterType
    name: str = Field(min_length=1, max_length=64)
    config: dict[str, Any]
    # Lets an operator stop forwarding without discarding the configuration.
    # Load-bearing for the tier gate: a config for a now-gated type can always
    # be disabled, which is the difference between "frozen" and "stuck".
    # Defaults true, so configs written before this field existed keep working.
    enabled: bool = True

    @field_validator("config")
    @classmethod
    def _config_required_keys(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("config must be an object")
        return v


class ExporterRead(BaseModel):
    type: ExporterType
    name: str
    config_redacted: dict[str, Any]
    # Surfaced so "why am I seeing no events?" is answerable from the API rather
    # than from the logs. Defaults true for entries written before the field.
    enabled: bool = True


# Per-type secret fields that MUST be passed as a secret reference.
# We accept either the literal field name (e.g. "token") or
# ``<field>_ref`` to make the intent explicit on the wire.
_SECRET_FIELDS: dict[str, set[str]] = {
    "splunk_hec": {"token"},
    "elastic": {"api_key", "basic_auth_password"},
    "sentinel": {"shared_key"},
    "datadog": {"api_key"},
    "chronicle": {"bearer_token"},
    "webhook": {"bearer_token"},  # optional
}


def _gated_type_error(etype: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            f"exporter type '{etype}' is not enabled on this deployment. "
            "Set PLATFORM_ENABLE_SIEM_EXTENDED=true to enable it "
            f"(enabled by default: {', '.join(sorted(TIER_B_EXPORTER_TYPES))})."
        ),
    )


def _validate_exporter_tier_on_create(exporter: ExporterCreate) -> None:
    """No carve-outs on create. A gated type cannot be created at all.

    There is deliberately no ``enabled=false`` exemption here: the disable
    carve-out exists to let an operator turn OFF a config that predates the
    gate, and on create there is no legacy config to preserve. Allowing a
    disabled-but-gated create would let anyone stage Sentinel/Datadog/Chronicle
    exporters on a deployment where the flag is off — inert, unreviewed, and
    silently activated for every staged config at once the day
    PLATFORM_ENABLE_SIEM_EXTENDED flips. "Frozen" has to mean you cannot
    accumulate a backlog behind the flag.

    Note on unknown types: unreachable from HTTP, where ``ExporterType`` is a
    ``Literal`` and pydantic returns 422 before this runs. Kept as
    defence-in-depth for non-HTTP callers. The unknown-vs-gated distinction
    that operators actually observe is in the forwarder logs
    (``siem_unknown_exporter_type`` vs ``siem_exporter_type_gated``), not here.
    """
    if exporter_type_allowed(exporter.type):
        return
    if not exporter_type_known(exporter.type):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unknown exporter type '{exporter.type}'. Known types: "
                f"{', '.join(sorted(TIER_B_EXPORTER_TYPES | TIER_C_EXPORTER_TYPES))}."
            ),
        )
    raise _gated_type_error(exporter.type)


def _validate_exporter_tier_on_update(
    exporter: ExporterCreate, stored: dict[str, Any]
) -> None:
    """Updates are judged against the STORED record, not the payload alone.

    When the stored type is gated, the only accepted write is *turning it off*:
    ``enabled: false`` with every other field identical to what is already
    stored. Anything else — rewriting config, swapping secret refs, changing
    the type, or flipping it back on — is rejected.

    Why this is stricter than "disabling is allowed": a check that only looked
    at ``payload.enabled`` would accept a PUT that sets ``enabled: false`` while
    *also* rewriting the exporter's config and secret refs, or changing its type
    outright. That edit would sit inert and become live the moment the flag
    flips — the gate would be guarding the wrong noun. The stored record is the
    only thing that says what the operator is actually allowed to preserve.

    Migrating a gated exporter to an allowed type is deliberately NOT expressed
    here: delete it and create the replacement, so the new config passes create
    validation on its own merits.
    """
    stored_type = str(stored.get("type") or "")

    if exporter_type_allowed(stored_type):
        # Nothing gated is being preserved — the payload stands on its own.
        _validate_exporter_tier_on_create(exporter)
        return

    if exporter.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"exporter '{stored.get('name')}' has type '{stored_type}', which is not "
                "enabled on this deployment. It can be disabled (enabled=false) or "
                "deleted; to re-enable it, set PLATFORM_ENABLE_SIEM_EXTENDED=true."
            ),
        )

    unchanged = (
        exporter.type == stored_type
        and exporter.name == (stored.get("name") or "")
        and exporter.config == (stored.get("config") or {})
    )
    if not unchanged:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"exporter '{stored.get('name')}' has type '{stored_type}', which is not "
                "enabled on this deployment. Only 'enabled' may be changed while the "
                "type is gated — send the stored configuration unmodified with "
                "enabled=false, or delete the exporter."
            ),
        )


def _validate_secret_refs(exporter: ExporterCreate) -> None:
    """Enforce that secret-bearing fields are references, not raw values."""
    resolver = get_resolver()
    for field in _SECRET_FIELDS.get(exporter.type, set()):
        value = exporter.config.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field} must be a secret reference string",
            )
        if ":" not in value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"{field} must be a secret reference "
                    "(env:NAME / vault:path / awssm:arn)"
                ),
            )
        try:
            resolver.resolve(value)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field} secret could not be resolved: {exc}",
            ) from exc


def _redact(entry: dict[str, Any]) -> dict[str, Any]:
    redacted = {**entry, "config_redacted": {}}
    cfg = entry.get("config") or {}
    secret_fields = _SECRET_FIELDS.get(entry.get("type", ""), set())
    for k, v in cfg.items():
        if k in secret_fields:
            redacted["config_redacted"][k] = "***"
        else:
            redacted["config_redacted"][k] = v
    redacted.pop("config", None)
    return redacted


async def _load_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = (
        await db.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="org_not_found"
        )
    return org


def _exporters_list(org: Organization) -> list[dict[str, Any]]:
    settings = org.settings or {}
    raw = settings.get("siem_exporters", [])
    return list(raw) if isinstance(raw, list) else []


def _persist_exporters(
    org: Organization, exporters: list[dict[str, Any]]
) -> None:
    settings = dict(org.settings or {})
    settings["siem_exporters"] = exporters
    org.settings = settings
    flag_modified(org, "settings")


# ─────────────────────────────────────────────────── routes


@router.get("/exporters", response_model=list[ExporterRead])
async def list_exporters(
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> list[ExporterRead]:
    org = await _load_org(db, identity.org_id)
    return [ExporterRead(**_redact(e)) for e in _exporters_list(org)]


@router.post(
    "/exporters",
    response_model=ExporterRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_exporter(
    payload: ExporterCreate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ExporterRead:
    _validate_exporter_tier_on_create(payload)
    _validate_secret_refs(payload)
    org = await _load_org(db, identity.org_id)
    exporters = _exporters_list(org)
    if any(e.get("name") == payload.name for e in exporters):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="exporter_name_exists",
        )
    entry = payload.model_dump()
    exporters.append(entry)
    _persist_exporters(org, exporters)
    await db.commit()
    await get_forwarder().invalidate_org(str(org.id))
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(org.id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"siem_exporter:{payload.name}",
        detail={"action": "siem_exporter.created", "type": payload.type},
    )
    return ExporterRead(**_redact(entry))


@router.put("/exporters/{name}", response_model=ExporterRead)
async def update_exporter(
    name: str,
    payload: ExporterCreate,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> ExporterRead:
    if payload.name != name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="name_mismatch",
        )
    org = await _load_org(db, identity.org_id)
    exporters = _exporters_list(org)

    stored = next((e for e in exporters if e.get("name") == name), None)
    if stored is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="exporter_not_found"
        )

    # Judged against the stored record: a gated exporter may only be turned off,
    # not rewritten while disabled. See _validate_exporter_tier_on_update.
    _validate_exporter_tier_on_update(payload, stored)
    _validate_secret_refs(payload)

    updated = [payload.model_dump() if e.get("name") == name else e for e in exporters]
    _persist_exporters(org, updated)
    await db.commit()
    await get_forwarder().invalidate_org(str(org.id))
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(org.id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"siem_exporter:{name}",
        detail={"action": "siem_exporter.updated", "type": payload.type},
    )
    return ExporterRead(**_redact(payload.model_dump()))


@router.delete("/exporters/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_exporter(
    name: str,
    identity: IdentityContext = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
) -> None:
    org = await _load_org(db, identity.org_id)
    exporters = _exporters_list(org)
    remaining = [e for e in exporters if e.get("name") != name]
    if len(remaining) == len(exporters):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="exporter_not_found"
        )
    _persist_exporters(org, remaining)
    await db.commit()
    await get_forwarder().invalidate_org(str(org.id))
    log_event(
        AuditEventType.CONFIG_CHANGED,
        AuditOutcome.SUCCESS,
        tenant_id=str(org.id),
        subject=str(identity.user_id) if identity.user_id else "system",
        resource=f"siem_exporter:{name}",
        detail={"action": "siem_exporter.deleted"},
    )
