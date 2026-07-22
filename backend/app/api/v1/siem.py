"""SIEM exporter admin routes — list / create / update / delete.

Per-org SIEM configuration lives on ``Organization.settings.siem_exporters``
as a list of ``{type, name, config, enabled}`` entries. Secret material (HEC
tokens, shared keys, bearer tokens) MUST be passed as secret refs
(``env:NAME`` / ``vault:path`` / ``awssm:arn``) — raw secrets are rejected at
validation time so they never land in the JSONB column, and resolved on the
send path (``app/siem/exporters.py``), never here.

Secret fields are named exactly (``token``, ``shared_key``, …); there is no
``<field>_ref`` alias. Read responses redact known secret fields plus any key
whose name reads as a secret, so a mis-named key cannot echo verbatim.

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
    SECRET_CONFIG_FIELDS,
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


# Per-type secret fields that MUST be passed as a secret reference. The single
# source of truth lives with the exporters (the module that resolves them on the
# send path); importing it here keeps validation, redaction and resolution
# describing the SAME fields — a divergence would mean validating one field and
# leaking another.
#
# NOTE: only the exact field name is a "known secret". A ``<field>_ref`` spelling
# is NOT recognised — an earlier docstring claimed it was, which was false: it
# would have skipped validation AND redaction and then TypeError'd at build. The
# redactor below is pattern-based specifically so a mis-named secret key still
# does not echo verbatim.
_SECRET_FIELDS: dict[str, frozenset[str]] = SECRET_CONFIG_FIELDS

# Substrings that mark a config key as secret-bearing regardless of the per-type
# map. A deny-list, so it can miss a secret under an innocuous key name — the
# per-type map is the authority, this is the backstop that stops the reported
# ``token_ref`` leak and its cousins. Full allow-list redaction (show only known
# non-secret keys) is the stronger form; see docs/GAPS.md.
_SECRET_KEY_PATTERNS: tuple[str, ...] = (
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "shared_key",
    "bearer",
    "credential",
    "private",
    "auth",  # basic_auth_*, authorization, … — catches the N1 dead-field class
)


def _looks_secret(key: str, secret_fields: frozenset[str]) -> bool:
    if key in secret_fields:
        return True
    lowered = key.lower()
    return any(pat in lowered for pat in _SECRET_KEY_PATTERNS)


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

    if not exporter_type_known(stored_type) or exporter_type_allowed(stored_type):
        # Either nothing gated is being preserved, or the stored record is a
        # type we do not recognise at all (hand-edited or corrupted JSONB).
        # Neither is a legacy gated config, so the payload stands on its own.
        #
        # The unknown case is checked FIRST because it would otherwise fall into
        # the gated branch below and tell the operator to set
        # PLATFORM_ENABLE_SIEM_EXTENDED — advice the flag cannot honour, since
        # it only ever un-gates the four known Tier C types. Unreachable from
        # HTTP today (ExporterType is a Literal), but the branch order is the
        # bug, not the reachability.
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


def _is_pure_disable(payload: ExporterCreate, stored: dict[str, Any]) -> bool:
    """Whether this update only flips ``enabled`` to false, leaving type, name
    and config exactly as stored. Such an update sends nothing, so it needs no
    resolvable secret."""
    return (
        payload.enabled is False
        and payload.type == str(stored.get("type") or "")
        and payload.name == (stored.get("name") or "")
        and payload.config == (stored.get("config") or {})
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
    secret_fields = _SECRET_FIELDS.get(entry.get("type", ""), frozenset())
    for k, v in cfg.items():
        # Redact known secret fields AND anything whose key name reads as a
        # secret — so a mis-spelled key like ``token_ref`` cannot echo the
        # secret verbatim just because it is not in the per-type map.
        redacted["config_redacted"][k] = "***" if _looks_secret(k, secret_fields) else v
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

    # A pure disable — enabled=false with config/type identical to what is
    # stored — skips secret-ref validation. Disabling stops forwarding, so
    # nothing will be sent and nothing needs to resolve; requiring the ref to
    # resolve here would trap an operator whose secret var has since rotated or
    # been unmounted into being unable to turn a broken exporter OFF. They could
    # only delete it — the exact corner the disable carve-out exists to avoid.
    if not _is_pure_disable(payload, stored):
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
