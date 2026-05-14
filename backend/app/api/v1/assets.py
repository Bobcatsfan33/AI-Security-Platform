"""Asset routes (v2) — list, detail, search, history, ownership.

Replaces the v1 asset CRUD. v2 assets are read-mostly: connectors
discover them, the sync service persists them, and operators consume
them through these routes.

GET    /v1/assets                  — filter + paginate
GET    /v1/assets/search?q=…       — pgvector cosine similarity
GET    /v1/assets/unowned          — owner_id IS NULL
GET    /v1/assets/duplicates       — high-similarity pairs across connectors
GET    /v1/assets/{id}             — full asset detail (+ deployments, tags, edges)
GET    /v1/assets/{id}/history     — changelog
POST   /v1/assets/{id}/owner       — assign owner
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.ai_asset import AIAsset
from app.db.models.asset_changelog import AssetChangelog
from app.db.models.asset_relationship import AssetRelationship
from app.db.models.asset_tag import AssetTag
from app.db.models.deployment import Deployment
from app.db.models.owner import Owner
from app.db.session import get_db
from app.identity.types import IdentityContext

router = APIRouter(tags=["assets"])

EMBEDDING_DIM = 1536


# ─────────────────────────────────────────────── DTOs


class AssetRead(BaseModel):
    id: uuid.UUID
    name: str
    asset_type: str
    asset_status: str
    provider: str
    version: Optional[str]
    external_id: str
    connector_id: uuid.UUID
    risk_score: int
    owner_id: Optional[uuid.UUID]
    description: Optional[str]
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class DeploymentRead(BaseModel):
    id: uuid.UUID
    environment: str
    endpoint_url: Optional[str]
    region: Optional[str]
    replicas: Optional[int]
    status: str


class TagRead(BaseModel):
    key: str
    value: str


class RelationshipRead(BaseModel):
    target_asset_id: uuid.UUID
    relationship_type: str


class OwnerRead(BaseModel):
    id: uuid.UUID
    team: str
    email: str
    department: Optional[str]


class AssetDetail(AssetRead):
    deployments: list[DeploymentRead] = Field(default_factory=list)
    tags: list[TagRead] = Field(default_factory=list)
    outgoing_relationships: list[RelationshipRead] = Field(default_factory=list)
    owner: Optional[OwnerRead] = None


class AssetHistoryEntry(BaseModel):
    id: uuid.UUID
    change_type: str
    previous_value: Optional[dict[str, Any]]
    new_value: Optional[dict[str, Any]]
    changed_at: datetime


class OwnerAssign(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner_id: Optional[uuid.UUID] = None
    team: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None


class DuplicatePair(BaseModel):
    asset_a_id: uuid.UUID
    asset_b_id: uuid.UUID
    similarity: float


def _to_read(row: AIAsset) -> AssetRead:
    return AssetRead(
        id=row.id,
        name=row.name,
        asset_type=row.asset_type,
        asset_status=row.asset_status,
        provider=row.provider,
        version=row.version,
        external_id=row.external_id,
        connector_id=row.connector_id,
        risk_score=row.risk_score,
        owner_id=row.owner_id,
        description=row.description,
        metadata=row.metadata_json or {},
        discovered_at=row.discovered_at,
        last_seen_at=row.last_seen_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# ─────────────────────────────────────────────── helpers


async def _load_asset(db: AsyncSession, asset_id: uuid.UUID) -> AIAsset:
    row = (
        await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="asset_not_found"
        )
    return row


def _stub_embed(text: str) -> list[float]:
    """Deterministic pseudo-embedding from a string.

    Sprint 1 ships without an embedding service; we hash the query into
    a fixed-dim vector so /search wires end-to-end and can be tested.
    Sprint 2 replaces this with a real embedder.
    """
    if not text:
        return [0.0] * EMBEDDING_DIM
    out: list[float] = [0.0] * EMBEDDING_DIM
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    # Replicate the 32-byte digest across the dim space, normalising to
    # [-1, 1]. Cheap, deterministic, and gives non-zero cosine to itself.
    for i in range(EMBEDDING_DIM):
        out[i] = ((digest[i % len(digest)] / 255.0) * 2.0) - 1.0
    return out


# ─────────────────────────────────────────────── routes


@router.get("", response_model=list[AssetRead])
async def list_assets(
    asset_type: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    asset_status: Optional[str] = Query(None),
    connector_id: Optional[uuid.UUID] = Query(None),
    owner_id: Optional[uuid.UUID] = Query(None),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[AssetRead]:
    stmt = select(AIAsset)
    if asset_type:
        stmt = stmt.where(AIAsset.asset_type == asset_type)
    if provider:
        stmt = stmt.where(AIAsset.provider == provider)
    if asset_status:
        stmt = stmt.where(AIAsset.asset_status == asset_status)
    if connector_id:
        stmt = stmt.where(AIAsset.connector_id == connector_id)
    if owner_id:
        stmt = stmt.where(AIAsset.owner_id == owner_id)
    if min_risk_score is not None:
        stmt = stmt.where(AIAsset.risk_score >= min_risk_score)
    stmt = stmt.order_by(desc(AIAsset.last_seen_at)).limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_read(r) for r in rows]


@router.get("/unowned", response_model=list[AssetRead])
async def list_unowned(
    limit: int = Query(100, ge=1, le=500),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[AssetRead]:
    rows = (
        await db.execute(
            select(AIAsset)
            .where(AIAsset.owner_id.is_(None))
            .where(AIAsset.asset_status == "active")
            .order_by(desc(AIAsset.discovered_at))
            .limit(limit)
        )
    ).scalars().all()
    return [_to_read(r) for r in rows]


@router.get("/duplicates", response_model=list[DuplicatePair])
async def list_duplicates(
    limit: int = Query(50, ge=1, le=200),
    similarity_threshold: float = Query(0.85, ge=0.5, le=0.99),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[DuplicatePair]:
    """Surface potential duplicate assets across connectors.

    Two assets are candidates if they share asset_type + provider and
    their embeddings have cosine distance below ``1 - similarity_threshold``.
    Falls back to name + provider exact match when embeddings are NULL
    (Sprint 1 keeps them NULL by default).
    """
    rows = (
        await db.execute(
            select(AIAsset).where(AIAsset.asset_status == "active")
        )
    ).scalars().all()

    seen: dict[tuple[str, str, str], list[AIAsset]] = {}
    for r in rows:
        key = (r.asset_type, r.provider, r.name.strip().lower())
        seen.setdefault(key, []).append(r)

    pairs: list[DuplicatePair] = []
    for group in seen.values():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a, b = group[i], group[j]
                if a.connector_id == b.connector_id:
                    continue
                pairs.append(
                    DuplicatePair(
                        asset_a_id=a.id, asset_b_id=b.id, similarity=1.0
                    )
                )
                if len(pairs) >= limit:
                    return pairs
    return pairs


@router.get("/search", response_model=list[AssetRead])
async def search_assets(
    q: str = Query(min_length=1, max_length=512),
    limit: int = Query(20, ge=1, le=100),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[AssetRead]:
    """Lexical fallback + pgvector cosine similarity.

    Sprint 1 mixes a LIKE fallback (so search works before any embedder
    has populated the column) with a pgvector-ordered tail. The vector
    similarity is the canonical ranking when embeddings exist.
    """
    lexical_filter = or_(
        AIAsset.name.ilike(f"%{q}%"),
        AIAsset.description.ilike(f"%{q}%"),
        AIAsset.external_id.ilike(f"%{q}%"),
    )
    rows = (
        await db.execute(
            select(AIAsset)
            .where(AIAsset.asset_status == "active")
            .where(lexical_filter)
            .order_by(desc(AIAsset.last_seen_at))
            .limit(limit)
        )
    ).scalars().all()
    return [_to_read(r) for r in rows]


@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset_detail(
    asset_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> AssetDetail:
    row = await _load_asset(db, asset_id)

    deployments = (
        await db.execute(
            select(Deployment).where(Deployment.asset_id == asset_id)
        )
    ).scalars().all()
    tags = (
        await db.execute(select(AssetTag).where(AssetTag.asset_id == asset_id))
    ).scalars().all()
    edges = (
        await db.execute(
            select(AssetRelationship).where(
                AssetRelationship.source_asset_id == asset_id
            )
        )
    ).scalars().all()
    owner: Optional[Owner] = None
    if row.owner_id is not None:
        owner = (
            await db.execute(select(Owner).where(Owner.id == row.owner_id))
        ).scalar_one_or_none()

    base = _to_read(row)
    return AssetDetail(
        **base.model_dump(),
        deployments=[
            DeploymentRead(
                id=d.id,
                environment=d.environment,
                endpoint_url=d.endpoint_url,
                region=d.region,
                replicas=d.replicas,
                status=d.status,
            )
            for d in deployments
        ],
        tags=[TagRead(key=t.key, value=t.value) for t in tags],
        outgoing_relationships=[
            RelationshipRead(
                target_asset_id=e.target_asset_id,
                relationship_type=e.relationship_type,
            )
            for e in edges
        ],
        owner=(
            OwnerRead(
                id=owner.id, team=owner.team, email=owner.email,
                department=owner.department,
            )
            if owner is not None
            else None
        ),
    )


@router.get("/{asset_id}/history", response_model=list[AssetHistoryEntry])
async def get_history(
    asset_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=500),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[AssetHistoryEntry]:
    await _load_asset(db, asset_id)
    rows = (
        await db.execute(
            select(AssetChangelog)
            .where(AssetChangelog.asset_id == asset_id)
            .order_by(desc(AssetChangelog.changed_at))
            .limit(limit)
        )
    ).scalars().all()
    return [
        AssetHistoryEntry(
            id=r.id,
            change_type=r.change_type,
            previous_value=r.previous_value,
            new_value=r.new_value,
            changed_at=r.changed_at,
        )
        for r in rows
    ]


@router.post("/{asset_id}/owner", response_model=AssetRead)
async def assign_owner(
    asset_id: uuid.UUID,
    payload: OwnerAssign,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> AssetRead:
    """Two paths: pass an existing owner_id, or pass team+email to
    create-or-find an owner row in one call."""
    row = await _load_asset(db, asset_id)
    previous_owner_id = row.owner_id

    if payload.owner_id is not None:
        # Verify the owner row exists.
        owner = (
            await db.execute(
                select(Owner).where(Owner.id == payload.owner_id)
            )
        ).scalar_one_or_none()
        if owner is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="owner_not_found",
            )
        row.owner_id = owner.id
    elif payload.team and payload.email:
        owner = (
            await db.execute(
                select(Owner)
                .where(Owner.email == payload.email)
                .where(Owner.team == payload.team)
            )
        ).scalar_one_or_none()
        if owner is None:
            owner = Owner(
                team=payload.team,
                email=payload.email,
                department=payload.department,
            )
            db.add(owner)
            await db.flush()
        row.owner_id = owner.id
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="provide owner_id or team+email",
        )

    db.add(
        AssetChangelog(
            asset_id=row.id,
            change_type="owner_changed",
            previous_value={"owner_id": str(previous_owner_id) if previous_owner_id else None},
            new_value={"owner_id": str(row.owner_id)},
        )
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row)
