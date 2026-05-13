"""Threat intelligence engine — orchestrates clustering + novel detection.

The engine pulls all opted-in tenants' findings, anonymises each one,
runs them through the clusterer, and exposes the resulting clusters
as read-only intel that every tenant can query.

Storage is in-memory for Sprint 9. A future Sprint 10 migration moves
the clusters into a dedicated table so they survive restarts.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.finding import Finding
from app.db.models.organization import Organization
from app.threat_intel.clustering import (
    AttackSample,
    Cluster,
    GreedyClusterer,
    is_novel,
    to_sample,
)

logger = logging.getLogger("platform.threat_intel.engine")


@dataclass
class EngineState:
    clusterer: GreedyClusterer = field(default_factory=GreedyClusterer)
    last_built_at: datetime | None = None
    samples_processed: int = 0
    novel_samples: list[AttackSample] = field(default_factory=list)


_state = EngineState()


def reset_state_for_tests() -> None:
    global _state
    _state = EngineState()


async def rebuild_clusters(db: AsyncSession) -> EngineState:
    """Rebuild the clusterer from scratch over every opt-in finding.

    Idempotent: safe to call as often as needed. Sprint 9 builds the
    clusters in-memory and re-runs them on every API hit; later sprints
    will move this to a periodic job.
    """
    new_state = EngineState()

    opted_in_orgs = await _opted_in_org_ids(db)
    if not opted_in_orgs:
        _replace_state(new_state)
        return new_state

    rows = (
        await db.execute(
            select(Finding).where(Finding.org_id.in_(opted_in_orgs))
        )
    ).scalars().all()

    for row in rows:
        sample = to_sample(
            finding_id=str(row.id),
            org_id=str(row.org_id),
            category=row.category or "unknown",
            severity=row.severity or "info",
            control_mappings=row.control_mappings or [],
            prompt_sent=row.prompt_sent or "",
        )
        existing_clusters = new_state.clusterer.clusters()
        if is_novel(sample, clusters=existing_clusters):
            new_state.novel_samples.append(sample)
        new_state.clusterer.add(sample)
        new_state.samples_processed += 1

    new_state.last_built_at = datetime.now(timezone.utc)
    _replace_state(new_state)
    return new_state


async def _opted_in_org_ids(db: AsyncSession) -> list[uuid.UUID]:
    rows = (await db.execute(select(Organization))).scalars().all()
    return [
        r.id
        for r in rows
        if (r.settings or {}).get("threat_intel_share", False) is True
    ]


def _replace_state(new: EngineState) -> None:
    global _state
    _state = new


def current_state() -> EngineState:
    return _state


def clusters_snapshot() -> list[Cluster]:
    return _state.clusterer.clusters()


def novel_samples_snapshot() -> list[AttackSample]:
    return list(_state.novel_samples)


def cluster_summary() -> list[dict]:
    """Dashboard-friendly summary — top clusters by size."""
    out: list[dict] = []
    for c in clusters_snapshot()[:50]:
        out.append(
            {
                "id": c.id,
                "category": c.category,
                "severity": c.severity,
                "size": c.size,
                "supporting_orgs": len(c.orgs),
                "top_keywords": [t for t, _ in c.keyword_counts.most_common(8)],
                "top_controls": [c for c, _ in c.control_counts.most_common(4)],
                "fingerprint": c.fingerprint(),
            }
        )
    return out
