"""aibom FUNCTION against a REAL asset row — proven before the mount (GAP-001).

Phase 0 graded aibom as "3 endpoints" and it would have AttributeError'd on the
first request: its glue read typed columns the v2.0 pivot deleted. The lesson
(siem mounted but couldn't deliver a byte; aibom "reachable" but non-functional)
is that FUNCTION is the bar, not reachability. So this proves every aibom
computation works against a real ``AIAsset`` row — a genuine ``metadata_json``
JSONB round-trip through Postgres — BEFORE the router is mounted. The HTTP +
tenant-isolation tests come with the mount commit.

Postgres-backed; skips locally without a database, runs in CI.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text

from app.aibom.blast_radius import compute_blast_radius
from app.aibom.builder import build_bom
from app.aibom.drift import compute_drift
from app.aibom.risk import score_supply_chain
from app.api.v1.aibom import _asset_to_dict
from app.db.models.ai_asset import AIAsset
from app.db.models.connector import Connector
from app.db.models.organization import Organization
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def asset_factory() -> AsyncIterator:
    """Insert a real org + connector, and hand back a coroutine that inserts an
    AIAsset with a chosen metadata_json. Everything CASCADE-cleans on the org."""
    org_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    async with SessionLocal() as db:
        db.add(Organization(id=org_id, name="aibom-org", slug=f"aibom-{uuid.uuid4().hex[:8]}"))
        await db.flush()
        db.add(
            Connector(
                id=connector_id,
                org_id=org_id,
                name="c",
                connector_type="mock",
                config_encrypted={},
                is_enabled=True,
            )
        )
        await db.commit()

    created: list[uuid.UUID] = []

    async def _make(metadata: dict) -> AIAsset:
        aid = uuid.uuid4()
        async with SessionLocal() as db:
            db.add(
                AIAsset(
                    id=aid,
                    org_id=org_id,
                    name="asset",
                    asset_type="agent",
                    provider="openai",
                    external_id=f"ext-{aid.hex[:8]}",
                    connector_id=connector_id,
                    metadata_json=metadata,
                )
            )
            await db.commit()
        created.append(aid)
        async with SessionLocal() as db:
            return (
                await db.execute(
                    text("SELECT * FROM ai_assets WHERE id = :id"), {"id": aid}
                )
            ).mappings().one()

    yield _make

    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": org_id})
        await db.commit()


async def _row(asset_id: uuid.UUID) -> AIAsset:
    """Load the ORM row so _asset_to_dict sees a real AIAsset with a real
    metadata_json that survived a JSONB round-trip."""
    from sqlalchemy import select

    async with SessionLocal() as db:
        return (
            await db.execute(select(AIAsset).where(AIAsset.id == asset_id))
        ).scalar_one()


# ─────────────────────────────────────────── the honest-empty case, for real


async def test_all_four_computations_run_on_a_bare_real_asset(asset_factory) -> None:
    """The case Phase 0's audit would have crashed on: a real row whose
    metadata_json is empty. Every computation must produce an honest result, not
    an AttributeError and not a fabricated number."""
    created = await asset_factory({})
    row = await _row(created["id"])

    asset = _asset_to_dict(row)
    assert asset["id"] == str(created["id"])
    assert "provider" in asset

    # None of these raise; blast radius is low with reasons stating absence.
    assert build_bom(asset) is not None
    assert score_supply_chain(asset).score >= 0.0
    assert compute_drift(current=asset, baseline=None) is not None

    br = compute_blast_radius(asset)
    assert br.severity == "low"
    reasons = {f.name: f.detail for f in br.factors}
    assert reasons["tool_reach"] == "no tool grants recorded"
    assert reasons["downstream_fanout"] == "no downstream connections known"


async def test_metadata_with_only_unknown_keys_invents_nothing(asset_factory) -> None:
    """Permissive-when-missing, end to end: a real metadata_json of only unknown
    keys must yield the same blast radius as an empty one — nothing invented from
    a key the model does not understand."""
    junk = await asset_factory({"wibble": 1, "unknown": ["x"], "notes": "hi"})
    empty = await asset_factory({})

    a = compute_blast_radius(_asset_to_dict(await _row(junk["id"])))
    b = compute_blast_radius(_asset_to_dict(await _row(empty["id"])))
    # asset_id differs; compare the computed substance.
    assert a.score == b.score
    assert [f.detail for f in a.factors] == [f.detail for f in b.factors]


# ─────────────────────────────────────────── the rich case, for real


async def test_rich_agentic_asset_reads_its_metadata(asset_factory) -> None:
    created = await asset_factory(
        {
            "is_agentic": True,
            "human_in_loop_required": False,
            "max_tool_calls_per_session": 500,
            "tools": ["shell", "http"],
            "mcp_servers": ["fs"],
            "allowed_external_actions": ["send_email", "wire_transfer"],
            "downstream_consumers": ["billing", "crm"],
            "exposure": "public",
            "data_classification": "restricted",
        }
    )
    br = compute_blast_radius(_asset_to_dict(await _row(created["id"])))

    assert br.severity in ("high", "critical")
    assert br.reach["downstream_consumers"] == ["billing", "crm"]
    assert br.reach["autonomy"]["is_agentic"] is True
    assert "no external actions granted" not in [f.detail for f in br.factors]


async def test_blast_radius_is_deterministic_across_reloads(asset_factory) -> None:
    """Same stored row, reloaded and recomputed twice, is byte-identical — the
    property a design partner relies on when they rerun the number."""
    created = await asset_factory(
        {"is_agentic": True, "tools": ["a", "b"], "downstream_consumers": ["y", "x"]}
    )
    first = compute_blast_radius(_asset_to_dict(await _row(created["id"])))
    second = compute_blast_radius(_asset_to_dict(await _row(created["id"])))
    assert first == second
