"""Red Team campaign routes (v2).

Run the attack-strategy library against a target model, judge each response,
and persist the campaign + the findings worth hardening against. The target
(and optional attack-generator / LLM-judge) models are described inline as
connector specs — Red Teaming no longer rides on the dropped v1
``connector_configs`` table.

A live run needs real model credentials behind the ``api_key_ref``; without
them the target connector errors and the campaign is recorded as ``failed``
with the error, never as a fabricated pass.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.connectors.base import ConnectorConfigError
from app.db.models.red_team import RedTeamCampaign, RedTeamFinding
from app.db.session import SessionLocal, get_db
from app.identity.types import IdentityContext
from app.redteam.campaign import CampaignRunner
from app.redteam.generator import AttackGenerator, GenerationRequest
from app.redteam.judge import AttackJudge
from app.redteam.model_connectors import ConnectorSpec, build_model_connector
from app.redteam.service import (
    campaign_summary_from_report,
    finding_rows_from_report,
    score_and_label,
)
from app.redteam.strategies import STRATEGIES, by_id

router = APIRouter(tags=["redteam"])


# ─────────────────────────────────────────────── DTOs


class ConnectorSpecIn(BaseModel):
    provider: str = Field(
        description="openai | anthropic | ollama | azure_openai | bedrock | custom"
    )
    model: str
    api_key_ref: str = Field(default="", description="env:NAME or vault:path — never a raw secret")
    config: dict[str, Any] = Field(default_factory=dict)

    def to_spec(self) -> ConnectorSpec:
        return ConnectorSpec(
            provider=self.provider,
            model=self.model,
            api_key_ref=self.api_key_ref,
            config=self.config,
        )


class CampaignCreate(BaseModel):
    target: ConnectorSpecIn
    asset_id: uuid.UUID | None = None
    asset_description: str = "an AI assistant"
    system_prompt: str = Field(default="", description="The target's system prompt, to red-team.")
    generator: ConnectorSpecIn | None = Field(
        default=None, description="Model for LLM attack generation. None = seed attacks only."
    )
    judge: ConnectorSpecIn | None = Field(
        default=None, description="Model for the LLM judge. None = indicator-scan judging only."
    )
    strategy_ids: list[str] = Field(default_factory=list)
    max_attacks: int | None = Field(default=None, ge=1, le=1000)
    attacks_per_strategy: int = Field(default=2, ge=1, le=10)


class CampaignSummary(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    status: str
    total_attacks: int
    successful_attacks: int
    success_rate: float
    target_errors: int
    score: float
    risk_label: str | None
    total_cost_usd: float
    summary: dict[str, Any]
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None


class FindingOut(BaseModel):
    id: uuid.UUID
    strategy_id: str
    category: str
    severity: str
    classification: str
    compliance_score: float
    confidence: float
    prompt: str
    response: str
    recommendation: str


def _summary(row: RedTeamCampaign) -> CampaignSummary:
    return CampaignSummary(
        id=row.id,
        asset_id=row.asset_id,
        status=row.status,
        total_attacks=row.total_attacks,
        successful_attacks=row.successful_attacks,
        success_rate=row.success_rate,
        target_errors=row.target_errors,
        score=row.score,
        risk_label=row.risk_label,
        total_cost_usd=row.total_cost_usd,
        summary=row.summary or {},
        error_message=row.error_message,
        started_at=row.started_at,
        completed_at=row.completed_at,
    )


# ─────────────────────────────────────────────── background runner


def _resolve_strategies(strategy_ids: list[str]) -> list[Any]:
    if not strategy_ids:
        return list(STRATEGIES)
    return [s for s in (by_id(sid) for sid in strategy_ids) if s is not None]


async def _run_campaign(campaign_id: uuid.UUID, payload: CampaignCreate) -> None:
    async with SessionLocal() as db:
        row = (
            await db.execute(select(RedTeamCampaign).where(RedTeamCampaign.id == campaign_id))
        ).scalar_one_or_none()
        if row is None:
            return
        row.status = "running"
        row.started_at = datetime.now(UTC)
        await db.commit()

        try:
            target = build_model_connector(payload.target.to_spec())
            generator = AttackGenerator(
                generator_connector=(
                    build_model_connector(payload.generator.to_spec())
                    if payload.generator
                    else None
                ),
                attacks_per_strategy=payload.attacks_per_strategy,
            )
            judge = AttackJudge(
                judge_connector=(
                    build_model_connector(payload.judge.to_spec()) if payload.judge else None
                )
            )
            runner = CampaignRunner(target_connector=target, generator=generator, judge=judge)
            request = GenerationRequest(
                asset_id=str(payload.asset_id or ""),
                asset_description=payload.asset_description,
                system_prompt=payload.system_prompt,
            )
            report = await runner.run_campaign(
                request=request,
                strategies=_resolve_strategies(payload.strategy_ids),
                max_attacks=payload.max_attacks,
            )

            for finding in finding_rows_from_report(
                report, org_id=row.org_id, campaign_id=row.id, asset_id=row.asset_id
            ):
                db.add(finding)

            score, label = score_and_label(report.success_rate)
            row.status = "completed"
            row.total_attacks = report.total_attacks
            row.successful_attacks = report.successful_attacks
            row.target_errors = report.target_errors
            row.success_rate = report.success_rate
            row.score = score
            row.risk_label = label
            row.total_cost_usd = report.total_cost_usd
            row.summary = campaign_summary_from_report(report)
            row.completed_at = datetime.now(UTC)
            await db.commit()
        except Exception as exc:
            row.status = "failed"
            row.error_message = str(exc)[:1000]
            row.completed_at = datetime.now(UTC)
            await db.commit()


# ─────────────────────────────────────────────── routes


@router.post("/campaigns", response_model=CampaignSummary, status_code=status.HTTP_201_CREATED)
async def start_campaign(
    payload: CampaignCreate,
    background_tasks: BackgroundTasks,
    identity: IdentityContext = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> CampaignSummary:
    # Validate the connector specs up-front so a bad provider fails fast (400),
    # not silently inside the background task.
    try:
        build_model_connector(payload.target.to_spec())
        if payload.generator:
            build_model_connector(payload.generator.to_spec())
        if payload.judge:
            build_model_connector(payload.judge.to_spec())
    except ConnectorConfigError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    row = RedTeamCampaign(
        id=uuid.uuid4(),
        org_id=identity.org_id,
        asset_id=payload.asset_id,
        status="created",
        strategy_ids=payload.strategy_ids,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    background_tasks.add_task(_run_campaign, row.id, payload)
    return _summary(row)


@router.get("/campaigns", response_model=list[CampaignSummary])
async def list_campaigns(
    asset_id: uuid.UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[CampaignSummary]:
    stmt = select(RedTeamCampaign).where(RedTeamCampaign.org_id == identity.org_id)
    if asset_id:
        stmt = stmt.where(RedTeamCampaign.asset_id == asset_id)
    stmt = stmt.order_by(RedTeamCampaign.created_at.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return [_summary(r) for r in rows]


async def _load_campaign(
    db: AsyncSession, campaign_id: uuid.UUID, org_id: uuid.UUID
) -> RedTeamCampaign:
    row = (
        await db.execute(
            select(RedTeamCampaign).where(
                RedTeamCampaign.id == campaign_id, RedTeamCampaign.org_id == org_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="campaign_not_found")
    return row


@router.get("/campaigns/{campaign_id}", response_model=CampaignSummary)
async def get_campaign(
    campaign_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> CampaignSummary:
    return _summary(await _load_campaign(db, campaign_id, identity.org_id))


@router.get("/campaigns/{campaign_id}/findings", response_model=list[FindingOut])
async def list_findings(
    campaign_id: uuid.UUID,
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> list[FindingOut]:
    await _load_campaign(db, campaign_id, identity.org_id)
    rows = (
        (
            await db.execute(
                select(RedTeamFinding)
                .where(
                    RedTeamFinding.campaign_id == campaign_id,
                    RedTeamFinding.org_id == identity.org_id,
                )
                .order_by(RedTeamFinding.compliance_score.desc())
            )
        )
        .scalars()
        .all()
    )
    return [
        FindingOut(
            id=r.id,
            strategy_id=r.strategy_id,
            category=r.category,
            severity=r.severity,
            classification=r.classification,
            compliance_score=r.compliance_score,
            confidence=r.confidence,
            prompt=r.prompt,
            response=r.response,
            recommendation=r.recommendation,
        )
        for r in rows
    ]


@router.get("/strategies", response_model=list[dict[str, Any]])
async def list_strategies(
    identity: IdentityContext = Depends(require_role("viewer")),
) -> list[dict[str, Any]]:
    return [
        {
            "id": s.id,
            "category": s.category,
            "name": s.name,
            "description": s.description,
            "severity": s.severity,
            "attack_type": s.attack_type,
        }
        for s in STRATEGIES
    ]
