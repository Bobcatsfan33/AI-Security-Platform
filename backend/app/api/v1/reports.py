"""Report generation routes.

Two formats:

  GET /v1/reports/{eval_id}?template=executive_summary
      → Markdown (text/markdown)

  GET /v1/reports/{eval_id}?template=executive_summary&format=pdf
      → PDF (application/pdf). Requires weasyprint + markdown optional
      deps; returns 501 with a clear message when absent.

Templates: executive_summary | technical_detail | owasp_llm_top10 |
nist_ai_rmf | soc2_ai | eu_ai_act.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_role
from app.db.models.ai_asset import AIAsset
from app.db.models.evaluation import Evaluation
from app.db.models.finding import Finding
from app.db.models.organization import Organization
from app.db.session import get_db
from app.identity.types import IdentityContext
from app.reports.builder import build_report, render_pdf

router = APIRouter(tags=["reports"])

TemplateName = Literal[
    "executive_summary",
    "technical_detail",
    "owasp_llm_top10",
    "nist_ai_rmf",
    "soc2_ai",
    "eu_ai_act",
]


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": str(f.id),
        "title": f.title,
        "category": f.category,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "confidence": f.confidence,
        "remediation_status": f.remediation_status,
        "control_mappings": list(f.control_mappings or []),
        "prompt_sent": f.prompt_sent,
        "response_received": f.response_received,
        "judge_reasoning": f.judge_reasoning,
        "recommendation": f.recommendation,
    }


def _asset_to_dict(a: AIAsset) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "name": a.name,
        "provider": a.provider,
        "model_name": a.model_name,
        "environment": a.environment,
        "exposure": a.exposure,
        "data_classification": a.data_classification,
        "system_prompt": a.system_prompt,
        "tools": a.tools or [],
        "rag_sources": a.rag_sources or [],
        "regulatory_scope": a.regulatory_scope or [],
        "human_in_loop_required": a.human_in_loop_required,
    }


def _evaluation_to_dict(e: Evaluation) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "score": e.score,
        "risk_label": e.risk_label,
        "tests_run": e.tests_run,
        "tests_passed": e.tests_passed,
        "tests_failed": e.tests_failed,
        "findings_count": e.findings_count,
        "critical_findings": e.critical_findings,
        "model_cost_usd": e.model_cost_usd,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "completed_at": e.completed_at.isoformat() if e.completed_at else None,
    }


@router.get("/{evaluation_id}")
async def get_report(
    evaluation_id: uuid.UUID,
    template: TemplateName = Query("executive_summary"),
    format: Literal["markdown", "pdf"] = Query("markdown"),
    identity: IdentityContext = Depends(require_role("viewer")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Render a report for one evaluation.

    The evaluation must belong to the caller's org. Cross-tenant access
    returns 404 (same as every other tenant-scoped route).
    """
    eval_row = (
        await db.execute(
            select(Evaluation).where(
                Evaluation.id == evaluation_id,
                Evaluation.org_id == identity.org_id,
            )
        )
    ).scalar_one_or_none()
    if eval_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")

    asset = (
        await db.execute(select(AIAsset).where(AIAsset.id == eval_row.asset_id))
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="asset_for_evaluation_not_found",
        )

    findings_rows = (
        await db.execute(
            select(Finding).where(Finding.evaluation_id == evaluation_id)
        )
    ).scalars().all()

    org = (
        await db.execute(
            select(Organization).where(Organization.id == identity.org_id)
        )
    ).scalar_one_or_none()
    org_name = org.name if org else ""

    markdown = build_report(
        template=template,
        asset=_asset_to_dict(asset),
        evaluation=_evaluation_to_dict(eval_row),
        findings=[_finding_to_dict(f) for f in findings_rows],
        org_name=org_name,
    )

    if format == "markdown":
        return Response(
            content=markdown,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f'inline; filename="{template}-{evaluation_id}.md"'
                )
            },
        )

    # PDF
    try:
        pdf_bytes = render_pdf(markdown)
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(exc),
        ) from exc
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{template}-{evaluation_id}.pdf"'
            )
        },
    )
