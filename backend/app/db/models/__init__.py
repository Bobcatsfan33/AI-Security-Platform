"""Aggregator: import all model modules so SQLAlchemy registers them on Base.metadata.

v2.0 pivot — governance models (Policy, Evaluation, Finding, TestCase,
McpCall, McpToolProfile, McpViolation, ConnectorConfig) and their tables
were dropped. The v2 surface is the asset graph: connectors,
ai_assets, owners, deployments, sync_jobs, asset_tags,
asset_relationships, asset_changelog. Auth-side models (Organization,
User, ApiKey, IdpConfig) are preserved.

Governance revival — ``Policy`` (migration 0007), and now the four
``Evaluation`` / ``Finding`` / ``TestCase`` / ``ConnectorConfig`` governance
models (migration 0008) are back, reintroduced against the v1 DDL from
migrations 0001/0002 and marked TenantScoped. The dropped ``mcp`` models
remain out (their page has no revival yet — see the quarantine manifest in
``tests/unit/test_no_broken_imports.py``).
"""

from app.db.models.ai_asset import AIAsset
from app.db.models.api_key import ApiKey
from app.db.models.asset_changelog import AssetChangelog
from app.db.models.asset_relationship import AssetRelationship
from app.db.models.asset_tag import AssetTag
from app.db.models.connector import Connector
from app.db.models.connector_config import ConnectorConfig
from app.db.models.deployment import Deployment
from app.db.models.evaluation import Evaluation
from app.db.models.finding import Finding
from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.models.owner import Owner
from app.db.models.policy import Policy
from app.db.models.red_team import RedTeamCampaign, RedTeamFinding
from app.db.models.sync_job import SyncJob
from app.db.models.test_case import TestCase
from app.db.models.user import User

__all__ = [
    "Organization",
    "User",
    "ApiKey",
    "IdpConfig",
    "Connector",
    "ConnectorConfig",
    "Owner",
    "AIAsset",
    "Deployment",
    "SyncJob",
    "AssetTag",
    "AssetRelationship",
    "AssetChangelog",
    "Policy",
    "Evaluation",
    "Finding",
    "TestCase",
    "RedTeamCampaign",
    "RedTeamFinding",
]
