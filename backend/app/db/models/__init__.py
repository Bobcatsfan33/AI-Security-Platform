"""Aggregator: import all model modules so SQLAlchemy registers them on Base.metadata."""

from app.db.models.ai_asset import AIAsset
from app.db.models.api_key import ApiKey
from app.db.models.evaluation import Evaluation
from app.db.models.finding import Finding
from app.db.models.idp_config import IdpConfig
from app.db.models.organization import Organization
from app.db.models.policy import Policy
from app.db.models.test_case import TestCase
from app.db.models.user import User

__all__ = [
    "Organization",
    "User",
    "ApiKey",
    "IdpConfig",
    "AIAsset",
    "TestCase",
    "Evaluation",
    "Finding",
    "Policy",
]
