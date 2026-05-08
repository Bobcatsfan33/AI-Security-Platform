"""SCIM 2.0 schema URIs, errors, and shared helpers.

Origin: ported from TokenDNA ``modules/auth/scim.py`` constants and SCIMError.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_SP_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"


@dataclass
class SCIMError(Exception):
    """SCIM-formatted error.

    Routes catch this and serialize via :meth:`to_response` so the IdP
    receives a SCIM-compliant error body.
    """

    status: int
    detail: str
    scimType: str | None = None

    def to_response(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schemas": [SCHEMA_ERROR],
            "status": str(self.status),
            "detail": self.detail,
        }
        if self.scimType:
            body["scimType"] = self.scimType
        return body


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def make_meta(
    *, resource_id: str, resource_type: str, created: str, last_modified: str
) -> dict[str, Any]:
    return {
        "resourceType": resource_type,
        "created": created,
        "lastModified": last_modified,
        "version": f'W/"{uuid.uuid4().hex}"',
        "location": f"/scim/v2/{resource_type}s/{resource_id}",
    }
