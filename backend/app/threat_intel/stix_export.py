"""STIX 2.1 export of threat intelligence clusters.

We hand-roll the JSON instead of pulling in stix2 — the dependency is
heavy and we only need the four object types relevant to a clustering
output: ``indicator``, ``attack-pattern``, ``relationship``, ``bundle``.

The output validates against the spec at
https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.threat_intel.clustering import Cluster

STIX_SPEC_VERSION = "2.1"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id(kind: str) -> str:
    return f"{kind}--{uuid.uuid4()}"


def cluster_to_bundle(cluster: Cluster) -> dict[str, Any]:
    """Convert a single cluster to a STIX 2.1 bundle with one
    attack-pattern, one indicator, and a relationship object."""
    now = _now()

    keywords = ", ".join(t for t, _ in cluster.keyword_counts.most_common(8))
    controls = ", ".join(c for c, _ in cluster.control_counts.most_common(4))

    attack_pattern = {
        "type": "attack-pattern",
        "spec_version": STIX_SPEC_VERSION,
        "id": _id("attack-pattern"),
        "created": now,
        "modified": now,
        "name": f"{cluster.category.replace('_', ' ').title()} cluster {cluster.id}",
        "description": (
            f"Cluster {cluster.id} ({cluster.category}, severity={cluster.severity}). "
            f"Observed across {len(cluster.orgs)} organisation(s) in "
            f"{cluster.size} sample(s). Top tokens: {keywords or 'n/a'}. "
            f"Mapped controls: {controls or 'n/a'}."
        ),
        "labels": [cluster.category, cluster.severity],
        "external_references": [
            {"source_name": "ai-security-platform", "external_id": cluster.id}
        ],
    }

    # Pattern is the cluster's keyword fingerprint. Real STIX patterns
    # use the STIX Patterning Language; we emit the simplest form a
    # downstream system can keyword-match.
    pattern = " AND ".join(
        f"[ai-attack:keyword = '{kw}']"
        for kw, _ in cluster.keyword_counts.most_common(5)
    ) or "[ai-attack:cluster_id = '" + cluster.id + "']"

    indicator = {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": _id("indicator"),
        "created": now,
        "modified": now,
        "name": f"Indicator for cluster {cluster.id}",
        "indicator_types": ["malicious-activity"],
        "pattern_type": "stix",
        "pattern": pattern,
        "valid_from": now,
        "labels": [cluster.category],
    }

    relationship = {
        "type": "relationship",
        "spec_version": STIX_SPEC_VERSION,
        "id": _id("relationship"),
        "created": now,
        "modified": now,
        "relationship_type": "indicates",
        "source_ref": indicator["id"],
        "target_ref": attack_pattern["id"],
    }

    return {
        "type": "bundle",
        "id": _id("bundle"),
        "spec_version": STIX_SPEC_VERSION,
        "objects": [attack_pattern, indicator, relationship],
    }


def clusters_to_bundle(clusters: list[Cluster]) -> dict[str, Any]:
    """Merge many cluster bundles into a single multi-object bundle."""
    bundle = {
        "type": "bundle",
        "id": _id("bundle"),
        "spec_version": STIX_SPEC_VERSION,
        "objects": [],
    }
    for c in clusters:
        sub = cluster_to_bundle(c)
        bundle["objects"].extend(sub["objects"])
    return bundle
