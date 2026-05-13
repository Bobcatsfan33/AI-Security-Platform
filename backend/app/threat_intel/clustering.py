"""Attack pattern clustering.

Findings from many tenants are anonymised and projected into a small
feature space (category + control mappings + a bag-of-keywords from
the redacted prompt). Two findings cluster together when their
features overlap above a threshold.

We use Jaccard similarity over token sets — robust to length variation
and trivial to compute without a heavy ML dependency. For Sprint 9 this
is sufficient; an embedding-based clusterer is a future replacement
behind the :class:`Clusterer` Protocol.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Protocol

from app.threat_intel.anonymize import hash_id, redact_text

logger = logging.getLogger("platform.threat_intel.clustering")

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


@dataclass(frozen=True)
class AttackSample:
    """A single anonymised finding ready to be clustered."""

    finding_hash: str           # HMAC hash of the original finding ID
    org_hash: str               # HMAC hash of org_id
    category: str               # e.g. prompt_injection, pii_leakage
    severity: str
    control_mappings: tuple[str, ...]
    keywords: frozenset[str]    # tokens from the redacted prompt


@dataclass
class Cluster:
    id: str
    samples: list[AttackSample] = field(default_factory=list)
    orgs: set[str] = field(default_factory=set)
    keyword_counts: Counter[str] = field(default_factory=Counter)
    control_counts: Counter[str] = field(default_factory=Counter)
    category: str = ""
    severity: str = ""

    @property
    def size(self) -> int:
        return len(self.samples)

    def fingerprint(self) -> str:
        # The "signature" tokens are the most common keywords across
        # samples — these become the cluster's anchor for matching
        # incoming findings.
        return ",".join(t for t, _ in self.keyword_counts.most_common(8))


class Clusterer(Protocol):
    def add(self, sample: AttackSample) -> Cluster: ...
    def clusters(self) -> list[Cluster]: ...


# ─────────────────────────────────────────── extraction


def to_sample(
    *,
    finding_id: str,
    org_id: str,
    category: str,
    severity: str,
    control_mappings: Iterable[str],
    prompt_sent: str,
) -> AttackSample:
    redacted = redact_text(prompt_sent or "")
    keywords = frozenset(
        m.group(0).lower()
        for m in _TOKEN_RE.finditer(redacted)
        if not m.group(0).startswith("[REDACTED")
    )
    return AttackSample(
        finding_hash=hash_id(finding_id),
        org_hash=hash_id(org_id),
        category=category,
        severity=severity,
        control_mappings=tuple(sorted(set(control_mappings))),
        keywords=keywords,
    )


# ─────────────────────────────────────────── similarity


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


# ─────────────────────────────────────────── greedy clusterer


class GreedyClusterer:
    """Online clusterer. Each new sample joins the most similar existing
    cluster if the similarity exceeds ``threshold``; otherwise it seeds
    a new cluster. Category must match for two samples to be in the
    same cluster (we don't merge prompt_injection with pii_leakage)."""

    def __init__(self, *, threshold: float = 0.3) -> None:
        self._threshold = threshold
        self._clusters: dict[str, Cluster] = {}
        self._next_id = 1

    def add(self, sample: AttackSample) -> Cluster:
        best: Cluster | None = None
        best_score = 0.0
        for c in self._clusters.values():
            if c.category != sample.category:
                continue
            score = self._similarity_to_cluster(c, sample)
            if score > best_score:
                best_score = score
                best = c
        if best is None or best_score < self._threshold:
            cid = f"c-{self._next_id:06d}"
            self._next_id += 1
            best = Cluster(id=cid, category=sample.category, severity=sample.severity)
            self._clusters[cid] = best
        self._merge(best, sample)
        return best

    def clusters(self) -> list[Cluster]:
        return sorted(self._clusters.values(), key=lambda c: c.size, reverse=True)

    @staticmethod
    def _similarity_to_cluster(cluster: Cluster, sample: AttackSample) -> float:
        # Compare sample to the cluster's top-keyword fingerprint.
        cluster_top = frozenset(
            t for t, _ in cluster.keyword_counts.most_common(20)
        )
        return jaccard(cluster_top, sample.keywords)

    @staticmethod
    def _merge(cluster: Cluster, sample: AttackSample) -> None:
        cluster.samples.append(sample)
        cluster.orgs.add(sample.org_hash)
        for kw in sample.keywords:
            cluster.keyword_counts[kw] += 1
        for c in sample.control_mappings:
            cluster.control_counts[c] += 1
        # Severity climbs but never decreases
        cluster.severity = _max_severity(cluster.severity, sample.severity)


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


# ─────────────────────────────────────────── novel detection


def is_novel(
    sample: AttackSample,
    *,
    clusters: list[Cluster],
    min_supporting_orgs: int = 3,
    threshold: float = 0.3,
) -> bool:
    """A finding is *novel* when it doesn't match any cluster supported
    by at least ``min_supporting_orgs`` distinct orgs. Single-org
    clusters don't suppress novelty — that's how we surface the first
    appearance of an emerging attack across customers."""
    for c in clusters:
        if c.category != sample.category:
            continue
        if len(c.orgs) < min_supporting_orgs:
            continue
        if GreedyClusterer._similarity_to_cluster(c, sample) >= threshold:
            return False
    return True
