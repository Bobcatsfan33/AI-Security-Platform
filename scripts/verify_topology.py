#!/usr/bin/env python3
"""Check a RENDERED Kubernetes topology against the HA/DR runbook's claims.

The runbook says things like "RF >= 3", "primary plus replica", "anti-affinity
so replicas span nodes". Those were prose. This reads the manifests that will
actually be applied and decides whether the prose is true of them.

Deliberately operates on rendered YAML rather than on Helm values. Values are
an input to a template; what reaches the cluster is the output, and the gap
between the two is exactly where a conditional silently drops a
PodDisruptionBudget. Rendering first also means this works on kustomize output,
a hand-written manifest, or `kubectl get -o yaml` from a live cluster.

Usage:
    helm template cell deploy/helm/aisp-data-tier -f values.yaml > cell.yaml
    python3 scripts/verify_topology.py cell.yaml [more.yaml ...]
    python3 scripts/verify_topology.py --profile control-plane rendered.yaml

Exit 0 when every check passes; 1 with a report otherwise.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass, field

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised by the CI bootstrap
    sys.exit("verify_topology.py needs PyYAML (pip install pyyaml)")

# An image reference is acceptable only as repo@sha256:<64 hex>. Anything else
# is mutable: `:latest` obviously, but also `:v24.2.7`, which a registry owner
# can re-point at different bytes whenever they like. Evidence that names a
# mutable reference is evidence about nothing in particular.
_DIGEST_REF = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")

# Env var names that must never carry a literal value. Matched on the NAME, so
# a rename to something creative still has to get past review rather than past
# a regex on the value.
_SECRET_NAME_HINT = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL|_KEY$|^KEY$)",
    re.IGNORECASE,
)

# Values that look like credential material wherever they appear.
_SECRET_VALUE_HINT = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)

# Connection strings with an inline password: postgresql://user:pw@host.
# The capture deliberately excludes the empty password and common placeholders
# so a documented example does not read as a leak.
_INLINE_CREDENTIAL = re.compile(r"://[^:/\s]+:([^@/\s]+)@")
_PLACEHOLDER = frozenset(
    {"", "password", "changeme", "placeholder", "example", "redacted", "xxx", "..."}
)

_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet"})


@dataclass
class Component:
    """One HA claim, expressed as the numbers a manifest must show."""

    label: str
    min_replicas: int
    needs_pdb: bool = True
    needs_hard_anti_affinity: bool = False
    needs_liveness: bool = True
    # Readiness gates TRAFFIC. A component nothing routes to has no use for
    # one, and demanding it would push someone to add a probe whose result no
    # controller reads — a green check standing in for a guarantee.
    needs_readiness: bool = True
    annotations: dict[str, int] = field(default_factory=dict)


# The data tier. Every floor here restates a line from docs/HA-DR-RUNBOOK.md.
DATA_TIER = (
    Component("postgres", min_replicas=2, needs_hard_anti_affinity=True),
    Component("redis", min_replicas=2, needs_hard_anti_affinity=True),
    Component("redis-sentinel", min_replicas=3, needs_hard_anti_affinity=True),
    Component("clickhouse", min_replicas=2, needs_hard_anti_affinity=True),
    Component("clickhouse-keeper", min_replicas=3, needs_hard_anti_affinity=True),
    Component(
        "redpanda",
        min_replicas=3,
        needs_hard_anti_affinity=True,
        annotations={
            "aisp.io/topic-replication-factor": 3,
            "aisp.io/min-insync-replicas": 2,
        },
    ),
)

# The control plane. Stateless, so anti-affinity is soft (see the chart helper)
# and this does not demand the hard form.
CONTROL_PLANE = (
    Component("api", min_replicas=2),
    # Liveness only: nothing routes to the consumer, so a readiness probe
    # would report a state no controller reads. See the chart's heartbeat note.
    Component("epa-consumer", min_replicas=2, needs_readiness=False),
)

PROFILES = {"data-tier": DATA_TIER, "control-plane": CONTROL_PLANE}


def _load(paths: list[pathlib.Path]) -> list[dict]:
    docs: list[dict] = []
    for path in paths:
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(doc, dict) and doc.get("kind"):
                docs.append(doc)
    return docs


def _containers(doc: dict) -> list[dict]:
    """Every container in a workload, a bare Pod, or a CronJob's nested spec."""
    spec = doc.get("spec") or {}
    pod_specs = []
    if doc.get("kind") == "CronJob":
        pod_specs.append(
            ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template", {}).get("spec", {})
        )
    elif doc.get("kind") == "Pod":
        pod_specs.append(spec)
    else:
        pod_specs.append((spec.get("template") or {}).get("spec") or {})
    out: list[dict] = []
    for pod in pod_specs:
        if not isinstance(pod, dict):
            continue
        out.extend(pod.get("containers") or [])
        out.extend(pod.get("initContainers") or [])
    return out


def _pod_spec(doc: dict) -> dict:
    spec = doc.get("spec") or {}
    if doc.get("kind") == "CronJob":
        return ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template", {}).get(
            "spec", {}
        ) or {}
    if doc.get("kind") == "Pod":
        return spec
    return (spec.get("template") or {}).get("spec") or {}


def _component_of(doc: dict) -> str | None:
    labels = ((doc.get("metadata") or {}).get("labels")) or {}
    return labels.get("app.kubernetes.io/component")


def check_images_are_digest_pinned(docs: list[dict]) -> list[str]:
    problems = []
    for doc in docs:
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")
        for container in _containers(doc):
            image = container.get("image", "")
            if not _DIGEST_REF.match(image):
                problems.append(
                    f"{doc['kind']}/{name} container {container.get('name')!r} uses "
                    f"a mutable image reference {image!r}; require repo@sha256:<64 hex>"
                )
    return problems


def check_no_plaintext_secrets(docs: list[dict]) -> list[str]:
    problems = []
    for doc in docs:
        kind = doc.get("kind")
        name = (doc.get("metadata") or {}).get("name", "<unnamed>")

        if kind == "Secret":
            # A rendered Secret means credential material is sitting in the
            # manifest, in CI logs, and in whatever reviewed the diff.
            for key in ("data", "stringData"):
                for field_name in (doc.get(key) or {}):
                    problems.append(
                        f"Secret/{name} carries literal {key}.{field_name}; supply it from "
                        "an externally managed Secret (secretKeyRef) instead"
                    )

        for container in _containers(doc):
            for env in container.get("env") or []:
                env_name = env.get("name", "")
                value = env.get("value")
                if value is None:
                    continue
                text = str(value)
                if _SECRET_NAME_HINT.search(env_name):
                    problems.append(
                        f"{kind}/{name} env {env_name} has a literal value; "
                        "use valueFrom.secretKeyRef"
                    )
                    continue
                if _SECRET_VALUE_HINT.search(text):
                    problems.append(
                        f"{kind}/{name} env {env_name} contains credential-shaped material"
                    )
                    continue
                match = _INLINE_CREDENTIAL.search(text)
                if match and match.group(1).lower() not in _PLACEHOLDER:
                    problems.append(
                        f"{kind}/{name} env {env_name} embeds a password in a connection URL"
                    )
    return problems


def check_topology(docs: list[dict], components: tuple[Component, ...]) -> list[str]:
    problems = []
    workloads = {
        _component_of(d): d for d in docs if d.get("kind") in _WORKLOAD_KINDS and _component_of(d)
    }
    # Match a PDB by what it SELECTS, not by its own labels. A PDB's whole
    # meaning is its selector, and charts routinely leave component labels off
    # the PDB object itself — keying on metadata would report a missing budget
    # that is sitting right there, protecting the workload correctly.
    pdb_components = set()
    for doc in docs:
        if doc.get("kind") != "PodDisruptionBudget":
            continue
        selector = ((doc.get("spec") or {}).get("selector") or {}).get("matchLabels") or {}
        component = selector.get("app.kubernetes.io/component") or _component_of(doc)
        if component:
            pdb_components.add(component)

    # An HPA's minReplicas is the real floor for anything it governs: the
    # Deployment omits spec.replicas precisely so the autoscaler can own it,
    # and reading the absent field as "zero replicas" would fail a correctly
    # configured, highly available service.
    hpa_floor: dict[str, int] = {}
    for doc in docs:
        if doc.get("kind") != "HorizontalPodAutoscaler":
            continue
        spec = doc.get("spec") or {}
        target_name = (spec.get("scaleTargetRef") or {}).get("name")
        minimum = spec.get("minReplicas")
        if target_name is None or minimum is None:
            continue
        for component, workload in workloads.items():
            if (workload.get("metadata") or {}).get("name") == target_name:
                hpa_floor[component] = int(minimum)

    for component in components:
        doc = workloads.get(component.label)
        if doc is None:
            problems.append(f"{component.label}: no Deployment/StatefulSet found")
            continue
        declared = (doc.get("spec") or {}).get("replicas")
        autoscaled = hpa_floor.get(component.label)
        effective = max(
            int(declared) if declared is not None else 0,
            autoscaled if autoscaled is not None else 0,
        )
        if effective < component.min_replicas:
            detail = f"replicas={declared}"
            if autoscaled is not None:
                detail += f", hpa.minReplicas={autoscaled}"
            problems.append(f"{component.label}: {detail}, needs >= {component.min_replicas}")

        if component.needs_pdb and component.label not in pdb_components:
            problems.append(
                f"{component.label}: no PodDisruptionBudget — a node drain may take "
                "the whole component down at once"
            )

        affinity = (_pod_spec(doc).get("affinity") or {}).get("podAntiAffinity") or {}
        hard = affinity.get("requiredDuringSchedulingIgnoredDuringExecution")
        soft = affinity.get("preferredDuringSchedulingIgnoredDuringExecution")
        if component.needs_hard_anti_affinity:
            if not hard:
                problems.append(
                    f"{component.label}: needs REQUIRED pod anti-affinity — a stateful "
                    "replica co-scheduled with its primary cannot survive the node"
                )
        elif not (hard or soft):
            problems.append(f"{component.label}: no pod anti-affinity")

        required_probes = [
            probe
            for probe, needed in (
                ("readinessProbe", component.needs_readiness),
                ("livenessProbe", component.needs_liveness),
            )
            if needed
        ]
        for container in _containers(doc):
            for probe in required_probes:
                if not container.get(probe):
                    problems.append(
                        f"{component.label}: container {container.get('name')!r} has no {probe}"
                    )

        for key, minimum in component.annotations.items():
            raw = ((doc.get("metadata") or {}).get("annotations") or {}).get(key)
            if raw is None:
                problems.append(f"{component.label}: missing annotation {key}")
            elif int(raw) < minimum:
                problems.append(f"{component.label}: {key}={raw}, needs >= {minimum}")

    return problems


def run(paths: list[pathlib.Path], profile: str) -> list[tuple[str, list[str]]]:
    docs = _load(paths)
    if not docs:
        return [("manifests parsed", ["no Kubernetes documents found in the given files"])]
    return [
        ("images are digest-pinned", check_images_are_digest_pinned(docs)),
        ("no plaintext secrets", check_no_plaintext_secrets(docs)),
        (f"{profile} topology floors", check_topology(docs, PROFILES[profile])),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="+", type=pathlib.Path)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="data-tier")
    args = parser.parse_args()

    failed = False
    for title, problems in run(args.manifests, args.profile):
        if problems:
            failed = True
            print(f"FAIL  {title}")
            for problem in problems:
                print(f"        - {problem}")
        else:
            print(f"ok    {title}")
    if failed:
        print("\ntopology verification FAILED", file=sys.stderr)
        return 1
    print("\ntopology verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
