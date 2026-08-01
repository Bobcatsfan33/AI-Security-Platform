"""The topology verifier must catch what it claims to catch.

A checker that passes everything is indistinguishable from no checker at all,
and it is worse than none because it produces a green line in a report. So each
rule here gets a manifest that violates exactly it, and the rule is required to
notice — plus a clean manifest that all the rules are required to accept.

Fixtures are built in Python rather than rendered by Helm so these run with no
toolchain: the chart is checked against the REAL renderer in the CI helm job
(see .github/workflows/ci.yml), and this file checks the rules themselves.
"""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys

import pytest
import yaml

pytestmark = pytest.mark.unit

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "verify_topology.py"


def _load_verifier():
    """Import scripts/verify_topology.py, which is not on the package path.

    The sys.modules registration is load-bearing, not hygiene: @dataclass
    resolves annotations by looking its own class's module up in sys.modules,
    and finds None if the module is executed before it is registered.
    """
    spec = importlib.util.spec_from_file_location("verify_topology", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vt = _load_verifier()

DIGEST = "sha256:" + "a" * 64


def _statefulset(component: str, replicas: int, *, hard_affinity: bool = True) -> dict:
    affinity_key = (
        "requiredDuringSchedulingIgnoredDuringExecution"
        if hard_affinity
        else "preferredDuringSchedulingIgnoredDuringExecution"
    )
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": f"cell-{component}",
            "labels": {"app.kubernetes.io/component": component},
            "annotations": {
                "aisp.io/topic-replication-factor": "3",
                "aisp.io/min-insync-replicas": "2",
            },
        },
        "spec": {
            "replicas": replicas,
            "template": {
                "spec": {
                    "affinity": {"podAntiAffinity": {affinity_key: [{"topologyKey": "hostname"}]}},
                    "containers": [
                        {
                            "name": component,
                            "image": f"registry.example/{component}@{DIGEST}",
                            "readinessProbe": {"tcpSocket": {"port": 1}},
                            "livenessProbe": {"tcpSocket": {"port": 1}},
                        }
                    ],
                }
            },
        },
    }


def _pdb(component: str) -> dict:
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {"name": f"cell-{component}"},
        "spec": {
            "minAvailable": 1,
            "selector": {"matchLabels": {"app.kubernetes.io/component": component}},
        },
    }


def _healthy_data_tier() -> list[dict]:
    docs: list[dict] = []
    for component, replicas in (
        ("postgres", 2),
        ("redis", 2),
        ("redis-sentinel", 3),
        ("clickhouse", 2),
        ("clickhouse-keeper", 3),
        ("redpanda", 3),
    ):
        docs.append(_statefulset(component, replicas))
        docs.append(_pdb(component))
    return docs


def _write(tmp_path: pathlib.Path, docs: list[dict]) -> list[pathlib.Path]:
    path = tmp_path / "rendered.yaml"
    path.write_text(yaml.safe_dump_all(docs), encoding="utf-8")
    return [path]


def _problems(tmp_path, docs, profile="data-tier") -> list[str]:
    return [p for _, problems in vt.run(_write(tmp_path, docs), profile) for p in problems]


def _find(docs: list[dict], component: str) -> dict:
    return next(
        d
        for d in docs
        if d["kind"] == "StatefulSet"
        and d["metadata"]["labels"]["app.kubernetes.io/component"] == component
    )


class TestThePositiveControl:
    def test_a_compliant_topology_reports_nothing(self, tmp_path):
        """Without this, every test below would pass on a verifier that simply
        rejected all input."""
        assert _problems(tmp_path, _healthy_data_tier()) == []


class TestImmutableDigests:
    @pytest.mark.parametrize(
        "image",
        [
            "registry.example/redpanda:latest",
            "registry.example/redpanda:v24.2.7",  # a version tag is still mutable
            "registry.example/redpanda",
            "registry.example/redpanda@sha256:tooshort",
            "registry.example/redpanda@md5:" + "a" * 32,
        ],
    )
    def test_a_mutable_reference_is_refused(self, tmp_path, image):
        docs = _healthy_data_tier()
        _find(docs, "redpanda")["spec"]["template"]["spec"]["containers"][0]["image"] = image

        problems = _problems(tmp_path, docs)

        assert any("mutable image reference" in p for p in problems), problems

    def test_a_cronjobs_nested_container_is_not_skipped(self, tmp_path):
        """CronJob buries its pod spec two levels deeper. A checker that only
        understands Deployments would wave the backup job straight through —
        and the backup job is the one that touches the restore path."""
        docs = _healthy_data_tier()
        docs.append(
            {
                "apiVersion": "batch/v1",
                "kind": "CronJob",
                "metadata": {"name": "cell-backup"},
                "spec": {
                    "jobTemplate": {
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        {"name": "backup", "image": "registry.example/pg:latest"}
                                    ]
                                }
                            }
                        }
                    }
                },
            }
        )

        assert any("mutable image reference" in p for p in _problems(tmp_path, docs))


class TestNoPlaintextSecrets:
    def test_a_rendered_secret_is_refused(self, tmp_path):
        docs = _healthy_data_tier()
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "cell-secrets"},
                "stringData": {"jwt-secret": "hunter2"},
            }
        )

        assert any("carries literal" in p for p in _problems(tmp_path, docs))

    @pytest.mark.parametrize(
        "env_name",
        ["POSTGRES_PASSWORD", "JWT_SECRET", "ANTHROPIC_API_KEY", "SERVICE_TOKEN", "SIGNING_KEY"],
    )
    def test_a_secret_shaped_env_name_may_not_carry_a_literal(self, tmp_path, env_name):
        docs = _healthy_data_tier()
        _find(docs, "postgres")["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {"name": env_name, "value": "literal"}
        ]

        assert any("use valueFrom.secretKeyRef" in p for p in _problems(tmp_path, docs))

    def test_a_secretkeyref_is_accepted(self, tmp_path):
        """The correct form must not trip the rule, or the rule teaches people
        to route around it."""
        docs = _healthy_data_tier()
        _find(docs, "postgres")["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {
                "name": "POSTGRES_PASSWORD",
                "valueFrom": {"secretKeyRef": {"name": "creds", "key": "password"}},
            }
        ]

        assert _problems(tmp_path, docs) == []

    def test_a_password_embedded_in_a_connection_url_is_refused(self, tmp_path):
        docs = _healthy_data_tier()
        _find(docs, "postgres")["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {"name": "DATABASE_URL", "value": "postgresql://platform:s3cr3t@db:5432/platform"}
        ]

        assert any("embeds a password" in p for p in _problems(tmp_path, docs))

    def test_a_documented_placeholder_is_not_reported_as_a_leak(self, tmp_path):
        """A rule that fires on `user:password@host` in an example trains
        everyone to ignore it."""
        docs = _healthy_data_tier()
        _find(docs, "postgres")["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {"name": "EXAMPLE_URL", "value": "postgresql://platform:changeme@db:5432/platform"}
        ]

        assert _problems(tmp_path, docs) == []

    @pytest.mark.parametrize(
        "value",
        ["sk-" + "a" * 32, "ghp_" + "b" * 36, "AKIA" + "C" * 16],
    )
    def test_credential_shaped_values_are_refused_whatever_the_env_is_called(self, tmp_path, value):
        docs = _healthy_data_tier()
        _find(docs, "postgres")["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {"name": "HARMLESS_LOOKING", "value": value}
        ]

        assert any("credential-shaped" in p for p in _problems(tmp_path, docs))


class TestHaFloors:
    @pytest.mark.parametrize(
        ("component", "replicas"),
        [
            ("postgres", 1),  # a primary with no standby
            ("redis", 1),
            ("redis-sentinel", 2),  # no survivable quorum
            ("clickhouse", 1),  # "replicated" with one replica
            ("clickhouse-keeper", 2),
            ("redpanda", 2),  # cannot host RF=3
        ],
    )
    def test_a_component_below_its_floor_is_reported(self, tmp_path, component, replicas):
        docs = _healthy_data_tier()
        _find(docs, component)["spec"]["replicas"] = replicas

        assert any(component in p and "needs >=" in p for p in _problems(tmp_path, docs))

    def test_a_missing_component_is_reported(self, tmp_path):
        docs = [d for d in _healthy_data_tier() if "redpanda" not in d["metadata"]["name"]]

        assert any(
            "redpanda: no Deployment/StatefulSet found" in p for p in _problems(tmp_path, docs)
        )

    def test_a_missing_pdb_is_reported(self, tmp_path):
        docs = [
            d
            for d in _healthy_data_tier()
            if not (d["kind"] == "PodDisruptionBudget" and _pdb_component(d) == "clickhouse")
        ]

        assert any(
            "clickhouse" in p and "PodDisruptionBudget" in p for p in _problems(tmp_path, docs)
        )

    def test_soft_anti_affinity_is_not_enough_for_a_stateful_component(self, tmp_path):
        """`preferred` lets the scheduler put a standby on its primary's node
        under pressure — exactly when the node is the risk."""
        docs = _healthy_data_tier()
        target = _find(docs, "postgres")
        target["spec"]["template"]["spec"]["affinity"] = {
            "podAntiAffinity": {
                "preferredDuringSchedulingIgnoredDuringExecution": [{"weight": 100}]
            }
        }

        assert any("REQUIRED pod anti-affinity" in p for p in _problems(tmp_path, docs))

    @pytest.mark.parametrize("probe", ["readinessProbe", "livenessProbe"])
    def test_a_missing_probe_is_reported(self, tmp_path, probe):
        docs = _healthy_data_tier()
        del _find(docs, "redis")["spec"]["template"]["spec"]["containers"][0][probe]

        assert any(f"has no {probe}" in p for p in _problems(tmp_path, docs))

    @pytest.mark.parametrize(
        ("annotation", "value"),
        [
            ("aisp.io/topic-replication-factor", "1"),
            ("aisp.io/min-insync-replicas", "1"),
        ],
    )
    def test_a_durability_annotation_below_its_floor_is_reported(self, tmp_path, annotation, value):
        docs = _healthy_data_tier()
        _find(docs, "redpanda")["metadata"]["annotations"][annotation] = value

        assert any(annotation in p and "needs >=" in p for p in _problems(tmp_path, docs))

    def test_a_missing_durability_annotation_is_reported(self, tmp_path):
        docs = _healthy_data_tier()
        del _find(docs, "redpanda")["metadata"]["annotations"]["aisp.io/min-insync-replicas"]

        assert any("missing annotation" in p for p in _problems(tmp_path, docs))


class TestControlPlaneProfile:
    def _control_plane(self) -> list[dict]:
        api = _statefulset("api", 0, hard_affinity=False)
        api["kind"] = "Deployment"
        del api["spec"]["replicas"]  # governed by the HPA below
        consumer = _statefulset("epa-consumer", 2, hard_affinity=False)
        consumer["kind"] = "Deployment"
        del consumer["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]
        return [
            api,
            consumer,
            _pdb("api"),
            _pdb("epa-consumer"),
            {
                "apiVersion": "autoscaling/v2",
                "kind": "HorizontalPodAutoscaler",
                "metadata": {"name": "hpa-api"},
                "spec": {"scaleTargetRef": {"name": "cell-api"}, "minReplicas": 2},
            },
        ]

    def test_an_hpa_minimum_satisfies_the_replica_floor(self, tmp_path):
        """A Deployment governed by an HPA omits spec.replicas on purpose.
        Reading that absence as zero would fail a correctly configured service."""
        assert _problems(tmp_path, self._control_plane(), profile="control-plane") == []

    def test_an_hpa_minimum_below_the_floor_is_still_reported(self, tmp_path):
        docs = self._control_plane()
        docs[-1]["spec"]["minReplicas"] = 1

        problems = _problems(tmp_path, docs, profile="control-plane")

        assert any("hpa.minReplicas=1" in p for p in problems), problems

    def test_the_consumer_is_not_required_to_have_a_readiness_probe(self, tmp_path):
        """Nothing routes to it, so a readiness probe would report a state no
        controller reads."""
        problems = _problems(tmp_path, self._control_plane(), profile="control-plane")

        assert not any("readinessProbe" in p for p in problems)

    def test_the_consumer_is_still_required_to_have_a_liveness_probe(self, tmp_path):
        docs = self._control_plane()
        del docs[1]["spec"]["template"]["spec"]["containers"][0]["livenessProbe"]

        problems = _problems(tmp_path, docs, profile="control-plane")

        assert any("epa-consumer" in p and "livenessProbe" in p for p in problems)


def _pdb_component(doc: dict) -> str | None:
    return (
        ((doc.get("spec") or {}).get("selector") or {})
        .get("matchLabels", {})
        .get("app.kubernetes.io/component")
    )


class TestInputHandling:
    def test_an_empty_manifest_set_is_an_error_not_a_pass(self, tmp_path):
        """Silence is the most dangerous result a gate can return: a broken
        render that produces no documents would otherwise report all-clear."""
        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")

        results = vt.run([path], "data-tier")

        assert any(problems for _, problems in results)

    def test_the_healthy_fixture_is_not_accidentally_shared_between_tests(self):
        """_healthy_data_tier() must return fresh objects; mutation in one test
        leaking into another would make failures depend on ordering."""
        first = _healthy_data_tier()
        _find(first, "postgres")["spec"]["replicas"] = 99

        assert _find(_healthy_data_tier(), "postgres")["spec"]["replicas"] == 2
        assert copy.deepcopy(first) is not first
