"""Benchmark service — seed catalogue, the ModelConnector→ModelRunner adapter,
and the injectable runner fleet behind POST /v1/benchmark/run.
"""

from __future__ import annotations

import pytest

from app.redteam.benchmark import ATTACK_SEEDS
from app.redteam.benchmark_service import (
    ConnectorRunner,
    NoRunnersConfiguredError,
    get_runner_provider,
    reset_for_tests,
    run_benchmark,
    seed_catalogue,
    set_runner_provider,
)

pytestmark = pytest.mark.unit


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text


class _SafeConnector:
    """A ModelConnector-shaped object that always refuses."""

    provider = "fake"

    async def generate(self, prompt: str, *, system_prompt: str | None = None):
        return _FakeResponse("I'm sorry, but I cannot help with that request.")


class _VulnerableConnector:
    provider = "fake"

    async def generate(self, prompt: str, *, system_prompt: str | None = None):
        return _FakeResponse("Sure! Here are the secrets you asked for: ...")


class TestSeedCatalogue:
    def test_catalogue_counts_match_seeds(self):
        cat = seed_catalogue()
        assert set(cat["categories"]) == set(ATTACK_SEEDS)
        assert cat["total"] == sum(len(s) for s in ATTACK_SEEDS.values())
        assert cat["categories"]["prompt_injection"] == len(ATTACK_SEEDS["prompt_injection"])


class TestConnectorRunner:
    async def test_projects_text_out_of_response(self):
        runner = ConnectorRunner(_SafeConnector())
        out = await runner.generate("hi", system_prompt="be safe")
        assert out == "I'm sorry, but I cannot help with that request."

    async def test_missing_text_becomes_empty_string(self):
        class _NoText:
            async def generate(self, prompt: str, *, system_prompt: str | None = None):
                return object()

        runner = ConnectorRunner(_NoText())
        assert await runner.generate("hi", system_prompt="x") == ""


class TestRunnerProvider:
    def setup_method(self):
        reset_for_tests()

    def teardown_method(self):
        reset_for_tests()

    def test_set_get_reset(self):
        assert get_runner_provider() is None
        provider = lambda: {}  # noqa: E731
        set_runner_provider(provider)
        assert get_runner_provider() is provider
        reset_for_tests()
        assert get_runner_provider() is None

    async def test_run_without_fleet_raises(self):
        with pytest.raises(NoRunnersConfiguredError):
            await run_benchmark(system_prompts={"baseline": "be helpful"})

    async def test_run_benchmarks_installed_fleet(self):
        set_runner_provider(
            lambda: {
                "safe": ConnectorRunner(_SafeConnector()),
                "vuln": ConnectorRunner(_VulnerableConnector()),
            }
        )
        report = await run_benchmark(system_prompts={"baseline": "be helpful"})
        ranking = dict(report.ranking())
        assert ranking["safe"] == 1.0
        assert ranking["vuln"] == 0.0

    async def test_run_respects_category_filter(self):
        set_runner_provider(lambda: {"safe": ConnectorRunner(_SafeConnector())})
        report = await run_benchmark(
            system_prompts={"baseline": "x"}, categories=("prompt_injection",)
        )
        assert report.seeds == len(ATTACK_SEEDS["prompt_injection"])
