"""Benchmark service — the wiring between the model-benchmark harness
(:mod:`app.redteam.benchmark`) and the API.

The harness itself is provider-agnostic: it benchmarks anything implementing
the ``ModelRunner`` protocol (``async generate(prompt, *, system_prompt) ->
str``). This module supplies two things the route needs:

* :class:`ConnectorRunner` — adapts the platform's existing
  :class:`~app.connectors.base.ModelConnector` (which returns a rich
  ``ConnectorResponse``) to the ``str``-returning ``ModelRunner`` the harness
  wants. So once model connectors are wired into a deployment, benchmarking
  them is one wrapper away.
* an injectable **runner provider** — the fleet of named models to benchmark.
  Lifespan/tests install it; the default is empty. A live multi-model run
  needs real model connectors with credentials, which is the documented
  Phase-4 boundary — so the route is honest about an empty fleet rather than
  fabricating results.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol, runtime_checkable

from app.redteam.benchmark import (
    ATTACK_SEEDS,
    BenchmarkReport,
    ModelRunner,
    benchmark_models,
)


@runtime_checkable
class _ConnectorLike(Protocol):
    def generate(self, prompt: str, *, system_prompt: str | None = ...) -> Awaitable[object]: ...


class ConnectorRunner:
    """Adapt a :class:`ModelConnector` to the harness's ``ModelRunner``.

    The connector returns a ``ConnectorResponse``; the harness only needs the
    text, so we project ``.text`` out.
    """

    def __init__(self, connector: _ConnectorLike) -> None:
        self._connector = connector

    async def generate(self, prompt: str, *, system_prompt: str) -> str:
        resp = await self._connector.generate(prompt, system_prompt=system_prompt)
        return getattr(resp, "text", "") or ""


def seed_catalogue() -> dict[str, object]:
    """The benchmark attack-seed catalogue — categories, per-category counts,
    and total. Backs the UI and lets clients see the baseline without a run."""
    by_category = {category: len(seeds) for category, seeds in ATTACK_SEEDS.items()}
    return {
        "categories": by_category,
        "total": sum(by_category.values()),
    }


# ─────────────────────────────────────────────── injectable runner fleet

RunnerProvider = Callable[[], dict[str, ModelRunner]]

_provider: RunnerProvider | None = None


def set_runner_provider(provider: RunnerProvider | None) -> None:
    global _provider
    _provider = provider


def get_runner_provider() -> RunnerProvider | None:
    return _provider


def reset_for_tests() -> None:
    global _provider
    _provider = None


class NoRunnersConfiguredError(RuntimeError):
    """Raised when a benchmark run is requested but no model fleet is wired.
    Live multi-model benchmarking needs registered model connectors with
    credentials (the Phase-4 boundary)."""


async def run_benchmark(
    *,
    system_prompts: dict[str, str],
    categories: tuple[str, ...] | None = None,
) -> BenchmarkReport:
    """Run the benchmark over the installed runner fleet.

    Raises :class:`NoRunnersConfiguredError` when no fleet is installed, so the
    route can return a clear 'not configured' response instead of an empty,
    misleading report.
    """
    provider = get_runner_provider()
    runners = provider() if provider is not None else {}
    if not runners:
        raise NoRunnersConfiguredError(
            "No model runners are configured. Live model benchmarking requires "
            "registered model connectors with credentials."
        )
    return await benchmark_models(runners, system_prompts=system_prompts, categories=categories)
