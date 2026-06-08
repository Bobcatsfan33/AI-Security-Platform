"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  ApiError,
  benchmark,
  riskIndex,
  type BenchmarkReport,
  type BenchmarkSeeds,
  type RiskComponents,
  type RiskIndexResult,
  type RiskModel,
} from "@/lib/api";

const COMPONENT_LABELS: Record<keyof RiskComponents, string> = {
  supply_chain_score: "Supply-chain risk",
  iam_over_privilege: "IAM over-privilege",
  runtime_block_rate: "Runtime exposure",
  redteam_success_rate: "Red-team exposure",
};

const GRADE_STYLES: Record<string, string> = {
  A: "bg-emerald-100 text-emerald-800",
  B: "bg-lime-100 text-lime-800",
  C: "bg-amber-100 text-amber-800",
  D: "bg-orange-100 text-orange-800",
  F: "bg-red-100 text-red-800",
};

const ZERO_COMPONENTS: RiskComponents = {
  supply_chain_score: 0,
  iam_over_privilege: 0,
  runtime_block_rate: 0,
  redteam_success_rate: 0,
};

export default function PosturePage() {
  return (
    <div>
      <h1 className="mb-1 text-2xl font-semibold">AI Risk Posture</h1>
      <p className="mb-6 max-w-3xl text-sm text-slate-600">
        Compute an asset&apos;s blended AI Risk Index from its component scores,
        and benchmark model resilience against the red-team attack seeds.
      </p>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RiskIndexCard />
        <BenchmarkCard />
      </div>
    </div>
  );
}

function RiskIndexCard() {
  const [components, setComponents] = useState<RiskComponents>(ZERO_COMPONENTS);
  const [model, setModel] = useState<RiskModel | null>(null);
  const [result, setResult] = useState<RiskIndexResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        setModel(await riskIndex.model());
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Failed to load model");
      }
    })();
  }, []);

  async function compute(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      setResult(await riskIndex.compute({ asset_id: "preview", ...components }));
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Compute failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-5 py-3">
        <h2 className="font-medium">Risk Index calculator</h2>
      </div>
      <div className="space-y-4 px-5 py-4">
        {(Object.keys(COMPONENT_LABELS) as Array<keyof RiskComponents>).map((key) => (
          <label key={key} className="block">
            <div className="mb-1 flex justify-between text-sm">
              <span className="text-slate-700">{COMPONENT_LABELS[key]}</span>
              <span className="font-mono text-xs text-slate-500">
                {components[key].toFixed(2)}
              </span>
            </div>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={components[key]}
              onChange={(e) =>
                setComponents((prev) => ({ ...prev, [key]: Number(e.target.value) }))
              }
              className="w-full"
              aria-label={COMPONENT_LABELS[key]}
            />
          </label>
        ))}

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => void compute()}
            disabled={busy}
            className="rounded-md bg-slate-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
          >
            {busy ? "Computing…" : "Compute index"}
          </button>
          {result ? (
            <div className="flex items-center gap-2">
              <span className="text-2xl font-semibold tabular-nums">
                {result.score.toFixed(1)}
              </span>
              <span
                className={`rounded-full px-2.5 py-0.5 text-sm font-semibold ${GRADE_STYLES[result.grade] ?? GRADE_STYLES.A}`}
              >
                {result.grade}
              </span>
            </div>
          ) : null}
        </div>

        {error ? (
          <p className="text-sm text-red-600">
            {error} <Link href="/login" className="underline">Sign in</Link>
          </p>
        ) : null}

        {model ? (
          <p className="text-xs text-slate-400">
            Weights:{" "}
            {Object.entries(model.weights)
              .map(([k, v]) => `${k} ${Math.round(v * 100)}%`)
              .join(" · ")}
          </p>
        ) : null}
      </div>
    </section>
  );
}

function BenchmarkCard() {
  const [seeds, setSeeds] = useState<BenchmarkSeeds | null>(null);
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        setSeeds(await benchmark.seeds());
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Failed to load seeds");
      }
    })();
  }, []);

  async function run(): Promise<void> {
    setBusy(true);
    setError(null);
    setReport(null);
    try {
      setReport(
        await benchmark.run({ system_prompts: { baseline: "You are a helpful assistant." } }),
      );
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Run failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-5 py-3">
        <h2 className="font-medium">Model benchmark</h2>
      </div>
      <div className="space-y-4 px-5 py-4">
        {seeds ? (
          <div>
            <p className="mb-2 text-sm text-slate-600">
              {seeds.total} attack seeds across {Object.keys(seeds.categories).length}{" "}
              categories
            </p>
            <ul className="flex flex-wrap gap-2">
              {Object.entries(seeds.categories).map(([cat, count]) => (
                <li
                  key={cat}
                  className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs text-slate-700"
                >
                  {cat} · {count}
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-sm text-slate-500">Loading seeds…</p>
        )}

        <button
          type="button"
          onClick={() => void run()}
          disabled={busy}
          className="rounded-md bg-slate-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
        >
          {busy ? "Running…" : "Run baseline benchmark"}
        </button>

        {error ? <p className="text-sm text-amber-700">{error}</p> : null}

        {report ? (
          <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
            {report.ranking.map((r) => (
              <li key={r.model} className="flex items-center justify-between px-3 py-2 text-sm">
                <span className="font-mono text-xs">{r.model}</span>
                <span className="tabular-nums text-slate-600">
                  {(r.resilience * 100).toFixed(0)}% resilient
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </section>
  );
}
