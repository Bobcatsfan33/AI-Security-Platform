"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  ApiError,
  type Asset,
  type Evaluation,
  type Finding,
} from "@/lib/api";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function AssetDetailPage({ params }: PageProps) {
  const { id } = use(params);
  const [asset, setAsset] = useState<Asset | null>(null);
  const [evaluations, setEvaluations] = useState<Evaluation[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void load();
  }, [id]);

  async function load(): Promise<void> {
    try {
      setError(null);
      // Evaluations/findings routes are quarantined since the v2 pivot
      // (see backend tests/unit/test_no_broken_imports.py). Degrade to
      // empty lists instead of failing the whole page.
      const [a, e, f] = await Promise.all([
        api.get<Asset>(`/v1/assets/${id}`),
        api.get<Evaluation[]>(`/v1/evaluations?asset_id=${id}`).catch(() => []),
        api.get<Finding[]>(`/v1/findings?asset_id=${id}`).catch(() => []),
      ]);
      setAsset(a);
      setEvaluations(e);
      setFindings(f);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function runEvaluation(): Promise<void> {
    setBusy(true);
    try {
      await api.post<Evaluation>("/v1/evaluations", {
        asset_id: id,
        max_test_cases: 20,
      });
      void load();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "evaluation failed");
    } finally {
      setBusy(false);
    }
  }

  if (error) {
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
        {error}
      </p>
    );
  }
  if (!asset) {
    return <p className="text-sm text-slate-500">Loading…</p>;
  }

  return (
    <div>
      <div className="mb-1 flex items-center gap-2 text-sm text-slate-500">
        <Link href="/assets" className="hover:underline">
          Assets
        </Link>{" "}
        / <span>{asset.name}</span>
      </div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">{asset.name}</h1>
        <button
          type="button"
          onClick={runEvaluation}
          disabled={busy}
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
        >
          {busy ? "Starting…" : "Run evaluation"}
        </button>
      </div>

      <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat label="Score" value={asset.last_evaluation_score?.toFixed(0) ?? "—"} />
        <Stat label="Open findings" value={asset.open_findings_count.toString()} />
        <Stat
          label="Critical findings"
          value={asset.critical_findings_count.toString()}
        />
      </section>

      <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <h2 className="mb-3 font-medium">Configuration</h2>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <KV k="Provider" v={asset.provider} />
            <KV k="Model" v={asset.model_name} />
            <KV k="Environment" v={asset.environment} />
            <KV k="Exposure" v={asset.exposure} />
            <KV k="Data class." v={asset.data_classification} />
            <KV k="Status" v={asset.status} />
            <KV k="Runtime agent" v={asset.runtime_agent_connected ? "connected" : "—"} />
          </dl>
        </div>
        <div className="rounded-lg border border-slate-200 bg-white p-5">
          <h2 className="mb-3 font-medium">Evaluations</h2>
          {evaluations.length === 0 ? (
            <p className="text-sm text-slate-500">No evaluations yet.</p>
          ) : (
            <ul className="space-y-2">
              {evaluations.slice(0, 8).map((e) => (
                <li
                  key={e.id}
                  className="flex items-center justify-between text-sm"
                >
                  <Link
                    href={`/evaluations/${e.id}`}
                    className="text-slate-700 hover:underline"
                  >
                    {e.eval_type} — {e.status}
                  </Link>
                  <span className="text-slate-500">
                    {e.score.toFixed(0)} / {e.findings_count} findings
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section>
        <h2 className="mb-3 font-medium">Findings</h2>
        {findings.length === 0 ? (
          <p className="text-sm text-slate-500">No findings yet.</p>
        ) : (
          <ul className="overflow-hidden rounded-lg border border-slate-200 bg-white">
            {findings.slice(0, 20).map((f) => (
              <li
                key={f.id}
                className="border-b border-slate-200 px-5 py-3 last:border-b-0"
              >
                <div className="flex items-center justify-between">
                  <Link
                    href={`/findings`}
                    className="text-sm text-slate-700 hover:underline"
                  >
                    {f.title}
                  </Link>
                  <SeverityBadge severity={f.severity} />
                </div>
                <div className="mt-0.5 text-xs text-slate-500">
                  {f.category} · {f.remediation_status}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

interface StatProps {
  label: string;
  value: string;
}

function Stat({ label, value }: StatProps) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  );
}

interface KVProps {
  k: string;
  v: string | null;
}

function KV({ k, v }: KVProps) {
  return (
    <>
      <dt className="text-slate-500">{k}</dt>
      <dd className="text-slate-900">{v ?? "—"}</dd>
    </>
  );
}

interface SeverityBadgeProps {
  severity: string;
}

const severityColors: Record<string, string> = {
  info: "bg-slate-100 text-slate-700",
  low: "bg-emerald-100 text-emerald-700",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-700",
};

function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
        severityColors[severity] ?? severityColors.medium
      }`}
    >
      {severity}
    </span>
  );
}
