"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  ApiError,
  type Asset,
  type DashboardPolicyEffectiveness,
  type DashboardRuntimeOverview,
  type DashboardTrafficRow,
} from "@/lib/api";

const WINDOWS = ["1h", "6h", "24h", "7d", "30d"] as const;
type Window = (typeof WINDOWS)[number];

export default function DashboardPage() {
  const [overview, setOverview] = useState<DashboardRuntimeOverview | null>(null);
  const [policy, setPolicy] = useState<DashboardPolicyEffectiveness | null>(null);
  const [traffic, setTraffic] = useState<DashboardTrafficRow[] | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [window, setWindow] = useState<Window>("24h");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [window]);

  async function loadAll(): Promise<void> {
    try {
      setError(null);
      const [ov, pe, tr, as] = await Promise.all([
        api.get<DashboardRuntimeOverview>(`/v1/dashboards/runtime?time_range=${window}`),
        api.get<DashboardPolicyEffectiveness>(
          `/v1/dashboards/policy-effectiveness?time_range=${window}`,
        ),
        api.get<{ time_range: string; rows: DashboardTrafficRow[] }>(
          `/v1/dashboards/traffic?time_range=${window}&limit=20`,
        ),
        api.get<Asset[]>("/v1/assets"),
      ]);
      setOverview(ov);
      setPolicy(pe);
      setTraffic(tr.rows);
      setAssets(as);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  const postureScore = computePostureScore(assets);

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">
            Executive Dashboard
          </h1>
          <p className="text-sm text-slate-600">
            Organization-wide AI security posture and runtime health.
          </p>
        </div>
        <select
          value={window}
          onChange={(e) => setWindow(e.target.value as Window)}
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm"
        >
          {WINDOWS.map((w) => (
            <option key={w} value={w}>
              Last {w}
            </option>
          ))}
        </select>
      </div>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : null}

      {/* Top-level KPI cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Posture score"
          value={postureScore !== null ? `${postureScore}/100` : "—"}
          tone={
            postureScore === null
              ? "neutral"
              : postureScore >= 80
                ? "good"
                : postureScore >= 60
                  ? "warn"
                  : "bad"
          }
        />
        <KpiCard
          label="Events"
          value={overview ? overview.total_events.toLocaleString() : "—"}
          tone="neutral"
        />
        <KpiCard
          label="Block rate"
          value={overview ? `${overview.block_rate_pct.toFixed(1)}%` : "—"}
          tone={
            overview && overview.block_rate_pct > 10
              ? "warn"
              : overview && overview.block_rate_pct > 25
                ? "bad"
                : "good"
          }
        />
        <KpiCard
          label="p95 latency"
          value={overview ? `${overview.p95_latency_ms.toFixed(0)} ms` : "—"}
          tone={
            overview && overview.p95_latency_ms > 1000
              ? "warn"
              : "good"
          }
        />
      </div>

      <section>
        <h2 className="mb-3 text-lg font-semibold text-slate-900">
          Asset risk heatmap
        </h2>
        <RiskHeatmap assets={assets} />
      </section>

      <section>
        <h2 className="mb-3 text-lg font-semibold text-slate-900">
          Top assets by traffic
        </h2>
        <TrafficTable rows={traffic} />
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div>
          <h2 className="mb-3 text-lg font-semibold text-slate-900">
            Policy pipeline effectiveness
          </h2>
          <PolicyEffectivenessPanel effectiveness={policy} />
        </div>
        <div>
          <h2 className="mb-3 text-lg font-semibold text-slate-900">
            Top block reasons
          </h2>
          <BlockReasonsList reasons={policy?.top_block_reasons ?? null} />
        </div>
      </section>
    </div>
  );
}

// ────────────────────────────────────────── components

type Tone = "good" | "warn" | "bad" | "neutral";

const toneClasses: Record<Tone, string> = {
  good: "border-emerald-200 bg-emerald-50 text-emerald-700",
  warn: "border-yellow-200 bg-yellow-50 text-yellow-800",
  bad: "border-red-200 bg-red-50 text-red-700",
  neutral: "border-slate-200 bg-white text-slate-900",
};

function KpiCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: Tone;
}) {
  return (
    <div className={`rounded-lg border p-4 ${toneClasses[tone]}`}>
      <div className="text-xs uppercase tracking-wide text-current/70">
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  );
}

function RiskHeatmap({ assets }: { assets: Asset[] }) {
  if (assets.length === 0) {
    return (
      <p className="rounded-md border border-slate-200 bg-white p-4 text-sm text-slate-500">
        No assets registered yet.
      </p>
    );
  }
  // x = exposure rank (internal=1, internal_users=2, customer_facing=3, public_internet=4)
  // y = risk_score (0–100 inverted: 100 - score)
  // size = open_findings_count
  const exposureRank: Record<string, number> = {
    internal: 1,
    internal_users: 2,
    customer_facing: 3,
    public_internet: 4,
  };
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <svg viewBox="0 0 400 240" className="w-full max-w-2xl">
        {/* axes */}
        <line x1="40" y1="200" x2="380" y2="200" stroke="#cbd5e1" />
        <line x1="40" y1="20" x2="40" y2="200" stroke="#cbd5e1" />
        <text x="200" y="225" textAnchor="middle" fill="#64748b" fontSize="11">
          Exposure
        </text>
        <text
          x="20"
          y="110"
          textAnchor="middle"
          fill="#64748b"
          fontSize="11"
          transform="rotate(-90 20 110)"
        >
          Risk (100 − score)
        </text>
        {assets.map((a) => {
          const ex = exposureRank[a.exposure] ?? 1;
          const x = 40 + ((ex - 1) / 3) * 320 + 30;
          const score = a.last_evaluation_score ?? 50;
          const risk = 100 - score;
          const y = 200 - (risk / 100) * 170;
          const r = Math.min(14, 3 + Math.sqrt(a.open_findings_count || 1));
          const fill =
            a.critical_findings_count > 0
              ? "#ef4444"
              : a.open_findings_count > 0
                ? "#f59e0b"
                : "#10b981";
          return (
            <g key={a.id}>
              <circle cx={x} cy={y} r={r} fill={fill} fillOpacity={0.6} />
              <title>
                {a.name} — {a.exposure} · score {score} · findings{" "}
                {a.open_findings_count}
              </title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function TrafficTable({ rows }: { rows: DashboardTrafficRow[] | null }) {
  if (rows === null) {
    return <p className="text-sm text-slate-500">Loading…</p>;
  }
  if (rows.length === 0) {
    return (
      <p className="rounded-md border border-slate-200 bg-white p-4 text-sm text-slate-500">
        No runtime telemetry in this window.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-3 py-2">Asset</th>
            <th className="px-3 py-2">Events</th>
            <th className="px-3 py-2">Blocked</th>
            <th className="px-3 py-2">Avg latency</th>
            <th className="px-3 py-2">Tokens</th>
            <th className="px-3 py-2">Cost USD</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.asset_id} className="border-t border-slate-100">
              <td className="px-3 py-2">
                <Link
                  href={`/assets/${r.asset_id}`}
                  className="font-mono text-xs hover:underline"
                >
                  {r.asset_id.slice(0, 8)}…
                </Link>
              </td>
              <td className="px-3 py-2">{r.total_events.toLocaleString()}</td>
              <td className="px-3 py-2">{r.blocked.toLocaleString()}</td>
              <td className="px-3 py-2">{r.avg_latency_ms.toFixed(0)} ms</td>
              <td className="px-3 py-2">
                {(r.token_input + r.token_output).toLocaleString()}
              </td>
              <td className="px-3 py-2">
                ${r.estimated_cost_usd.toFixed(2)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PolicyEffectivenessPanel({
  effectiveness,
}: {
  effectiveness: DashboardPolicyEffectiveness | null;
}) {
  if (!effectiveness) {
    return <p className="text-sm text-slate-500">Loading…</p>;
  }
  const total =
    effectiveness.stage1_hits +
    effectiveness.stage2_hits +
    effectiveness.stage3_hits +
    effectiveness.no_match;
  const pct = (n: number): string =>
    total === 0 ? "0%" : `${((100 * n) / total).toFixed(1)}%`;
  return (
    <div className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm">
      <Row label="Stage 1 (regex/PII)" value={pct(effectiveness.stage1_hits)} />
      <Row label="Stage 2 (ONNX)" value={pct(effectiveness.stage2_hits)} />
      <Row label="Stage 3 (LLM judge)" value={pct(effectiveness.stage3_hits)} />
      <Row label="No match" value={pct(effectiveness.no_match)} />
      <hr className="my-2" />
      <Row
        label="Avg latency · Stage 1"
        value={`${effectiveness.stage1_avg_us.toFixed(0)} µs`}
      />
      <Row
        label="Avg latency · Stage 2"
        value={`${effectiveness.stage2_avg_us.toFixed(0)} µs`}
      />
      <Row
        label="Avg latency · Stage 3"
        value={`${effectiveness.stage3_avg_ms.toFixed(0)} ms`}
      />
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-600">{label}</span>
      <span className="font-medium text-slate-900">{value}</span>
    </div>
  );
}

function BlockReasonsList({
  reasons,
}: {
  reasons: Array<{ block_reason: string; count: number }> | null;
}) {
  if (reasons === null) {
    return <p className="text-sm text-slate-500">Loading…</p>;
  }
  if (reasons.length === 0) {
    return (
      <p className="rounded-md border border-slate-200 bg-white p-4 text-sm text-slate-500">
        No blocks in this window.
      </p>
    );
  }
  const max = Math.max(...reasons.map((r) => r.count));
  return (
    <ul className="space-y-2 rounded-lg border border-slate-200 bg-white p-4 text-sm">
      {reasons.map((r) => (
        <li key={r.block_reason}>
          <div className="flex items-center justify-between">
            <span className="truncate font-mono text-xs">{r.block_reason}</span>
            <span className="font-medium">{r.count}</span>
          </div>
          <div className="mt-1 h-1.5 rounded bg-slate-100">
            <div
              className="h-1.5 rounded bg-orange-400"
              style={{ width: `${(100 * r.count) / max}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

// ────────────────────────────────────────── derived metrics

function computePostureScore(assets: Asset[]): number | null {
  if (assets.length === 0) return null;
  const scores = assets
    .map((a) => a.last_evaluation_score)
    .filter((s): s is number => typeof s === "number");
  if (scores.length === 0) return null;
  const baseline = scores.reduce((a, b) => a + b, 0) / scores.length;
  const critical = assets.reduce(
    (acc, a) => acc + (a.critical_findings_count || 0),
    0,
  );
  // Each critical drops the org score by 5, capped at 50.
  const penalty = Math.min(50, critical * 5);
  return Math.max(0, Math.round(baseline - penalty));
}
