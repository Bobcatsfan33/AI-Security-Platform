"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  ApiError,
  type Asset,
  type CampaignSummary,
  type Strategy,
} from "@/lib/api";

export default function RedTeamPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [strategies, setStrategies] = useState<Strategy[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<string>("");
  const [maxAttacks, setMaxAttacks] = useState<number>(30);

  useEffect(() => {
    void load();
    const t = setInterval(() => void loadCampaigns(), 5000);
    return () => clearInterval(t);
  }, []);

  async function load(): Promise<void> {
    try {
      setError(null);
      const [a, s] = await Promise.all([
        api.get<Asset[]>("/v1/assets"),
        api.get<Strategy[]>("/v1/redteam/strategies"),
      ]);
      setAssets(a);
      setStrategies(s);
      void loadCampaigns();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function loadCampaigns(): Promise<void> {
    try {
      const data = await api.get<CampaignSummary[]>("/v1/redteam/campaigns");
      setCampaigns(data);
    } catch {
      // silent — error displayed on initial load
    }
  }

  async function startCampaign(): Promise<void> {
    if (!selectedAsset) {
      setError("Pick an asset first");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.post<CampaignSummary>("/v1/redteam/campaigns", {
        asset_id: selectedAsset,
        max_attacks: maxAttacks,
        auto_create_regression: true,
      });
      void loadCampaigns();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "start failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1 className="mb-6 text-2xl font-semibold">Red Team Campaigns</h1>

      <section className="mb-8 rounded-lg border border-slate-200 bg-white p-5">
        <h2 className="mb-3 font-medium">Start a campaign</h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <label className="text-sm">
            <span className="mb-1 block font-medium">Asset</span>
            <select
              value={selectedAsset}
              onChange={(e) => setSelectedAsset(e.target.value)}
              className="w-full rounded-md border border-slate-300 px-3 py-2"
            >
              <option value="">— select —</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.provider} / {a.model_name})
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block font-medium">Max attacks</span>
            <input
              type="number"
              value={maxAttacks}
              onChange={(e) => setMaxAttacks(Number(e.target.value))}
              min={1}
              max={1000}
              className="w-full rounded-md border border-slate-300 px-3 py-2"
            />
          </label>
          <div className="flex items-end">
            <button
              type="button"
              onClick={startCampaign}
              disabled={busy}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {busy ? "Starting…" : "Start campaign"}
            </button>
          </div>
        </div>
        <p className="mt-3 text-xs text-slate-500">
          Successful LLM-generated attacks are auto-promoted to permanent
          regression test cases.
        </p>
      </section>

      {error ? (
        <p className="mb-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}
        </p>
      ) : null}

      <section className="mb-8">
        <h2 className="mb-3 font-medium">Recent campaigns</h2>
        {campaigns.length === 0 ? (
          <p className="text-sm text-slate-500">No campaigns yet.</p>
        ) : (
          <ul className="overflow-hidden rounded-lg border border-slate-200 bg-white">
            {campaigns.map((c) => (
              <li
                key={c.evaluation_id}
                className="border-b border-slate-200 px-5 py-4 last:border-b-0"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <Link
                      href={`/evaluations/${c.evaluation_id}`}
                      className="font-mono text-sm text-slate-700 hover:underline"
                    >
                      {c.evaluation_id.slice(0, 8)}…
                    </Link>{" "}
                    · {c.status}
                  </div>
                  <div className="text-right text-sm">
                    {c.successful_attacks}/{c.total_attacks} succeeded ·{" "}
                    {(c.success_rate * 100).toFixed(1)}% rate ·{" "}
                    {c.novel_findings} novel
                  </div>
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  asset {c.asset_id.slice(0, 8)}… · cost $
                  {c.total_cost_usd.toFixed(4)}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2 className="mb-3 font-medium">
          Strategy library ({strategies.length})
        </h2>
        <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {strategies.map((s) => (
            <li
              key={s.id}
              className="rounded-lg border border-slate-200 bg-white p-4"
            >
              <div className="flex items-center justify-between">
                <span className="font-medium">{s.name}</span>
                <SeverityBadge severity={s.severity} />
              </div>
              <div className="mt-0.5 text-xs text-slate-500">
                {s.category} · {s.attack_type}
              </div>
              <p className="mt-2 text-sm text-slate-700">{s.description}</p>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

const severityColors: Record<string, string> = {
  info: "bg-slate-100 text-slate-700",
  low: "bg-emerald-100 text-emerald-700",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-700",
};

function SeverityBadge({ severity }: { severity: string }) {
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
