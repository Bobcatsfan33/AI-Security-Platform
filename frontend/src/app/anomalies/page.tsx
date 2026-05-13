"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, ApiError, type Anomaly, type Asset } from "@/lib/api";

const WINDOWS = ["1h", "6h", "24h", "7d"] as const;

export default function AnomaliesPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetId, setAssetId] = useState<string>("");
  const [currentWindow, setCurrentWindow] =
    useState<(typeof WINDOWS)[number]>("1h");
  const [baselineWindow, setBaselineWindow] =
    useState<(typeof WINDOWS)[number]>("7d");
  const [anomalies, setAnomalies] = useState<Anomaly[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadAssets();
  }, []);

  useEffect(() => {
    if (assetId) void loadAnomalies();
  }, [assetId, currentWindow, baselineWindow]);

  async function loadAssets(): Promise<void> {
    try {
      const data = await api.get<Asset[]>("/v1/assets");
      setAssets(data);
      if (data.length > 0 && !assetId) {
        setAssetId(data[0].id);
      }
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function loadAnomalies(): Promise<void> {
    try {
      setError(null);
      const params = new URLSearchParams({
        asset_id: assetId,
        current_window: currentWindow,
        baseline_window: baselineWindow,
      });
      const data = await api.get<Anomaly[]>(
        `/v1/anomalies?${params.toString()}`,
      );
      setAnomalies(data);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-2xl font-semibold text-slate-900">Anomalies</h1>
        <p className="text-sm text-slate-600">
          Statistical drift detected on agent runtime behaviour.
        </p>
      </header>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <select
          value={assetId}
          onChange={(e) => setAssetId(e.target.value)}
          className="rounded-md border border-slate-300 px-2 py-1.5"
        >
          {assets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
        <span className="text-slate-500">current:</span>
        <select
          value={currentWindow}
          onChange={(e) =>
            setCurrentWindow(e.target.value as (typeof WINDOWS)[number])
          }
          className="rounded-md border border-slate-300 px-2 py-1.5"
        >
          {WINDOWS.map((w) => (
            <option key={w} value={w}>
              {w}
            </option>
          ))}
        </select>
        <span className="text-slate-500">baseline:</span>
        <select
          value={baselineWindow}
          onChange={(e) =>
            setBaselineWindow(e.target.value as (typeof WINDOWS)[number])
          }
          className="rounded-md border border-slate-300 px-2 py-1.5"
        >
          {WINDOWS.map((w) => (
            <option key={w} value={w}>
              {w}
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
      ) : anomalies === null ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : anomalies.length === 0 ? (
        <p className="rounded-md border border-slate-200 bg-white p-4 text-sm text-slate-500">
          No anomalies detected.
        </p>
      ) : (
        <ul className="space-y-3">
          {anomalies.map((a) => (
            <li
              key={a.id}
              className="rounded-lg border border-slate-200 bg-white p-4"
            >
              <div className="flex items-center justify-between">
                <span className="font-medium text-slate-900">{a.title}</span>
                <SeverityBadge severity={a.severity} />
              </div>
              <div className="mt-1 text-xs text-slate-500">
                {a.kind} · {new Date(a.detected_at).toLocaleString()}
              </div>
              <pre className="mt-2 overflow-x-auto rounded bg-slate-50 p-2 text-xs text-slate-700">
                {JSON.stringify(a.detail, null, 2)}
              </pre>
            </li>
          ))}
        </ul>
      )}
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
