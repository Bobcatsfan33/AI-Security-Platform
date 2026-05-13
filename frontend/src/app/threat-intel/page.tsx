"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  ApiError,
  type ThreatIntelCluster,
  type ThreatIntelStatus,
} from "@/lib/api";

export default function ThreatIntelPage() {
  const [status, setStatus] = useState<ThreatIntelStatus | null>(null);
  const [clusters, setClusters] = useState<ThreatIntelCluster[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rebuilding, setRebuilding] = useState(false);

  useEffect(() => {
    void load();
  }, []);

  async function load(): Promise<void> {
    try {
      setError(null);
      const [s, c] = await Promise.all([
        api.get<ThreatIntelStatus>("/v1/threat-intel/status"),
        api.get<ThreatIntelCluster[]>("/v1/threat-intel/clusters"),
      ]);
      setStatus(s);
      setClusters(c);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function rebuild(): Promise<void> {
    try {
      setRebuilding(true);
      setError(null);
      const updated = await api.post<ThreatIntelStatus>(
        "/v1/threat-intel/rebuild",
        {},
      );
      setStatus(updated);
      const c = await api.get<ThreatIntelCluster[]>(
        "/v1/threat-intel/clusters",
      );
      setClusters(c);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "rebuild failed");
    } finally {
      setRebuilding(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">
            Threat Intelligence
          </h1>
          <p className="text-sm text-slate-600">
            Cross-tenant attack pattern clusters (opt-in tenants only).
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={`${
              process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
            }/v1/threat-intel/stix`}
            target="_blank"
            rel="noreferrer"
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
          >
            Download STIX 2.1
          </a>
          <button
            onClick={() => void rebuild()}
            disabled={rebuilding}
            className="rounded-md bg-slate-900 px-3 py-1.5 text-sm text-white disabled:opacity-50"
          >
            {rebuilding ? "Rebuilding…" : "Rebuild clusters"}
          </button>
        </div>
      </div>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : null}

      {status ? (
        <div className="grid gap-4 sm:grid-cols-4">
          <StatusCard label="Samples" value={status.samples_processed} />
          <StatusCard label="Clusters" value={status.cluster_count} />
          <StatusCard label="Novel" value={status.novel_count} />
          <StatusCard
            label="Last built"
            value={
              status.last_built_at
                ? new Date(status.last_built_at).toLocaleString()
                : "never"
            }
          />
        </div>
      ) : null}

      {clusters === null ? (
        <p className="text-sm text-slate-500">Loading clusters…</p>
      ) : clusters.length === 0 ? (
        <p className="rounded-md border border-slate-200 bg-white p-4 text-sm text-slate-500">
          No clusters yet. Click <em>Rebuild clusters</em> to ingest opt-in
          tenant findings.
        </p>
      ) : (
        <ul className="space-y-3">
          {clusters.map((c) => (
            <li
              key={c.id}
              className="rounded-lg border border-slate-200 bg-white p-4"
            >
              <div className="flex items-center justify-between">
                <span className="font-medium">
                  {c.category}{" "}
                  <span className="ml-2 text-xs text-slate-500">{c.id}</span>
                </span>
                <SeverityBadge severity={c.severity} />
              </div>
              <div className="mt-1 text-xs text-slate-500">
                {c.size} samples across {c.supporting_orgs} org(s)
              </div>
              {c.top_keywords.length > 0 ? (
                <div className="mt-2 flex flex-wrap gap-1">
                  {c.top_keywords.map((k) => (
                    <span
                      key={k}
                      className="rounded bg-slate-100 px-2 py-0.5 font-mono text-xs"
                    >
                      {k}
                    </span>
                  ))}
                </div>
              ) : null}
              {c.top_controls.length > 0 ? (
                <div className="mt-2 text-xs text-slate-600">
                  <strong>Controls:</strong> {c.top_controls.join(", ")}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function StatusCard({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-2xl font-semibold text-slate-900">{value}</div>
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
