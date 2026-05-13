"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, ApiError, type Finding } from "@/lib/api";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "open", "in_progress", "remediated", "verified", "accepted_risk", "false_positive"];

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("open");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void load();
  }, [severity, status]);

  async function load(): Promise<void> {
    try {
      setError(null);
      const params = new URLSearchParams();
      if (severity) params.set("severity", severity);
      if (status) params.set("remediation_status", status);
      const data = await api.get<Finding[]>(
        `/v1/findings?${params.toString()}`,
      );
      setFindings(data);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function changeStatus(id: string, newStatus: string): Promise<void> {
    try {
      await api.patch<Finding>(`/v1/findings/${id}/remediation`, {
        remediation_status: newStatus,
      });
      void load();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "update failed");
    }
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Findings</h1>
        <div className="flex items-center gap-2 text-sm">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-md border border-slate-300 px-2 py-1.5"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s || "all severities"}
              </option>
            ))}
          </select>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="rounded-md border border-slate-300 px-2 py-1.5"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s || "all statuses"}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : findings === null ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : findings.length === 0 ? (
        <p className="text-sm text-slate-500">No findings match the filter.</p>
      ) : (
        <ul className="space-y-3">
          {findings.map((f) => (
            <li
              key={f.id}
              className="rounded-lg border border-slate-200 bg-white p-4"
            >
              <div className="flex items-center justify-between">
                <span className="font-medium">{f.title}</span>
                <SeverityBadge severity={f.severity} />
              </div>
              <div className="mt-1 flex items-center justify-between text-xs text-slate-500">
                <span>
                  {f.category} · risk {f.risk_score.toFixed(0)} ·{" "}
                  <Link
                    href={`/assets/${f.asset_id}`}
                    className="hover:underline"
                  >
                    asset {f.asset_id.slice(0, 8)}…
                  </Link>
                </span>
                <span>{new Date(f.created_at).toLocaleString()}</span>
              </div>
              {f.judge_reasoning ? (
                <p className="mt-2 text-sm text-slate-700">
                  {f.judge_reasoning}
                </p>
              ) : null}
              {f.recommendation ? (
                <p className="mt-2 text-sm text-slate-600">
                  <strong>Remediation:</strong> {f.recommendation}
                </p>
              ) : null}
              <div className="mt-3 flex items-center gap-2 text-xs">
                <span className="text-slate-500">Status:</span>
                <select
                  value={f.remediation_status}
                  onChange={(e) => void changeStatus(f.id, e.target.value)}
                  className="rounded-md border border-slate-300 px-2 py-1"
                >
                  {STATUSES.filter(Boolean).map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
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
