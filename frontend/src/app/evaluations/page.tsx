"use client";

import { PreviewBadge } from "@/components/PreviewBadge";
import { useEffect, useState } from "react";
import Link from "next/link";

import { api, ApiError, type Evaluation } from "@/lib/api";

export default function EvaluationsPage() {
  const [evals, setEvals] = useState<Evaluation[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 5000);
    return () => clearInterval(t);
  }, []);

  async function load(): Promise<void> {
    try {
      setError(null);
      const data = await api.get<Evaluation[]>("/v1/evaluations");
      setEvals(data);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  return (
    <div>
      <div className="mb-6 flex items-center gap-2">
        <h1 className="text-2xl font-semibold">Evaluations</h1>
        <PreviewBadge variant="heading" />
      </div>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : evals === null ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : evals.length === 0 ? (
        <p className="text-sm text-slate-500">
          No evaluations yet. Start one from an asset detail page.
        </p>
      ) : (
        <ul className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          {evals.map((e) => (
            <li
              key={e.id}
              className="border-b border-slate-200 px-5 py-4 last:border-b-0"
            >
              <div className="flex items-center justify-between">
                <div>
                  <Link
                    href={`/evaluations/${e.id}`}
                    className="font-mono text-sm text-slate-700 hover:underline"
                  >
                    {e.id.slice(0, 8)}…
                  </Link>
                  <span className="ml-3 text-sm text-slate-500">
                    {e.eval_type}
                  </span>
                  <StatusBadge status={e.status} />
                </div>
                <div className="text-right text-sm">
                  <div>
                    Score: <strong>{e.score.toFixed(0)}</strong> ({e.risk_label ?? "—"})
                  </div>
                  <div className="text-slate-500">
                    {e.tests_passed}/{e.tests_run} passed · {e.findings_count} findings
                  </div>
                </div>
              </div>
              <div className="mt-1 flex items-center justify-between text-xs text-slate-500">
                <Link
                  href={`/assets/${e.asset_id}`}
                  className="hover:underline"
                >
                  asset {e.asset_id.slice(0, 8)}…
                </Link>
                <span>
                  {e.completed_at
                    ? `completed ${new Date(e.completed_at).toLocaleString()}`
                    : e.started_at
                      ? `running since ${new Date(e.started_at).toLocaleString()}`
                      : `created ${new Date(e.created_at).toLocaleString()}`}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

interface StatusBadgeProps {
  status: string;
}

const statusColors: Record<string, string> = {
  created: "bg-slate-100 text-slate-700",
  running: "bg-blue-100 text-blue-700",
  completed: "bg-emerald-100 text-emerald-700",
  failed: "bg-red-100 text-red-700",
  cancelled: "bg-slate-100 text-slate-500",
};

function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span
      className={`ml-2 rounded-full px-2 py-0.5 text-xs font-medium ${
        statusColors[status] ?? statusColors.created
      }`}
    >
      {status}
    </span>
  );
}
