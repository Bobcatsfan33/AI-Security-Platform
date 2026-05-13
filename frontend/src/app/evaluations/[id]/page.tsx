"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  ApiError,
  type Evaluation,
  type Finding,
} from "@/lib/api";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function EvaluationDetailPage({ params }: PageProps) {
  const { id } = use(params);
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 3000);
    return () => clearInterval(t);
  }, [id]);

  async function load(): Promise<void> {
    try {
      setError(null);
      const [e, f] = await Promise.all([
        api.get<Evaluation>(`/v1/evaluations/${id}`),
        api.get<Finding[]>(`/v1/findings?evaluation_id=${id}`),
      ]);
      setEvaluation(e);
      setFindings(f);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  if (error) {
    return (
      <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
        {error}
      </p>
    );
  }
  if (!evaluation) {
    return <p className="text-sm text-slate-500">Loading…</p>;
  }

  return (
    <div>
      <div className="mb-1 text-sm text-slate-500">
        <Link href="/evaluations" className="hover:underline">
          Evaluations
        </Link>{" "}
        / <span className="font-mono">{evaluation.id.slice(0, 8)}…</span>
      </div>
      <h1 className="mb-6 text-2xl font-semibold">
        Evaluation — {evaluation.status}
      </h1>

      <section className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-4">
        <Stat label="Score" value={evaluation.score.toFixed(0)} />
        <Stat label="Risk label" value={evaluation.risk_label ?? "—"} />
        <Stat
          label="Tests passed"
          value={`${evaluation.tests_passed}/${evaluation.tests_run}`}
        />
        <Stat
          label="Findings"
          value={`${evaluation.findings_count} (${evaluation.critical_findings} critical)`}
        />
      </section>

      <section className="mb-8 rounded-lg border border-slate-200 bg-white p-5">
        <h2 className="mb-3 font-medium">Summary</h2>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
          <KV k="Type" v={evaluation.eval_type} />
          <KV
            k="Asset"
            v={
              <Link
                href={`/assets/${evaluation.asset_id}`}
                className="text-slate-700 hover:underline"
              >
                {evaluation.asset_id.slice(0, 8)}…
              </Link>
            }
          />
          <KV
            k="Cost"
            v={`$${evaluation.model_cost_usd.toFixed(4)}`}
          />
          <KV
            k="Duration"
            v={
              evaluation.duration_seconds
                ? `${evaluation.duration_seconds}s`
                : "—"
            }
          />
        </dl>
        {Object.keys(evaluation.summary).length > 0 ? (
          <pre className="mt-4 overflow-x-auto rounded-md bg-slate-50 p-3 text-xs">
            {JSON.stringify(evaluation.summary, null, 2)}
          </pre>
        ) : null}
      </section>

      <section>
        <h2 className="mb-3 font-medium">Findings</h2>
        {findings.length === 0 ? (
          <p className="text-sm text-slate-500">
            {evaluation.status === "running"
              ? "Evaluation in progress…"
              : "No findings."}
          </p>
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
                <div className="mt-1 text-xs text-slate-500">
                  {f.category} · risk {f.risk_score.toFixed(0)} · conf{" "}
                  {f.confidence.toFixed(2)} · {f.remediation_status}
                </div>
                {f.judge_reasoning ? (
                  <p className="mt-2 text-sm text-slate-700">
                    {f.judge_reasoning}
                  </p>
                ) : null}
                {f.prompt_sent ? (
                  <details className="mt-2 text-sm">
                    <summary className="cursor-pointer text-slate-500">
                      Prompt → Response
                    </summary>
                    <div className="mt-2 space-y-2">
                      <pre className="overflow-x-auto rounded-md bg-slate-50 p-3 text-xs">
                        {f.prompt_sent}
                      </pre>
                      <pre className="overflow-x-auto rounded-md bg-slate-50 p-3 text-xs">
                        {f.response_received ?? ""}
                      </pre>
                    </div>
                  </details>
                ) : null}
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
      <div className="mt-1 text-xl font-semibold">{value}</div>
    </div>
  );
}

interface KVProps {
  k: string;
  v: React.ReactNode;
}

function KV({ k, v }: KVProps) {
  return (
    <>
      <dt className="text-slate-500">{k}</dt>
      <dd className="text-slate-900">{v}</dd>
    </>
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
