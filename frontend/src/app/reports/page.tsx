"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, ApiError, type Evaluation } from "@/lib/api";

const TEMPLATES: Array<{ id: string; label: string }> = [
  { id: "executive_summary", label: "Executive summary" },
  { id: "technical_detail", label: "Technical detail" },
  { id: "owasp_llm_top10", label: "OWASP LLM Top 10" },
  { id: "nist_ai_rmf", label: "NIST AI RMF" },
  { id: "soc2_ai", label: "SOC 2 (AI)" },
  { id: "eu_ai_act", label: "EU AI Act" },
];

export default function ReportsPage() {
  const [evals, setEvals] = useState<Evaluation[] | null>(null);
  const [evalId, setEvalId] = useState("");
  const [template, setTemplate] = useState(TEMPLATES[0].id);
  const [report, setReport] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadEvals();
  }, []);

  async function loadEvals(): Promise<void> {
    try {
      setError(null);
      const data = await api.get<Evaluation[]>("/v1/evaluations");
      setEvals(data);
      if (data.length > 0 && !evalId) setEvalId(data[0].id);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function generate(): Promise<void> {
    if (!evalId) return;
    try {
      setError(null);
      setLoading(true);
      setReport(null);
      const md = await api.getText(
        `/v1/reports/${evalId}?template=${template}`,
      );
      setReport(md);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "report failed");
    } finally {
      setLoading(false);
    }
  }

  function download(): void {
    if (!report) return;
    const blob = new Blob([report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${template}-${evalId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <h1 className="mb-6 text-2xl font-semibold">Reports</h1>

      <div className="mb-4 flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          <span className="text-slate-500">Evaluation</span>
          <select
            value={evalId}
            onChange={(e) => setEvalId(e.target.value)}
            className="min-w-[22rem] rounded-md border border-slate-300 px-2 py-1.5"
          >
            {evals === null ? (
              <option value="">Loading…</option>
            ) : evals.length === 0 ? (
              <option value="">No evaluations</option>
            ) : (
              evals.map((ev) => (
                <option key={ev.id} value={ev.id}>
                  {ev.id.slice(0, 8)}… · {ev.status} · score{" "}
                  {ev.score.toFixed(0)} · {ev.findings_count} findings
                </option>
              ))
            )}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-slate-500">Template</span>
          <select
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            className="rounded-md border border-slate-300 px-2 py-1.5"
          >
            {TEMPLATES.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => void generate()}
          disabled={!evalId || loading}
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          {loading ? "Generating…" : "Generate"}
        </button>
        {report ? (
          <button
            type="button"
            onClick={download}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100"
          >
            Download .md
          </button>
        ) : null}
      </div>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : report ? (
        <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg border border-slate-200 bg-white p-5 text-sm leading-relaxed text-slate-800">
          {report}
        </pre>
      ) : (
        <p className="text-sm text-slate-500">
          Pick an evaluation and template, then Generate.
        </p>
      )}
    </div>
  );
}
