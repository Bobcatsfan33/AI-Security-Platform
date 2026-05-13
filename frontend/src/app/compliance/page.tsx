"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  API_BASE,
  api,
  ApiError,
  getToken,
  type ComplianceFramework,
} from "@/lib/api";

const FRAMEWORKS = ["soc2", "iso27001", "fedramp_moderate"] as const;
type FrameworkId = (typeof FRAMEWORKS)[number];

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<ComplianceFramework[] | null>(
    null,
  );
  const [framework, setFramework] = useState<FrameworkId>("soc2");
  const [periodStart, setPeriodStart] = useState<string>(defaultStart());
  const [periodEnd, setPeriodEnd] = useState<string>(defaultEnd());
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    void load();
  }, []);

  async function load(): Promise<void> {
    try {
      setError(null);
      const data = await api.get<ComplianceFramework[]>(
        "/v1/compliance/frameworks",
      );
      setFrameworks(data);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function downloadPack(): Promise<void> {
    setDownloading(true);
    setError(null);
    try {
      const token = getToken();
      const params = new URLSearchParams({
        framework,
        period_start: new Date(periodStart).toISOString(),
        period_end: new Date(periodEnd).toISOString(),
      });
      const resp = await fetch(
        `${API_BASE}/v1/compliance/evidence-pack?${params}`,
        { headers: token ? { Authorization: `Bearer ${token}` } : {} },
      );
      if (!resp.ok) {
        throw new Error(
          `${resp.status} ${resp.statusText}: ${await resp.text()}`,
        );
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `evidence-pack-${framework}-${periodStart}-${periodEnd}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "download failed");
    } finally {
      setDownloading(false);
    }
  }

  const selected = frameworks?.find((f) => f.id === framework);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-900">Compliance</h1>
        <p className="text-sm text-slate-600">
          Download evidence packs for auditor review.
        </p>
      </header>

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : null}

      <div className="grid gap-4 rounded-lg border border-slate-200 bg-white p-4 sm:grid-cols-2">
        <label className="text-sm">
          <span className="text-slate-600">Framework</span>
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value as FrameworkId)}
            className="mt-1 block w-full rounded-md border border-slate-300 px-2 py-1.5"
          >
            {FRAMEWORKS.map((f) => (
              <option key={f} value={f}>
                {frameworks?.find((x) => x.id === f)?.name ?? f}
              </option>
            ))}
          </select>
        </label>
        <div />
        <label className="text-sm">
          <span className="text-slate-600">Period start</span>
          <input
            type="date"
            value={periodStart}
            onChange={(e) => setPeriodStart(e.target.value)}
            className="mt-1 block w-full rounded-md border border-slate-300 px-2 py-1.5"
          />
        </label>
        <label className="text-sm">
          <span className="text-slate-600">Period end</span>
          <input
            type="date"
            value={periodEnd}
            onChange={(e) => setPeriodEnd(e.target.value)}
            className="mt-1 block w-full rounded-md border border-slate-300 px-2 py-1.5"
          />
        </label>
        <div className="sm:col-span-2">
          <button
            onClick={() => void downloadPack()}
            disabled={downloading}
            className="rounded-md bg-slate-900 px-4 py-2 text-sm text-white disabled:opacity-50"
          >
            {downloading ? "Building pack…" : "Download evidence pack"}
          </button>
        </div>
      </div>

      {selected ? (
        <div>
          <h2 className="mb-3 text-lg font-semibold text-slate-900">
            Controls covered ({selected.control_count})
          </h2>
          <ul className="grid gap-2 sm:grid-cols-2">
            {selected.controls.map((c) => (
              <li
                key={c.id}
                className="rounded-md border border-slate-200 bg-white p-3 text-sm"
              >
                <span className="font-mono text-xs text-slate-500">
                  {c.id}
                </span>
                <div className="mt-0.5 font-medium text-slate-900">
                  {c.title}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function defaultStart(): string {
  const d = new Date();
  d.setMonth(d.getMonth() - 3);
  return d.toISOString().slice(0, 10);
}

function defaultEnd(): string {
  return new Date().toISOString().slice(0, 10);
}
