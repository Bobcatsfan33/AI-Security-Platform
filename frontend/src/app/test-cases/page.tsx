"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, ApiError, type TestCase } from "@/lib/api";

const CATEGORIES = [
  "",
  "prompt_injection",
  "credential_leakage",
  "data_exfiltration",
  "unsafe_tool_use",
  "jailbreak",
  "indirect_injection",
];

export default function TestCasesPage() {
  const [cases, setCases] = useState<TestCase[] | null>(null);
  const [category, setCategory] = useState("");
  const [includeGlobal, setIncludeGlobal] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void load();
  }, [category, includeGlobal]);

  async function load(): Promise<void> {
    try {
      setError(null);
      const params = new URLSearchParams();
      if (category) params.set("category", category);
      params.set("include_global", String(includeGlobal));
      const data = await api.get<TestCase[]>(
        `/v1/test-cases?${params.toString()}`,
      );
      setCases(data);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Test Cases</h1>
        <div className="flex items-center gap-3 text-sm">
          <label className="flex items-center gap-1.5 text-slate-600">
            <input
              type="checkbox"
              checked={includeGlobal}
              onChange={(e) => setIncludeGlobal(e.target.checked)}
            />
            Include shared library
          </label>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded-md border border-slate-300 px-2 py-1.5"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c || "all categories"}
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
      ) : cases === null ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : cases.length === 0 ? (
        <p className="text-sm text-slate-500">No test cases match the filter.</p>
      ) : (
        <ul className="space-y-3">
          {cases.map((tc) => (
            <li
              key={tc.id}
              className="rounded-lg border border-slate-200 bg-white p-4"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium">{tc.name}</span>
                <div className="flex items-center gap-2">
                  {tc.is_global ? (
                    <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-700">
                      shared
                    </span>
                  ) : null}
                  <SeverityBadge severity={tc.severity} />
                </div>
              </div>
              <div className="mt-1 text-xs text-slate-500">
                {tc.category}
                {tc.sub_category ? ` · ${tc.sub_category}` : ""} ·{" "}
                {tc.attack_type} · {tc.source}
              </div>
              {tc.description ? (
                <p className="mt-2 text-sm text-slate-700">{tc.description}</p>
              ) : null}
              <p className="mt-2 text-sm text-slate-600">
                <strong>Expected:</strong> {tc.expected_behavior}
              </p>
              {tc.control_mappings.length > 0 || tc.tags.length > 0 ? (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {tc.control_mappings.map((c) => (
                    <span
                      key={c}
                      className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600"
                    >
                      {c}
                    </span>
                  ))}
                  {tc.tags.map((t) => (
                    <span
                      key={t}
                      className="rounded bg-sky-50 px-1.5 py-0.5 text-xs text-sky-700"
                    >
                      #{t}
                    </span>
                  ))}
                </div>
              ) : null}
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
