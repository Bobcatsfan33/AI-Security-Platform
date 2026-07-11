"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  api,
  ApiError,
  type McpToolProfile,
  type McpViolation,
} from "@/lib/api";

export default function McpPage() {
  const [tools, setTools] = useState<McpToolProfile[] | null>(null);
  const [violations, setViolations] = useState<McpViolation[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void load();
  }, []);

  async function load(): Promise<void> {
    try {
      setError(null);
      const [t, v] = await Promise.all([
        api.get<McpToolProfile[]>("/v1/mcp/tools"),
        api.get<McpViolation[]>("/v1/mcp/violations"),
      ]);
      setTools(t);
      setViolations(v);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  if (error) {
    return (
      <div>
        <h1 className="mb-6 text-2xl font-semibold">MCP Inspection</h1>
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-semibold">MCP Inspection</h1>

      <section>
        <h2 className="mb-3 text-lg font-medium text-slate-800">
          Tool Profiles
        </h2>
        {tools === null ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : tools.length === 0 ? (
          <p className="text-sm text-slate-500">No tool profiles defined.</p>
        ) : (
          <ul className="space-y-2">
            {tools.map((t) => (
              <li
                key={t.id}
                className="rounded-lg border border-slate-200 bg-white p-4"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm font-medium">
                    {t.tool_name}
                  </span>
                  <div className="flex items-center gap-2">
                    {t.is_builtin ? (
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">
                        built-in
                      </span>
                    ) : null}
                    <AccessModeBadge mode={t.access_mode} />
                  </div>
                </div>
                {t.description ? (
                  <p className="mt-1 text-sm text-slate-600">{t.description}</p>
                ) : null}
                {t.forbidden_params.length > 0 ? (
                  <p className="mt-2 text-xs text-slate-500">
                    Forbidden params: {t.forbidden_params.join(", ")}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-lg font-medium text-slate-800">Violations</h2>
        {violations === null ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : violations.length === 0 ? (
          <p className="text-sm text-slate-500">No violations recorded.</p>
        ) : (
          <ul className="space-y-2">
            {violations.map((v) => (
              <li
                key={v.id}
                className="rounded-lg border border-slate-200 bg-white p-4"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-sm font-medium">
                    {v.tool_name}
                  </span>
                  <div className="flex items-center gap-2 text-xs">
                    <RecommendationBadge recommendation={v.recommendation} />
                    <span className="text-slate-500">
                      risk {v.risk_score.toFixed(0)}
                    </span>
                  </div>
                </div>
                <div className="mt-1 flex items-center justify-between text-xs text-slate-500">
                  <span>
                    session {v.session_id.slice(0, 12)}… · {v.resolution_status}
                  </span>
                  <span>{new Date(v.created_at).toLocaleString()}</span>
                </div>
                {v.violations.length > 0 ? (
                  <p className="mt-2 text-xs text-slate-500">
                    {v.violations.length} rule
                    {v.violations.length === 1 ? "" : "s"} triggered
                    {v.chain_matches.length > 0
                      ? ` · ${v.chain_matches.length} chain match${
                          v.chain_matches.length === 1 ? "" : "es"
                        }`
                      : ""}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

const accessModeColors: Record<string, string> = {
  read: "bg-emerald-100 text-emerald-700",
  write: "bg-yellow-100 text-yellow-800",
  execute: "bg-orange-100 text-orange-800",
  admin: "bg-red-100 text-red-700",
  exfil: "bg-red-100 text-red-700",
};

function AccessModeBadge({ mode }: { mode: string }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
        accessModeColors[mode] ?? "bg-slate-100 text-slate-700"
      }`}
    >
      {mode}
    </span>
  );
}

const recommendationColors: Record<string, string> = {
  allow: "bg-emerald-100 text-emerald-700",
  flag: "bg-yellow-100 text-yellow-800",
  block: "bg-red-100 text-red-700",
};

function RecommendationBadge({ recommendation }: { recommendation: string }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 font-medium ${
        recommendationColors[recommendation] ?? "bg-slate-100 text-slate-700"
      }`}
    >
      {recommendation}
    </span>
  );
}
