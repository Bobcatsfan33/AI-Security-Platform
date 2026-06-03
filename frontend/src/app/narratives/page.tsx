"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import {
  ApiError,
  narratives,
  type DispositionInput,
  type NarrativeStatus,
  type ThreatNarrative,
} from "@/lib/api";

const STATUSES: NarrativeStatus[] = [
  "open",
  "confirmed",
  "false_positive",
  "suppressed",
  "resolved",
];
const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];

export default function WorkbenchPage() {
  const [items, setItems] = useState<ThreatNarrative[] | null>(null);
  const [selected, setSelected] = useState<ThreatNarrative | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const data = await narratives.list({
        status: statusFilter,
        severity: severityFilter,
      });
      setItems(data);
      if (data.length > 0 && !selected) setSelected(data[0]);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, severityFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  async function openNarrative(id: string): Promise<void> {
    try {
      setSelected(await narratives.get(id));
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function disposition(body: DispositionInput): Promise<void> {
    if (!selected) return;
    try {
      const updated = await narratives.disposition(selected.id, body);
      setSelected(updated);
      await load();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "disposition failed");
    }
  }

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-2xl font-semibold text-slate-900">
          Analyst Workbench
        </h1>
        <p className="text-sm text-slate-600">
          Tier-3 threat narratives — one actionable incident per causal flow,
          with the full kill-chain timeline.
        </p>
      </header>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <span className="text-slate-500">status:</span>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-md border border-slate-300 px-2 py-1.5"
        >
          <option value="">all</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span className="text-slate-500">severity:</span>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-md border border-slate-300 px-2 py-1.5"
        >
          {SEVERITIES.map((s) => (
            <option key={s || "all"} value={s}>
              {s || "all"}
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
      ) : items === null ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : items.length === 0 ? (
        <p className="rounded-md border border-slate-200 bg-white p-4 text-sm text-slate-500">
          No narratives. The EPA fleet produces these as correlated incidents.
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_1.4fr]">
          <ul className="space-y-2">
            {items.map((n) => (
              <li key={n.id}>
                <button
                  onClick={() => void openNarrative(n.id)}
                  className={`w-full rounded-lg border p-3 text-left ${
                    selected?.id === n.id
                      ? "border-slate-900 bg-white"
                      : "border-slate-200 bg-white hover:border-slate-400"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-900">
                      {n.title}
                    </span>
                    <SeverityBadge severity={n.severity} />
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-slate-500">
                    <StatusPill status={n.status} />
                    <span>· {n.signal_count} signals</span>
                    <span>· {n.agents.length} agents</span>
                  </div>
                </button>
              </li>
            ))}
          </ul>

          {selected ? (
            <NarrativeDetail narrative={selected} onDisposition={disposition} />
          ) : null}
        </div>
      )}
    </div>
  );
}

function NarrativeDetail({
  narrative,
  onDisposition,
}: {
  narrative: ThreatNarrative;
  onDisposition: (body: DispositionInput) => Promise<void>;
}) {
  const [rationale, setRationale] = useState("");

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="font-semibold text-slate-900">{narrative.title}</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            {narrative.kind} · flow {narrative.correlation_id.slice(0, 12)} ·
            confidence {(narrative.confidence * 100).toFixed(0)}%
          </p>
        </div>
        <SeverityBadge severity={narrative.severity} />
      </div>

      <Section title="Kill chain (causal timeline)">
        {narrative.causal_timeline.length === 0 ? (
          <p className="text-xs text-slate-400">
            No timeline events captured for this flow.
          </p>
        ) : (
          <ol className="space-y-1">
            {narrative.causal_timeline.map((ev, i) => (
              <li
                key={i}
                className="flex items-center gap-2 text-xs text-slate-700"
              >
                <span className="font-mono text-slate-400">{i + 1}.</span>
                <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono">
                  {String(ev.event_type ?? "event")}
                </span>
                <span className="text-slate-500">
                  {String(ev.tool_name ?? ev.agent_instance_id ?? "")}
                </span>
              </li>
            ))}
          </ol>
        )}
      </Section>

      <Section title={`Contributing signals (${narrative.contributing.length})`}>
        <ul className="space-y-1">
          {narrative.contributing.map((c, i) => (
            <li key={i} className="text-xs text-slate-700">
              <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono">
                {String(c.kind ?? "signal")}
              </span>{" "}
              {String(c.title ?? "")}
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Disposition">
        <div className="mb-2 text-xs text-slate-500">
          Current: <StatusPill status={narrative.status} />
          {narrative.assignee ? ` · ${narrative.assignee}` : ""}
        </div>
        <textarea
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          placeholder="Rationale (recorded to the tamper-evident audit log)"
          className="mb-2 w-full rounded-md border border-slate-300 p-2 text-sm"
          rows={2}
        />
        <div className="flex flex-wrap gap-2">
          <DispositionButton
            label="Confirm"
            color="bg-red-600"
            onClick={() => onDisposition({ status: "confirmed", rationale })}
          />
          <DispositionButton
            label="False positive"
            color="bg-slate-600"
            onClick={() =>
              onDisposition({ status: "false_positive", rationale })
            }
          />
          <DispositionButton
            label="Suppress"
            color="bg-amber-600"
            onClick={() => onDisposition({ status: "suppressed", rationale })}
          />
          <DispositionButton
            label="Resolve"
            color="bg-emerald-600"
            onClick={() => onDisposition({ status: "resolved", rationale })}
          />
        </div>
      </Section>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mt-4 border-t border-slate-100 pt-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
        {title}
      </h3>
      {children}
    </div>
  );
}

function DispositionButton({
  label,
  color,
  onClick,
}: {
  label: string;
  color: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-md px-3 py-1.5 text-xs font-medium text-white ${color} hover:opacity-90`}
    >
      {label}
    </button>
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

const statusColors: Record<string, string> = {
  open: "bg-blue-100 text-blue-700",
  confirmed: "bg-red-100 text-red-700",
  false_positive: "bg-slate-100 text-slate-600",
  suppressed: "bg-amber-100 text-amber-700",
  resolved: "bg-emerald-100 text-emerald-700",
};

function StatusPill({ status }: { status: string }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
        statusColors[status] ?? statusColors.open
      }`}
    >
      {status}
    </span>
  );
}
