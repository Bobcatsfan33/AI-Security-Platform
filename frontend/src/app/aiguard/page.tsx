"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import {
  aiguard,
  ApiError,
  type AIGuardAction,
  type AIGuardDirection,
  type AIGuardResponse,
  type DetectorAction,
  type DetectorConfig,
  type DetectorOutcome,
} from "@/lib/api";

type TuningRow = { threshold: number; action: DetectorAction | "default" };

function defaultRows(
  names: string[],
  defaults: Record<string, number>,
): Record<string, TuningRow> {
  return Object.fromEntries(
    names.map((name) => [
      name,
      { threshold: defaults[name] ?? 0.5, action: "default" as const },
    ]),
  );
}

const VERDICT_STYLES: Record<AIGuardAction, string> = {
  allow: "bg-emerald-100 text-emerald-800",
  detect: "bg-amber-100 text-amber-800",
  block: "bg-red-100 text-red-800",
};

const SEVERITY_STYLES: Record<string, string> = {
  info: "bg-slate-100 text-slate-600",
  low: "bg-sky-100 text-sky-700",
  medium: "bg-amber-100 text-amber-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export default function AIGuardPage() {
  const [thresholds, setThresholds] = useState<Record<string, number> | null>(null);
  const [tuning, setTuning] = useState<Record<string, TuningRow>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setError(null);
        const cat = await aiguard.detectors();
        setThresholds(cat.default_thresholds);
        setTuning(defaultRows(cat.detectors, cat.default_thresholds));
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Failed to load detectors");
      }
    })();
  }, []);

  function updateRow(name: string, patch: Partial<TuningRow>): void {
    setTuning((prev) => ({ ...prev, [name]: { ...prev[name], ...patch } }));
  }

  function resetTuning(): void {
    if (!thresholds) return;
    setTuning(defaultRows(Object.keys(tuning), thresholds));
  }

  function buildConfig(): Record<string, DetectorConfig> {
    return Object.fromEntries(
      Object.entries(tuning).map(([name, row]) => [
        name,
        row.action === "default"
          ? { threshold: row.threshold }
          : { threshold: row.threshold, action: row.action },
      ]),
    );
  }

  return (
    <div>
      <div className="mb-2 flex items-baseline justify-between">
        <h1 className="text-2xl font-semibold">AI Guard</h1>
        <span className="text-sm text-slate-500">
          Content inspection · {Object.keys(tuning).length} detectors
        </span>
      </div>
      <p className="mb-6 max-w-3xl text-sm text-slate-600">
        Tune per-detector thresholds and actions, then run a live inspection. A
        block or detect verdict is published into the narrative pipeline and
        joins the behavioural flow it belongs to.
      </p>

      {error ? (
        <p className="mb-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : null}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <DetectorTuning
          tuning={tuning}
          loading={thresholds === null}
          onChange={updateRow}
          onReset={resetTuning}
        />
        <InspectPlayground buildConfig={buildConfig} />
      </div>
    </div>
  );
}

interface DetectorTuningProps {
  tuning: Record<string, TuningRow>;
  loading: boolean;
  onChange: (name: string, patch: Partial<TuningRow>) => void;
  onReset: () => void;
}

function DetectorTuning({ tuning, loading, onChange, onReset }: DetectorTuningProps) {
  const names = Object.keys(tuning).sort();
  return (
    <section className="rounded-lg border border-slate-200 bg-white">
      <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3">
        <h2 className="font-medium">Detector tuning</h2>
        <button
          type="button"
          onClick={onReset}
          className="rounded-md border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-50"
        >
          Reset defaults
        </button>
      </div>
      {loading ? (
        <p className="px-5 py-4 text-sm text-slate-500">Loading detectors…</p>
      ) : (
        <ul className="max-h-[28rem] divide-y divide-slate-100 overflow-y-auto">
          {names.map((name) => {
            const row = tuning[name];
            return (
              <li key={name} className="flex items-center gap-3 px-5 py-2.5">
                <span className="w-40 shrink-0 truncate font-mono text-xs" title={name}>
                  {name}
                </span>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={row.threshold}
                  onChange={(e) => onChange(name, { threshold: Number(e.target.value) })}
                  className="flex-1"
                  aria-label={`${name} threshold`}
                />
                <span className="w-10 shrink-0 text-right font-mono text-xs text-slate-600">
                  {row.threshold.toFixed(2)}
                </span>
                <select
                  value={row.action}
                  onChange={(e) =>
                    onChange(name, { action: e.target.value as TuningRow["action"] })
                  }
                  className="shrink-0 rounded-md border border-slate-300 px-2 py-1 text-xs"
                  aria-label={`${name} action`}
                >
                  <option value="default">default</option>
                  <option value="block">block</option>
                  <option value="detect">detect</option>
                  <option value="off">off</option>
                </select>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

interface InspectPlaygroundProps {
  buildConfig: () => Record<string, DetectorConfig>;
}

function InspectPlayground({ buildConfig }: InspectPlaygroundProps) {
  const [text, setText] = useState("");
  const [direction, setDirection] = useState<AIGuardDirection>("inbound");
  const [correlationKey, setCorrelationKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIGuardResponse | null>(null);

  async function inspect(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const res = await aiguard.inspect({
        text,
        direction,
        config: buildConfig(),
        correlation_key: correlationKey || undefined,
      });
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Inspection failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-5 py-3">
        <h2 className="font-medium">Live inspection</h2>
      </div>
      <div className="space-y-3 px-5 py-4">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={4}
          placeholder="Paste a prompt or response to inspect…"
          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
        />
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-sm">
            <span className="mr-2 text-slate-600">Direction</span>
            <select
              value={direction}
              onChange={(e) => setDirection(e.target.value as AIGuardDirection)}
              className="rounded-md border border-slate-300 px-2 py-1 text-sm"
            >
              <option value="inbound">inbound</option>
              <option value="outbound">outbound</option>
            </select>
          </label>
          <input
            value={correlationKey}
            onChange={(e) => setCorrelationKey(e.target.value)}
            placeholder="correlation_key (optional)"
            className="flex-1 rounded-md border border-slate-300 px-3 py-1.5 font-mono text-xs"
          />
          <button
            type="button"
            onClick={() => void inspect()}
            disabled={busy || text.length === 0}
            className="rounded-md bg-slate-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
          >
            {busy ? "Inspecting…" : "Inspect"}
          </button>
        </div>
        {error ? <p className="text-sm text-red-600">{error}</p> : null}
        {result ? <InspectResult result={result} /> : null}
      </div>
    </section>
  );
}

function InspectResult({ result }: { result: AIGuardResponse }) {
  const triggered = result.detectors.filter((d) => d.triggered);
  return (
    <div className="space-y-3 border-t border-slate-100 pt-3">
      <div className="flex items-center gap-3">
        <span
          className={`rounded-full px-3 py-0.5 text-sm font-semibold uppercase ${VERDICT_STYLES[result.action]}`}
        >
          {result.action}
        </span>
        <span className="text-sm text-slate-600">{result.reason}</span>
        <span className="ml-auto font-mono text-xs text-slate-400">
          {result.latency_ms.toFixed(1)} ms
        </span>
      </div>

      {result.narrative?.published ? (
        <p className="rounded-md border border-indigo-200 bg-indigo-50 p-2 text-xs text-indigo-700">
          Published to narrative pipeline ·{" "}
          {result.narrative.narrative_ids.map((id) => (
            <Link key={id} href={`/narratives/${id}`} className="font-mono underline">
              {id.slice(0, 8)}
            </Link>
          ))}
        </p>
      ) : null}

      {triggered.length === 0 ? (
        <p className="text-sm text-slate-500">No detectors triggered.</p>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
          {triggered.map((d) => (
            <DetectorRow key={d.name} d={d} />
          ))}
        </ul>
      )}
    </div>
  );
}

function DetectorRow({ d }: { d: DetectorOutcome }) {
  return (
    <li className="flex items-center gap-2 px-3 py-2 text-sm">
      <span className="font-mono text-xs">{d.name}</span>
      <span
        className={`rounded-full px-2 py-0.5 text-xs ${SEVERITY_STYLES[d.severity] ?? SEVERITY_STYLES.info}`}
      >
        {d.severity}
      </span>
      <span className="ml-auto font-mono text-xs text-slate-500">
        {d.confidence.toFixed(2)} ≥ {d.threshold.toFixed(2)} · {d.action}
      </span>
    </li>
  );
}
