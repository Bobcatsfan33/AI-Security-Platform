"use client";

import { PreviewBadge } from "@/components/PreviewBadge";
import { useEffect, useState } from "react";
import Link from "next/link";

import {
  ApiError,
  redteam,
  type CampaignCreate,
  type RedTeamCampaign,
  type RedTeamFinding,
  type RedTeamStrategy,
} from "@/lib/api";

const STATUS_STYLES: Record<string, string> = {
  created: "bg-slate-100 text-slate-600",
  running: "bg-sky-100 text-sky-700",
  completed: "bg-emerald-100 text-emerald-800",
  failed: "bg-red-100 text-red-800",
};

const RISK_STYLES: Record<string, string> = {
  good: "bg-emerald-100 text-emerald-800",
  needs_hardening: "bg-amber-100 text-amber-800",
  high_risk: "bg-red-100 text-red-800",
};

const PROVIDERS = ["openai", "anthropic", "ollama", "azure_openai", "bedrock", "custom"];

export default function RedTeamPage() {
  return (
    <div>
      <div className="mb-1 flex items-center gap-2">
        <h1 className="text-2xl font-semibold">Red Team</h1>
        <PreviewBadge variant="heading" />
      </div>
      <p className="mb-6 max-w-3xl text-sm text-slate-600">
        Run the attack-strategy library against a target model, judge each
        response, and review the findings worth hardening against.
      </p>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <LaunchCard />
        <StrategiesCard />
      </div>
      <CampaignsCard />
    </div>
  );
}

function LaunchCard() {
  const [provider, setProvider] = useState("openai");
  const [model, setModel] = useState("");
  const [apiKeyRef, setApiKeyRef] = useState("");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [launched, setLaunched] = useState<string | null>(null);

  async function launch(): Promise<void> {
    setBusy(true);
    setError(null);
    setLaunched(null);
    try {
      const body: CampaignCreate = {
        target: { provider, model, api_key_ref: apiKeyRef },
        system_prompt: systemPrompt,
      };
      const created = await redteam.createCampaign(body);
      setLaunched(created.id);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Launch failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-lg border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-5 py-3">
        <h2 className="font-medium">Launch campaign</h2>
      </div>
      <div className="space-y-3 px-5 py-4">
        <div className="grid grid-cols-2 gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-slate-600">Provider</span>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="w-full rounded-md border border-slate-300 px-2 py-1.5"
            >
              {PROVIDERS.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-slate-600">Model</span>
            <input
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="gpt-4o-mini"
              className="w-full rounded-md border border-slate-300 px-2 py-1.5"
            />
          </label>
        </div>
        <label className="block text-sm">
          <span className="mb-1 block text-slate-600">API key ref</span>
          <input
            value={apiKeyRef}
            onChange={(e) => setApiKeyRef(e.target.value)}
            placeholder="env:OPENAI_API_KEY"
            className="w-full rounded-md border border-slate-300 px-2 py-1.5 font-mono text-xs"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block text-slate-600">Target system prompt (to red-team)</span>
          <textarea
            value={systemPrompt}
            onChange={(e) => setSystemPrompt(e.target.value)}
            rows={3}
            placeholder="You are a helpful assistant…"
            className="w-full rounded-md border border-slate-300 px-2 py-1.5 text-sm"
          />
        </label>
        <button
          type="button"
          onClick={() => void launch()}
          disabled={busy || model.length === 0}
          className="rounded-md bg-slate-900 px-4 py-1.5 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
        >
          {busy ? "Launching…" : "Launch campaign"}
        </button>
        {launched ? (
          <p className="text-sm text-emerald-700">
            Campaign {launched.slice(0, 8)} launched — runs in the background.
          </p>
        ) : null}
        {error ? (
          <p className="text-sm text-red-600">
            {error}{" "}
            <Link href="/login" className="underline">
              Sign in
            </Link>
          </p>
        ) : null}
      </div>
    </section>
  );
}

function StrategiesCard() {
  const [strategies, setStrategies] = useState<RedTeamStrategy[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setStrategies(await redteam.strategies());
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Failed to load strategies");
      }
    })();
  }, []);

  return (
    <section className="rounded-lg border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-5 py-3">
        <h2 className="font-medium">
          Attack strategies{strategies ? ` (${strategies.length})` : ""}
        </h2>
      </div>
      <div className="px-5 py-4">
        {error ? <p className="text-sm text-red-600">{error}</p> : null}
        {strategies === null ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : (
          <ul className="max-h-72 space-y-2 overflow-y-auto">
            {strategies.map((s) => (
              <li key={s.id} className="text-sm">
                <span className="font-medium">{s.name}</span>{" "}
                <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">
                  {s.category}
                </span>
                <p className="text-xs text-slate-500">{s.description}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function CampaignsCard() {
  const [campaigns, setCampaigns] = useState<RedTeamCampaign[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  async function load(): Promise<void> {
    try {
      const data = await redteam.listCampaigns();
      setCampaigns(data);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Failed to load campaigns");
    }
  }

  useEffect(() => {
    void (async () => {
      await load();
    })();
  }, []);

  return (
    <section className="mt-6 rounded-lg border border-slate-200 bg-white">
      <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3">
        <h2 className="font-medium">Campaigns</h2>
        <button
          type="button"
          onClick={() => void load()}
          className="rounded-md border border-slate-300 px-2.5 py-1 text-xs hover:bg-slate-50"
        >
          Refresh
        </button>
      </div>
      <div className="px-5 py-4">
        {error ? <p className="text-sm text-red-600">{error}</p> : null}
        {campaigns === null ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : campaigns.length === 0 ? (
          <p className="text-sm text-slate-500">No campaigns yet.</p>
        ) : (
          <ul className="divide-y divide-slate-100">
            {campaigns.map((c) => (
              <li key={c.id} className="py-2">
                <div className="flex items-center gap-3 text-sm">
                  <span className="font-mono text-xs text-slate-500">{c.id.slice(0, 8)}</span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-xs ${STATUS_STYLES[c.status] ?? STATUS_STYLES.created}`}
                  >
                    {c.status}
                  </span>
                  {c.status === "completed" ? (
                    <>
                      <span className="text-slate-600">
                        {c.successful_attacks}/{c.total_attacks} succeeded
                      </span>
                      <span className="tabular-nums">score {c.score.toFixed(0)}</span>
                      {c.risk_label ? (
                        <span
                          className={`rounded-full px-2 py-0.5 text-xs ${RISK_STYLES[c.risk_label] ?? ""}`}
                        >
                          {c.risk_label}
                        </span>
                      ) : null}
                    </>
                  ) : null}
                  {c.error_message ? (
                    <span className="truncate text-xs text-red-600" title={c.error_message}>
                      {c.error_message}
                    </span>
                  ) : null}
                  <button
                    type="button"
                    onClick={() => setSelected(selected === c.id ? null : c.id)}
                    className="ml-auto rounded-md border border-slate-300 px-2 py-0.5 text-xs hover:bg-slate-50"
                  >
                    {selected === c.id ? "Hide" : "Findings"}
                  </button>
                </div>
                {selected === c.id ? <FindingsList campaignId={c.id} /> : null}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function FindingsList({ campaignId }: { campaignId: string }) {
  const [findings, setFindings] = useState<RedTeamFinding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setFindings(await redteam.findings(campaignId));
      } catch (err: unknown) {
        setError(err instanceof ApiError ? err.message : "Failed to load findings");
      }
    })();
  }, [campaignId]);

  if (error) return <p className="mt-2 text-sm text-red-600">{error}</p>;
  if (findings === null) return <p className="mt-2 text-sm text-slate-500">Loading findings…</p>;
  if (findings.length === 0)
    return <p className="mt-2 text-sm text-slate-500">No findings for this campaign.</p>;

  return (
    <ul className="mt-2 divide-y divide-slate-100 rounded-md border border-slate-200 bg-slate-50">
      {findings.map((f) => (
        <li key={f.id} className="px-3 py-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs">{f.strategy_id}</span>
            <span className="rounded-full bg-slate-200 px-2 py-0.5 text-xs">{f.category}</span>
            <span className="ml-auto text-xs text-slate-500">
              {f.classification} · {(f.compliance_score * 100).toFixed(0)}%
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-600">{f.recommendation}</p>
        </li>
      ))}
    </ul>
  );
}
