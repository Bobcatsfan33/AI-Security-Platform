"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, ApiError, type Asset } from "@/lib/api";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  useEffect(() => {
    void load();
  }, []);

  async function load(): Promise<void> {
    try {
      setError(null);
      const data = await api.get<Asset[]>("/v1/assets");
      setAssets(data);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Assets</h1>
        <button
          type="button"
          onClick={() => setShowCreate((s) => !s)}
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800"
        >
          {showCreate ? "Cancel" : "Register asset"}
        </button>
      </div>

      {showCreate ? (
        <CreateAssetForm
          onCreated={() => {
            setShowCreate(false);
            void load();
          }}
        />
      ) : null}

      {error ? (
        <p className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : null}

      {assets === null ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : assets.length === 0 ? (
        <p className="text-sm text-slate-500">No assets yet. Register one above.</p>
      ) : (
        <ul className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          {assets.map((a) => (
            <li
              key={a.id}
              className="border-b border-slate-200 px-5 py-4 last:border-b-0"
            >
              <div className="flex items-center justify-between">
                <div>
                  <Link
                    href={`/assets/${a.id}`}
                    className="font-medium text-slate-900 hover:underline"
                  >
                    {a.name}
                  </Link>
                  <div className="mt-0.5 text-sm text-slate-500">
                    {a.provider} · {a.model_name} · {a.environment} ·{" "}
                    {a.data_classification}
                  </div>
                </div>
                <div className="text-right text-sm">
                  <div>
                    Score:{" "}
                    <strong>
                      {a.last_evaluation_score === null
                        ? "—"
                        : a.last_evaluation_score.toFixed(0)}
                    </strong>
                  </div>
                  <div className="text-slate-500">
                    {a.open_findings_count} open ({a.critical_findings_count}{" "}
                    critical)
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

interface CreateAssetFormProps {
  onCreated: () => void;
}

function CreateAssetForm({ onCreated }: CreateAssetFormProps) {
  const [name, setName] = useState("");
  const [provider, setProvider] = useState("openai");
  const [model, setModel] = useState("");
  const [environment, setEnvironment] = useState("dev");
  const [exposure, setExposure] = useState("internal_only");
  const [classification, setClassification] = useState("internal");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post<Asset>("/v1/assets", {
        name,
        provider,
        model_name: model,
        environment,
        exposure,
        data_classification: classification,
        system_prompt: systemPrompt || null,
      });
      onCreated();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "create failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={submit}
      className="mb-6 rounded-lg border border-slate-200 bg-white p-5"
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Field label="Name">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          />
        </Field>
        <Field label="Provider">
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          >
            <option value="openai">openai</option>
            <option value="anthropic">anthropic</option>
            <option value="ollama">ollama</option>
            <option value="azure_openai">azure_openai</option>
            <option value="bedrock">bedrock</option>
            <option value="custom">custom</option>
          </select>
        </Field>
        <Field label="Model">
          <input
            value={model}
            onChange={(e) => setModel(e.target.value)}
            required
            placeholder="gpt-4o-mini"
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          />
        </Field>
        <Field label="Environment">
          <select
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          >
            <option value="dev">dev</option>
            <option value="staging">staging</option>
            <option value="production">production</option>
          </select>
        </Field>
        <Field label="Exposure">
          <select
            value={exposure}
            onChange={(e) => setExposure(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          >
            <option value="internal_only">internal_only</option>
            <option value="api_only">api_only</option>
            <option value="customer_facing">customer_facing</option>
            <option value="public">public</option>
          </select>
        </Field>
        <Field label="Data classification">
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          >
            <option value="public">public</option>
            <option value="internal">internal</option>
            <option value="confidential">confidential</option>
            <option value="restricted">restricted</option>
            <option value="regulated">regulated</option>
          </select>
        </Field>
        <div className="sm:col-span-2">
          <Field label="System prompt (optional)">
            <textarea
              value={systemPrompt}
              onChange={(e) => setSystemPrompt(e.target.value)}
              rows={3}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
            />
          </Field>
        </div>
      </div>
      {error ? <p className="mt-3 text-sm text-red-600">{error}</p> : null}
      <button
        type="submit"
        disabled={busy}
        className="mt-4 rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
      >
        {busy ? "Creating…" : "Create"}
      </button>
    </form>
  );
}

interface FieldProps {
  label: string;
  children: React.ReactNode;
}

function Field({ label, children }: FieldProps) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium text-slate-700">{label}</span>
      {children}
    </label>
  );
}
