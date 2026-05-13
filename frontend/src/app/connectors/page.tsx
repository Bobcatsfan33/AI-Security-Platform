"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

import { api, ApiError, type Connector } from "@/lib/api";

export default function ConnectorsPage() {
  const [connectors, setConnectors] = useState<Connector[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  useEffect(() => {
    void load();
  }, []);

  async function load(): Promise<void> {
    try {
      setError(null);
      const data = await api.get<Connector[]>("/v1/connectors");
      setConnectors(data);
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "load failed");
    }
  }

  async function test(id: string): Promise<void> {
    setTesting(id);
    try {
      await api.post<unknown>(`/v1/connectors/${id}/test`, {});
      void load();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "test failed");
    } finally {
      setTesting(null);
    }
  }

  return (
    <div>
      <h1 className="mb-6 text-2xl font-semibold">Connectors</h1>

      <CreateConnectorForm onCreated={() => void load()} />

      {error ? (
        <p className="mb-4 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}{" "}
          <Link href="/login" className="underline">
            Sign in
          </Link>
        </p>
      ) : null}

      {connectors === null ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : connectors.length === 0 ? (
        <p className="text-sm text-slate-500">No connectors registered yet.</p>
      ) : (
        <ul className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          {connectors.map((c) => {
            const ok = (c.verification_status as { ok?: boolean } | null)?.ok;
            return (
              <li
                key={c.id}
                className="border-b border-slate-200 px-5 py-4 last:border-b-0"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium">{c.display_name}</div>
                    <div className="text-sm text-slate-500">
                      {c.provider} · {c.model} ·{" "}
                      {c.api_key_ref_present ? "key configured" : "no key"}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {ok === true ? (
                      <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs text-emerald-700">
                        verified
                      </span>
                    ) : ok === false ? (
                      <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs text-red-700">
                        failed
                      </span>
                    ) : (
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600">
                        untested
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => void test(c.id)}
                      disabled={testing === c.id}
                      className="rounded-md border border-slate-300 px-3 py-1 text-xs hover:bg-slate-50 disabled:opacity-50"
                    >
                      {testing === c.id ? "Testing…" : "Test"}
                    </button>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

interface CreateConnectorFormProps {
  onCreated: () => void;
}

function CreateConnectorForm({ onCreated }: CreateConnectorFormProps) {
  const [provider, setProvider] = useState("openai");
  const [displayName, setDisplayName] = useState("");
  const [model, setModel] = useState("");
  const [apiKeyRef, setApiKeyRef] = useState("");
  const [encPendingKey, setEncPendingKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [show, setShow] = useState(false);

  async function submit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const finalRef = encPendingKey
        ? `enc-pending:${encPendingKey}`
        : apiKeyRef;
      await api.post<Connector>("/v1/connectors", {
        provider,
        display_name: displayName,
        model,
        api_key_ref: finalRef,
        config: {},
      });
      setDisplayName("");
      setModel("");
      setApiKeyRef("");
      setEncPendingKey("");
      setShow(false);
      onCreated();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "create failed");
    } finally {
      setBusy(false);
    }
  }

  if (!show) {
    return (
      <button
        type="button"
        onClick={() => setShow(true)}
        className="mb-6 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-800"
      >
        Register connector
      </button>
    );
  }

  return (
    <form
      onSubmit={submit}
      className="mb-6 rounded-lg border border-slate-200 bg-white p-5"
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Provider</span>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2"
          >
            <option value="openai">openai</option>
            <option value="anthropic">anthropic</option>
            <option value="ollama">ollama</option>
            <option value="azure_openai">azure_openai</option>
            <option value="bedrock">bedrock</option>
            <option value="custom">custom</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Display name</span>
          <input
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            required
            className="w-full rounded-md border border-slate-300 px-3 py-2"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Model</span>
          <input
            value={model}
            onChange={(e) => setModel(e.target.value)}
            required
            placeholder="gpt-4o-mini"
            className="w-full rounded-md border border-slate-300 px-3 py-2"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">
            API key ref (env:NAME or vault:path)
          </span>
          <input
            value={apiKeyRef}
            onChange={(e) => setApiKeyRef(e.target.value)}
            placeholder="env:OPENAI_API_KEY"
            className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs"
          />
        </label>
        <div className="sm:col-span-2">
          <label className="text-sm">
            <span className="mb-1 block font-medium">
              …or paste plaintext (encrypted at storage)
            </span>
            <input
              value={encPendingKey}
              onChange={(e) => setEncPendingKey(e.target.value)}
              placeholder="sk-..."
              type="password"
              className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs"
            />
          </label>
        </div>
      </div>
      {error ? <p className="mt-3 text-sm text-red-600">{error}</p> : null}
      <div className="mt-4 flex items-center gap-2">
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-50"
        >
          {busy ? "Creating…" : "Create"}
        </button>
        <button
          type="button"
          onClick={() => setShow(false)}
          className="rounded-md border border-slate-300 px-4 py-2 text-sm hover:bg-slate-50"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
