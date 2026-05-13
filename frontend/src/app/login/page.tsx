"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import {
  clearSession,
  getUser,
  setSession,
  type Session,
} from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [orgSlug, setOrgSlug] = useState("");
  const [devToken, setDevToken] = useState("");
  const [devOrgId, setDevOrgId] = useState("");
  const [devUserId, setDevUserId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const currentUser = getUser();

  function startOidc() {
    if (!orgSlug) {
      setError("Enter an org slug first");
      return;
    }
    const apiBase =
      process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
    window.location.href = `${apiBase}/v1/auth/oidc/${encodeURIComponent(orgSlug)}/login`;
  }

  function useDevToken() {
    if (!devToken || !devOrgId) {
      setError("Token + org_id required");
      return;
    }
    const session: Session = {
      access_token: devToken,
      user: {
        id: devUserId || "dev-user",
        email: "dev@local",
        name: "Dev",
        role: "admin",
        org_id: devOrgId,
      },
    };
    setSession(session);
    router.push("/");
  }

  function logout() {
    clearSession();
    router.refresh();
  }

  return (
    <div className="mx-auto max-w-md">
      <h1 className="mb-6 text-2xl font-semibold">Sign in</h1>

      {currentUser ? (
        <div className="mb-6 rounded-lg border border-slate-200 bg-white p-4">
          <p className="text-sm">
            Signed in as <strong>{currentUser.email}</strong>{" "}
            <span className="text-slate-500">
              ({currentUser.role}, org {currentUser.org_id.slice(0, 8)})
            </span>
          </p>
          <button
            type="button"
            onClick={logout}
            className="mt-3 rounded-md border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50"
          >
            Log out
          </button>
        </div>
      ) : null}

      <section className="mb-8 rounded-lg border border-slate-200 bg-white p-5">
        <h2 className="mb-3 text-lg font-medium">OIDC SSO</h2>
        <p className="mb-3 text-sm text-slate-600">
          Redirect to your IDP. The platform must have an active OIDC IdpConfig
          for this org.
        </p>
        <label className="mb-3 block text-sm">
          <span className="mb-1 block font-medium">Org slug</span>
          <input
            value={orgSlug}
            onChange={(e) => setOrgSlug(e.target.value)}
            placeholder="acme"
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
          />
        </label>
        <button
          type="button"
          onClick={startOidc}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
        >
          Start OIDC login
        </button>
      </section>

      <section className="rounded-lg border border-slate-200 bg-white p-5">
        <h2 className="mb-3 text-lg font-medium">Dev token (local only)</h2>
        <p className="mb-3 text-sm text-slate-600">
          Paste an access token you minted via{" "}
          <code className="rounded bg-slate-100 px-1">issue_token_pair</code>{" "}
          in the backend, plus the matching org_id, to bypass OIDC during dev.
        </p>
        <label className="mb-3 block text-sm">
          <span className="mb-1 block font-medium">Access token (JWT)</span>
          <textarea
            value={devToken}
            onChange={(e) => setDevToken(e.target.value)}
            rows={4}
            className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs"
          />
        </label>
        <label className="mb-3 block text-sm">
          <span className="mb-1 block font-medium">Org ID (UUID)</span>
          <input
            value={devOrgId}
            onChange={(e) => setDevOrgId(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs"
          />
        </label>
        <label className="mb-3 block text-sm">
          <span className="mb-1 block font-medium">User ID (optional)</span>
          <input
            value={devUserId}
            onChange={(e) => setDevUserId(e.target.value)}
            className="w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs"
          />
        </label>
        <button
          type="button"
          onClick={useDevToken}
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-800"
        >
          Save dev session
        </button>
      </section>

      {error ? (
        <p className="mt-4 text-sm text-red-600">{error}</p>
      ) : null}
    </div>
  );
}
