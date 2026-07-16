// Shared agent-routing logic for the OpenAI and Anthropic Node wrappers.

const DEFAULT_AGENT_URL = "http://localhost:8400";
const DEFAULT_HEALTH_TIMEOUT_MS = 1000;

export function agentUrl(): string {
  return (process.env.PLATFORM_AGENT_URL ?? DEFAULT_AGENT_URL).replace(/\/$/, "");
}

// Environments that are a deliberate statement of "not production", and so buy
// a direct fallback when the agent is down. An ALLOWLIST, not "anything that
// isn't production": the else-branch of a negative test is where typos land, and
// PLATFORM_ENV=porduction resolving to "fall back, unprotected" is the single
// worst outcome this module can produce.
//
// Keep in sync with sdks/python/platform_sdk/_routing.py — the shared decision
// table in sdks/routing-cases.json is what actually holds them together.
const NON_PRODUCTION_ENVS = new Set([
  "dev",
  "development",
  "staging",
  "stage",
  "test",
  "testing",
  "ci",
  "local",
  "sandbox",
]);

/**
 * Whether to fall back to a direct API call when the agent is unreachable.
 *
 * The rule, matching the runtime agent's AGENT_NO_POLICY_BEHAVIOR exactly so
 * the platform has one convention rather than two:
 *
 *   - PLATFORM_FALLBACK_DIRECT is explicit and always wins (only the literal
 *     "true" enables fallback — the safe reading of an ambiguous value is the
 *     protected one);
 *   - otherwise PLATFORM_ENV decides, and only a RECOGNISED non-production
 *     environment falls back.
 *
 * Unset, empty and unrecognised all fail CLOSED. Deliberately stricter than the
 * first cut, which defaulted to fallback unless PLATFORM_ENV said prod — so a
 * production deployment that simply forgot to set PLATFORM_ENV shipped
 * unprotected traffic behind a console.warn. That is the most dangerous
 * possible place to be permissive.
 */
export function fallbackDirect(): boolean {
  const explicit = process.env.PLATFORM_FALLBACK_DIRECT;
  if (explicit !== undefined) {
    return explicit.trim().toLowerCase() === "true";
  }
  return NON_PRODUCTION_ENVS.has((process.env.PLATFORM_ENV ?? "").trim().toLowerCase());
}

export async function agentReachable(): Promise<boolean> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), DEFAULT_HEALTH_TIMEOUT_MS);
  try {
    const resp = await fetch(`${agentUrl()}/healthz`, {
      method: "GET",
      signal: controller.signal,
    });
    return resp.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

interface ResolveOptions {
  proxyPath: string;
  directDefault: string;
}

export async function resolveBaseUrl({
  proxyPath,
  directDefault,
}: ResolveOptions): Promise<string> {
  if (await agentReachable()) {
    return agentUrl() + proxyPath;
  }
  if (fallbackDirect()) {
    // eslint-disable-next-line no-console
    console.warn(
      `[platform-sdk] agent at ${agentUrl()} unreachable — falling back to ${directDefault}. LLM traffic is NOT protected.`,
    );
    return directDefault;
  }
  const env = process.env.PLATFORM_ENV ?? "";
  throw new Error(
    `[platform-sdk] the runtime agent at ${agentUrl()} is unreachable, and fallback is off ` +
      `(PLATFORM_ENV="${env}" is not a recognised non-production environment). ` +
      `Refusing to send LLM traffic unprotected.\n` +
      `\n` +
      `  Developing locally?  export PLATFORM_ENV=development\n` +
      `                       (recognised: ${[...NON_PRODUCTION_ENVS].sort().join(", ")})\n` +
      `  Running for real?    start the runtime agent, or point the SDK at it with\n` +
      `                       PLATFORM_AGENT_URL=http://<host>:8400\n` +
      `  Deliberately opting out of protection?  PLATFORM_FALLBACK_DIRECT=true\n`,
  );
}
