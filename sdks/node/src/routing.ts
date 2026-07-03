// Shared agent-routing logic for the OpenAI and Anthropic Node wrappers.

const DEFAULT_AGENT_URL = "http://localhost:8400";
const DEFAULT_HEALTH_TIMEOUT_MS = 1000;

export function agentUrl(): string {
  return (process.env.PLATFORM_AGENT_URL ?? DEFAULT_AGENT_URL).replace(/\/$/, "");
}

export function fallbackDirect(): boolean {
  // Deny-by-default in production: fail closed unless explicitly enabled.
  const isProd = ["prod", "production"].includes((process.env.PLATFORM_ENV ?? "").toLowerCase());
  const dflt = isProd ? "false" : "true";
  return (process.env.PLATFORM_FALLBACK_DIRECT ?? dflt).toLowerCase() === "true";
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
  throw new Error(
    `[platform-sdk] agent at ${agentUrl()} unreachable AND PLATFORM_FALLBACK_DIRECT=false — refusing to send unprotected LLM traffic.`,
  );
}
