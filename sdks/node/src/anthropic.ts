// Drop-in Anthropic client wrapper.
//
// Replace:
//   import Anthropic from "@anthropic-ai/sdk";
// With:
//   import { Anthropic } from "@platform/sdk/anthropic";

import { resolveBaseUrl } from "./routing.js";

interface AnthropicClientOptions {
  baseURL?: string;
  apiKey?: string;
  [key: string]: unknown;
}

const DIRECT_BASE_URL =
  process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com";

/**
 * Construct an Anthropic client routed through the local runtime
 * agent when reachable.
 *
 * The upstream `@anthropic-ai/sdk` package is a peer dependency.
 */
export async function Anthropic(
  options: AnthropicClientOptions = {},
): Promise<unknown> {
  // Peer dependency — resolved at runtime by consuming apps.
  const upstreamName = "@anthropic-ai/sdk";
  const upstream = await import(upstreamName);
  const baseURL = await resolveBaseUrl({
    proxyPath: "/proxy",
    directDefault: DIRECT_BASE_URL,
  });
  const ClientCtor =
    (upstream as { default?: unknown; Anthropic?: unknown }).Anthropic
      ?? (upstream as { default?: unknown }).default;
  if (typeof ClientCtor !== "function") {
    throw new Error(
      "[platform-sdk/anthropic] could not locate the Anthropic constructor on the upstream `@anthropic-ai/sdk` package.",
    );
  }
  const Ctor = ClientCtor as new (opts: AnthropicClientOptions) => unknown;
  return new Ctor({ ...options, baseURL });
}
