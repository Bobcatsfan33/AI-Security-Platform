// Drop-in OpenAI client wrapper.
//
// Replace:
//   import OpenAI from "openai";
// With:
//   import { OpenAI } from "@platform/sdk/openai";

import { resolveBaseUrl } from "./routing.js";

interface OpenAIClientOptions {
  baseURL?: string;
  apiKey?: string;
  [key: string]: unknown;
}

const DIRECT_BASE_URL =
  process.env.OPENAI_BASE_URL ?? "https://api.openai.com/v1";

/**
 * Construct an OpenAI client routed through the local runtime agent
 * when reachable, otherwise the direct upstream (with a warning).
 *
 * The upstream `openai` package is a peer dependency — install it
 * separately in your application.
 */
export async function OpenAI(options: OpenAIClientOptions = {}): Promise<unknown> {
  // Peer dependency — resolved at runtime by consuming apps that
  // install `openai`. Indirect import to keep TS from requiring the
  // package at build time.
  const upstreamName = "openai";
  const upstream = await import(upstreamName);
  const baseURL = await resolveBaseUrl({
    proxyPath: "/proxy/v1",
    directDefault: DIRECT_BASE_URL,
  });
  const ClientCtor = (upstream as { default?: unknown; OpenAI?: unknown }).OpenAI
    ?? (upstream as { default?: unknown }).default;
  if (typeof ClientCtor !== "function") {
    throw new Error(
      "[platform-sdk/openai] could not locate the OpenAI constructor on the upstream `openai` package.",
    );
  }
  const Ctor = ClientCtor as new (opts: OpenAIClientOptions) => unknown;
  return new Ctor({ ...options, baseURL });
}
