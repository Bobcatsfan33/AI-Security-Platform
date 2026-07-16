// The fail-closed branch (GAP-005).
//
// Mirrors sdks/python/tests/test_routing.py case for case. The two SDKs make
// the same promise — LLM traffic is protected or it does not flow — so they
// are tested against the same contract. A divergence between them is a bug in
// whichever one drifted, and keeping the suites parallel is how that shows up.
//
// Contract:
//   * PLATFORM_FALLBACK_DIRECT is explicit and always wins.
//   * Unset, it resolves by environment: prod/production -> closed;
//     anything else -> open.
//   * Falling back is never silent.

import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { agentReachable, agentUrl, fallbackDirect, resolveBaseUrl } from "./routing.js";

const PROXY_PATH = "/proxy/v1";
const DIRECT = "https://api.openai.com/v1";
const ENV_VARS = ["PLATFORM_ENV", "PLATFORM_FALLBACK_DIRECT", "PLATFORM_AGENT_URL"] as const;

const realFetch = globalThis.fetch;
let savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  // Snapshot and clear, so a developer's real shell can never make a security
  // test pass.
  savedEnv = {};
  for (const key of ENV_VARS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of ENV_VARS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
  globalThis.fetch = realFetch;
  mock.restoreAll();
});

/** Pretend the agent's /healthz answers (or doesn't). */
function stubAgent(state: "up" | "down" | "unhealthy"): void {
  globalThis.fetch = (async () => {
    if (state === "down") throw new TypeError("fetch failed");
    return new Response("", { status: state === "up" ? 200 : 503 });
  }) as typeof fetch;
}

const resolve = () => resolveBaseUrl({ proxyPath: PROXY_PATH, directDefault: DIRECT });

describe("fallbackDirect — the environment default", () => {
  for (const env of ["prod", "production", "PROD", "Production", "PrOdUcTiOn"]) {
    it(`fails closed by default in ${env}`, () => {
      process.env.PLATFORM_ENV = env;
      assert.equal(fallbackDirect(), false);
    });
  }

  for (const env of ["dev", "development", "staging", "test", "", "anything-else"]) {
    it(`falls back by default in ${env || "(empty)"}`, () => {
      process.env.PLATFORM_ENV = env;
      assert.equal(fallbackDirect(), true);
    });
  }

  it("falls back by default when PLATFORM_ENV is unset", () => {
    assert.equal(fallbackDirect(), true);
  });
});

describe("fallbackDirect — explicit always wins", () => {
  it("explicit false overrides the dev default", () => {
    process.env.PLATFORM_ENV = "dev";
    process.env.PLATFORM_FALLBACK_DIRECT = "false";
    assert.equal(fallbackDirect(), false);
  });

  it("explicit true overrides the prod default", () => {
    // An operator opting out of protection in prod gets what they asked for —
    // but it must be explicit, never a default.
    process.env.PLATFORM_ENV = "production";
    process.env.PLATFORM_FALLBACK_DIRECT = "true";
    assert.equal(fallbackDirect(), true);
  });

  for (const value of ["TRUE", "True", "tRuE"]) {
    it(`treats ${value} as true`, () => {
      process.env.PLATFORM_FALLBACK_DIRECT = value;
      assert.equal(fallbackDirect(), true);
    });
  }

  for (const value of ["yes", "1", "on", "", "  ", "truthy", "0", "no"]) {
    it(`does not treat ${JSON.stringify(value)} as true`, () => {
      // The safe reading of an ambiguous value is the protected one: a typo
      // like PLATFORM_FALLBACK_DIRECT=1 must not silently unprotect traffic.
      process.env.PLATFORM_ENV = "production";
      process.env.PLATFORM_FALLBACK_DIRECT = value;
      assert.equal(fallbackDirect(), false);
    });
  }
});

describe("resolveBaseUrl — the decision", () => {
  it("always uses a reachable agent, even with fallback enabled", async () => {
    stubAgent("up");
    process.env.PLATFORM_FALLBACK_DIRECT = "true";
    assert.equal(await resolve(), `http://localhost:8400${PROXY_PATH}`);
  });

  it("honours PLATFORM_AGENT_URL and strips its trailing slash", async () => {
    stubAgent("up");
    process.env.PLATFORM_AGENT_URL = "http://agent.internal:9000/";
    assert.equal(await resolve(), `http://agent.internal:9000${PROXY_PATH}`);
  });

  it("refuses to send when prod and the agent is down", async () => {
    // THE test: production, agent unreachable, nothing explicitly set.
    stubAgent("down");
    process.env.PLATFORM_ENV = "production";
    await assert.rejects(resolve, /refusing to send unprotected LLM traffic/);
  });

  it("names the escape hatch in the refusal", async () => {
    // An error that stops a deploy must say how to proceed deliberately, or
    // someone reaches for a worse workaround.
    stubAgent("down");
    process.env.PLATFORM_ENV = "production";
    await assert.rejects(resolve, /PLATFORM_FALLBACK_DIRECT/);
  });

  it("falls back to direct in dev when the agent is down", async () => {
    stubAgent("down");
    mock.method(console, "warn", () => {});
    assert.equal(await resolve(), DIRECT);
  });

  it("is loud when it falls back", async () => {
    // An unprotected call that looks identical to a protected one is how this
    // fails in the field.
    stubAgent("down");
    const warn = mock.method(console, "warn", () => {});

    await resolve();

    assert.equal(warn.mock.callCount(), 1);
    assert.match(warn.mock.calls[0].arguments[0] as string, /NOT protected/);
  });

  it("is quiet on the happy path", async () => {
    // An alarm that always fires is ignored.
    stubAgent("up");
    const warn = mock.method(console, "warn", () => {});

    await resolve();

    assert.equal(warn.mock.callCount(), 0);
  });
});

describe("agentReachable — what counts as up", () => {
  it("is false when the health check throws", async () => {
    stubAgent("down");
    assert.equal(await agentReachable(), false);
  });

  it("is false for a listening-but-unhealthy agent", async () => {
    // A 503 is not protection.
    stubAgent("unhealthy");
    assert.equal(await agentReachable(), false);
  });

  it("is false when nothing is listening", async () => {
    // Exercises the real fetch path rather than a stub, so a refactor that
    // swallows the wrong error and returns true fails here.
    process.env.PLATFORM_AGENT_URL = "http://127.0.0.1:1";
    assert.equal(await agentReachable(), false);
  });

  it("defaults to the documented agent URL", () => {
    assert.equal(agentUrl(), "http://localhost:8400");
  });
});
