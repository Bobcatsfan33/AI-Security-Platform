// The fail-closed branch (GAP-005).
//
// The ENV -> fallback decision table is SHARED with the Python suite:
// sdks/routing-cases.json. Both suites load that file and iterate it, so a case
// added for one language is automatically demanded of the other.
//
// This replaces a prose claim that the two suites mirrored each other "case for
// case" — which was already false when it was written (Python had
// malformed-URL and transport-failure cases Node lacked; Node had a default-URL
// case Python lacked). Prose cannot hold two lists in sync; a shared table can.
//
// Transport-level behaviour (fetch vs urllib, what counts as "down") is
// legitimately language-specific and stays hand-written below.
//
// Contract:
//   * PLATFORM_FALLBACK_DIRECT is explicit and always wins.
//   * Otherwise PLATFORM_ENV decides, and only a RECOGNISED non-production
//     environment falls back. Unset, empty and unrecognised all fail CLOSED.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { agentReachable, agentUrl, fallbackDirect, resolveBaseUrl } from "./routing.js";

interface SharedCase {
  name: string;
  why?: string;
  env: Record<string, string>;
  fallback: boolean;
}

// Resolved from this file's location so it works from src/ and dist/ alike.
const CASES_FILE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "routing-cases.json");
const SHARED_CASES: SharedCase[] = JSON.parse(readFileSync(CASES_FILE, "utf8")).cases;

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

describe("the shared decision table", () => {
  for (const testCase of SHARED_CASES) {
    it(testCase.name, () => {
      for (const [key, value] of Object.entries(testCase.env)) {
        process.env[key] = value;
      }

      assert.equal(fallbackDirect(), testCase.fallback, testCase.why ?? testCase.name);
    });
  }

  it("covers the dangerous default", () => {
    // A guard on the table itself. The first cut defaulted to FALLBACK on unset
    // PLATFORM_ENV, so a production deployment that forgot the variable shipped
    // unprotected traffic behind a console.warn. If that case ever falls out of
    // the table, both suites would go quiet about the exact regression that
    // motivated them.
    const unset = SHARED_CASES.filter((c) => Object.keys(c.env).length === 0);
    assert.ok(unset.length > 0, "the table must cover a completely unset environment");
    assert.ok(
      unset.every((c) => c.fallback === false),
      "an unset environment must fail CLOSED",
    );
  });
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
    await assert.rejects(resolve, /Refusing to send LLM traffic unprotected/);
  });

  it("names exactly which variable to set in the refusal", async () => {
    // This error WILL trip first-run developers — the accepted cost of failing
    // closed on unset. So it has to be the most useful error in the codebase:
    // one that stops someone without telling them how to proceed deliberately
    // is one they route around with a worse workaround.
    stubAgent("down");
    process.env.PLATFORM_ENV = "production";

    await assert.rejects(resolve, (err: Error) => {
      assert.match(err.message, /PLATFORM_ENV=development/, "must name the dev fix verbatim");
      assert.match(err.message, /PLATFORM_FALLBACK_DIRECT/, "must name the opt-out");
      assert.match(err.message, /PLATFORM_AGENT_URL/, "must name how to reach a real agent");
      return true;
    });
  });

  it("falls back to direct in dev when the agent is down", async () => {
    stubAgent("down");
    process.env.PLATFORM_ENV = "development";
    mock.method(console, "warn", () => {});
    assert.equal(await resolve(), DIRECT);
  });

  it("refuses when the environment is unset", async () => {
    // The behaviour change, head-on: no PLATFORM_ENV at all used to mean "fall
    // back, unprotected, with a warning". It now refuses.
    stubAgent("down");
    await assert.rejects(resolve, /not a recognised non-production environment/);
  });

  it("refuses on a typo'd environment rather than falling back", async () => {
    // "porduction" is not production, and under the old rule that made it a dev
    // box. The allowlist means a typo fails closed.
    stubAgent("down");
    process.env.PLATFORM_ENV = "porduction";
    await assert.rejects(resolve, /Refusing to send LLM traffic unprotected/);
  });

  it("is loud when it falls back", async () => {
    // An unprotected call that looks identical to a protected one is how this
    // fails in the field.
    stubAgent("down");
    process.env.PLATFORM_ENV = "development";
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
