# @platform/sdk (Node)

Drop-in wrappers for the OpenAI and Anthropic clients that route LLM traffic
through the AI Security Platform's runtime agent. One-line import change:

```ts
// import OpenAI from "openai";
import { OpenAI } from "@platform/sdk/openai";

const client = await OpenAI(); // same API, now inspected inline by the runtime agent
```

## The one thing to know: this fails closed

If the runtime agent is unreachable, the SDK **refuses to send** rather than
quietly calling the provider directly. Traffic is protected, or it does not
flow.

You will meet this on your first run, and that is deliberate. Set your
environment:

```bash
export PLATFORM_ENV=development   # now the SDK falls back to direct calls, loudly
```

### The rule

| `PLATFORM_FALLBACK_DIRECT` | `PLATFORM_ENV` | Agent down → |
|---|---|---|
| `true` | *(any)* | direct call, with a `console.warn` |
| `false` (or any non-`true` value) | *(any)* | **throw** |
| *(unset)* | `development` / `dev` / `staging` / `stage` / `test` / `testing` / `ci` / `local` / `sandbox` | direct call, with a `console.warn` |
| *(unset)* | `production` / `prod` | **throw** |
| *(unset)* | **unset, empty, or anything unrecognised** | **throw** |

`PLATFORM_FALLBACK_DIRECT` is explicit and always wins. Only the literal
`"true"` enables fallback — `yes`, `1` and `on` do not, because the safe reading
of an ambiguous value is the protected one.

### Why unset means throw

> **Behaviour change.** This SDK previously fell back to direct calls unless
> `PLATFORM_ENV` said production. So a production deployment that simply forgot
> to set `PLATFORM_ENV` shipped **unprotected traffic behind a `console.warn`** —
> the most dangerous place to be permissive, reached by doing nothing.

Absence of information is not evidence of a development box. Only a
*deliberately named* non-production environment buys the fallback; unset and
unrecognised (`PLATFORM_ENV=porduction`) both throw. This matches the runtime
agent's `AGENT_NO_POLICY_BEHAVIOR` exactly, so the platform has one convention
rather than two.

The cost is one line of setup friction, once. The alternative is unprotected
production traffic nobody notices.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PLATFORM_AGENT_URL` | `http://localhost:8400` | Where the runtime agent listens |
| `PLATFORM_ENV` | *(unset → fail closed)* | Deployment environment |
| `PLATFORM_FALLBACK_DIRECT` | *(unset → decided by `PLATFORM_ENV`)* | Explicit override |

## Falling back is never silent

A fallback emits a `console.warn` naming the agent URL and stating that traffic
is **not protected**. An unprotected call must never look identical to a
protected one.

## Tests

```bash
npm ci && npm run build && npm test
```

The `PLATFORM_ENV` → fallback decision table is shared with the Python SDK
([`../routing-cases.json`](../routing-cases.json)); both suites iterate it, so a
case added for one language is demanded of the other. `../mutation_check.sh`
runs in CI and fails the build if either suite would stay green with the
fail-closed default removed.
