# Examples

Runnable from `backend/` with the package installed (`pip install -e .`).

## `quickstart.py` — 60 seconds, no services

```bash
python -m examples.quickstart
```

Five probes through the real detection path: an ordinary request, prompt
injections in English, German, and Chinese, and — the one worth pausing on — a
question *about* an injection, which is allowed.

No database, no Docker, no API key, no model download. It is the same code the
Go agent calls inline and the same code behind `POST /v1/aiguard/inspect`, so
what you see here is what runs in the request path.

## Using it in your own code

The whole integration is one call:

```python
from app.aiguard.service import AIGuardService
from app.detectors.base import Direction

guard = AIGuardService()
verdict = guard.inspect(text=user_input, direction=Direction.INBOUND)

if verdict.action != "allow":
    raise ValueError(f"blocked: {', '.join(verdict.triggered)}")
```

In production you would not import the service — you would point your LLM
client at the Go agent, which runs the same pipeline out of process and adds
telemetry, policy versioning, and the audit trail. See
[`sdks/`](../../sdks/) for drop-in OpenAI and Anthropic wrappers, and
[`docs/QUICKSTART.md`](../../docs/QUICKSTART.md) for the full stack.

## A note on what these numbers are not

The probes here are chosen to show the shape of the decision boundary, not to
measure detection quality. Measured efficacy lives in
[`docs/EFFICACY-HARNESS.md`](../../docs/EFFICACY-HARNESS.md), where every number
is stamped `synthetic-demonstration` because it was measured on hand-authored
corpora rather than real traffic.
