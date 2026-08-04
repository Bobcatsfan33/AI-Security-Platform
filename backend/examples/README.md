# Examples

Runnable from `backend/` with the package installed (`pip install -e .`).
Needs Python 3.11+.

## `quickstart.py` — under a minute, no services

```bash
python -m examples.quickstart
```

Five probes through the real detection path: an ordinary request, prompt
injections in English, German, and Chinese, and — the one worth pausing on — a
question *about* an injection, which is allowed.

No database, no Docker, no API key, no model download. It is the same code the
Go agent calls inline and the same code behind `POST /v1/aiguard/inspect`, so
what you see here is what runs in the request path.

## `guarded_chat.py` — what the guardrail actually changes

```bash
python -m examples.guarded_chat
```

Replays one five-turn support session twice: unguarded, then guarded. Same
turns, same stubbed model. Unguarded, an injection hidden in a retrieved
document walks the model into leaking its system prompt. Guarded, that turn and
a German injection are refused and the rest of the session still works —
including the user *asking what an injection is*, which is allowed.

The stub model is deliberately gullible and has no refusal training: a model
that declines on its own would hide whether the guardrail did anything. It
obeys commands, not mentions — an earlier version leaked on any text containing
"ignore" and "instruction", which made the guarded run leak on a turn the
guardrail had correctly allowed. The flaw was in the fake model, not the guard.

**It self-checks.** `main()` exits non-zero if the unguarded run stops leaking
or the guarded run starts, so this file cannot rot into a demo of something
that no longer happens. `tests/unit/test_examples.py` asserts the same claims,
including the negative ones.

Captured output: [`docs/media/guarded-chat.txt`](../../docs/media/guarded-chat.txt).

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
