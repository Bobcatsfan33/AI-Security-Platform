# Contributing

Contributions welcome. This document is short on ceremony and specific about the
two things that trip people up here: the setup, and the house style around
evidence.

## Setup

Verified on a clean clone. If a step below doesn't work, that's a bug — open an
issue.

```bash
git clone https://github.com/Bobcatsfan33/AI-Security-Platform
cd AI-Security-Platform/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m examples.quickstart      # ~30s from clone; no services needed
pytest -m unit                     # the unit suite, also no services
```

That is enough to work on detectors, the efficacy harness, reports, or SDKs.

**For anything touching the database or the API**, you need Postgres and Redis:

```bash
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
docker compose up -d postgres redis          # from the repository root

export DATABASE_URL=postgresql+asyncpg://platform:platform@localhost:5432/platform
export REDIS_URL=redis://localhost:6379/0
alembic upgrade head
pytest                                        # full suite
```

`JWT_SECRET` must be exported **before** `docker compose` — the compose file
interpolates the whole document, so it is required even when you are only
starting the datastores. Full-stack setup, including ClickHouse and Redpanda, is
in [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

**Go agent:** `cd runtime-agent && go test ./...`
**Frontend:** `cd frontend && npm install && npm run dev`

## Before you open a PR

```bash
cd backend
ruff check app tests scripts examples
black --check app tests scripts examples
pytest --cov=app --cov-report=term-missing    # 80% floor is enforced

cd ..
scripts/mutation_check.sh backend             # needs `python` on PATH — use the venv
python3 scripts/verify_enterprise_readiness.py
```

Commits need a DCO sign-off (`git commit -s`). One concern per PR.

## <a id="how-this-repo-is-run"></a>How this repo is run

PRs here carry more evidence than you may be used to. That is deliberate, and
it is worth understanding before you are surprised by a review.

**A claim points at something mechanical.** "Improves detection" is not a
result; a before/after number from
[the efficacy harness](docs/EFFICACY-HARNESS.md) is. "It's tested" is not a
result; a test that fails when you revert the fix is. If you cannot point at
the thing, say so plainly — that is always an acceptable answer here.

**Gaps get written down.** [`docs/GAPS.md`](docs/GAPS.md) and
[`docs/enterprise-readiness.json`](docs/enterprise-readiness.json) exist because
a known weakness that nobody recorded is indistinguishable from one nobody
found. If your change leaves something unfinished, add it there rather than
smoothing over it in the PR description.

**Numbers carry their caveats.** Every efficacy measurement in this repository
was taken on synthetic, hand-authored corpora, and every report is stamped
`synthetic-demonstration`. Do not quote those numbers as product efficacy in a
commit message, a PR, or a doc — they measure whether a fix generalises beyond
its motivating cases, and nothing more.

**Tests are checked for biting.** `scripts/mutation_check.sh` reintroduces real
regressions and fails the build if the suite stays green. A ratchet
([`test_router_coverage_ratchet.py`](backend/tests/unit/test_router_coverage_ratchet.py))
forces every mounted route to carry HTTP and cross-tenant tests, and a
cross-tenant claim only counts if the test actually compares two tenants.
Exemption lists may only shrink.

**Negative tests matter as much as positive ones.** A detector change that
raises recall while blocking ordinary traffic is not an improvement. If you
touch detection, show what still passes, not only what now gets caught.

**Fail closed.** If a policy stage cannot run, the request is refused. Do not
add a path that degrades to "allow" on error without saying so loudly and
counting it.

None of this is meant to be intimidating. The short version: show your work, and
be straight about what you don't know.

## Good first issues

Issues labelled
[`good first issue`](https://github.com/Bobcatsfan33/AI-Security-Platform/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
have context, a pointer to the relevant code, and acceptance criteria written
out. They are real gaps, not busywork invented for newcomers.

If you would rather find your own, two honest starting points:

- `backend/tests/unit/test_router_coverage_ratchet.py` lists every mounted route
  still missing HTTP or cross-tenant tests. Each row is a scoped task, and
  removing one is a self-verifying contribution.
- The internal detection benchmark reports per-class rates. `secrets` currently
  scores **0.00** and `toxicity` **0.50** — both are real, both are visible in
  CI output.

## Reporting a vulnerability

Please don't open a public issue. See [`SECURITY.md`](SECURITY.md).

## Code of conduct

Be decent. Assume good faith, especially across a language barrier — a project
about multilingual detection should manage that much. Harassment gets you
removed.
