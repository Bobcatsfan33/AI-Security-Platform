# Dependency license scan — BUSL-1.1 → Apache-2.0 relicense

**Date:** 2026-08-02
**Base commit:** `8713e48` (`main`)
**Question:** does anything this repository depends on carry terms that are
incompatible with distributing the work under Apache-2.0?

**Verdict: no blockers.** No strong copyleft (GPL / AGPL / LGPL-for-linked-code
/ SSPL / CDDL / EPL) appears anywhere in the Python, Go, or Node dependency
sets. Three obligations to be aware of are listed under
[Findings](#findings-obligations-not-blockers); none of them prevent
Apache-2.0 distribution.

This is a point-in-time scan of pinned/locked dependency sets. It is
audit-supporting evidence, not a legal opinion, and it does not carry forward
to future dependency bumps.

---

## Method

| Ecosystem | Tool | Scope |
|---|---|---|
| Python | `pip-licenses` 5.x against `backend/.venv` | filtered to the 98 distributions pinned in `backend/requirements.lock`, of which 72 are also in `backend/requirements-runtime.lock` (what the production image ships) |
| Go | `go-licenses report ./...` in `runtime-agent/` | the full build-reachable module graph |
| Node — app | `license-checker --production` in `frontend/` | 23 production packages |
| Node — SDK | `license-checker --production` in `sdks/node/` | 1 package (the SDK has no runtime dependencies) |

Reproduce:

```sh
backend/.venv/bin/pip install pip-licenses && backend/.venv/bin/pip-licenses --format=json --order=license
(cd runtime-agent && go-licenses report ./...)
(cd frontend  && npx license-checker@25.0.1 --production --json)
(cd sdks/node && npx license-checker@25.0.1 --production --json)
```

**On the Python scope.** The developer venv also contains ad-hoc tooling that
is *not* in either lock file (`torch`, `transformers`, `onnx`, `optimum`,
`pip_audit`, `cyclonedx-python-lib`, `uv`, and others pulled in for the Stage-2
model-export script and for security scanning). Those are excluded from
`python-licenses.json` because they are not dependencies of the distributed
artifact. They were checked separately and are likewise free of copyleft.

## Results

Raw output is retained alongside this file:
[`python-licenses.json`](python-licenses.json),
[`go-licenses.csv`](go-licenses.csv),
[`frontend-licenses.json`](frontend-licenses.json),
[`sdk-node-licenses.json`](sdk-node-licenses.json).

| Ecosystem | Packages | License families observed |
|---|---|---|
| Python (locked) | 98 | MIT, Apache-2.0, BSD-2/3-Clause, ISC, PSF-2.0, MPL-2.0, Unlicense, MIT-0 |
| Go | 9 (8 third-party + this module) | MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 |
| Node — frontend | 23 | MIT, Apache-2.0, ISC, BSD-3-Clause, 0BSD, CC-BY-4.0, LGPL-3.0-or-later |
| Node — SDK | 1 | Apache-2.0 |

## Findings (obligations, not blockers)

1. **MPL-2.0 — `certifi`, `pathspec`, `tqdm` (dual MPL-2.0 AND MIT).**
   MPL-2.0 is file-level copyleft and §3.3 explicitly permits distributing the
   covered files as part of a Larger Work under other terms, including
   Apache-2.0. All three are consumed unmodified, so the obligation is to keep
   them separately identifiable and pass along their terms — which is what
   installing them as ordinary wheels already does. `pathspec` is dev-only
   (a `black` dependency); it is not in the runtime lock.

2. **LGPL-3.0-or-later — `@img/sharp-libvips-*`.** An *optional*,
   platform-specific transitive dependency of Next.js (via `sharp`), never a
   direct dependency: `frontend/package.json` declares only `next`, `react`,
   `react-dom`. It is a prebuilt shared library consumed unmodified and
   dynamically, which is the case LGPL is written for, and Apache-2.0 works
   may be combined with LGPL-3.0 components. The obligation — do not modify or
   statically link it, and pass along its terms and source offer — is
   satisfied by shipping it as the untouched npm package. Whether it reaches
   the runtime image at all depends on Next.js output tracing; the build stage
   (`npm ci`) does install it.

3. **CC-BY-4.0 — `caniuse-lite`.** A browser-support *data* set, not code, used
   at build time by Autoprefixer/Browserslist. Attribution-only; no
   restriction on Apache-2.0 distribution.

Also noted, not a finding: `email-validator` is Unlicense (public domain
dedication), which imposes nothing.

## Two artifacts corrected by this scan

* **`runtime-agent/LICENSE` did not exist.** `go-licenses` reported
  `Unknown` for all ten of this repository's own Go packages: Go module zips
  for a nested module contain only that subdirectory, so a consumer running
  `go get .../ai-security-platform/runtime-agent` would have received the code
  with no license text at all. A copy of the root `LICENSE` now sits in
  `runtime-agent/`, and the scan resolves it as Apache-2.0.

* **`frontend/package.json` had no `license` field.** Added as `Apache-2.0`.
  Note that `license-checker` still reports the frontend root package as
  `UNLICENSED` because the package is marked `"private": true` — that is the
  tool's handling of private packages, not a missing declaration. The declared
  field is asserted directly by
  `backend/tests/unit/test_license_consistency.py`.
