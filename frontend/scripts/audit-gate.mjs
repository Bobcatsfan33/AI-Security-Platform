#!/usr/bin/env node
// The frontend npm-audit gate — BLOCKING, with expiring, justified exceptions.
//
// Replaces `npm audit --audit-level=high`. That plain gate is correct in spirit
// but unworkable in practice: a Next.js app accretes transitive advisories
// (libvips via sharp, babel, postcss) that land continuously in the advisory DB
// and block EVERY pull request for reasons unrelated to the change — twice in
// one afternoon during GAP-001. The answer is not to weaken the gate (it stays
// blocking; see docs/GAPS.md, "the gate never goes warn-only") but to make
// deferral honest: time-boxed, owned, justified by OUR exposure, and revisited
// on a clock.
//
// Two tiers, enforced here:
//   1. HARD BAR — a source advisory on a NON-OPTIONAL PRODUCTION dependency
//      (the `--omit=dev --omit=optional` closure) gets NO exception. It ships in
//      the artifact we sign; it must be fixed, not deferred.
//   2. EXCEPTION-ELIGIBLE — dev / build-chain / optional-and-unused advisories
//      may be deferred, and only if a non-expired entry in audit-exceptions.json
//      names them with a written justification, an owner, and an expiry.
//
// An EXPIRED exception fails the build. So does an exception with no expiry, an
// expiry more than 90 days after it was added, or a malformed entry. An expired
// exception is a red gate, never a stale ignore.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FRONTEND = join(dirname(fileURLToPath(import.meta.url)), "..");
const EXCEPTIONS_FILE = join(FRONTEND, "audit-exceptions.json");
const BLOCKING_SEVERITIES = new Set(["high", "critical"]);
const MAX_EXCEPTION_DAYS = 90;
const DEFAULT_EXCEPTION_DAYS = 30; // longer than this needs a written window_reason

function fail(msg) {
  console.error(`\n✖ audit gate: ${msg}`);
  process.exit(1);
}

function npmJson(args) {
  // npm audit exits non-zero when vulnerabilities exist; we parse the JSON
  // regardless and decide ourselves. `npm ls` can also exit non-zero on peer
  // warnings — same handling.
  try {
    return JSON.parse(execFileSync("npm", args, { cwd: FRONTEND, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }));
  } catch (err) {
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout);
      } catch {
        /* fall through */
      }
    }
    fail(`could not run \`npm ${args.join(" ")}\`: ${err.message}`);
  }
}

// ── exceptions: load, validate, and build the non-expired allowlist ──────────

function loadExceptions() {
  let raw;
  try {
    raw = JSON.parse(readFileSync(EXCEPTIONS_FILE, "utf8"));
  } catch (err) {
    fail(`cannot read ${EXCEPTIONS_FILE}: ${err.message}`);
  }
  const entries = raw.exceptions ?? [];
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);

  const allow = new Map(); // id -> entry
  for (const e of entries) {
    for (const field of ["id", "package", "justification", "owner", "added", "expires"]) {
      if (!e[field]) fail(`exception ${JSON.stringify(e.id ?? e)} is missing '${field}'`);
    }
    if (e.justification.length < 40) {
      fail(`exception ${e.id}: justification is too thin to be grounded in real exposure`);
    }
    const added = new Date(e.added);
    const expires = new Date(e.expires);
    if (Number.isNaN(added.getTime()) || Number.isNaN(expires.getTime())) {
      fail(`exception ${e.id}: 'added'/'expires' must be YYYY-MM-DD dates`);
    }
    const spanDays = (expires - added) / 86_400_000;
    if (spanDays > MAX_EXCEPTION_DAYS) {
      fail(`exception ${e.id}: expiry is ${Math.round(spanDays)}d after 'added' — max ${MAX_EXCEPTION_DAYS}d`);
    }
    if (spanDays > DEFAULT_EXCEPTION_DAYS && !e.window_reason) {
      fail(
        `exception ${e.id}: window is ${Math.round(spanDays)}d (>${DEFAULT_EXCEPTION_DAYS} default) ` +
          `but has no 'window_reason' — say why it needs longer, so the default stays meaningful`,
      );
    }
    if (expires < today) {
      fail(
        `exception ${e.id} (${e.package}) EXPIRED on ${e.expires}. An expired exception is a red gate: ` +
          `fix the advisory, or renew the exception with fresh justification and a new expiry.`,
      );
    }
    allow.set(e.id, e);
  }
  return allow;
}

// ── source advisories: the package actually carrying each GHSA ───────────────
//
// `omitFlags` scopes the audit. The FULL audit (no flags) finds everything; the
// prod audit (`--omit=dev --omit=optional`) finds only what ships in the signed
// artifact. We trust npm's own omit handling here rather than walking `npm ls`,
// because `npm ls --omit=optional` still LISTS an installed optional package
// (sharp), whereas `npm audit --omit=optional` correctly excludes it.

function sourceAdvisories(omitFlags = []) {
  const audit = npmJson(["audit", "--json", ...omitFlags]);
  const found = new Map(); // "pkg::id" -> {pkg, id, severity}
  for (const info of Object.values(audit.vulnerabilities ?? {})) {
    for (const via of info.via ?? []) {
      // A string `via` is a downstream EFFECT (a package vulnerable only because
      // it depends on another). The object `via` is the SOURCE advisory. Keying
      // on the source means excepting sharp also clears `next`, which is high
      // solely because it bundles sharp.
      if (typeof via !== "object") continue;
      if (!BLOCKING_SEVERITIES.has(via.severity)) continue;
      const id = (via.url ?? "").split("/").pop() || String(via.source ?? via.name);
      found.set(`${via.name}::${id}`, { pkg: via.name, id, severity: via.severity });
    }
  }
  return found;
}

// ── the gate ─────────────────────────────────────────────────────────────────

const allow = loadExceptions();
const prodKeys = new Set(sourceAdvisories(["--omit=dev", "--omit=optional"]).keys());
const advisories = [...sourceAdvisories().values()];

const hardFailures = [];
const unallowlisted = [];
const deferred = [];
const usedExceptions = new Set();

for (const a of advisories) {
  if (prodKeys.has(`${a.pkg}::${a.id}`)) {
    // Present in the signed artifact's dependency closure. No exception, ever.
    hardFailures.push(a);
  } else if (allow.has(a.id)) {
    deferred.push({ ...a, exception: allow.get(a.id) });
    usedExceptions.add(a.id);
  } else {
    unallowlisted.push(a);
  }
}

for (const { pkg, id, exception } of deferred) {
  const days = Math.round((new Date(exception.expires) - Date.now()) / 86_400_000);
  console.log(`• deferred: ${pkg} ${id} — expires ${exception.expires} (${days}d), owner ${exception.owner}`);
}

// A stale exception (allowlisted but no longer flagged) should be pruned, not
// left to rot — warn, don't fail.
for (const id of allow.keys()) {
  if (!usedExceptions.has(id)) {
    console.log(`⚠ exception ${id} no longer matches any advisory — remove it from audit-exceptions.json`);
  }
}

if (hardFailures.length) {
  console.error("\n✖ PRODUCTION dependency advisories — no exception is permitted for these:");
  for (const a of hardFailures) console.error(`    ${a.pkg} ${a.id} (${a.severity})`);
}
if (unallowlisted.length) {
  console.error("\n✖ high/critical advisories with no exception:");
  for (const a of unallowlisted) console.error(`    ${a.pkg} ${a.id} (${a.severity})`);
  console.error(
    "\n  Fix them, or (dev/optional only) add a justified, expiring entry to " +
      "frontend/audit-exceptions.json.",
  );
}

if (hardFailures.length || unallowlisted.length) process.exit(1);
console.log(`\n✔ audit gate passed (${deferred.length} deferred under exception, all non-expired).`);
