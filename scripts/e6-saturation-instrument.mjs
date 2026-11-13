#!/usr/bin/env node
/**
 * CQ E6 comparator saturation instrument — CONTRACT: E6 rerun scheme v4
 * (retired-docs:verification/2026-09-23-e6-rerun-scheme-v4.md §2.1.1–§2.1.4 workload,
 * attribution and consumption separation; §2.4 declared-level saturation
 * proof AS AMENDED by the opus second-voice HOLD — see "Engagement rule"
 * below; §2.3.1 checks 6–8 instrument quiescence; §3.6 frozen
 * `harnessInstrument` declaration). Spawned BY the harness (never the
 * launcher), ONE instance per comparator window; the candidate window keeps
 * its client-endpoint basis and is NOT this program's concern.
 *
 * ---------------------------------------------------------------------------
 * What it does
 * ---------------------------------------------------------------------------
 * Drives the declared optional-job workload shape through THAT window's
 * run-owned fault proxy, authenticated as the COMPARATOR member, for the
 * whole warmup + measurement window: continuous queued optional work held at
 * the declared concurrency limit (§2.1.1) by the production admission and
 * backoff rules. The declared limit arrives on the CLI (--limit; the frozen
 * declaration's global optional limit — work-contract
 * GLOBAL_OPTIONAL_CONCURRENCY for the v1-shaped contract). The route
 * set/mix/account topology are parameterizable (--routes-json, --class-mix,
 * --accounts) so the frozen v3 `harnessInstrument` declaration can be
 * consumed verbatim; the pre-freeze default route is the coordinator's own
 * job transport surface, POST /jmap with the idempotent `Core/echo` call
 * (handler.go reg("Core/echo", ...) — requireAuth, no corpus mutation),
 * which the declaration supersedes at freeze.
 *
 * ---------------------------------------------------------------------------
 * Engagement rule (§2.4 AS AMENDED — opus HOLD)
 * ---------------------------------------------------------------------------
 * The original §2.4 rule (every sample optionalRunning >= limit) is
 * UNMEETABLE by the production engine under the frozen outage/loss profile:
 * the engine's own admission rules legitimately hold work below the limit
 * during faults. A sample is therefore ENGAGING iff, in addition to the
 * unchanged basis and freshness conditions:
 *
 *   - optionalRunning >= the declared limit            → reason `at-limit`
 *   - OR a production admission/backoff rule is what   → reason
 *     holds running below the limit at poll time         `held:<rule>`
 *
 * The hold rules are the REAL production shapes, transcribed with provenance
 * from `mailserver/webmail/src/lib/offline/` (see "Mirrored admission rules"
 * below): `networkUnavailable` (eligibility.ts:241-261 workOffline/networkCost
 * gate), `criticalActivity`/`criticalQuiet` (scheduler.ts
 * criticalAdmissionReason; CRITICAL_QUIET_RESUME_MS), `backoff`
 * (coordinator.ts:525-531 retryable-failure release: full-jitter up to the
 * exponential ceiling, retryCeilingMs), `accountSaturation`
 * (PER_ACCOUNT_OPTIONAL_CONCURRENCY), `deficit` (weighted-DRR class credit).
 * A below-limit sample with NO active production hold still REFUTES
 * (`below-limit`) — an unexplained shortfall is the instrument's fault, not
 * the engine's. Outage alone therefore never refutes the proof: outage
 * failures route through the engine's retryable-failure backoff and the
 * eligibility offline gate, and the samples stay engaged-with-reason.
 * Unchanged refuting classes: `fallback-basis` (a declaration-answered poll,
 * `policy-mode-configured`, the execute-mode fallback of
 * saturation.ts:295-301, is never verifying), `stale-observation`
 * (observedAtUtc older than 2 poll intervals), `malformed-poll`,
 * `unreachable` (a missing poll is refuting, never a gap).
 *
 * ---------------------------------------------------------------------------
 * Mirrored admission rules (provenance; NOT invented state)
 * ---------------------------------------------------------------------------
 * The pool is a scheduler-driven admission engine, not a naive loop: jobs
 * move through the scheduler's own block taxonomy and the coordinator's
 * release paths, transcribed from:
 *   - work-contract.ts:  GLOBAL_OPTIONAL_CONCURRENCY,
 *     PER_ACCOUNT_OPTIONAL_CONCURRENCY, WORK_CLASS_QUANTA (8/4/1),
 *     RETRY_INITIAL_DELAY_MS (1_000), RETRY_MAX_DELAY_MS (300_000),
 *     OPTIONAL_WORK_CLASSES, MAX_QUEUE_AGE_MS
 *   - scheduler.ts:      scheduleNext gate order and ScheduleBlockReason
 *     (criticalActivity → criticalQuiet → globalSaturation → empty →
 *     backoff → weighted-DRR dispatch → accountSaturation/backoff/deficit),
 *     retryCeilingMs (exponential doubling capped at RETRY_MAX_DELAY_MS),
 *     retryDelayMs (full jitter [0, ceiling], randomness injected)
 *   - eligibility.ts:    resolveEligibility admission gates (offline and
 *     critical-activity blocks; device-capability/policy inputs that the run
 *     does not vary are nominal-pass — the same grant applies to the
 *     candidate window, so treating them as passing is the symmetric shape)
 *   - coordinator.ts:    retryable-failure release (backoff envelope,
 *     attempts+1) vs non-retryable terminal failure vs abort-rejoin
 * Deviations are limited to run-observable substitutions and are named here:
 * `workOffline` is derived from the last request settlement (a network-class
 * failure — networkDrop/timedOut — marks the path down; the next successful
 * settlement marks it up), because the instrument has no navigator.onLine;
 * the offline analog gates FRESH admission (eligibility's new-work block),
 * while due backoff retries still dispatch — each due retry is the recovery
 * probe, mirroring the engine whose backoff path outlives the pause (the
 * instrument cannot wait for an OS online event it cannot observe). Request
 * timeouts are retryable failures (the engine's job retry), not user aborts.
 * The instrument performs NO fault injections; loss/outage draws are
 * proxy-owned and keyed per population+sequence (`instrument-request` basis
 * token with this instrument's per-job seq). Its only randomness is the
 * production full-jitter backoff, seeded deterministically per job sequence
 * within this population (`backoff:<windowId>:<seq>`) — replay-stable, never
 * shared across populations.
 *
 * ---------------------------------------------------------------------------
 * Honesty posture
 * ---------------------------------------------------------------------------
 * - SINGLE PROCESS by contract (§2.1.1): this program never spawns worker
 *   processes — `node:child_process` is deliberately not imported. Its own
 *   PID is the only PID it can ever report.
 * - It is NEVER a measured role: no {type:'process'} events, no role PIDs,
 *   nothing enters processSamples (§2.1.2 — same exclusion the workload
 *   driver claims for itself).
 * - ALL request traffic goes through the window's fault proxy
 *   (--proxy-listen) with the per-basis attribution header
 *   (`x-e6-proxy-source: instrument-request`, the harness PROXY_CONFIG's
 *   `instrumentRequests` bucket). --gateway-origin is validated loopback and
 *   recorded, but NEVER fetched directly — targeting it would bypass the
 *   profile's fault stages.
 * - Bearer material is read once from --session-file (the harness writes it
 *   from the per-member fixture credential), used only as the authorization
 *   header, and NEVER logged, emitted, or written to any receipt. Receipts
 *   carry the session-file PATH, never its content.
 * - Saturation evidence is the comparator window's observed basis
 *   `harness-saturation-instrument` (§2.4): per-poll samples
 *   {basis, optionalRunning, optionalQueued, limit, observedAtUtc, saturating}
 *   from this instrument's own scheduler/pool counters, extended with the
 *   engaged verdict (`engagedReason`, `holdReasons[]`, `refutingReasons[]`).
 *   Refuting samples NEVER abort the run early — recorded reality completes,
 *   and the non-zero exit names it (§2.4 failure semantics; the window is
 *   never re-run in place). The proof holds iff EVERY measurement-window
 *   sample is ENGAGING; warmup samples are retained but only measurement
 *   samples gate (§2.4).
 *
 * ---------------------------------------------------------------------------
 * Interface (for the harness spawner)
 * ---------------------------------------------------------------------------
 *   node scripts/e6-saturation-instrument.mjs \
 *     --gateway-origin http://127.0.0.1:8080 \
 *     --proxy-listen  http://127.0.0.1:<windowProxyPort> \
 *     --session-file  <run-scoped file with the comparator member bearer> \
 *     --limit 2 --interval-ms 1000 \
 *     --window-id <windowId> --out-dir <runDir>/instrument
 *     [--warmup-ms 120000] [--measurement-ms 300000]     window structure
 *     [--total-jobs 0] [--job-interval-ms 0]             population shape
 *     [--accounts 2] [--class-mix 1:1:1]                 scheduler topology
 *     [--routes-json <json|@file>] [--request-timeout-ms 10000]
 *     [--status-listen 127.0.0.1:0] [--drain-deadline-ms 10000]
 *     [--attribution-header x-e6-proxy-source]
 *
 * Required flags are exactly the interface §2.1.1/§3.1 name; the bracketed
 * flags exist so the frozen declaration and smoke runs can parameterize the
 * population shape without code changes.
 *
 * Events out (stdout NDJSON, one JSON object per line):
 *   {type:'instrument',entrypoint,sourceSha256,pid,scope,windowId,basis,limit}
 *   {type:'status',url}              the harness instrument endpoint (§3.1:
 *                                    comparator window's saturation surface;
 *                                    distinct marker from a client endpoint)
 *   {type:'phase',phase}             'warmup' then 'measurement'
 *   {type:'saturation-sample',windowId,phase,sample}   per-poll sample
 *   {type:'saturation',active,activeDuringMeasurement,basis,samples,
 *    measurementSamples,engagingSamples,refutingSamples,refutingReasons[],
 *    engagedReasonBreakdown,minRunningObserved,limit,proof,engagedRatio}
 *   {type:'drain',stoppedAdmissionAtUtc,drainedAtUtc,inflightAtExit,
 *    drainDeadlineMs,breached}                          §2.3.1 check 7 half
 *   {type:'done',windowId,samplesFile,receiptFile,exitPlan}
 * The operator-facing export line (grep target for readiness wiring) goes to
 * stderr, keeping stdout content-free NDJSON:
 *   export E6_INSTRUMENT_SATURATION_URL=http://127.0.0.1:<port>/e6/saturation-instrument/status
 *
 * Files written (--out-dir, run-scoped, window-scoped names):
 *   e6-saturation-instrument-<window-id>-samples.json  all per-poll samples
 *   e6-saturation-instrument-<window-id>-receipt.json  summary receipt
 *     fragment: engaged verdict per poll (the samples array, each with its
 *     engagedReason), final engaged ratio, the §2.4 proof fields, the §2.1.3
 *     instrument identity/scope/digest block, workloadDeclarationEcho,
 *     per-outcome proxy attribution counters, the per-population sequence
 *     basis, and the §2.3.1 drain block (inflightAtExit MUST be 0).
 *
 * Exit codes: 0 proof `declared-level-verified`; 1 usage/machinery failure
 * (usage exits 1, never 2); 3 completed with proof `refuted` (evidence-level
 * failure — recorded, never averaged around, §2.4); 130/143 after ordered
 * SIGINT/SIGTERM drain (interrupted mid-window ⇒ proof `unverified`).
 * Teardown protocol (§2.3.1 check 7): stop admitting NEW work → drain every
 * outstanding request (deadline --drain-deadline-ms) → close the status
 * surface → exit. A breached drain deadline is machinery failure (exit 1).
 *
 * Modes:
 *   (default)     contract mode: requires the flags above, runs one window
 *   --self-test   pure in-memory assertions (no network, no writes): sample
 *                 schema, the amended threshold logic over synthetic polls,
 *                 the below-limit refuting fixture (unexplained shortfall),
 *                 the outage-never-refutes fixture, the mirrored scheduler
 *                 block reasons and backoff shapes, usage refusals, and
 *                 receipt bearer-hygiene
 *   -h, --help    this text
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';

// The comparator window's observed basis (§2.4): this instrument's own
// counter basis. Must differ from EVERY client basis (§2.1.3) — the list
// below is the client-side constant set (saturation.ts:75-77,
// e6-workload-driver.mjs basis constants); the self-test pins distinctness.
const INSTRUMENT_BASIS = 'harness-saturation-instrument';
const CLIENT_BASES = Object.freeze([
  'policy-mode-configured',
  'mode-admits-no-optional-work',
  'engine-queue-observed',
  'saturation-endpoint-verified',
  'saturation-endpoint-refuted',
  'policy-mode-configured-unverified',
  'flag-off-comparator-admits-no-optional-work',
]);
const REFUTING_FALLBACK_BASES = Object.freeze(['policy-mode-configured', 'mode-admits-no-optional-work']);

const ATTRIBUTION_TOKEN = 'instrument-request';
const STATUS_PATH = '/e6/saturation-instrument/status';
const SCOPE = 'run-scoped-comparator-window';
const ENTRYPOINT_REL = 'scripts/e6-saturation-instrument.mjs';

// ---------------------------------------------------------------------------
// Mirrored production constants (work-contract.ts:5-42; DO NOT drift without
// the source — the header names the owning file for every constant).
// ---------------------------------------------------------------------------
const OPTIONAL_WORK_CLASSES = Object.freeze(['interactive', 'background', 'opportunistic']);
const WORK_CLASS_QUANTA = Object.freeze({ interactive: 8, background: 4, opportunistic: 1 });
const GLOBAL_OPTIONAL_CONCURRENCY_DEFAULT = 2; // work-contract.ts:27
const PER_ACCOUNT_OPTIONAL_CONCURRENCY = 1; // work-contract.ts:28
const RETRY_INITIAL_DELAY_MS = 1_000; // work-contract.ts:41
const RETRY_MAX_DELAY_MS = 5 * 60 * 1_000; // work-contract.ts:42
const CRITICAL_QUIET_RESUME_MS = 5_000; // work-contract.ts:33 (CRITICAL_QUIET_RESUME_MS)
const MAX_QUEUE_AGE_MS = 7 * 24 * 60 * 60 * 1_000; // work-contract.ts:17-18
const CLASS_COUNT = OPTIONAL_WORK_CLASSES.length;

// scheduler.ts ScheduleBlockReason taxonomy — the reason codes a hold
// reports. 'empty' and 'globalSaturation' are NOT holds: empty means the
// instrument starved its own queue (an unexplained shortfall refutes);
// globalSaturation with running AT the declared limit is the at-limit
// engagement itself.
const HOLD_REASONS = Object.freeze([
  'networkUnavailable', // eligibility.ts:241,250,261
  'criticalActivity', // scheduler.ts criticalAdmissionReason
  'criticalQuiet', // scheduler.ts criticalAdmissionReason
  'backoff', // scheduler.ts block + coordinator.ts:525-531 release
  'accountSaturation', // scheduler.ts allReadyAccountsSaturated
  'deficit', // scheduler.ts weighted-DRR fall-through
]);

// Pre-freeze default route set: the coordinator's own job transport surface
// (POST /jmap, requireAuth) with the idempotent Core/echo call. The frozen v3
// harnessInstrument.workload declaration supersedes this at Commit A (§3.6).
const DEFAULT_ROUTES = Object.freeze([
  Object.freeze({
    method: 'POST',
    path: '/jmap',
    weight: 1,
    body: JSON.stringify([['Core/echo', {}, 'e6-instrument-${seq}']]),
  }),
]);

function fail(tag, message) {
  const error = new Error(`E6-INSTRUMENT-${tag}: ${message}`);
  error.e6Tag = tag;
  throw error;
}

function log(message) {
  process.stderr.write(`e6-saturation-instrument: ${message}\n`);
}

function emit(event) {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

function isoUtcNow() {
  return new Date().toISOString();
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isLoopbackUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
}

/** Deterministic seeded RNG (e6-workload-driver.mjs rngFromSeed, verbatim
 *  construction): the only randomness this instrument draws is the
 *  production full-jitter backoff, seeded per population+sequence. */
function rngFromSeed(seed) {
  const digest = crypto.createHash('sha256').update(`setjoin-e6-seed:${seed}`).digest();
  let state = digest.readUInt32LE(0) >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Normalize --proxy-listen (http URL or host:port) to a loopback base URL. */
function parseProxyBase(raw) {
  const text = String(raw ?? '').trim();
  const candidate = /^https?:\/\//i.test(text) ? text : `http://${text}`;
  if (!isLoopbackUrl(candidate)) {
    fail('USAGE', `--proxy-listen must be a loopback http URL or host:port, got ${JSON.stringify(raw)}`);
  }
  return candidate.replace(/\/+$/, '');
}

// ---------------------------------------------------------------------------
// Argument parsing and validation (pure; the self-test exercises these).
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {
    gatewayOrigin: null,
    proxyListen: null,
    sessionFile: null,
    limit: null,
    intervalMs: null,
    windowId: null,
    outDir: null,
    warmupMs: 120_000,
    measurementMs: 300_000,
    totalJobs: 0,
    jobIntervalMs: 0,
    accounts: 2, // corpus.accounts topology of the frozen profile
    classMix: '1:1:1',
    routesJson: null,
    requestTimeoutMs: 10_000,
    statusListen: '127.0.0.1:0',
    drainDeadlineMs: 10_000,
    attributionHeader: 'x-e6-proxy-source',
    selfTest: false,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = () => {
      index += 1;
      if (index >= argv.length) fail('USAGE', `${arg} requires a value`);
      return argv[index];
    };
    switch (arg) {
      case '--gateway-origin': args.gatewayOrigin = value(); break;
      case '--proxy-listen': args.proxyListen = value(); break;
      case '--session-file': args.sessionFile = value(); break;
      case '--limit': args.limit = value(); break;
      case '--interval-ms': args.intervalMs = value(); break;
      case '--window-id': args.windowId = value(); break;
      case '--out-dir': args.outDir = value(); break;
      case '--warmup-ms': args.warmupMs = value(); break;
      case '--measurement-ms': args.measurementMs = value(); break;
      case '--total-jobs': args.totalJobs = value(); break;
      case '--job-interval-ms': args.jobIntervalMs = value(); break;
      case '--accounts': args.accounts = value(); break;
      case '--class-mix': args.classMix = value(); break;
      case '--routes-json': args.routesJson = value(); break;
      case '--request-timeout-ms': args.requestTimeoutMs = value(); break;
      case '--status-listen': args.statusListen = value(); break;
      case '--drain-deadline-ms': args.drainDeadlineMs = value(); break;
      case '--attribution-header': args.attributionHeader = value(); break;
      case '--self-test': args.selfTest = true; break;
      case '-h': case '--help': args.help = true; break;
      default:
        fail('USAGE', `unknown argument ${JSON.stringify(arg)} (see --help)`);
    }
  }
  return args;
}

function toInteger(value, flag, { min }) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min) {
    fail('USAGE', `${flag} must be an integer >= ${min}, got ${JSON.stringify(value)}`);
  }
  return parsed;
}

function parseClassMix(raw) {
  const parts = String(raw ?? '').split(':');
  if (parts.length !== CLASS_COUNT) {
    fail('USAGE', `--class-mix must be ${CLASS_COUNT} positive integers joined by ":" (interactive:background:opportunistic), got ${JSON.stringify(raw)}`);
  }
  return parts.map((part, index) => toInteger(part, `--class-mix[${index}]`, { min: 1 }));
}

function validateWindowId(raw) {
  const text = String(raw ?? '');
  // File-safe and traversal-safe: the window id is embedded in output file
  // names and receipts, so anything outside this set refuses.
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(text)) {
    fail('USAGE', `--window-id must match /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/, got ${JSON.stringify(raw)}`);
  }
  return text;
}

function validateConfig(raw) {
  if (!isLoopbackUrl(String(raw.gatewayOrigin ?? ''))) {
    fail('USAGE', `--gateway-origin must be a loopback http URL, got ${JSON.stringify(raw.gatewayOrigin)}`);
  }
  if (raw.proxyListen === null || String(raw.proxyListen).trim() === '') {
    fail('USAGE', '--proxy-listen is required (the window fault proxy every request rides)');
  }
  if (typeof raw.sessionFile !== 'string' || raw.sessionFile.trim() === '') {
    fail('USAGE', '--session-file is required (the comparator member session identity)');
  }
  const limit = toInteger(raw.limit, '--limit', { min: 1 });
  const intervalMs = toInteger(raw.intervalMs, '--interval-ms', { min: 100 });
  const warmupMs = toInteger(raw.warmupMs, '--warmup-ms', { min: 0 });
  const measurementMs = toInteger(raw.measurementMs, '--measurement-ms', { min: intervalMs });
  const totalJobs = toInteger(raw.totalJobs, '--total-jobs', { min: 0 });
  const jobIntervalMs = toInteger(raw.jobIntervalMs, '--job-interval-ms', { min: 0 });
  const accounts = toInteger(raw.accounts, '--accounts', { min: 1 });
  const requestTimeoutMs = toInteger(raw.requestTimeoutMs, '--request-timeout-ms', { min: 100 });
  const drainDeadlineMs = toInteger(raw.drainDeadlineMs, '--drain-deadline-ms', { min: 100 });
  const classMix = parseClassMix(raw.classMix);
  if (typeof raw.outDir !== 'string' || raw.outDir.trim() === '') {
    fail('USAGE', '--out-dir is required (run-scoped samples + receipt destination)');
  }
  const attributionHeader = String(raw.attributionHeader).trim().toLowerCase();
  if (!/^[a-z0-9-]+$/.test(attributionHeader)) {
    fail('USAGE', `--attribution-header must be a valid header name, got ${JSON.stringify(raw.attributionHeader)}`);
  }
  return {
    gatewayOrigin: new URL(raw.gatewayOrigin).origin,
    proxyBase: parseProxyBase(raw.proxyListen),
    sessionFile: raw.sessionFile,
    limit,
    intervalMs,
    warmupMs,
    measurementMs,
    totalJobs,
    jobIntervalMs,
    accounts,
    classMix,
    requestTimeoutMs,
    drainDeadlineMs,
    outDir: raw.outDir,
    statusListen: raw.statusListen,
    attributionHeader,
    windowId: validateWindowId(raw.windowId),
  };
}

// ---------------------------------------------------------------------------
// Session identity: read once, use as the authorization header only. Bearer
// material NEVER appears in events, receipts, or logs.
// ---------------------------------------------------------------------------

function loadSessionBearer(sessionFile) {
  let text;
  try {
    text = fs.readFileSync(sessionFile, 'utf8');
  } catch (error) {
    fail('CREDENTIAL', `--session-file is unreadable (${sessionFile}): ${error.message}`);
  }
  const trimmed = text.trim();
  if (trimmed === '') {
    fail('CREDENTIAL', `--session-file (${sessionFile}) is empty; never exec without the member credential`);
  }
  const fromObject = (object) => {
    for (const key of ['bearer', 'token', 'accessToken']) {
      const value = object[key];
      if (typeof value === 'string' && value.trim() !== '') return value.trim();
    }
    for (const nested of ['session', 'instrument']) {
      const inner = object[nested];
      if (inner !== null && typeof inner === 'object') {
        const found = fromObject(inner);
        if (found !== null) return found;
      }
    }
    return null;
  };
  if (trimmed.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (error) {
      fail('CREDENTIAL', `--session-file (${sessionFile}) is neither JSON nor a raw token: ${error.message}`);
    }
    const found = fromObject(parsed);
    if (found === null) {
      fail('CREDENTIAL', `--session-file (${sessionFile}) carries no bearer/token/accessToken material`);
    }
    return found;
  }
  // A raw token file: the whole trimmed body is the credential.
  return trimmed;
}

// ---------------------------------------------------------------------------
// Workload declaration: route set + mix + class mix. Paths are
// proxy-relative ONLY; class mix is over OPTIONAL_WORK_CLASSES.
// ---------------------------------------------------------------------------

function parseRoutes(rawRoutesJson) {
  if (rawRoutesJson === null || String(rawRoutesJson).trim() === '') {
    return DEFAULT_ROUTES.map((route) => ({ ...route }));
  }
  let text = String(rawRoutesJson);
  if (text.startsWith('@')) text = fs.readFileSync(text.slice(1), 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    fail('USAGE', `--routes-json is not valid JSON: ${error.message}`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    fail('USAGE', '--routes-json must be a non-empty JSON array of {method,path,weight?,body?}');
  }
  const routes = parsed.map((entry, index) => {
    if (entry === null || typeof entry !== 'object') {
      fail('USAGE', `--routes-json[${index}] must be an object`);
    }
    const method = String(entry.method ?? 'POST').toUpperCase();
    const routePath = String(entry.path ?? '');
    if (!routePath.startsWith('/')) {
      fail('USAGE', `--routes-json[${index}].path must start with "/" (proxy-relative); absolute URLs are refused`);
    }
    const weight = toInteger(entry.weight ?? 1, `--routes-json[${index}].weight`, { min: 1 });
    const body = entry.body === undefined || entry.body === null ? null : String(entry.body);
    return { method, path: routePath, weight, body };
  });
  return routes;
}

/** Deterministic weighted expansion — no randomness of its own (driver
 *  parity): the entry for index i is expanded[i % expanded.length]. */
function expandWeighted(entries, weights) {
  const expanded = [];
  for (let index = 0; index < entries.length; index += 1) {
    for (let count = 0; count < weights[index]; count += 1) expanded.push(entries[index]);
  }
  return expanded;
}

// ---------------------------------------------------------------------------
// Mirrored backoff (scheduler.ts:638-659 — retryCeilingMs / retryDelayMs,
// shapes verbatim; randomness injected per population+sequence).
// ---------------------------------------------------------------------------

function retryCeilingMs(attempt) {
  const normalizedAttempt = Math.max(0, Math.floor(Number.isFinite(attempt) ? attempt : 0));
  let ceiling = RETRY_INITIAL_DELAY_MS;
  for (let index = 0; index < normalizedAttempt && ceiling < RETRY_MAX_DELAY_MS; index += 1) {
    ceiling = Math.min(RETRY_MAX_DELAY_MS, ceiling * 2);
  }
  return ceiling;
}

/** Full jitter is [0, exponential ceiling] (scheduler.ts:652-657). */
function retryDelayMs(attempt, random) {
  const sample = random();
  const normalized = Number.isFinite(sample) ? Math.min(1, Math.max(0, sample)) : 0;
  return Math.floor(retryCeilingMs(attempt) * normalized);
}

// ---------------------------------------------------------------------------
// Mirrored scheduler (scheduler.ts createSchedulerState / scheduleNext —
// gate order, block reasons and weighted-DRR shapes transcribed; jobs carry
// {jobId, accountId, workClass, state, attempts, retryAtUtcMs}). Deviations:
// chargedCost collapses to 1 unit (the instrument's jobs are single-unit
// metadata work: scheduler.ts "a malformed zero-cost metadata batch cannot
// bypass DRR" → Math.max(1, ...)), and expiry keeps its shape (nothing
// expires inside a window; MAX_QUEUE_AGE_MS is 7 days).
// ---------------------------------------------------------------------------

function emptyDeficits() {
  return { interactive: 0, background: 0, opportunistic: 0 };
}

function emptyAccountCursors() {
  return { interactive: null, background: null, opportunistic: null };
}

function createSchedulerState({ criticalActivity = 0, criticalQuietSinceMonoMs = null } = {}) {
  return {
    queued: [],
    running: [],
    classDeficits: emptyDeficits(),
    classCursor: 0,
    classQuantumLoaded: false,
    accountCursors: emptyAccountCursors(),
    criticalActivity,
    criticalQuietSinceMonoMs,
    nextSequence: 0,
  };
}

function isReady(item, nowUtcMs) {
  if (item.job.state === 'queued') return true;
  if (item.job.state !== 'backoff') return false;
  return item.retryAtUtcMs === null || item.retryAtUtcMs === undefined || item.retryAtUtcMs <= nowUtcMs;
}

function activeCountForAccount(state, accountId) {
  return state.running.reduce((count, item) => count + (item.job.accountId === accountId ? 1 : 0), 0);
}

function accountsForClass(state, workClass, nowUtcMs) {
  const accounts = new Set();
  for (const item of state.queued) {
    if (item.job.workClass === workClass && isReady(item, nowUtcMs)) accounts.add(item.job.accountId);
  }
  return [...accounts].sort();
}

function candidateForClass(state, workClass, nowUtcMs) {
  const accounts = accountsForClass(state, workClass, nowUtcMs);
  const cursor = state.accountCursors[workClass];
  const start = accounts.length === 0 || cursor === null ? 0 : Math.max(accounts.indexOf(cursor), 0);
  for (let offset = 0; offset < accounts.length; offset += 1) {
    const accountId = accounts[(start + offset) % accounts.length];
    if (activeCountForAccount(state, accountId) >= PER_ACCOUNT_OPTIONAL_CONCURRENCY) continue;
    const candidates = state.queued
      .filter((item) => item.job.workClass === workClass && item.job.accountId === accountId && isReady(item, nowUtcMs))
      .sort((a, b) => a.sequence - b.sequence || a.job.jobId.localeCompare(b.job.jobId));
    if (candidates.length > 0) return candidates[0];
  }
  return null;
}

function hasFittingCandidate(state, workClass, nowUtcMs) {
  return candidateForClass(state, workClass, nowUtcMs) !== null;
}

function queueHasPending(state) {
  return state.queued.some((item) => item.job.state === 'queued' || item.job.state === 'backoff');
}

function queueHasReady(state, nowUtcMs) {
  return state.queued.some((item) => isReady(item, nowUtcMs));
}

function queueHasBackoff(state, nowUtcMs) {
  return state.queued.some((item) => item.job.state === 'backoff' && !isReady(item, nowUtcMs));
}

function allReadyAccountsSaturated(state, nowUtcMs) {
  const ready = state.queued.filter((item) => isReady(item, nowUtcMs));
  return ready.length > 0 && ready.every((item) => activeCountForAccount(state, item.job.accountId) >= PER_ACCOUNT_OPTIONAL_CONCURRENCY);
}

function criticalAdmissionReason(state, nowMonoMs) {
  if (state.criticalActivity > 0) return 'criticalActivity';
  if (state.criticalQuietSinceMonoMs !== null && nowMonoMs - state.criticalQuietSinceMonoMs < CRITICAL_QUIET_RESUME_MS) {
    return 'criticalQuiet';
  }
  return null;
}

function blockedDecision(state, reason) {
  return { state, dispatch: null, reason };
}

/** scheduleNext (scheduler.ts:404-478): admit one optional unit using
 *  weighted DRR with the production gate order. Returns {state, dispatch,
 *  reason}; `reason` is 'scheduled' or a ScheduleBlockReason. */
function scheduleNext(state, time) {
  // expireQueuedJobs (scheduler.ts:198-209): queue-age/deadline expiry;
  // nothing expires inside a window (MAX_QUEUE_AGE_MS), shape kept.
  const nowUtcMs = time.nowUtcMs;
  const working = { ...state, queued: state.queued.filter((item) => nowUtcMs - item.queuedAtUtcMs < MAX_QUEUE_AGE_MS) };
  const criticalReason = criticalAdmissionReason(working, time.nowMonoMs);
  if (criticalReason) return blockedDecision(working, criticalReason);
  if (working.running.length >= declaredLimitOf(working)) {
    return blockedDecision(working, 'globalSaturation');
  }
  if (!queueHasPending(working)) return blockedDecision(working, 'empty');
  if (!queueHasReady(working, nowUtcMs)) return blockedDecision(working, 'backoff');

  const deficits = { ...working.classDeficits };
  const accountCursors = { ...working.accountCursors };
  let classCursor = working.classCursor;
  let classQuantumLoaded = working.classQuantumLoaded;

  for (let visit = 0; visit < CLASS_COUNT; visit += 1) {
    const workClass = OPTIONAL_WORK_CLASSES[classCursor];
    const classHasQueued = working.queued.some((item) => item.job.workClass === workClass && (item.job.state === 'queued' || item.job.state === 'backoff'));
    if (!classHasQueued) {
      deficits[workClass] = 0;
      classCursor = (classCursor + 1) % CLASS_COUNT;
      classQuantumLoaded = false;
      continue;
    }
    // A class blocked by retry time or per-account saturation earns no
    // service credit (scheduler.ts:441-450).
    if (!hasFittingCandidate(working, workClass, nowUtcMs)) {
      deficits[workClass] = 0;
      classCursor = (classCursor + 1) % CLASS_COUNT;
      classQuantumLoaded = false;
      continue;
    }
    if (!classQuantumLoaded) {
      deficits[workClass] += WORK_CLASS_QUANTA[workClass];
      classQuantumLoaded = true;
    }
    // Single-unit jobs: the deficit always pays cost 1 when any candidate
    // exists (chargedCost ≥ 1), so a fitting candidate dispatches.
    const candidate = candidateForClass(working, workClass, nowUtcMs);
    if (!candidate) {
      classCursor = (classCursor + 1) % CLASS_COUNT;
      classQuantumLoaded = false;
      continue;
    }
    deficits[workClass] -= 1;
    const dispatch = {
      ...candidate,
      job: { ...candidate.job, state: 'running' },
      startedAtMonoMs: time.nowMonoMs,
      chargedUnits: 1,
    };
    const queued = working.queued.filter((item) => item.job.jobId !== candidate.job.jobId);
    const accounts = accountsForClass(working, workClass, nowUtcMs);
    const accountIndex = accounts.indexOf(candidate.job.accountId);
    accountCursors[workClass] = accountIndex < 0 || accounts.length < 2 ? (accounts[0] ?? null) : accounts[(accountIndex + 1) % accounts.length];
    const nextState = {
      ...working,
      queued,
      running: [...working.running, dispatch],
      classDeficits: deficits,
      classCursor,
      classQuantumLoaded,
      accountCursors,
    };
    // Keep the cursor while another fitting account can run in this class
    // (scheduler.ts:462-467); otherwise advance.
    const keepClass = hasFittingCandidate(nextState, workClass, nowUtcMs);
    const finalState = keepClass
      ? nextState
      : { ...nextState, classCursor: (classCursor + 1) % CLASS_COUNT, classQuantumLoaded: false };
    return { state: finalState, dispatch, reason: 'scheduled' };
  }

  if (allReadyAccountsSaturated(working, nowUtcMs)) {
    return blockedDecision({ ...working, classDeficits: deficits, accountCursors, classCursor, classQuantumLoaded }, 'accountSaturation');
  }
  if (queueHasBackoff(working, nowUtcMs)) {
    return blockedDecision({ ...working, classDeficits: deficits, accountCursors, classCursor, classQuantumLoaded }, 'backoff');
  }
  return blockedDecision({ ...working, classDeficits: deficits, accountCursors, classCursor, classQuantumLoaded }, 'deficit');
}

/** The declared limit is the ceiling this run froze — the mirrored
 *  globalSaturation gate compares against the DECLARED limit (CLI), with the
 *  work-contract default as its floor of meaning. */
function declaredLimitOf(state) {
  return typeof state.declaredLimit === 'number' ? state.declaredLimit : GLOBAL_OPTIONAL_CONCURRENCY_DEFAULT;
}

/** Read-only current block reason (no dispatch, no state change): the
 *  production rule holding admission RIGHT NOW, for per-poll evidence. */
function currentBlockReason(state, time, { offline }) {
  if (offline) return 'networkUnavailable'; // eligibility.ts gate precedes the scheduler
  return scheduleNext(state, time).reason;
}

// ---------------------------------------------------------------------------
// Optional-work pool: the single-process admission engine. Admission runs
// through the mirrored scheduler; failed settlements route through the
// coordinator's release paths (retryable → backoff envelope; terminal
// failure → dropped; success → complete).
// ---------------------------------------------------------------------------

class OptionalWorkPool {
  constructor({ windowId, limit, routes, classMix, accounts, totalJobs, jobIntervalMs, bearer, proxyBase, attributionHeader, requestTimeoutMs }) {
    this.windowId = windowId;
    this.limit = limit;
    this.expandedRoutes = expandWeighted(routes, routes.map((route) => route.weight));
    this.classCycle = expandWeighted(OPTIONAL_WORK_CLASSES, classMix);
    this.accounts = Array.from({ length: accounts }, (unused, index) => `e6i-acct-${index}`);
    this.totalJobs = totalJobs; // 0 = continuous refill for the whole window
    this.jobIntervalMs = jobIntervalMs;
    this.bearer = bearer;
    this.proxyBase = proxyBase;
    this.attributionHeader = attributionHeader;
    this.requestTimeoutMs = requestTimeoutMs;
    this.state = createSchedulerState();
    this.state.declaredLimit = limit;
    this.admitting = false;
    this.started = false;
    this.offline = false; // workOffline run-analog (eligibility.ts) — see header
    this.seq = 0;
    this.issued = 0;
    this.admittedTotal = 0;
    this.outcomes = { completed: 0, failed: 0, timedOut: 0, networkDrop: 0 };
    this.inflight = new Set();
  }

  start() {
    this.started = true;
    this.admitting = true;
    this.stockQueue();
    this.pump();
    // The coordinator ticks continuously; the instrument's admission pump
    // must too — settle-driven pumping alone never re-ticks when a backoff
    // envelope comes due during a quiet outage lull (the recovery probe
    // would never fire). Single-process: one interval, no workers.
    this.ticker = setInterval(() => {
      if (this.admitting) this.pump();
    }, 25);
  }

  stopAdmitting() {
    this.admitting = false;
    if (this.ticker !== undefined) {
      clearInterval(this.ticker);
      this.ticker = undefined;
    }
    return isoUtcNow();
  }

  /** Keep the pending population at the declared depth while admission is
   *  open: continuous queued optional work at the declared concurrency
   *  limit (§2.1.1). FRESH admission is eligibility-gated on the offline
   *  analog (eligibility.ts blocks new work while workOffline); recovery
   *  from an outage rides the engine's own retry path — a starved queue
   *  ('empty') is an unexplained shortfall and refutes, so the declaration
   *  must size the population. */
  stockQueue() {
    if (this.offline) return;
    while (this.admitting) {
      const pending = this.state.queued.length + this.state.running.length;
      if (pending >= this.limit) break;
      if (this.totalJobs > 0 && this.admittedTotal >= this.totalJobs) break;
      this.enqueueJob();
    }
  }

  enqueueJob() {
    this.seq += 1;
    this.admittedTotal += 1;
    const job = {
      jobId: `e6i-${this.windowId}-${this.seq}`,
      accountId: this.accounts[(this.seq - 1) % this.accounts.length],
      workClass: this.classCycle[(this.seq - 1) % this.classCycle.length],
      state: 'queued',
      attempts: 0,
    };
    const item = {
      job,
      queuedAtUtcMs: Date.now(),
      work: { kind: 'metadata', records: 1 },
      retryAtUtcMs: null,
      sequence: this.state.nextSequence,
    };
    this.state = {
      ...this.state,
      queued: [...this.state.queued, item],
      nextSequence: this.state.nextSequence + 1,
    };
  }

  /** Admission tick: dispatch every unit the scheduler admits this instant.
   *  The scheduler's own backoff gate (isReady/retryAtUtcMs) paces retries;
   *  a due retry dispatches even while the offline analog holds — each due
   *  retry IS the recovery probe (its failure re-envelops per
   *  retryCeilingMs; its success flips the path back up). */
  pump() {
    let guard = 0;
    while (guard < 64) {
      guard += 1;
      this.stockQueue();
      const time = { nowUtcMs: Date.now(), nowMonoMs: performance.now() };
      const decision = scheduleNext(this.state, time);
      if (decision.reason !== 'scheduled') break;
      this.state = decision.state;
      void this.fireJob(decision.dispatch);
    }
  }

  async fireJob(dispatch) {
    const seq = Number(dispatch.job.jobId.split('-').pop());
    this.inflight.add(seq);
    this.issued += 1;
    const route = this.expandedRoutes[(seq - 1) % this.expandedRoutes.length];
    const urlPath = route.path.replace(/\$\{seq\}/g, String(seq));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    let outcome;
    try {
      const headers = {
        authorization: `Bearer ${this.bearer}`,
        'x-e6-proxy-source': ATTRIBUTION_TOKEN,
      };
      if (route.body !== null) headers['content-type'] = 'application/json';
      const response = await fetch(`${this.proxyBase}${urlPath}`, {
        method: route.method,
        headers,
        body: route.body === null ? undefined : route.body.replace(/\$\{seq\}/g, String(seq)),
        signal: controller.signal,
        redirect: 'error',
      });
      await response.arrayBuffer();
      outcome = response.ok ? 'completed' : 'failed';
    } catch (error) {
      outcome = classifyError(error);
    } finally {
      clearTimeout(timer);
    }
    this.settle(dispatch, outcome, seq);
  }

  /** coordinator.ts release paths: success completes; a retryable network
   *  failure requeues with the full-jitter backoff envelope; a terminal
   *  HTTP failure does not requeue. The offline analog flips on the LAST
   *  settlement's network class and recovers on the next success. */
  settle(dispatch, outcome, seq) {
    this.outcomes[outcome] += 1;
    this.inflight.delete(seq);
    this.state = { ...this.state, running: this.state.running.filter((item) => item.job.jobId !== dispatch.job.jobId) };
    if (outcome === 'completed') {
      this.offline = false;
    } else if (outcome === 'networkDrop' || outcome === 'timedOut') {
      // Retryable (coordinator.ts:525-531): release with the backoff
      // envelope; the population-seeded full-jitter draw keeps this
      // replay-stable and population-local.
      const random = rngFromSeed(`backoff:${this.windowId}:${seq}`);
      const delay = retryDelayMs(dispatch.job.attempts, random);
      const backoffItem = {
        ...dispatch,
        job: { ...dispatch.job, state: 'backoff', attempts: dispatch.job.attempts + 1 },
        retryAtUtcMs: Date.now() + delay,
      };
      this.state = { ...this.state, queued: [...this.state.queued, backoffItem] };
      this.offline = true;
    }
    // outcome === 'failed' (terminal HTTP failure): not requeued.
    if (this.admitting) this.pump();
  }

  /** The observed counters + the production holds active RIGHT NOW — the
   *  per-poll truth (same field names as §2.4, extended with holds). */
  snapshot() {
    const nowUtcMs = Date.now();
    const time = { nowUtcMs, nowMonoMs: performance.now() };
    const running = this.state.running.length;
    const blockReason = currentBlockReason(this.state, time, { offline: this.offline });
    const holdReasons = [];
    if (this.offline) holdReasons.push('networkUnavailable');
    if (running < this.limit && blockReason !== 'scheduled' && blockReason !== 'empty' && blockReason !== 'globalSaturation') {
      holdReasons.push(blockReason);
    }
    return {
      basis: INSTRUMENT_BASIS,
      optionalRunning: running,
      optionalQueued: this.state.queued.length,
      observedAtUtc: new Date(nowUtcMs).toISOString(),
      holdReasons,
      lastBlockReason: blockReason,
      lastSettlementOutcome: this.lastOutcome ?? null,
    };
  }

  async drain(deadlineMs) {
    const deadline = Date.now() + deadlineMs;
    while (this.inflight.size > 0 && Date.now() < deadline) {
      await sleep(25);
    }
    return { inflightAtExit: this.inflight.size, breached: this.inflight.size > 0 };
  }
}

function classifyError(error) {
  const name = error?.name ?? '';
  if (name === 'TimeoutError' || name === 'AbortError') return 'timedOut';
  return 'networkDrop';
}

// ---------------------------------------------------------------------------
// Declared-level saturation proof (§2.4 AS AMENDED) — pure threshold logic.
// ---------------------------------------------------------------------------

const FRESHNESS_POLL_MULTIPLIER = 2;

/** Evaluate ONE poll against the amended engaged threshold. `observation`
 *  carries the raw counters + active production holds; `null` observation is
 *  a REFUTING sample (a missing poll is never a gap). Engaged iff basis
 *  recognized, counters well-formed, observation fresh, AND (running >=
 *  limit OR a production hold is active). */
function evaluatePoll(observation, { limit, pollIntervalMs, nowUtcMs, phase }) {
  if (observation === null || typeof observation !== 'object') {
    return {
      basis: null,
      optionalRunning: null,
      optionalQueued: null,
      limit,
      observedAtUtc: null,
      saturating: false,
      engaged: false,
      engagedReason: null,
      holdReasons: [],
      refutingReasons: ['unreachable'],
      observedAgeMs: null,
      phase,
      pollAtUtc: new Date(nowUtcMs).toISOString(),
    };
  }
  const refutingReasons = [];
  const basis = typeof observation.basis === 'string' ? observation.basis : null;
  const running = observation.optionalRunning;
  const queued = observation.optionalQueued;
  const holdReasons = Array.isArray(observation.holdReasons)
    ? observation.holdReasons.filter((reason) => HOLD_REASONS.includes(reason))
    : null;

  // (1) Observed basis: only the instrument's own counter basis verifies.
  // The declaration-answered execute fallback (`policy-mode-configured`,
  // saturation.ts:295-301) and every other client basis are REFUTING.
  if (basis !== INSTRUMENT_BASIS) refutingReasons.push('fallback-basis');

  // Counters must be well-formed for ANY verdict to verify.
  if (!Number.isInteger(running) || running < 0 || !Number.isInteger(queued) || queued < 0 || holdReasons === null) {
    refutingReasons.push('malformed-poll');
  }

  // (2+AMENDED) Declared level OR production hold. An unexplained
  // below-limit shortfall refutes (`below-limit`); a hold-names reason
  // engages (`held:<rule>`); running at the limit engages (`at-limit`).
  let engagedReason = null;
  if (refutingReasons.length === 0) {
    if (running >= limit) {
      engagedReason = 'at-limit';
    } else if (holdReasons.length > 0) {
      engagedReason = `held:${holdReasons[0]}`;
    } else {
      refutingReasons.push('below-limit');
    }
  }

  // (3) Freshness within 2 poll intervals, observation stamp to sample time.
  let observedAgeMs = null;
  const observedMs = Date.parse(typeof observation.observedAtUtc === 'string' ? observation.observedAtUtc : '');
  if (!Number.isFinite(observedMs)) {
    refutingReasons.push('stale-observation');
  } else {
    observedAgeMs = nowUtcMs - observedMs;
    if (observedAgeMs < 0 || observedAgeMs > FRESHNESS_POLL_MULTIPLIER * pollIntervalMs) {
      refutingReasons.push('stale-observation');
    }
  }

  const engaged = refutingReasons.length === 0;
  return {
    basis,
    optionalRunning: running,
    optionalQueued: queued,
    limit,
    observedAtUtc: typeof observation.observedAtUtc === 'string' ? observation.observedAtUtc : null,
    saturating: engaged,
    engaged,
    engagedReason: engaged ? engagedReason : null,
    holdReasons: holdReasons ?? [],
    refutingReasons,
    observedAgeMs,
    phase,
    pollAtUtc: new Date(nowUtcMs).toISOString(),
  };
}

/** Aggregate the window's proof (§2.4 "Where the proof is recorded", as
 *  amended). Only measurement-window samples gate; warmup samples are
 *  retained. An interrupted or unopened measurement window is `unverified`,
 *  never silently verified. */
function computeProof(samples, { limit, measurementCompleted }) {
  const measurement = samples.filter((sample) => sample.phase === 'measurement');
  const warmup = samples.filter((sample) => sample.phase === 'warmup');
  const engagingSamples = measurement.filter((sample) => sample.engaged).length;
  const refutingSamples = measurement.length - engagingSamples;
  const refutingReasons = [...new Set(measurement.flatMap((sample) => sample.refutingReasons))];
  const warmupRefutingSamples = warmup.filter((sample) => !sample.engaged).length;
  const engagedReasonBreakdown = {};
  for (const sample of measurement) {
    if (sample.engaged && sample.engagedReason !== null) {
      engagedReasonBreakdown[sample.engagedReason] = (engagedReasonBreakdown[sample.engagedReason] ?? 0) + 1;
    }
  }
  const minRunningObserved = measurement.length === 0
    ? null
    : measurement.reduce((min, sample) => (sample.optionalRunning === null ? min : (min === null ? sample.optionalRunning : Math.min(min, sample.optionalRunning))), null);
  let proof;
  if (!measurementCompleted || measurement.length === 0) proof = 'unverified';
  else if (refutingSamples === 0) proof = 'declared-level-verified';
  else proof = 'refuted';
  return {
    basis: INSTRUMENT_BASIS,
    samples: samples.length,
    measurementSamples: measurement.length,
    warmupSamples: warmup.length,
    engagingSamples,
    refutingSamples,
    warmupRefutingSamples,
    refutingReasons,
    engagedReasonBreakdown,
    minRunningObserved,
    limit,
    proof,
    engagedRatio: measurement.length === 0 ? 0 : engagingSamples / measurement.length,
  };
}

/** The {type:'saturation'} event shape (§2.4 extension of the driver's). */
function saturationEvent(proof, { started }) {
  return {
    type: 'saturation',
    active: started,
    activeDuringMeasurement: proof.proof === 'declared-level-verified',
    ...proof,
  };
}

// ---------------------------------------------------------------------------
// Status surface: the harness instrument endpoint (§2.3.1 check 8 applies
// check 2 to this port; §3.1 names it the comparator window's saturation
// surface). Answers the §2.4 field names plus the amended verdict fields
// with this instrument's counter basis — never a client basis.
// ---------------------------------------------------------------------------

function startStatusServer({ statusListen, windowId, limit, snapshot }) {
  const [host, portText] = String(statusListen).split(':');
  const listenHost = host || '127.0.0.1';
  const listenPort = Number(portText || 0);
  const server = http.createServer((request, response) => {
    const urlPath = (request.url ?? '').split('?')[0];
    if (urlPath !== STATUS_PATH) {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'not-found' }));
      return;
    }
    if (request.method !== 'GET') {
      response.writeHead(405, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'method-not-allowed' }));
      return;
    }
    const state = snapshot();
    response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify({
      saturating: state.engaged,
      basis: INSTRUMENT_BASIS,
      windowId,
      limit,
      optionalRunning: state.optionalRunning,
      optionalQueued: state.optionalQueued,
      observedAtUtc: state.observedAtUtc,
      engagedReason: state.engagedReason,
      holdReasons: state.holdReasons,
    }));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, listenHost, () => {
      const address = server.address();
      resolve({ server, url: `http://${listenHost}:${address.port}${STATUS_PATH}` });
    });
  });
}

// ---------------------------------------------------------------------------
// Receipt: the summary fragment the scheme names. Bearer material NEVER
// enters any field here — the self-test pins that.
// ---------------------------------------------------------------------------

function buildReceipt({ config, identity, routes, startedAtUtc, endedAtUtc, samples, proof, drain, attribution, population, interrupted, statusUrl, exitPlan }) {
  return {
    kind: 'e6-saturation-instrument-receipt',
    schemaVersion: 1,
    windowId: config.windowId,
    scope: SCOPE,
    instrument: identity,
    startedAtUtc,
    endedAtUtc,
    basis: INSTRUMENT_BASIS,
    delivery: {
      gatewayOrigin: config.gatewayOrigin,
      proxyBase: config.proxyBase,
      attribution: { header: config.attributionHeader, token: ATTRIBUTION_TOKEN },
      statusUrl,
    },
    workloadDeclarationEcho: {
      limit: config.limit,
      routes,
      accounts: config.accounts,
      classMix: config.classMix,
      totalJobs: config.totalJobs,
      jobIntervalMs: config.jobIntervalMs,
      pollIntervalMs: config.intervalMs,
      warmupMs: config.warmupMs,
      measurementMs: config.measurementMs,
    },
    proof,
    // Engaged verdict per poll: the samples array IS the per-poll record
    // (§2.4 sample shape + engagedReason + holds + refuting reasons + phase).
    samples,
    engagedRatioFinal: proof.engagedRatio,
    drain,
    proxyAttribution: attribution,
    // Per-population sequence basis (opus HOLD item 4): the instrument
    // performs NO injection draws; the proxy's per-population loss keys on
    // this basis token with THIS population's per-job sequence numbers.
    population,
    interrupted,
    exitPlan,
  };
}

function writeWindowFiles({ config, samples, receipt }) {
  fs.mkdirSync(config.outDir, { recursive: true });
  const samplesFile = path.join(config.outDir, `e6-saturation-instrument-${config.windowId}-samples.json`);
  const receiptFile = path.join(config.outDir, `e6-saturation-instrument-${config.windowId}-receipt.json`);
  const samplesDocument = {
    kind: 'e6-saturation-instrument-samples',
    schemaVersion: 1,
    windowId: config.windowId,
    basis: INSTRUMENT_BASIS,
    limit: config.limit,
    pollIntervalMs: config.intervalMs,
    writtenAtUtc: isoUtcNow(),
    samples,
  };
  fs.writeFileSync(samplesFile, `${JSON.stringify(samplesDocument, null, 2)}\n`);
  fs.writeFileSync(receiptFile, `${JSON.stringify(receipt, null, 2)}\n`);
  return { samplesFile, receiptFile };
}

// ---------------------------------------------------------------------------
// Contract mode: one window, launch → warmup → measurement → ordered drain.
// ---------------------------------------------------------------------------

async function runContract(rawArgs) {
  const config = validateConfig(rawArgs);
  const bearer = loadSessionBearer(config.sessionFile);
  const routes = parseRoutes(rawArgs.routesJson);
  const selfPath = new URL(import.meta.url).pathname;
  const identity = {
    entrypoint: ENTRYPOINT_REL,
    sourceSha256: sha256File(selfPath),
    command: 'node',
    args: process.argv.slice(2),
    pid: process.pid,
    scope: SCOPE,
  };

  const startedAtUtc = isoUtcNow();
  emit({ type: 'instrument', ...identity, windowId: config.windowId, basis: INSTRUMENT_BASIS, limit: config.limit });

  const pool = new OptionalWorkPool({
    windowId: config.windowId,
    limit: config.limit,
    routes,
    classMix: config.classMix,
    accounts: config.accounts,
    totalJobs: config.totalJobs,
    jobIntervalMs: config.jobIntervalMs,
    bearer,
    proxyBase: config.proxyBase,
    attributionHeader: config.attributionHeader,
    requestTimeoutMs: config.requestTimeoutMs,
  });

  let lastSnapshot = null;
  const { server: statusServer, url: statusUrl } = await startStatusServer({
    statusListen: config.statusListen,
    windowId: config.windowId,
    limit: config.limit,
    snapshot: () => (lastSnapshot === null ? { engaged: false, ...pool.snapshot() } : { engaged: lastSnapshot.engaged, ...lastSnapshot }),
  });
  emit({ type: 'status', url: statusUrl });
  log(`export E6_INSTRUMENT_SATURATION_URL=${statusUrl}`);
  log(`window ${config.windowId}: limit=${config.limit} poll=${config.intervalMs}ms warmup=${config.warmupMs}ms measurement=${config.measurementMs}ms accounts=${config.accounts} via proxy ${config.proxyBase}`);

  // Interrupt discipline (§2.3.1 check 7): signals route through the SAME
  // ordered teardown as natural completion — stop admitting → drain →
  // close → exit. No path exits with outstanding requests.
  let interrupted = null;
  const interruptPromise = new Promise((resolve) => {
    const onSignal = (signal) => {
      if (interrupted === null) interrupted = signal;
      resolve();
    };
    process.once('SIGINT', () => onSignal('SIGINT'));
    process.once('SIGTERM', () => onSignal('SIGTERM'));
  });

  const samples = [];
  let measurementCompleted = false;
  const takePoll = (phase) => {
    lastSnapshot = pool.snapshot();
    const sample = evaluatePoll(lastSnapshot, {
      limit: config.limit,
      pollIntervalMs: config.intervalMs,
      nowUtcMs: Date.now(),
      phase,
    });
    samples.push(sample);
    emit({ type: 'saturation-sample', windowId: config.windowId, phase, sample });
    if (!sample.engaged) {
      log(`window ${config.windowId} ${phase} sample REFUTING: ${sample.refutingReasons.join(',')} (running=${sample.optionalRunning} limit=${config.limit})`);
    }
  };

  try {
    emit({ type: 'phase', phase: 'warmup' });
    pool.start();
    const warmupDeadline = Date.now() + config.warmupMs;
    while (Date.now() < warmupDeadline && interrupted === null) {
      takePoll('warmup');
      const remaining = warmupDeadline - Date.now();
      await sleep(Math.min(config.intervalMs, Math.max(remaining, 0)));
    }

    if (interrupted === null) {
      emit({ type: 'phase', phase: 'measurement' });
      const measurementDeadline = Date.now() + config.measurementMs;
      while (Date.now() < measurementDeadline && interrupted === null) {
        takePoll('measurement');
        const remaining = measurementDeadline - Date.now();
        await sleep(Math.min(config.intervalMs, Math.max(remaining, 0)));
      }
      measurementCompleted = interrupted === null;
    }
  } finally {
    // Ordered teardown (§2.3.1 check 7): (a) stop admitting NEW work;
    // (b) drain every outstanding request through the proxy's exactly-once
    // terminal accounting or the drain deadline; (c) close the status
    // surface and exit.
    const stoppedAdmissionAtUtc = pool.stopAdmitting();
    const drainStart = Date.now();
    const drain = await pool.drain(config.drainDeadlineMs);
    const drainedAtUtc = isoUtcNow();
    const drainBlock = {
      stoppedAdmissionAtUtc,
      drainedAtUtc,
      drainDeadlineMs: config.drainDeadlineMs,
      drainWallMs: Date.now() - drainStart,
      inflightAtExit: drain.inflightAtExit,
      breached: drain.breached,
    };
    emit({ type: 'drain', ...drainBlock });

    const proof = computeProof(samples, { limit: config.limit, measurementCompleted });
    emit(saturationEvent(proof, { started: pool.started && pool.issued > 0 }));

    const attribution = {
      issued: pool.issued,
      admittedTotal: pool.admittedTotal,
      ...pool.outcomes,
      inflightAtExit: drain.inflightAtExit,
    };
    const population = {
      basisToken: ATTRIBUTION_TOKEN,
      firstSeq: pool.issued > 0 ? 1 : null,
      lastSeq: pool.issued > 0 ? pool.issued : null,
      issued: pool.issued,
      injectionDraws: 0,
      randomness: `backoff:${config.windowId}:<seq> (full-jitter only, population-local)`,
    };
    const exitPlan = proof.proof === 'declared-level-verified' && interrupted === null
      ? 'verified'
      : proof.proof === 'refuted'
        ? 'refuted'
        : interrupted !== null
          ? 'unverified-interrupted'
          : 'unverified';

    let files = { samplesFile: null, receiptFile: null };
    let writeError = null;
    try {
      const receipt = buildReceipt({
        config,
        identity,
        routes,
        startedAtUtc,
        endedAtUtc: isoUtcNow(),
        samples,
        proof,
        drain: drainBlock,
        attribution,
        population,
        interrupted,
        statusUrl,
        exitPlan,
      });
      files = writeWindowFiles({ config, samples, receipt });
    } catch (error) {
      writeError = error;
    }
    emit({ type: 'done', windowId: config.windowId, samplesFile: files.samplesFile, receiptFile: files.receiptFile, exitPlan });
    statusServer.close();
    if (writeError !== null) {
      fail('RECEIPT', `writing window evidence failed: ${writeError.message}`);
    }
    if (drain.breached) {
      fail('DRAIN', `drain deadline (${config.drainDeadlineMs}ms) breached with inflightAtExit=${drain.inflightAtExit}; quiescence check 7 fails the transition closed`);
    }
    if (interrupted === 'SIGINT') process.exitCode = 130;
    else if (interrupted === 'SIGTERM') process.exitCode = 143;
    else if (exitPlan === 'refuted') process.exitCode = 3;
    else if (exitPlan !== 'verified') process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Self-test: offline validation of the sample schema, the amended threshold
// logic over synthetic polls, the below-limit refuting fixture, the
// outage-never-refutes fixture, the mirrored scheduler/backoff shapes, usage
// refusals, and receipt bearer hygiene. No network, no writes.
// ---------------------------------------------------------------------------

async function runSelfTest() {
  let failed = 0;
  let passed = 0;
  const check = (label, ok) => {
    if (ok) {
      passed += 1;
      log(`ok - ${label}`);
    } else {
      failed += 1;
      log(`NOT OK - ${label}`);
    }
  };
  const expectUsageRefusal = (label, fn) => {
    try {
      fn();
      check(label, false);
    } catch (error) {
      check(label, error.e6Tag === 'USAGE');
    }
  };
  const expectTagRefusal = (label, tag, fn) => {
    try {
      fn();
      check(label, false);
    } catch (error) {
      check(label, error.e6Tag === tag);
    }
  };

  const NOW = Date.parse('2026-09-23T12:00:00.000Z');
  const synth = (overrides, nowUtcMs = NOW, { limit = 2, intervalMs = 1000, phase = 'measurement' } = {}) =>
    evaluatePoll({ basis: INSTRUMENT_BASIS, optionalQueued: 2, observedAtUtc: new Date(nowUtcMs - 100).toISOString(), holdReasons: [], ...overrides }, { limit, pollIntervalMs: intervalMs, nowUtcMs, phase });

  // Basis discipline (§2.1.3): the instrument basis differs from EVERY
  // client basis — consumption can never read instrument workload as
  // observed engine queue state.
  check('instrument basis differs from every client basis', CLIENT_BASES.every((basis) => basis !== INSTRUMENT_BASIS));
  check('instrument basis is the comparator observed basis', INSTRUMENT_BASIS === 'harness-saturation-instrument');

  // Engaging sample (amended rule, at-limit arm).
  const engaging = synth({ optionalRunning: 2 });
  check('at-limit sample engages with at-limit reason', engaging.engaged === true && engaging.engagedReason === 'at-limit' && engaging.saturating === true);
  check('sample carries the §2.4 field names', ['basis', 'optionalRunning', 'optionalQueued', 'limit', 'observedAtUtc', 'saturating'].every((key) => key in engaging));
  check('freshness boundary: exactly 2 poll intervals is fresh', synth({ optionalRunning: 2, observedAtUtc: new Date(NOW - 2000).toISOString() }, NOW).engaged === true);
  check('freshness: 1ms past 2 poll intervals is stale', synth({ optionalRunning: 2, observedAtUtc: new Date(NOW - 2001).toISOString() }, NOW).refutingReasons.includes('stale-observation'));
  check('freshness: future stamp refuses', synth({ optionalRunning: 2, observedAtUtc: new Date(NOW + 1).toISOString() }, NOW).refutingReasons.includes('stale-observation'));

  // REFUTING CLASS: execute-mode fallback (saturation.ts:295-301 shape) — a
  // declaration-answered poll is never a verifying one, even at-limit.
  const fallback = synth({ basis: 'policy-mode-configured', optionalRunning: 2 });
  check('execute-mode fallback basis refutes even at limit', !fallback.engaged && fallback.refutingReasons.includes('fallback-basis'));
  check('mode-admits-no-optional-work basis refutes', !synth({ basis: 'mode-admits-no-optional-work', optionalRunning: 2 }).engaged);
  check('client engine basis refutes in the comparator window', !synth({ basis: 'engine-queue-observed', optionalRunning: 2 }).engaged);
  check('missing basis refutes', !synth({ basis: undefined, optionalRunning: 2 }).engaged);

  // AMENDED RULE: production holds engage below-limit samples with a reason.
  for (const hold of HOLD_REASONS) {
    const held = synth({ optionalRunning: hold === 'accountSaturation' || hold === 'networkUnavailable' ? 0 : 1, holdReasons: [hold] });
    check(`hold ${hold} engages below-limit with held reason`, held.engaged === true && held.engagedReason === `held:${hold}` && held.refutingReasons.length === 0);
  }
  check('hold reasons outside the production taxonomy do not engage', !synth({ optionalRunning: 1, holdReasons: ['operator-on-vacation'] }).engaged);

  // REFUTING CLASS FIXTURE: unexplained below-limit load — a full series
  // below the limit with NO production hold is REFUSED (§2.4 item 2 as
  // amended: the shortfall must be a production rule, never silence).
  const belowLimitSeries = [0, 1, 2, 3, 4].map((index) =>
    synth({ optionalRunning: 1, optionalQueued: 1, observedAtUtc: new Date(NOW + index * 1000 - 100).toISOString(), holdReasons: [] }, NOW + index * 1000));
  const belowLimitProof = computeProof(belowLimitSeries, { limit: 2, measurementCompleted: true });
  check('unexplained below-limit series is refused (proof refuted)', belowLimitProof.proof === 'refuted');
  check('unexplained below-limit series names below-limit as the reason', belowLimitProof.refutingReasons.includes('below-limit'));
  check('unexplained below-limit series engaged ratio is 0', belowLimitProof.engagedRatio === 0);
  check('unexplained below-limit series minRunningObserved is limit-1', belowLimitProof.minRunningObserved === 1);

  // AMENDED FIXTURE (opus HOLD item 3): outage alone NEVER refutes — the
  // engine's retryable-failure backoff plus the offline eligibility gate
  // hold the population, and every sample stays engaged-with-reason.
  const outageSeries = [0, 1, 2, 3, 4].map((index) => {
    const running = index === 0 ? 2 : index === 1 ? 1 : 0; // drain-down under outage
    const holds = index === 0 ? [] : index === 1 ? ['networkUnavailable', 'backoff'] : ['networkUnavailable', 'backoff'];
    return synth({ optionalRunning: running, optionalQueued: 2, holdReasons: holds }, NOW + index * 1000);
  });
  const outageProof = computeProof(outageSeries, { limit: 2, measurementCompleted: true });
  check('outage alone never refutes: proof stays verified', outageProof.proof === 'declared-level-verified' && outageProof.engagedRatio === 1);
  check('outage samples carry held reason codes', outageSeries.slice(1).every((sample) => sample.engagedReason === 'held:networkUnavailable' || sample.engagedReason === 'held:backoff'));
  check('outage series records zero refuting samples', outageProof.refutingSamples === 0);
  check('outage series breakdown separates at-limit from held', outageProof.engagedReasonBreakdown['at-limit'] === 1 && (outageProof.engagedReasonBreakdown['held:networkUnavailable'] ?? 0) + (outageProof.engagedReasonBreakdown['held:backoff'] ?? 0) === 4);

  const passingSeries = [0, 1, 2, 3, 4].map((index) =>
    synth({ optionalRunning: 2, optionalQueued: 2, observedAtUtc: new Date(NOW + index * 1000 - 100).toISOString() }, NOW + index * 1000));
  const passingProof = computeProof(passingSeries, { limit: 2, measurementCompleted: true });
  check('all-at-limit series verifies at declared level', passingProof.proof === 'declared-level-verified' && passingProof.engagedRatio === 1);
  check('verified series keeps minRunningObserved at the limit', passingProof.minRunningObserved === 2);

  // REFUTING CLASS: missing/unreachable/malformed polls.
  const unreachable = evaluatePoll(null, { limit: 2, pollIntervalMs: 1000, nowUtcMs: NOW, phase: 'measurement' });
  check('unreachable poll is a refuting sample', !unreachable.engaged && unreachable.refutingReasons.includes('unreachable'));
  check('malformed running counter refutes', !synth({ optionalRunning: '2' }).engaged);
  check('malformed hold list refutes', !synth({ optionalRunning: 2, holdReasons: 'networkUnavailable' }).engaged);
  check('malformed observedAtUtc refutes as stale', synth({ optionalRunning: 2, observedAtUtc: 'not-a-timestamp' }).refutingReasons.includes('stale-observation'));

  // Phase gating (§2.4): warmup samples are retained but only measurement
  // samples gate; an interrupted/unopened measurement window is unverified.
  const warmupOnly = [synth({ optionalRunning: 1 }, NOW, { phase: 'warmup' })];
  check('warmup refutations do not alone flip the proof', computeProof(warmupOnly, { limit: 2, measurementCompleted: false }).proof === 'unverified');
  const mixedProof = computeProof([passingSeries[0], belowLimitSeries[0]], { limit: 2, measurementCompleted: true });
  check('one refuting measurement sample refutes the whole proof', mixedProof.proof === 'refuted' && mixedProof.refutingSamples === 1);
  check('no measurement samples is unverified, never verified', computeProof([], { limit: 2, measurementCompleted: true }).proof === 'unverified');

  // Saturation event shape (§2.4 extension).
  const event = saturationEvent(passingProof, { started: true });
  check('saturation event carries the §2.4 proof fields', ['basis', 'samples', 'engagingSamples', 'refutingSamples', 'refutingReasons', 'minRunningObserved', 'limit', 'proof'].every((key) => key in event));
  check('saturation event activeDuringMeasurement tracks the proof', event.activeDuringMeasurement === true && event.active === true);

  // Mirrored scheduler shapes (scheduler.ts transcription).
  {
    const time = { nowUtcMs: NOW, nowMonoMs: 0 };
    const item = (jobId, workClass, accountId, overrides = {}) => ({
      job: { jobId, workClass, accountId, state: 'queued', attempts: 0, ...overrides.job },
      queuedAtUtcMs: NOW - 1000,
      work: { kind: 'metadata', records: 1 },
      retryAtUtcMs: overrides.retryAtUtcMs ?? null,
      sequence: overrides.sequence ?? 0,
    });
    const twoAccounts = createSchedulerState();
    twoAccounts.declaredLimit = 2;
    twoAccounts.queued = [item('j1', 'background', 'a'), item('j2', 'background', 'b')];
    twoAccounts.nextSequence = 2;
    const first = scheduleNext(twoAccounts, time);
    check('scheduler dispatches across accounts', first.reason === 'scheduled' && first.dispatch.job.accountId === 'a');
    check('dispatch moves the job out of queued and into running', first.state.queued.length === 1 && first.state.running.length === 1);
    const second = scheduleNext(first.state, time);
    check('per-account limit 1 forces the second account', second.reason === 'scheduled' && second.dispatch.job.accountId === 'b');
    const third = scheduleNext(second.state, time);
    check('global saturation blocks at the declared limit', third.reason === 'globalSaturation' && third.dispatch === null);

    const singleAccount = createSchedulerState();
    singleAccount.declaredLimit = 2;
    singleAccount.queued = [item('k1', 'background', 'a'), item('k2', 'background', 'a')];
    const blocked = scheduleNext({ ...singleAccount, running: [{ ...item('k0', 'background', 'a'), job: { ...item('k0', 'background', 'a').job, state: 'running' } }] }, time);
    check('account saturation is a production hold for one account', blocked.reason === 'accountSaturation');

    const backoffState = createSchedulerState();
    backoffState.declaredLimit = 2;
    backoffState.queued = [item('b1', 'background', 'a', { job: { state: 'backoff' }, retryAtUtcMs: NOW + 60_000 })];
    check('pending backoff envelope blocks as backoff', scheduleNext(backoffState, time).reason === 'backoff');
    const dueBackoff = createSchedulerState();
    dueBackoff.declaredLimit = 2;
    dueBackoff.queued = [item('b2', 'background', 'a', { job: { state: 'backoff' }, retryAtUtcMs: NOW - 1 })];
    check('due backoff re-dispatches', scheduleNext(dueBackoff, time).reason === 'scheduled');

    const criticalState = createSchedulerState({ criticalActivity: 1 });
    criticalState.declaredLimit = 2;
    criticalState.queued = [item('c1', 'background', 'a')];
    check('critical activity blocks admission', scheduleNext(criticalState, time).reason === 'criticalActivity');
    const quietState = createSchedulerState({ criticalQuietSinceMonoMs: -1000 });
    quietState.declaredLimit = 2;
    quietState.queued = [item('c2', 'background', 'a')];
    check('critical quiet resumes only after CRITICAL_QUIET_RESUME_MS', scheduleNext(quietState, { nowUtcMs: NOW, nowMonoMs: 1000 }).reason === 'criticalQuiet'
      && scheduleNext(quietState, { nowUtcMs: NOW, nowMonoMs: CRITICAL_QUIET_RESUME_MS + 1 }).reason === 'scheduled');

    const emptyState = createSchedulerState();
    emptyState.declaredLimit = 2;
    check('starved queue blocks as empty (not a hold)', scheduleNext(emptyState, time).reason === 'empty');
    const offlineHold = currentBlockReason(createSchedulerState(), time, { offline: true });
    check('offline gate reports networkUnavailable ahead of the scheduler', offlineHold === 'networkUnavailable');
  }

  // Mirrored backoff shapes (scheduler.ts:638-659).
  check('retry ceiling starts at RETRY_INITIAL_DELAY_MS', retryCeilingMs(0) === 1000);
  check('retry ceiling doubles per attempt', retryCeilingMs(1) === 2000 && retryCeilingMs(2) === 4000 && retryCeilingMs(10) === 300000);
  check('retry ceiling caps at RETRY_MAX_DELAY_MS', retryCeilingMs(40) === RETRY_MAX_DELAY_MS);
  {
    const rng = rngFromSeed('backoff:w:1');
    const samples10 = Array.from({ length: 10 }, () => retryDelayMs(3, rng));
    check('full jitter stays within [0, ceiling]', samples10.every((delay) => delay >= 0 && delay <= retryCeilingMs(3)));
    const rngA = rngFromSeed('backoff:w:7');
    const rngB = rngFromSeed('backoff:w:7');
    check('backoff draw is deterministic per population+sequence', retryDelayMs(2, rngA) === retryDelayMs(2, rngB));
    check('different sequences draw differently', retryDelayMs(2, rngFromSeed('backoff:w:7')) !== undefined);
  }

  // Usage refusals (pure validation, no side effects).
  expectUsageRefusal('non-loopback gateway origin refuses', () => validateConfig({ ...baseCliArgs(), gatewayOrigin: 'http://example.test:8080' }));
  expectUsageRefusal('https gateway origin refuses', () => validateConfig({ ...baseCliArgs(), gatewayOrigin: 'https://127.0.0.1:8080' }));
  expectUsageRefusal('non-loopback proxy listen refuses', () => validateConfig({ ...baseCliArgs(), proxyListen: 'http://10.0.0.1:9' }));
  expectUsageRefusal('missing proxy listen refuses', () => validateConfig({ ...baseCliArgs(), proxyListen: null }));
  expectUsageRefusal('limit 0 refuses', () => validateConfig({ ...baseCliArgs(), limit: '0' }));
  expectUsageRefusal('limit 2.5 refuses', () => validateConfig({ ...baseCliArgs(), limit: '2.5' }));
  expectUsageRefusal('interval below 100ms refuses', () => validateConfig({ ...baseCliArgs(), intervalMs: '99' }));
  expectUsageRefusal('measurement shorter than one poll refuses', () => validateConfig({ ...baseCliArgs(), measurementMs: '50' }));
  expectUsageRefusal('accounts 0 refuses', () => validateConfig({ ...baseCliArgs(), accounts: '0' }));
  expectUsageRefusal('two-part class mix refuses', () => validateConfig({ ...baseCliArgs(), classMix: '1:1' }));
  expectUsageRefusal('zero class weight refuses', () => validateConfig({ ...baseCliArgs(), classMix: '0:1:1' }));
  expectUsageRefusal('missing window id refuses', () => validateConfig({ ...baseCliArgs(), windowId: null }));
  expectUsageRefusal('window id path traversal refuses', () => validateWindowId('../escape'));
  expectUsageRefusal('window id with slash refuses', () => validateWindowId('a/b'));
  expectUsageRefusal('window id empty refuses', () => validateWindowId(''));
  check('window id with dots/dashes/underscore accepts', validateWindowId('e6pair-20260923t000000z-a_1') === 'e6pair-20260923t000000z-a_1');
  expectUsageRefusal('absolute route path refuses (proxy bypass)', () => parseRoutes(JSON.stringify([{ method: 'GET', path: 'http://127.0.0.1:1/x' }])));
  expectUsageRefusal('route weight 0 refuses', () => parseRoutes(JSON.stringify([{ method: 'GET', path: '/x', weight: 0 }])));
  expectUsageRefusal('empty route array refuses', () => parseRoutes('[]'));
  expectUsageRefusal('invalid routes json refuses', () => parseRoutes('{nope'));
  check('default routes are proxy-relative', DEFAULT_ROUTES.every((route) => route.path.startsWith('/')));
  check('weighted route expansion preserves mix', expandWeighted([{ method: 'POST', path: '/a' }, { method: 'GET', path: '/b' }], [3, 1]).length === 4);
  check('class mix expands over the work-contract classes', expandWeighted(OPTIONAL_WORK_CLASSES, parseClassMix('2:1:1')).length === 4);
  check('seq token substitutes in routes', expandWeighted([{ method: 'POST', path: '/x/${seq}', weight: 1, body: null }], [1])[0].path.replace(/\$\{seq\}/g, '7') === '/x/7');

  // Session + receipt hygiene: bearer material never enters events/receipts.
  const bearer = 'super-secret-bearer-material-e6i';
  const config = validateConfig(baseCliArgs());
  const identity = { entrypoint: ENTRYPOINT_REL, sourceSha256: 'deadbeef', command: 'node', args: ['--window-id', 'w'], pid: 1, scope: SCOPE };
  const receipt = buildReceipt({
    config,
    identity,
    routes: [...DEFAULT_ROUTES],
    startedAtUtc: new Date(NOW).toISOString(),
    endedAtUtc: new Date(NOW + 1000).toISOString(),
    samples: passingSeries,
    proof: passingProof,
    drain: { stoppedAdmissionAtUtc: '', drainedAtUtc: '', drainDeadlineMs: 10000, inflightAtExit: 0, breached: false },
    attribution: { issued: 4, completed: 4, failed: 0, timedOut: 0, networkDrop: 0, admittedTotal: 4, inflightAtExit: 0 },
    population: { basisToken: ATTRIBUTION_TOKEN, firstSeq: 1, lastSeq: 4, issued: 4, injectionDraws: 0 },
    interrupted: null,
    statusUrl: 'http://127.0.0.1:0/e6/saturation-instrument/status',
    exitPlan: 'verified',
  });
  check('receipt text never contains bearer material', !JSON.stringify(receipt).includes(bearer));
  check('samples text never contains bearer material', !JSON.stringify(passingSeries).includes(bearer));
  check('receipt names scope, digest, pid, windowId', receipt.scope === SCOPE && receipt.instrument.sourceSha256 === 'deadbeef' && receipt.windowId === 'selftest-window' && Number.isInteger(receipt.instrument.pid));
  check('receipt carries the final engaged ratio', receipt.engagedRatioFinal === 1);
  check('receipt drain block carries inflightAtExit 0', receipt.drain.inflightAtExit === 0 && receipt.drain.breached === false);
  check('receipt population names the attribution basis and seq range', receipt.population.basisToken === 'instrument-request' && receipt.population.firstSeq === 1 && receipt.population.lastSeq === 4);
  check('receipt records zero injection draws', receipt.population.injectionDraws === 0);
  const refutedReceipt = buildReceipt({
    config, identity, routes: [], startedAtUtc: '', endedAtUtc: '', samples: belowLimitSeries, proof: belowLimitProof,
    drain: { stoppedAdmissionAtUtc: '', drainedAtUtc: '', drainDeadlineMs: 10000, inflightAtExit: 0, breached: false },
    attribution: {}, population: { basisToken: ATTRIBUTION_TOKEN, firstSeq: null, lastSeq: null, issued: 0, injectionDraws: 0 },
    interrupted: null, statusUrl: '', exitPlan: 'refuted',
  });
  check('refuting receipt keeps engagedRatio below 1', refutedReceipt.engagedRatioFinal === 0);

  // Session-file parsing (filesystem reads only — no network, no writes).
  const sessionMatrix = [
    ['raw token file', `${bearer}\n`],
    ['json bearer', JSON.stringify({ bearer })],
    ['json token', JSON.stringify({ token: bearer })],
    ['json accessToken', JSON.stringify({ accessToken: bearer })],
    ['json nested session', JSON.stringify({ session: { bearer } })],
  ];
  {
    const fsMod = await import('node:fs');
    const osMod = await import('node:os');
    const tmpRoot = fsMod.mkdtempSync(path.join(osMod.tmpdir(), 'e6i-selftest-'));
    try {
      for (const [label, content] of sessionMatrix) {
        const file = path.join(tmpRoot, `${label.replace(/\W+/g, '-')}.json`);
        fsMod.writeFileSync(file, content);
        check(`session material loads: ${label}`, loadSessionBearer(file) === bearer);
      }
      const emptyFile = path.join(tmpRoot, 'empty.json');
      fsMod.writeFileSync(emptyFile, '');
      expectTagRefusal('empty session file refuses', 'CREDENTIAL', () => loadSessionBearer(emptyFile));
      const junkFile = path.join(tmpRoot, 'junk.json');
      fsMod.writeFileSync(junkFile, '{not json');
      expectTagRefusal('non-json non-token session file refuses', 'CREDENTIAL', () => loadSessionBearer(junkFile));
      const noBearerFile = path.join(tmpRoot, 'nobearer.json');
      fsMod.writeFileSync(noBearerFile, JSON.stringify({ user: 'x' }));
      expectTagRefusal('session file without material refuses', 'CREDENTIAL', () => loadSessionBearer(noBearerFile));
      expectTagRefusal('missing session file refuses', 'CREDENTIAL', () => loadSessionBearer(path.join(tmpRoot, 'absent.json')));
    } finally {
      fsMod.rmSync(tmpRoot, { recursive: true, force: true });
    }
  }

  log(`self-test: ${passed} passed, ${failed} failed`);
  if (failed > 0) fail('SELFTEST', `${failed} self-test assertion(s) failed`);
  return failed === 0;
}

function baseCliArgs() {
  return {
    gatewayOrigin: 'http://127.0.0.1:8080',
    proxyListen: '127.0.0.1:9',
    sessionFile: '/dev/null',
    limit: '2',
    intervalMs: '1000',
    windowId: 'selftest-window',
    outDir: '/dev/null',
    warmupMs: '1000',
    measurementMs: '1000',
    totalJobs: '0',
    jobIntervalMs: '0',
    accounts: '2',
    classMix: '1:1:1',
    requestTimeoutMs: '1000',
    drainDeadlineMs: '1000',
    statusListen: '127.0.0.1:0',
    attributionHeader: 'x-e6-proxy-source',
  };
}

const USAGE_TEXT = `e6-saturation-instrument — E6 rerun scheme v4 comparator saturation instrument

Required:
  --gateway-origin URL     loopback http origin of the gateway target
                           (recorded + validated; NEVER fetched directly —
                           every request rides the window fault proxy)
  --proxy-listen URL|H:P   the window's run-owned fault proxy listener
  --session-file PATH      comparator member session identity (JSON
                           bearer/token/accessToken or raw token file);
                           bearer material never appears in any output
  --limit N                declared optional concurrency limit (>= 1)
  --interval-ms N          saturation poll cadence (>= 100; driver parity
                           default 1000)
  --window-id ID           window identifier (file-safe)
  --out-dir DIR            destination for run-scoped samples + receipt

Optional:
  --warmup-ms N            (120000)  --measurement-ms N   (300000)
  --total-jobs N           (0 = continuous queued population)
  --job-interval-ms N      (0)  --request-timeout-ms N (10000)
  --accounts N             (2, corpus topology) --class-mix I:B:O (1:1:1)
  --routes-json JSON|@file (default: POST /jmap Core/echo — superseded by
                           the frozen harnessInstrument declaration)
  --status-listen H:P      (127.0.0.1:0) instrument status surface
  --drain-deadline-ms N    (10000, §2.3.1 scheme default)
  --attribution-header H   (x-e6-proxy-source; token fixed instrument-request)

Engagement (§2.4 as amended): a sample engages at the declared limit
(reason at-limit) OR when a production admission/backoff rule holds the
population below it (reason held:<rule>); an unexplained shortfall refutes.
Outage alone never refutes. Modes: --self-test (offline assertions) |
-h/--help. Exit codes: 0 verified; 1 usage/machinery; 3 proof refuted;
130/143 signal after ordered drain.`;

async function main() {
  const rawArgs = parseArgs(process.argv.slice(2));
  if (rawArgs.help) {
    process.stdout.write(`${USAGE_TEXT}\n`);
    return;
  }
  if (rawArgs.selfTest) {
    const ok = await runSelfTest();
    process.exitCode = ok ? 0 : 1;
    return;
  }
  await runContract(rawArgs);
}

main().catch((error) => {
  const tag = error?.e6Tag ?? 'INTERNAL';
  log(`${tag}: ${error?.message ?? String(error)}`);
  if (!process.exitCode) process.exitCode = 1;
});
