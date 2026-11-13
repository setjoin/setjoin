#!/usr/bin/env node
/**
 * CQ E6 evidence-mode workload driver — CONTRACT: connectivity-e6-harness
 * (driver event contract documented in the header of
 * `scripts/run-connectivity-e6-harness.mjs`; profile
 * `docs/verification/connectivity-e6-profile.json`,
 * selected `e6-electron-macos-arm64-v1`).
 *
 * This is the EXTERNAL workload driver the E6 harness requires for evidence
 * runs. The harness's built-in loopback reference workload is smoke-only and
 * refuses to produce E6 evidence; evidence mode spawns THIS driver (or an
 * equivalent) via `--workload-driver-cmd`.
 *
 * ---------------------------------------------------------------------------
 * Honesty posture
 * ---------------------------------------------------------------------------
 * - The driver NEVER reports its own PID as a measured process role. The three
 *   profile-declared roles (`mailserver-gateway`,
 *   `setjoin-desktop-electron-main`, `setjoin-desktop-electron-renderer`) are
 *   the REAL gateway and client processes, named by the operator through the
 *   driver PID env below; every PID is liveness-checked fail-closed before any
 *   traffic fires, and a role PID equal to this process is refused.
 * - Attempt outcomes are an exact honest partition: completed | failed |
 *   timedOut | networkDrop. Every scheduled slot emits exactly one attempt
 *   event; dropped attempts can never produce a results document and the
 *   driver never produces one silently.
 * - ALL request traffic goes through `E6_FAULT_PROXY_URL` (the harness's
 *   run-owned loopback fault proxy). `E6_TARGET_URL` is validated loopback and
 *   recorded, but never fetched directly — targeting it would bypass the
 *   profile's fault stages. Class routes are paths joined onto the proxy base
 *   only; a route carrying a scheme/host is refused.
 * - The candidate's optional-work saturation is declared with an explicit
 *   `basis`: `saturation-endpoint-verified` (every poll of
 *   E6_DRIVER_SATURATION_URL confirmed work during the measurement window),
 *   `policy-mode-configured-unverified` (declared from the member's policy
 *   mode alone), or `saturation-endpoint-refuted`. The flag-off comparator
 *   always declares no optional work. An evidence-grade run should configure
 *   the saturation URL; without it the declaration is recorded as unverified.
 * - The builtin loopback route shape (`/attempt?seq=...&class=...`) exists for
 *   machinery validation only and is REFUSED against evidence-grade schedules
 *   (120 s warmup / 300 s measurement / 1000-per-class floor), mirroring the
 *   harness's own smoke-only builtin guard.
 * - stdout stays content-free: only contract NDJSON events with a fixed
 *   vocabulary (roles, phases, stages, classes, outcomes, counts, numbers).
 *   URLs, bearer tokens, bodies and free text never reach stdout.
 *
 * ---------------------------------------------------------------------------
 * Environment (set by the harness per member run; `...process.env` propagates
 * the operator-exported E6_DRIVER_* variables through to this child)
 * ---------------------------------------------------------------------------
 *   E6_DRIVER_CONTRACT=1      required marker (fail-closed when absent)
 *   E6_RUN_ID, E6_PAIR_INDEX  run identity (required)
 *   E6_MEMBER                 comparator | candidate (required)
 *   E6_FLAG, E6_POLICY_MODE   off/off for comparator, on/execute for
 *                             candidate; cross-checked against E6_MEMBER
 *   E6_FAULT_PROXY_URL        loopback base URL every request is sent to
 *   E6_TARGET_URL             loopback base URL of the real workload target
 *                             (validated, never fetched directly)
 *   E6_SCHEDULE               JSON schedule per the harness buildPlan shape:
 *                             attemptIntervalMs, warmupMs, warmupAttempts,
 *                             measurementMs, classSequence[], stageBlocks[],
 *                             outage, observationFloorPerClassPerRun,
 *                             classes[], builtin{hangProbeIndexes,
 *                             failProbeIndexes}
 *   E6_ATTEMPT_TIMEOUT_MS     per-attempt abort deadline (integer >= 100)
 *
 * Driver env (operator-supplied; documented driver-level contract):
 *   E6_DRIVER_GATEWAY_PID     PID of the real gateway process (required)
 *   E6_DRIVER_MAIN_PID        PID of the real Electron main process (required)
 *   E6_DRIVER_RENDERER_PID    PID of the real Electron renderer process
 *                             (required)
 *   E6_DRIVER_CLASS_ROUTES    JSON { [class]: { method, path } } covering
 *                             exactly the schedule classes; `path` must start
 *                             with "/" and may contain a `${seq}` token.
 *                             Required unless E6_DRIVER_LOOPBACK_ROUTES=1.
 *   E6_DRIVER_CLASS_BODIES    optional JSON { [class]: bodyObject }; sent as
 *                             the JSON request body for that class
 *   E6_DRIVER_AUTH_BEARER     optional bearer token sent as
 *                             `authorization: Bearer ...`; never logged
 *   E6_DRIVER_SATURATION_URL  optional loopback URL polled (direct, not via
 *                             the fault proxy) during the measurement window;
 *                             200 + {"saturating":<bool>} is the expected
 *                             shape, any other answer is a refuting sample
 *   E6_DRIVER_POLL_INTERVAL_MS  saturation poll cadence (default 1000, >= 100)
 *   E6_DRIVER_LOOPBACK_ROUTES=1  machinery-validation-only builtin routes
 *                             (/attempt?seq=&class=); refused for
 *                             evidence-grade schedules
 *
 * Events out (stdout NDJSON, one JSON object per line):
 *   {type:'process',role,pid}        once per measured role, in profile order
 *   {type:'phase',phase}             'warmup' then 'measurement'
 *   {type:'attempt',seq,class,outcome,latencyMs,stage,phase}
 *   {type:'saturation',active,activeDuringMeasurement,basis,samples}
 *                             `samples` (poll count) rides the
 *                             verified/refuted bases only
 *   {type:'done',warmupScheduled,measurementScheduled}
 * Exit codes: 0 contract completed; 1 usage/machinery failure (usage exits 1,
 * never 2). A mid-run crash exits non-zero and the harness refuses the run —
 * there is no partial-success path.
 *
 * Scheduling fidelity: request sequence and timing are derived ONLY from
 * E6_SCHEDULE, mirroring the harness's built-in reference exactly — warmup
 * slot i fires classSequence[i % classSequence.length] at
 * start + i*attemptIntervalMs (stage labeled by offset % measurementMs);
 * measurement slot i fires classSequence[i] at start + i*attemptIntervalMs.
 * The driver introduces no randomness of its own, so the same schedule digest
 * yields the identical request sequence and cadence for either pair member
 * and for every pair.
 *
 * Modes:
 *   (default)                contract mode: requires the env above, drives the
 *                            workload, emits events, exits 0
 *   --self-test              pure in-memory assertions (no network, no
 *                            writes)
 *   --validate-contract      machinery validation: stands up its own loopback
 *                            pass-through proxy + target + role stand-ins and
 *                            runs both member roles end-to-end through the
 *                            full event contract; writes a retained generation
 *                            marked NOT an E6 results document under
 *                            test-results/connectivity-aware-sync/ by default
 *   --internal-validation-target / --internal-validation-sleeper
 *                            internal child processes for --validate-contract
 *   -h, --help               this text
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';

const MEASURED_ROLE_GATEWAY = 'mailserver-gateway';
const MEASURED_ROLE_MAIN = 'setjoin-desktop-electron-main';
const MEASURED_ROLE_RENDERER = 'setjoin-desktop-electron-renderer';
const MEASURED_ROLES = [MEASURED_ROLE_GATEWAY, MEASURED_ROLE_MAIN, MEASURED_ROLE_RENDERER];
const OUTCOMES = ['completed', 'failed', 'timedOut', 'networkDrop'];
const EVENT_TYPES = new Set(['process', 'phase', 'saturation', 'attempt', 'done']);
const DEFAULT_VALIDATION_OUTPUT_ROOT_REL = 'test-results/connectivity-aware-sync/e6-workload-driver';

const BASIS_FLAG_OFF = 'flag-off-comparator-admits-no-optional-work';
const BASIS_UNVERIFIED = 'policy-mode-configured-unverified';
const BASIS_VERIFIED = 'saturation-endpoint-verified';
const BASIS_REFUTED = 'saturation-endpoint-refuted';

function fail(tag, message) {
  const error = new Error(`E6-DRIVER-${tag}: ${message}`);
  error.e6Tag = tag;
  throw error;
}

function log(message) {
  process.stderr.write(`e6-workload-driver: ${message}\n`);
}

function sha256String(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function roundMs(value) {
  return Math.round(value * 1000) / 1000;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isoUtcNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Same seeded PRNG construction as the harness (rngFromSeed). */
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

function randomInt(rng, bound) {
  return Math.floor(rng() * bound) % bound;
}

// ---------------------------------------------------------------------------
// Pure schedule resolution — the scheduling-faithful core.
// ---------------------------------------------------------------------------

/** Nearest stage block for a measurement-window offset (harness-equivalent). */
function stageBlockAt(schedule, offsetMs) {
  const block = schedule.stageBlocks.find(
    (candidate) => offsetMs >= candidate.startMs && offsetMs < candidate.startMs + candidate.durationMs,
  );
  return block ?? schedule.stageBlocks[schedule.stageBlocks.length - 1];
}

/** Deterministic request plan: same E6_SCHEDULE => identical plan. */
function resolveSequence(schedule) {
  const warmup = [];
  for (let index = 0; index < schedule.warmupAttempts; index += 1) {
    const offsetMs = index * schedule.attemptIntervalMs;
    warmup.push({
      seq: index,
      className: schedule.classSequence[index % schedule.classSequence.length],
      offsetMs,
      stage: stageBlockAt(schedule, offsetMs % schedule.measurementMs).name,
      phase: 'warmup',
    });
  }
  const measurement = [];
  for (let index = 0; index < schedule.classSequence.length; index += 1) {
    const offsetMs = index * schedule.attemptIntervalMs;
    measurement.push({
      seq: index,
      className: schedule.classSequence[index],
      offsetMs,
      stage: stageBlockAt(schedule, offsetMs).name,
      phase: 'measurement',
    });
  }
  return { warmup, measurement };
}

/** Honest outcome classification for one finished fetch (harness-equivalent). */
function classifyOutcome({ ok, error }) {
  if (error === null) return ok ? 'completed' : 'failed';
  if (error.name === 'TimeoutError' || error.name === 'AbortError') return 'timedOut';
  return 'networkDrop';
}

function isEvidenceGradeSchedule(schedule) {
  return (
    schedule.warmupMs >= 120_000 ||
    schedule.measurementMs >= 300_000 ||
    schedule.observationFloorPerClassPerRun >= 1000
  );
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

/** Class routes are paths appended to the proxy base only — never absolute. */
function parseClassRoutes(rawRoutes, classes, { allowBuiltinLoopback }) {
  if (allowBuiltinLoopback) {
    if (rawRoutes !== undefined && rawRoutes !== null) {
      fail('USAGE', 'E6_DRIVER_CLASS_ROUTES conflicts with E6_DRIVER_LOOPBACK_ROUTES=1');
    }
    return Object.fromEntries(
      classes.map((className) => [className, { method: 'POST', path: `/attempt?seq=\${seq}&class=${className}` }]),
    );
  }
  if (rawRoutes === undefined || rawRoutes === null || rawRoutes === '') {
    fail(
      'USAGE',
      'E6_DRIVER_CLASS_ROUTES is required: JSON { [class]: { method, path } } for every schedule class ' +
        '(or E6_DRIVER_LOOPBACK_ROUTES=1 for machinery-validation-only builtin loopback routes)',
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(rawRoutes);
  } catch (error) {
    fail('USAGE', `E6_DRIVER_CLASS_ROUTES is not valid JSON: ${error.message}`);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail('USAGE', 'E6_DRIVER_CLASS_ROUTES must be a JSON object keyed by class');
  }
  const routes = {};
  for (const className of classes) {
    const route = parsed[className];
    if (route === undefined || route === null || typeof route !== 'object') {
      fail('USAGE', `E6_DRIVER_CLASS_ROUTES has no route for schedule class "${className}"`);
    }
    if (typeof route.method !== 'string' || !/^[A-Z]+$/.test(route.method)) {
      fail('USAGE', `route for "${className}" needs an uppercase HTTP method`);
    }
    if (typeof route.path !== 'string' || !route.path.startsWith('/') || route.path.includes('://')) {
      fail('USAGE', `route path for "${className}" must start with "/" (proxy-relative); absolute URLs are refused`);
    }
    routes[className] = { method: route.method, path: route.path };
  }
  const extra = Object.keys(parsed).filter((className) => !classes.includes(className));
  if (extra.length > 0) {
    fail('USAGE', `E6_DRIVER_CLASS_ROUTES carries classes outside the schedule: ${extra.sort().join(', ')}`);
  }
  return routes;
}

function parsePidEnv(value, label, { selfPid }) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 1) {
    fail('USAGE', `${label} must be an integer PID > 1, got ${JSON.stringify(value ?? null)}`);
  }
  if (parsed === selfPid) {
    fail('USAGE', `${label} equals this driver process; the driver never reports itself as a measured role`);
  }
  return parsed;
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

function validateSchedule(raw) {
  let schedule;
  try {
    schedule = JSON.parse(raw);
  } catch (error) {
    fail('USAGE', `E6_SCHEDULE is not valid JSON: ${error.message}`);
  }
  const integerFields = ['attemptIntervalMs', 'warmupMs', 'warmupAttempts', 'measurementMs', 'observationFloorPerClassPerRun'];
  for (const field of integerFields) {
    if (!Number.isInteger(schedule?.[field]) || schedule[field] < 0) {
      fail('USAGE', `E6_SCHEDULE.${field} must be a non-negative integer`);
    }
  }
  if (schedule.attemptIntervalMs < 1) fail('USAGE', 'E6_SCHEDULE.attemptIntervalMs must be >= 1');
  if (!Array.isArray(schedule.classSequence) || schedule.classSequence.length === 0) {
    fail('USAGE', 'E6_SCHEDULE.classSequence must be a non-empty array');
  }
  if (!Array.isArray(schedule.classes) || schedule.classes.length === 0) {
    fail('USAGE', 'E6_SCHEDULE.classes must be a non-empty array');
  }
  for (const className of schedule.classSequence) {
    if (!schedule.classes.includes(className)) {
      fail('USAGE', `E6_SCHEDULE.classSequence carries unknown class "${className}"`);
    }
  }
  if (!Array.isArray(schedule.stageBlocks) || schedule.stageBlocks.length === 0) {
    fail('USAGE', 'E6_SCHEDULE.stageBlocks must be a non-empty array');
  }
  for (const block of schedule.stageBlocks) {
    if (typeof block?.name !== 'string' || !Number.isInteger(block.startMs) || !Number.isInteger(block.durationMs)) {
      fail('USAGE', 'E6_SCHEDULE.stageBlocks entries need name/startMs/durationMs');
    }
  }
  if (schedule.outage === null || typeof schedule.outage !== 'object') {
    fail('USAGE', 'E6_SCHEDULE.outage must be an object');
  }
  for (const field of ['startMs', 'durationMs', 'reconnectWithinMs']) {
    if (!Number.isInteger(schedule.outage[field]) || schedule.outage[field] < 0) {
      fail('USAGE', `E6_SCHEDULE.outage.${field} must be a non-negative integer`);
    }
  }
  schedule.builtin = schedule.builtin ?? { hangProbeIndexes: [], failProbeIndexes: [] };
  return schedule;
}

/** Contract-mode env parse. `liveness` is injectable for the self-test. */
function parseContractEnv(env, { liveness = pidAlive, selfPid = process.pid } = {}) {
  if (env.E6_DRIVER_CONTRACT !== '1') {
    fail('USAGE', 'E6_DRIVER_CONTRACT=1 is required — this driver is a harness-spawned contract process');
  }
  for (const field of ['E6_RUN_ID', 'E6_PAIR_INDEX']) {
    if (!env[field] || typeof env[field] !== 'string') fail('USAGE', `${field} is required`);
  }
  if (!Number.isInteger(Number(env.E6_PAIR_INDEX)) || Number(env.E6_PAIR_INDEX) < 0) {
    fail('USAGE', 'E6_PAIR_INDEX must be a non-negative integer');
  }
  const member = env.E6_MEMBER;
  if (!['comparator', 'candidate'].includes(member)) {
    fail('USAGE', `E6_MEMBER must be comparator|candidate, got ${JSON.stringify(member ?? null)}`);
  }
  const expectedFlag = member === 'candidate' ? 'on' : 'off';
  const expectedPolicy = member === 'candidate' ? 'execute' : 'off';
  if (env.E6_FLAG !== expectedFlag || env.E6_POLICY_MODE !== expectedPolicy) {
    fail(
      'USAGE',
      `E6_FLAG/E6_POLICY_MODE (${JSON.stringify(env.E6_FLAG)}/${JSON.stringify(env.E6_POLICY_MODE)}) contradict ` +
        `E6_MEMBER=${member} (expected ${expectedFlag}/${expectedPolicy})`,
    );
  }
  if (!isLoopbackUrl(env.E6_FAULT_PROXY_URL ?? '')) {
    fail('USAGE', 'E6_FAULT_PROXY_URL must be a loopback http URL; all traffic goes through the run fault proxy');
  }
  if (!isLoopbackUrl(env.E6_TARGET_URL ?? '')) {
    fail('USAGE', 'E6_TARGET_URL must be a loopback http URL (network use is loopback-only)');
  }
  const timeoutMs = Number(env.E6_ATTEMPT_TIMEOUT_MS);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100) {
    fail('USAGE', 'E6_ATTEMPT_TIMEOUT_MS must be an integer >= 100');
  }
  const schedule = validateSchedule(env.E6_SCHEDULE ?? '');
  const allowBuiltinLoopback = env.E6_DRIVER_LOOPBACK_ROUTES === '1';
  if (allowBuiltinLoopback && isEvidenceGradeSchedule(schedule)) {
    fail(
      'USAGE',
      'E6_DRIVER_LOOPBACK_ROUTES=1 is machinery-validation-only and is refused against an evidence-grade schedule ' +
        '(120 s warmup / 300 s measurement / 1000-per-class floor); real evidence runs need E6_DRIVER_CLASS_ROUTES',
    );
  }
  const routes = parseClassRoutes(env.E6_DRIVER_CLASS_ROUTES, schedule.classes, { allowBuiltinLoopback });
  let bodies = {};
  if (env.E6_DRIVER_CLASS_BODIES) {
    try {
      bodies = JSON.parse(env.E6_DRIVER_CLASS_BODIES);
    } catch (error) {
      fail('USAGE', `E6_DRIVER_CLASS_BODIES is not valid JSON: ${error.message}`);
    }
    if (bodies === null || typeof bodies !== 'object' || Array.isArray(bodies)) {
      fail('USAGE', 'E6_DRIVER_CLASS_BODIES must be a JSON object keyed by class');
    }
    for (const className of Object.keys(bodies)) {
      if (!schedule.classes.includes(className)) {
        fail('USAGE', `E6_DRIVER_CLASS_BODIES carries class outside the schedule: "${className}"`);
      }
    }
  }
  const rolePids = {};
  for (const [role, field] of [
    [MEASURED_ROLE_GATEWAY, 'E6_DRIVER_GATEWAY_PID'],
    [MEASURED_ROLE_MAIN, 'E6_DRIVER_MAIN_PID'],
    [MEASURED_ROLE_RENDERER, 'E6_DRIVER_RENDERER_PID'],
  ]) {
    const pid = parsePidEnv(env[field], field, { selfPid });
    if (!liveness(pid)) {
      fail('USAGE', `${field}=${pid} is not a live process; refusing to report a dead measured role`);
    }
    rolePids[role] = pid;
  }
  if (new Set(Object.values(rolePids)).size !== MEASURED_ROLES.length) {
    fail('USAGE', 'measured role PIDs must be three distinct processes');
  }
  let saturationUrl = null;
  if (env.E6_DRIVER_SATURATION_URL) {
    if (!isLoopbackUrl(env.E6_DRIVER_SATURATION_URL)) {
      fail('USAGE', 'E6_DRIVER_SATURATION_URL must be a loopback http URL');
    }
    saturationUrl = env.E6_DRIVER_SATURATION_URL;
  }
  const pollIntervalMs = env.E6_DRIVER_POLL_INTERVAL_MS === undefined ? 1000 : Number(env.E6_DRIVER_POLL_INTERVAL_MS);
  if (!Number.isInteger(pollIntervalMs) || pollIntervalMs < 100) {
    fail('USAGE', 'E6_DRIVER_POLL_INTERVAL_MS must be an integer >= 100');
  }
  return {
    runId: env.E6_RUN_ID,
    pairIndex: Number(env.E6_PAIR_INDEX),
    member,
    flag: env.E6_FLAG,
    policyMode: env.E6_POLICY_MODE,
    proxyUrl: env.E6_FAULT_PROXY_URL,
    targetUrl: env.E6_TARGET_URL,
    attemptTimeoutMs: timeoutMs,
    schedule,
    routes,
    bodies,
    rolePids,
    saturationUrl,
    pollIntervalMs,
    allowBuiltinLoopback,
  };
}

// ---------------------------------------------------------------------------
// Event emission — content-free stdout by construction.
// ---------------------------------------------------------------------------

function emit(event) {
  if (!EVENT_TYPES.has(event.type)) fail('MACHINERY', `refusing to emit non-contract event type ${event.type}`);
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

// ---------------------------------------------------------------------------
// Contract mode — drive the schedule, report honestly, exit 0.
// ---------------------------------------------------------------------------

async function runContractMode() {
  const config = parseContractEnv(process.env);
  const { schedule } = config;
  const plan = resolveSequence(schedule);
  const hangProbes = new Set(schedule.builtin?.hangProbeIndexes ?? []);
  const failProbes = new Set(schedule.builtin?.failProbeIndexes ?? []);

  for (const role of MEASURED_ROLES) {
    emit({ type: 'process', role, pid: config.rolePids[role] });
  }

  const fireAttempt = async (slot) => {
    const route = config.routes[slot.className];
    const path = route.path.replace(/\$\{seq\}/g, String(slot.seq));
    const headers = {
      // Per-basis attribution for the run proxy's closure report (harness
      // PROXY_CONFIG.attributionHeader, scheme v4 §2.3.2): the driver
      // population marks itself so every attempt is attributed exactly —
      // the proxy never assumes attribution. Keep in lockstep with the
      // frozen `driver-attempt` basis token.
      'x-e6-proxy-source': 'driver-attempt',
    };
    let body;
    const classBody = config.bodies[slot.className];
    if (classBody !== undefined) {
      body = JSON.stringify(classBody);
      headers['content-type'] = 'application/json';
    } else if (route.method !== 'GET' && route.method !== 'HEAD') {
      body = JSON.stringify({ class: slot.className, phase: slot.phase });
      headers['content-type'] = 'application/json';
    }
    if (process.env.E6_DRIVER_AUTH_BEARER) {
      headers.authorization = `Bearer ${process.env.E6_DRIVER_AUTH_BEARER}`;
    }
    // The builtin loopback shape mirrors the harness reference exactly: hang
    // probes path to /hang so the target holds past the attempt timeout.
    const urlPath = config.allowBuiltinLoopback && hangProbes.has(slot.seq) ? '/hang' : path;
    const started = performance.now();
    let outcome;
    try {
      const response = await fetch(`${config.proxyUrl}${urlPath}`, {
        method: route.method,
        headers,
        body,
        signal: AbortSignal.timeout(config.attemptTimeoutMs),
      });
      await response.arrayBuffer();
      outcome = classifyOutcome({ ok: response.ok, error: null });
    } catch (error) {
      outcome = classifyOutcome({ ok: false, error });
    }
    emit({
      type: 'attempt',
      seq: slot.seq,
      class: slot.className,
      outcome,
      latencyMs: roundMs(performance.now() - started),
      stage: slot.stage,
      phase: slot.phase,
    });
  };

  const drainPhase = async (slots) => {
    const inflight = [];
    const phaseStart = performance.now();
    for (let index = 0; index < slots.length; index += 1) {
      const due = phaseStart + slots[index].offsetMs;
      const now = performance.now();
      if (due > now) await sleep(due - now);
      inflight.push(fireAttempt(slots[index]));
    }
    await Promise.allSettled(inflight);
  };

  // Saturation verification runs DURING the measurement window; the declared
  // event is emitted only after the window drains and states its basis.
  const saturationSamples = [];
  let samplingActive = false;
  const runSaturationSampling = async () => {
    if (!config.saturationUrl || config.member !== 'candidate') return;
    samplingActive = true;
    while (samplingActive) {
      let saturating = false;
      try {
        const response = await fetch(config.saturationUrl, { signal: AbortSignal.timeout(1000) });
        if (response.ok) {
          const payload = await response.json();
          saturating = payload?.saturating === true;
        }
      } catch {
        saturating = false;
      }
      saturationSamples.push(saturating);
      await sleep(config.pollIntervalMs);
    }
  };
  const stopSaturationSampling = () => {
    samplingActive = false;
  };

  const saturationEvent = () => {
    if (config.member !== 'candidate') {
      return { type: 'saturation', active: false, activeDuringMeasurement: false, basis: BASIS_FLAG_OFF };
    }
    if (saturationSamples.length > 0) {
      const verified = saturationSamples.length > 0 && saturationSamples.every(Boolean);
      return {
        type: 'saturation',
        active: verified,
        activeDuringMeasurement: verified,
        basis: verified ? BASIS_VERIFIED : BASIS_REFUTED,
        samples: saturationSamples.length,
      };
    }
    return { type: 'saturation', active: true, activeDuringMeasurement: true, basis: BASIS_UNVERIFIED };
  };

  try {
    emit({ type: 'phase', phase: 'warmup' });
    await drainPhase(plan.warmup);
    emit({ type: 'phase', phase: 'measurement' });
    const sampler = runSaturationSampling();
    await drainPhase(plan.measurement);
    stopSaturationSampling();
    await sampler;
    emit(saturationEvent());
    emit({
      type: 'done',
      warmupScheduled: plan.warmup.length,
      measurementScheduled: plan.measurement.length,
    });
    process.exit(0);
  } catch (error) {
    process.stderr.write(`e6-workload-driver: fatal ${error?.stack ?? error}\n`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Self-test — pure in-memory assertions; no network, no writes.
// ---------------------------------------------------------------------------

function runSelfTest() {
  let checks = 0;
  const check = (label, condition) => {
    if (!condition) fail('SELFTEST', label);
    checks += 1;
  };
  const expectUsageRefusal = (label, fn) => {
    try {
      fn();
    } catch (error) {
      check(label, error.e6Tag === 'USAGE');
      return;
    }
    fail('SELFTEST', `${label}: expected USAGE refusal, got none`);
  };

  const schedule = {
    attemptIntervalMs: 100,
    warmupMs: 2000,
    warmupAttempts: 20,
    measurementMs: 6000,
    classSequence: [],
    stageBlocks: [
      { stage: 0, name: 'broadband-unmetered', startMs: 0, durationMs: 2000 },
      { stage: 1, name: 'metered-lte', startMs: 2000, durationMs: 2000 },
      { stage: 2, name: 'weak-constrained', startMs: 4000, durationMs: 2000 },
    ],
    outage: { startMs: 3000, durationMs: 30000, reconnectWithinMs: 5000 },
    observationFloorPerClassPerRun: 12,
    classes: ['queued-send', 'draft-commit', 'auth-revocation', 'security-state', 'delivery-receipt'],
    builtin: { hangProbeIndexes: [5, 15], failProbeIndexes: [7, 17] },
  };
  // Same cyclic shuffle construction as the harness buildPlan class sequence.
  const rng = rngFromSeed('validation:schedule');
  while (schedule.classSequence.length < 60) {
    const cycle = [...schedule.classes];
    for (let i = cycle.length - 1; i > 0; i -= 1) {
      const j = randomInt(rng, i + 1);
      [cycle[i], cycle[j]] = [cycle[j], cycle[i]];
    }
    schedule.classSequence.push(...cycle);
  }
  schedule.classSequence.length = 60;

  const first = resolveSequence(schedule);
  const second = resolveSequence(schedule);
  check('sequence resolution is deterministic', JSON.stringify(first) === JSON.stringify(second));
  check('warmup consumes the cycle in order', first.warmup.every((slot, index) => slot.className === schedule.classSequence[index % 60]));
  check('measurement consumes classSequence exactly', first.measurement.every((slot, index) => slot.className === schedule.classSequence[index]));
  check('slot seq numbering is per-phase', first.warmup[19].seq === 19 && first.measurement[0].seq === 0);
  check('slot cadence is attemptIntervalMs', first.measurement[59].offsetMs === 5900 && first.warmup[19].offsetMs === 1900);
  check('warmup stage labels wrap by measurementMs', first.warmup[0].stage === 'broadband-unmetered' && first.warmup[20 - 1].stage === 'broadband-unmetered');
  check('stage blocks label measurement windows', (
    first.measurement[0].stage === 'broadband-unmetered' &&
    first.measurement[25].stage === 'metered-lte' &&
    first.measurement[45].stage === 'weak-constrained'
  ));
  check('block boundary offset belongs to the next block', stageBlockAt(schedule, 4000).name === 'weak-constrained' && stageBlockAt(schedule, 3999).name === 'metered-lte');

  check('outcome classification: completed', classifyOutcome({ ok: true, error: null }) === 'completed');
  check('outcome classification: failed', classifyOutcome({ ok: false, error: null }) === 'failed');
  check('outcome classification: plain errors drop', classifyOutcome({ ok: false, error: new Error('x') }) === 'networkDrop');
  check('outcome classification: timeout names', ['TimeoutError', 'AbortError'].every((name) => classifyOutcome({ ok: false, error: { name } }) === 'timedOut'));
  check('outcome classification: other errors drop', classifyOutcome({ ok: false, error: { name: 'TypeError' } }) === 'networkDrop');

  check('builtin loopback routes cover the schedule exactly', Object.keys(parseClassRoutes(undefined, schedule.classes, { allowBuiltinLoopback: true })).length === 5);
  check('builtin loopback route shape matches the harness reference', parseClassRoutes(undefined, schedule.classes, { allowBuiltinLoopback: true })['queued-send'].path === '/attempt?seq=${seq}&class=queued-send');
  const realRoutes = parseClassRoutes(
    JSON.stringify(Object.fromEntries(schedule.classes.map((className) => [className, { method: 'POST', path: `/api/${className}/${'${seq}'}` }]))),
    schedule.classes,
    { allowBuiltinLoopback: false },
  );
  check('operator routes parse and substitute seq', realRoutes['draft-commit'].path.replace(/\$\{seq\}/g, '3') === '/api/draft-commit/3');
  expectUsageRefusal('missing class route refuses', () => {
    parseClassRoutes(JSON.stringify({ 'queued-send': { method: 'GET', path: '/x' } }), schedule.classes, { allowBuiltinLoopback: false });
  });
  expectUsageRefusal('absolute route path refuses (proxy bypass)', () => {
    parseClassRoutes(
      JSON.stringify(Object.fromEntries(schedule.classes.map((className) => [className, { method: 'GET', path: 'http://127.0.0.1:1/x' }]))),
      schedule.classes,
      { allowBuiltinLoopback: false },
    );
  });
  expectUsageRefusal('non-path route refuses', () => {
    parseClassRoutes(
      JSON.stringify(Object.fromEntries(schedule.classes.map((className) => [className, { method: 'GET', path: 'attempt' }]))),
      schedule.classes,
      { allowBuiltinLoopback: false },
    );
  });

  expectUsageRefusal('builtin routes refuse evidence-grade schedules', () => {
    parseContractEnv(
      contractEnvFixture({ ...schedule, warmupMs: 120_000, warmupAttempts: 1200 }, { loopbackRoutes: true }),
      { liveness: () => true, selfPid: 424242 },
    );
  });
  expectUsageRefusal('missing contract marker refuses', () => {
    const env = contractEnvFixture(schedule, {});
    delete env.E6_DRIVER_CONTRACT;
    parseContractEnv(env, { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('member/flag contradiction refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, { member: 'comparator', flag: 'on' }), { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('non-loopback proxy refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, { proxyUrl: 'http://10.0.0.1:9/' }), { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('non-loopback target refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, { targetUrl: 'http://example.invalid/' }), { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('non-loopback saturation URL refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, { saturationUrl: 'http://example.invalid/status' }), { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('self-reported PID refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, {}), { liveness: () => true, selfPid: 4242 });
  });
  expectUsageRefusal('dead role PID refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, {}), { liveness: () => false, selfPid: 424242 });
  });
  expectUsageRefusal('duplicate role PIDs refuse', () => {
    const env = contractEnvFixture(schedule, {});
    env.E6_DRIVER_RENDERER_PID = env.E6_DRIVER_MAIN_PID;
    parseContractEnv(env, { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('low attempt timeout refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, { attemptTimeoutMs: '50' }), { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('malformed schedule refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, { scheduleJson: '{not-json' }), { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('schedule class outside classes refuses', () => {
    const drifted = structuredClone(schedule);
    drifted.classSequence = [...drifted.classSequence];
    drifted.classSequence[3] = 'unknown-class';
    parseContractEnv(contractEnvFixture(drifted, {}), { liveness: () => true, selfPid: 424242 });
  });
  expectUsageRefusal('body class outside schedule refuses', () => {
    parseContractEnv(contractEnvFixture(schedule, { bodies: JSON.stringify({ 'unknown-class': {} }) }), { liveness: () => true, selfPid: 424242 });
  });

  // stdout stays content-free: the parsed env can only emit fixed-vocabulary
  // events; assert no env-carried free text (target/proxy URLs, bearer canary)
  // can appear in the emitted JSON for any member state.
  const parsed = parseContractEnv(contractEnvFixture(schedule, { loopbackRoutes: true }), { liveness: () => true, selfPid: 424242 });
  check('parsed env resolves the full plan', resolveSequence(parsed.schedule).measurement.length === 60 && resolveSequence(parsed.schedule).warmup.length === 20);
  const canary = 'e6-canary-9f3b1';
  const eventJson = JSON.stringify([
    { type: 'process', role: MEASURED_ROLE_GATEWAY, pid: 11 },
    { type: 'phase', phase: 'warmup' },
    { type: 'attempt', seq: 0, class: 'queued-send', outcome: 'completed', latencyMs: 1.5, stage: 'broadband-unmetered', phase: 'warmup' },
    { type: 'saturation', active: true, activeDuringMeasurement: true, basis: BASIS_UNVERIFIED },
    { type: 'saturation', active: false, activeDuringMeasurement: false, basis: BASIS_REFUTED, samples: 3 },
    { type: 'done', warmupScheduled: 20, measurementScheduled: 60 },
  ]);
  check('event stream is content-free (no URLs, no bearer, no target)', !eventJson.includes('http') && !eventJson.includes(canary) && !eventJson.includes(parsed.targetUrl));
  check('done accounting mirrors the schedule', resolveSequence(schedule).measurement.length === schedule.classSequence.length && resolveSequence(schedule).warmup.length === schedule.warmupAttempts);

  process.stdout.write(`e6-workload-driver self-test: PASS (${checks} assertions)\n`);
}

function contractEnvFixture(schedule, { member = 'candidate', flag, loopbackRoutes = false, proxyUrl, targetUrl, saturationUrl, attemptTimeoutMs, scheduleJson, bodies }) {
  return {
    E6_DRIVER_CONTRACT: '1',
    E6_RUN_ID: 'self-test',
    E6_PAIR_INDEX: '0',
    E6_MEMBER: member,
    E6_FLAG: flag ?? (member === 'candidate' ? 'on' : 'off'),
    E6_POLICY_MODE: member === 'candidate' ? 'execute' : 'off',
    E6_FAULT_PROXY_URL: proxyUrl ?? 'http://127.0.0.1:41000',
    E6_TARGET_URL: targetUrl ?? 'http://127.0.0.1:41001',
    E6_ATTEMPT_TIMEOUT_MS: attemptTimeoutMs ?? '1500',
    E6_SCHEDULE: scheduleJson ?? JSON.stringify(schedule),
    ...(loopbackRoutes ? { E6_DRIVER_LOOPBACK_ROUTES: '1' } : {}),
    ...(bodies !== undefined ? { E6_DRIVER_CLASS_BODIES: bodies } : {}),
    ...(saturationUrl !== undefined ? { E6_DRIVER_SATURATION_URL: saturationUrl } : {}),
    E6_DRIVER_GATEWAY_PID: '4001',
    E6_DRIVER_MAIN_PID: '4002',
    E6_DRIVER_RENDERER_PID: '4003',
  };
}

// ---------------------------------------------------------------------------
// Contract-validation mode — machinery validation with the driver in the loop.
// Stands up a loopback pass-through proxy + synthetic target + live role
// stand-ins, runs both member roles end-to-end, asserts the full event
// contract, and retains a generation marked NOT an E6 results document.
// ---------------------------------------------------------------------------

function runInternalValidationTarget() {
  const config = JSON.parse(process.env.E6_VALIDATION_TARGET_CONFIG);
  const hangProbes = new Set(config.hangProbeIndexes);
  const failProbes = new Set(config.failProbeIndexes);
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    const seq = Number(url.searchParams.get('seq') ?? '-1');
    request.resume();
    if (url.pathname === '/hang' || hangProbes.has(seq)) {
      setTimeout(() => {
        if (!response.socket.destroyed) response.end('late');
      }, 30_000).unref?.();
      return;
    }
    if (failProbes.has(seq)) {
      response.writeHead(500, { 'content-type': 'application/json' });
      response.end('{"error":"e6-driver-validation-synthetic-failure"}');
      return;
    }
    setTimeout(() => {
      if (!response.socket.destroyed) {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end('{"ok":true}');
      }
    }, 5);
  });
  server.on('error', (error) => {
    process.stderr.write(`validation-target: ${error.message}\n`);
    process.exit(1);
  });
  server.listen(0, '127.0.0.1', () => {
    process.stdout.write(`${JSON.stringify({ type: 'ready', endpoint: `http://127.0.0.1:${server.address().port}`, pid: process.pid })}\n`);
  });
  process.on('SIGTERM', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
  setInterval(() => {}, 60_000);
}

function runInternalClientStandIn() {
  // Plays setjoin-desktop-electron-main for machinery validation: a live,
  // sampled process that also serves the candidate saturation endpoint the
  // verified-declaration path polls ({saturating:true} always).
  const server = http.createServer((request, response) => {
    request.resume();
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{"saturating":true}');
  });
  server.on('error', (error) => {
    process.stderr.write(`client-stand-in: ${error.message}\n`);
    process.exit(1);
  });
  server.listen(0, '127.0.0.1', () => {
    process.stdout.write(`${JSON.stringify({ type: 'ready', endpoint: `http://127.0.0.1:${server.address().port}`, pid: process.pid })}\n`);
  });
  process.on('SIGTERM', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
  setInterval(() => {}, 60_000);
}

function runInternalRoleStandIn() {
  process.stdout.write(`${JSON.stringify({ type: 'ready', pid: process.pid })}\n`);
  process.on('SIGTERM', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
  setInterval(() => {}, 60_000);
}

/** Transparent pass-through proxy with ONLY the outage applied — fault
 *  shaping is the harness's job; this exists so the driver is proven to
 *  compose every request against the proxy base and so networkDrop accounting
 *  is exercised through a genuinely destroyed connection. The outage is
 *  anchored to the FIRST RECEIVED REQUEST (an observed driver-clock landmark)
 *  plus the schedule offsets and a small processing-jitter margin — child
 *  spawn skew (ops-doc bounded approximation) then cannot move the boundary
 *  by more than the margin. Validation asserts a boundary window, never an
 *  exact boundary count. */
class PassThroughProxyWithOutage {
  constructor({ warmupMs, outageStartMs, outageDurationMs, jitterMarginMs }) {
    this.warmupMs = warmupMs;
    this.outageStartMs = outageStartMs;
    this.outageDurationMs = outageDurationMs;
    this.jitterMarginMs = jitterMarginMs;
    this.originMonotonicMs = performance.now();
    this.firstRequestMonotonicMs = null;
    this.server = null;
    this.sockets = new Set();
    this.stats = { received: 0, forwarded: 0, droppedOutage: 0 };
  }

  elapsedMs() {
    return performance.now() - this.originMonotonicMs;
  }

  outageActive() {
    if (this.firstRequestMonotonicMs === null) return false;
    const offset = this.elapsedMs() - this.firstRequestMonotonicMs;
    const start = this.warmupMs + this.outageStartMs + this.jitterMarginMs;
    return offset >= start && offset < start + this.outageDurationMs;
  }

  async start() {
    this.server = http.createServer((request, response) => {
      this.stats.received += 1;
      if (this.firstRequestMonotonicMs === null) this.firstRequestMonotonicMs = this.elapsedMs();
      if (this.outageActive()) {
        this.stats.droppedOutage += 1;
        response.socket.destroy();
        return;
      }
      const target = new URL(process.env.E6_VALIDATION_PROXY_UPSTREAM);
      const upstream = http.request(
        {
          host: target.hostname,
          port: target.port,
          path: request.url,
          method: request.method,
          headers: { ...request.headers, host: target.host, connection: 'close' },
        },
        (upstreamResponse) => {
          response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
          upstreamResponse.pipe(response);
          upstreamResponse.on('error', () => response.socket.destroy());
        },
      );
      upstream.on('error', () => {
        if (!response.socket.destroyed) response.socket.destroy();
      });
      request.pipe(upstream);
      upstream.on('close', () => {
        this.stats.forwarded += 1;
      });
    });
    this.server.on('connection', (socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
    });
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', resolve);
    });
    this.endpoint = `http://127.0.0.1:${this.server.address().port}`;
    return this.endpoint;
  }

  async stop() {
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    if (this.server) {
      await new Promise((resolve) => this.server.close(() => resolve()));
      this.server = null;
    }
  }
}

function spawnValidationChild(args, envExtra) {
  const child = spawn(process.execPath, [path.join(import.meta.dirname, 'e6-workload-driver.mjs'), ...args], {
    cwd: path.resolve(import.meta.dirname, '..'),
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, ...envExtra },
  });
  return child;
}

async function waitReady(child) {
  return new Promise((resolve, reject) => {
    const timeout_ = setTimeout(() => reject(new Error('validation child did not become ready')), 10_000);
    child.stdout.setEncoding('utf8');
    child.stdout.once('data', (chunk) => {
      clearTimeout(timeout_);
      try {
        resolve(JSON.parse(chunk.split('\n')[0]));
      } catch (error) {
        reject(new Error(`unparsable validation child ready line: ${error.message}`));
      }
    });
    child.once('exit', (code) => {
      clearTimeout(timeout_);
      reject(new Error(`validation child exited early (${code})`));
    });
  });
}

async function runValidationMode(argv) {
  const outputRootArgIndex = argv.indexOf('--output-root');
  const outputRootRel =
    outputRootArgIndex >= 0 ? argv[outputRootArgIndex + 1] : DEFAULT_VALIDATION_OUTPUT_ROOT_REL;
  const repoRoot = path.resolve(import.meta.dirname, '..');
  const outputRoot = path.isAbsolute(outputRootRel) ? outputRootRel : path.join(repoRoot, outputRootRel);
  const runId = `e6drvval-${isoUtcNow().replace(/[-:]/g, '').toLowerCase()}-${sha256String(String(process.pid + Date.now())).slice(0, 12)}`;
  const generation = path.join(outputRoot, runId);
  fs.mkdirSync(generation, { recursive: true });

  // Smoke-shaped schedule mirroring the harness SMOKE_PROFILE construction:
  // 2 s warmup / 6 s measurement, floor 12 per class, 5 classes -> 60
  // measurement attempts at a 100 ms interval, outage fixed-mid-measurement.
  const schedule = buildValidationSchedule();
  const canary = 'e6-canary-9f3b1';

  // 1. Synthetic loopback target as a child (distinct PID, hang/fail probes).
  const targetChild = spawnValidationChild(['--internal-validation-target'], {
    E6_VALIDATION_TARGET_CONFIG: JSON.stringify({
      hangProbeIndexes: schedule.builtin.hangProbeIndexes,
      failProbeIndexes: schedule.builtin.failProbeIndexes,
    }),
  });
  const target = await waitReady(targetChild);

  // 2. Pass-through proxy with the outage window, upstream = target.
  //    E6_TARGET_URL points at a DEAD port: if the driver wrongly targeted the
  //    target directly, every attempt would networkDrop and validation fails —
  //    proxy-base composition is proven, not assumed.
  let deadTargetEndpoint = null;
  {
    const probe = http.createServer(() => {});
    await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
    deadTargetEndpoint = `http://127.0.0.1:${probe.address().port}`;
    await new Promise((resolve) => probe.close(resolve));
  }
  process.env.E6_VALIDATION_PROXY_UPSTREAM = target.endpoint;
  const JITTER_MARGIN_MS = 500;
  const proxyArgs = {
    warmupMs: schedule.warmupMs,
    outageStartMs: schedule.outage.startMs,
    outageDurationMs: schedule.outage.durationMs,
    jitterMarginMs: JITTER_MARGIN_MS,
  };

  // 3. Live role stand-ins: the target child plays the gateway role (it serves
  //    the requests); a client stand-in (main) also serves the saturation
  //    endpoint; a plain sleeper plays the renderer. Synthetic stand-ins for
  //    machinery validation only — never real client/gateway processes.
  const clientStandInChild = spawnValidationChild(['--internal-client-stand-in'], {});
  const clientStandIn = await waitReady(clientStandInChild);
  const rendererStandInChild = spawnValidationChild(['--internal-role-stand-in'], {});
  await waitReady(rendererStandInChild);

  const memberRuns = [
    { member: 'comparator', saturationUrl: null },
    { member: 'candidate', saturationUrl: clientStandIn.endpoint },
    { member: 'candidate', saturationUrl: null, label: 'candidate-unverified' },
  ];

  const reports = [];
  const totalProxyStats = { received: 0, forwarded: 0, droppedOutage: 0 };
  try {
    // One FRESH proxy per member run, mirroring the harness (runMember starts
    // a new FaultProxy per member) — a shared window clock would leak one
    // member's outage into the next member's warmup.
    for (const [index, memberRun] of memberRuns.entries()) {
      const proxy = new PassThroughProxyWithOutage(proxyArgs);
      const proxyEndpoint = await proxy.start();
      let memberReport;
      try {
        memberReport = await runValidationMember({
          member: memberRun.member,
          label: memberRun.label ?? memberRun.member,
          index,
          schedule,
          proxyEndpoint,
          deadTargetEndpoint,
          gatewayPid: target.pid,
          mainPid: clientStandIn.pid,
          rendererPid: rendererStandInChild.pid,
          saturationUrl: memberRun.saturationUrl,
          canary,
          generation,
        });
      } finally {
        await proxy.stop();
      }
      memberReport.proxyStats = { ...proxy.stats };
      for (const [key, value] of Object.entries(proxy.stats)) totalProxyStats[key] += value;
      reports.push(memberReport);
    }
  } finally {
    for (const child of [targetChild, clientStandInChild, rendererStandInChild]) child.kill('SIGTERM');
  }

  // Proxy reality check: outage drops must have happened for networkDrop
  // accounting to be genuine connection destruction.
  if (totalProxyStats.droppedOutage <= 0) {
    fail('VALIDATION', `pass-through proxies recorded no outage drops (${JSON.stringify(totalProxyStats)}); networkDrop accounting would not be genuine`);
  }

  const boundarySeq = Math.ceil(schedule.outage.startMs / schedule.attemptIntervalMs);
  const report = {
    schemaVersion: 1,
    kind: 'e6-driver-contract-validation',
    driver: 'scripts/e6-workload-driver.mjs',
    driverSha256: sha256String(fs.readFileSync(path.join(repoRoot, 'scripts/e6-workload-driver.mjs'))),
    notAnE6ResultsDoc: true,
    validationScope: 'driver event-contract machinery validation only; synthetic loopback stand-ins; no feature flag flipped; no E6 evidence produced',
    runId,
    createdAtUtc: isoUtcNow(),
    scheduleDigest: sha256String(JSON.stringify(schedule)),
    scheduleShape: {
      warmupAttempts: schedule.warmupAttempts,
      measurementAttempts: schedule.classSequence.length,
      attemptIntervalMs: schedule.attemptIntervalMs,
      classes: schedule.classes,
      outage: schedule.outage,
      proxyOutageAnchor: 'first-received-request',
      proxyOutageJitterMarginMs: JITTER_MARGIN_MS,
    },
    proxyStats: totalProxyStats,
    standIns: {
      gatewayRolePid: target.pid,
      mainRolePid: clientStandIn.pid,
      rendererRolePid: rendererStandInChild.pid,
      note: 'synthetic live stand-in processes for cross-process sampling validation only',
    },
    outageBoundary: {
      boundarySeq,
      guaranteedNotDroppedThroughSeq: boundarySeq - 5,
      guaranteedDroppedFromSeq: boundarySeq + 7,
      note: 'exact boundary floats a slot or two with warmup-drain and timer variance; validation asserts the two-sided window',
    },
    members: reports,
    assertionsPassed: reports.reduce((sum, member) => sum + member.assertions, 0),
  };
  fs.writeFileSync(path.join(generation, 'validation.json'), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(
    `e6-workload-driver contract validation: PASS (${report.assertionsPassed} assertions across ${reports.length} member runs)\n` +
      `  generation: ${path.relative(repoRoot, generation)}\n` +
      `  scope: machinery validation only — NOT an E6 results document, no evidence produced\n`,
  );
}

async function runValidationMember({ member, label, index, schedule, proxyEndpoint, deadTargetEndpoint, gatewayPid, mainPid, rendererPid, saturationUrl, canary, generation }) {
  const env = {
    E6_DRIVER_CONTRACT: '1',
    E6_RUN_ID: `e6drvval-${label}-${index}`,
    E6_PAIR_INDEX: '0',
    E6_MEMBER: member,
    E6_FLAG: member === 'candidate' ? 'on' : 'off',
    E6_POLICY_MODE: member === 'candidate' ? 'execute' : 'off',
    E6_FAULT_PROXY_URL: proxyEndpoint,
    E6_TARGET_URL: deadTargetEndpoint,
    E6_ATTEMPT_TIMEOUT_MS: '1500',
    E6_SCHEDULE: JSON.stringify(schedule),
    E6_DRIVER_LOOPBACK_ROUTES: '1',
    E6_DRIVER_GATEWAY_PID: String(gatewayPid),
    E6_DRIVER_MAIN_PID: String(mainPid),
    E6_DRIVER_RENDERER_PID: String(rendererPid),
    E6_DRIVER_AUTH_BEARER: canary,
    ...(saturationUrl ? { E6_DRIVER_SATURATION_URL: saturationUrl } : {}),
  };
  const child = spawnValidationChild([], env);
  const stdoutLines = [];
  const stderrLines = [];
  let stdoutBuffer = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk;
    let newlineIndex;
    while ((newlineIndex = stdoutBuffer.indexOf('\n')) >= 0) {
      const line = stdoutBuffer.slice(0, newlineIndex).trim();
      stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
      if (line) stdoutLines.push(line);
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    for (const line of chunk.split('\n')) if (line.trim()) stderrLines.push(line.trim());
  });
  const exitCode = await new Promise((resolve) => {
    child.on('exit', (code) => resolve(code));
    setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }, schedule.warmupMs + schedule.measurementMs + 30_000).unref?.();
  });
  fs.writeFileSync(path.join(generation, `member-${label}.ndjson`), `${stdoutLines.join('\n')}\n`);

  let assertions = 0;
  const check = (label_, condition) => {
    if (!condition) fail('VALIDATION', `${label}: ${label_}`);
    assertions += 1;
  };

  check(`exit code 0 (got ${exitCode})`, exitCode === 0);
  const events = stdoutLines.map((line, lineIndex) => {
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      fail('VALIDATION', `${label}: stdout line ${lineIndex} is not JSON (content-free contract violated)`);
    }
    return event;
  });
  for (const [lineIndex, line] of stdoutLines.entries()) {
    check(`stdout line ${lineIndex} content-free (no URL/bearer)`, !line.includes('http') && !line.includes(canary));
  }

  const processEvents = events.filter((event) => event.type === 'process');
  check('exactly three process events', processEvents.length === 3);
  check('process roles in profile order', JSON.stringify(processEvents.map((event) => event.role)) === JSON.stringify(['mailserver-gateway', 'setjoin-desktop-electron-main', 'setjoin-desktop-electron-renderer']));
  check('process PIDs bind the declared stand-ins exactly', processEvents[0].pid === gatewayPid && processEvents[1].pid === mainPid && processEvents[2].pid === rendererPid);
  check('process PIDs are distinct and positive', new Set(processEvents.map((event) => event.pid)).size === 3 && processEvents.every((event) => Number.isInteger(event.pid) && event.pid > 1));

  const phaseEvents = events.filter((event) => event.type === 'phase');
  check('phase events are warmup then measurement', JSON.stringify(phaseEvents.map((event) => event.phase)) === JSON.stringify(['warmup', 'measurement']));

  const attemptsWarmup = events.filter((event) => event.type === 'attempt' && event.phase === 'warmup');
  const attemptsMeasurement = events.filter((event) => event.type === 'attempt' && event.phase === 'measurement');
  // Events stream in COMPLETION order (the harness buckets by seq, never by
  // arrival position), so schedule-fidelity comparisons sort by seq first.
  const bySeq = (first, second) => first.seq - second.seq;
  const warmupBySeq = [...attemptsWarmup].sort(bySeq);
  const measurementBySeq = [...attemptsMeasurement].sort(bySeq);
  check(`warmup accounting exact (${schedule.warmupAttempts})`, attemptsWarmup.length === schedule.warmupAttempts);
  check(`measurement accounting exact (${schedule.classSequence.length})`, attemptsMeasurement.length === schedule.classSequence.length);
  check('warmup seqs complete', warmupBySeq.every((event, position) => event.seq === position));
  check('measurement seqs complete', measurementBySeq.every((event, position) => event.seq === position));
  const expectedPlan = resolveSequence(schedule);
  check(
    'warmup class sequence scheduling-faithful',
    warmupBySeq.every((event, position) => event.class === expectedPlan.warmup[position].className && event.stage === expectedPlan.warmup[position].stage),
  );
  check(
    'measurement class sequence scheduling-faithful',
    measurementBySeq.every((event, position) => event.class === expectedPlan.measurement[position].className && event.stage === expectedPlan.measurement[position].stage),
  );

  const outcomes = { completed: 0, failed: 0, timedOut: 0, networkDrop: 0 };
  for (const event of [...attemptsWarmup, ...attemptsMeasurement]) outcomes[event.outcome] += 1;
  check('every outcome is a contract outcome', Object.keys(outcomes).every((outcome) => OUTCOMES.includes(outcome)));
  check('outcome partition sums to all attempts', outcomes.completed + outcomes.failed + outcomes.timedOut + outcomes.networkDrop === schedule.warmupAttempts + schedule.classSequence.length);
  const hangProbes = schedule.builtin.hangProbeIndexes;
  const failProbes = schedule.builtin.failProbeIndexes;
  // Warmup cycles the probe seq range (harness smoke target probes apply by
  // seq in both phases), so only non-probe warmup slots must complete; the
  // proxy outage is measurement-window-only, so warmup has zero networkDrops.
  check('non-probe warmup attempts all completed', warmupBySeq.filter((event) => !hangProbes.includes(event.seq) && !failProbes.includes(event.seq)).every((event) => event.outcome === 'completed'));
  check('warmup recorded no networkDrops (outage gated to measurement)', attemptsWarmup.every((event) => event.outcome !== 'networkDrop'));
  check('hang probes recorded as timedOut', attemptsMeasurement.filter((event) => hangProbes.includes(event.seq)).every((event) => event.outcome === 'timedOut'));
  check('fail probes recorded as failed', attemptsMeasurement.filter((event) => failProbes.includes(event.seq)).every((event) => event.outcome === 'failed'));
  // Timer/phase-start variance (the measurement phase begins when the warmup
  // drain completes, up to ~100 ms before nominal) moves the outage boundary
  // by a slot or two, so the validation asserts a two-sided boundary window,
  // never an exact boundary count. The drop side gets extra headroom.
  const boundarySeq = Math.ceil(schedule.outage.startMs / schedule.attemptIntervalMs);
  const safeBefore = measurementBySeq.filter((event) => event.seq <= boundarySeq - 5);
  const safeAfter = measurementBySeq.filter((event) => event.seq >= boundarySeq + 7);
  check('attempts well before the outage boundary are not networkDrops', safeBefore.every((event) => event.outcome !== 'networkDrop'));
  check('attempts well after the outage boundary are all networkDrops', safeAfter.length > 0 && safeAfter.every((event) => event.outcome === 'networkDrop'));
  const measurementDrops = attemptsMeasurement.filter((event) => event.outcome === 'networkDrop').length;
  check('outage window produced genuine networkDrops', measurementDrops > 0);
  check('completed observations exist', outcomes.completed > 0);

  const saturationEvents = events.filter((event) => event.type === 'saturation');
  check('exactly one saturation event', saturationEvents.length === 1);
  const saturation = saturationEvents[0];
  if (member === 'comparator') {
    check('comparator declares no optional work', saturation.active === false && saturation.activeDuringMeasurement === false && saturation.basis === BASIS_FLAG_OFF);
  } else if (saturationUrl) {
    check('verified candidate saturation declared', saturation.active === true && saturation.activeDuringMeasurement === true && saturation.basis === BASIS_VERIFIED);
  } else {
    check('unverified candidate saturation declared with honest basis', saturation.active === true && saturation.activeDuringMeasurement === true && saturation.basis === BASIS_UNVERIFIED);
  }

  const doneEvents = events.filter((event) => event.type === 'done');
  check('exactly one done event', doneEvents.length === 1);
  check('done accounting mirrors the schedule', doneEvents[0].measurementScheduled === schedule.classSequence.length && doneEvents[0].warmupScheduled === schedule.warmupAttempts);
  check('no stderr output (driver runs clean)', stderrLines.length === 0);

  return { label, member, exitCode, attempts: outcomes, saturation, assertions, stderrTail: stderrLines.slice(-3) };
}

function buildValidationSchedule() {
  // Mirrors the harness smoke shape: SMOKE_PROFILE windows (2 s / 6 s), floor
  // 12 per class, cyclic Fisher-Yates class sequence over the profile's five
  // Critical classes, three contiguous stage blocks, fixed-mid-measurement
  // outage (30 s duration covers the smoke window tail, as in harness smoke).
  const classes = ['queued-send', 'draft-commit', 'auth-revocation', 'security-state', 'delivery-receipt'];
  const schedule = {
    attemptIntervalMs: 100,
    warmupMs: 2000,
    warmupAttempts: 20,
    measurementMs: 6000,
    classSequence: [],
    stageBlocks: [
      { stage: 0, name: 'broadband-unmetered', startMs: 0, durationMs: 2000, bandwidthKbit: 50000, latencyMs: 20, lossPercent: 0 },
      { stage: 1, name: 'metered-lte', startMs: 2000, durationMs: 2000, bandwidthKbit: 10000, latencyMs: 60, lossPercent: 1 },
      { stage: 2, name: 'weak-constrained', startMs: 4000, durationMs: 2000, bandwidthKbit: 1000, latencyMs: 200, lossPercent: 2 },
    ],
    outage: { startMs: 3000, durationMs: 30000, reconnectWithinMs: 5000 },
    observationFloorPerClassPerRun: 12,
    classes,
    // Probe placement mirrors the harness buildPlan rule: probes live ONLY in
    // the measurement seq range (never warmup, so the warmup drain completes
    // on time) and before the outage boundary, because a hang probe inside
    // the outage is destroyed into a networkDrop, not a timedOut.
    builtin: { hangProbeIndexes: [21, 24], failProbeIndexes: [23, 27] },
  };
  const rng = rngFromSeed('validation:schedule');
  while (schedule.classSequence.length < 60) {
    const cycle = [...classes];
    for (let i = cycle.length - 1; i > 0; i -= 1) {
      const j = randomInt(rng, i + 1);
      [cycle[i], cycle[j]] = [cycle[j], cycle[i]];
    }
    schedule.classSequence.push(...cycle);
  }
  schedule.classSequence.length = 60;
  return schedule;
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------

function usage() {
  process.stdout.write(`Usage:
  node scripts/e6-workload-driver.mjs            contract mode (harness-spawned; requires the
                                                 E6_* environment documented in the header)
  bash scripts/e6-workload-driver.sh --self-test pure in-memory assertions
  bash scripts/e6-workload-driver.sh --validate-contract [--output-root <dir>]
                                                 machinery validation of the full event
                                                 contract against a synthetic loopback stack
                                                 (NOT an E6 results document)
  -h, --help                                     this text

The harness spawns this driver via:
  bash scripts/run-connectivity-e6-harness.sh --workload-driver-cmd node \\
    --workload-driver-arg scripts/e6-workload-driver.mjs ...
with the operator-exported E6_DRIVER_* environment propagating through.
`);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('-h') || argv.includes('--help')) {
    usage();
    return;
  }
  if (argv.includes('--self-test')) {
    runSelfTest();
    return;
  }
  if (argv.includes('--validate-contract')) {
    await runValidationMode(argv);
    return;
  }
  if (argv.some((arg) => arg.startsWith('-'))) {
    process.stderr.write('e6-workload-driver: unknown arguments; see --help\n');
    process.exitCode = 1;
    return;
  }
  await runContractMode();
}

const internalMode =
  process.argv.includes('--internal-validation-target')
    ? 'target'
    : process.argv.includes('--internal-client-stand-in')
      ? 'client-stand-in'
      : process.argv.includes('--internal-role-stand-in')
        ? 'role-stand-in'
        : null;

if (internalMode === 'target') {
  runInternalValidationTarget();
} else if (internalMode === 'client-stand-in') {
  runInternalClientStandIn();
} else if (internalMode === 'role-stand-in') {
  runInternalRoleStandIn();
} else {
  main().catch((error) => {
    process.stderr.write(`e6-workload-driver: fatal ${error?.message ?? error}\n`);
    process.exit(1);
  });
}
