#!/usr/bin/env node
/**
 * CQ E6 paired-run harness — deterministic driver for the frozen comparison
 * profile `docs/verification/connectivity-e6-profile.json`
 * (selected profile `e6-electron-macos-arm64-v1`).
 *
 * CONTRACT: connectivity-e6-harness
 * Executes the frozen protocol of plan
 * `retired-docs:superpowers/plans/2026-08-11-connectivity-aware-sync-resource-qos.md`
 * ("E6 reproducible comparison" + section 8): flag-OFF comparator versus
 * execute-candidate pairs, identical workloads, randomized member order,
 * 120 s warmup / 300 s measurement, >= 1000 completed observations per
 * Critical class per member run, nearest-rank p95/p99, 10,000 seeded paired
 * bootstrap resamples with upper one-sided 95% bounds against the section 8
 * ceilings (p95 5% / 50 ms, p99 10% / 100 ms, peak CPU/RSS 10%), failures and
 * timeouts enumerated separately with all attempts retained, and a
 * `postResultChangesProhibited` seal binding profile digest, seeds, tool
 * versions and pair-document digests. Existing generation directories are
 * never overwritten; reruns write new dated generations. `--smoke` output is
 * machinery validation only and is structurally NOT an E6 results document.
 *
 * ---------------------------------------------------------------------------
 * ENTRY POINTS (CQ-DP2 — the import is inert; frozen on the profile node
 * v26.8.1)
 * ---------------------------------------------------------------------------
 *
 * Entry detection is the `import.meta.main` guard at the bottom of this file.
 * Importing this module as a library is INERT: evaluation only defines
 * classes/functions/constants — no CLI dispatch or output, no self-hash
 * read/hashing, no file writes, no listeners, no child processes, no timers.
 * `HARNESS_SHA256` (run-seal binding of this file) is read lazily at the top
 * of `main()`, never at module scope, and still hashes this exact file so a
 * seal keeps binding the running source. Frozen entry paths:
 *
 *   1. Direct CLI   node scripts/run-connectivity-e6-harness.mjs [args]
 *   2. Shell wrapper
 *        bash scripts/run-connectivity-e6-harness.sh [args]
 *      execs node with this file as the entry module; arguments pass through
 *      verbatim.
 *   3. --self-test  in-memory schema/verdict assertions; writes nothing.
 *   4. --internal-smoke-target
 *      child re-invocation spawned by startSmokeTargetChild() for --smoke
 *      (E6_SMOKE_TARGET_CONFIG env; prints one ready line, holds the loop).
 *   5. --internal-member-simulator
 *      child re-invocation spawned by the built-in reference workload driver
 *      for --smoke (E6_* env; emits driver-contract NDJSON on stdout).
 *   6. Library import
 *        scripts/run-connectivity-e6-harness.proxy.test.mjs
 *      imports the real FaultProxy / HOP_BY_HOP_HEADERS /
 *      stripHopByHopHeaders directly — no argv/stdout patching.
 *
 * Argument handling, exit codes (0 ok; 1 machinery/validation/usage; 3
 * evidence run with overall verdict FAIL; 127 driver spawn failure; 130
 * interrupted), signal handling and owned-resource cleanup are identical on
 * paths 1-3 and unchanged on the child paths.
 *
 * ---------------------------------------------------------------------------
 * OPS RUNBOOK — sustained 20-pair E6 evidence run (operator procedure)
 * ---------------------------------------------------------------------------
 *
 * Scope and honesty
 *   This harness PRODUCES evidence documents; it never flips a production
 *   flag and never enables behavior outside its own run-scoped loopback
 *   processes. A full run is the `CAS-E6-*` core-lane evidence producer; the
 *   gate verdict lives in the aggregate document and stays with the case
 *   lane.
 *
 * Environment (all required before starting; the harness fail-closes if absent)
 *   1. Host matches the frozen profile: macOS arm64 (profile.host), node
 *      v26.8.1, go1.27.1, rustc 1.97.1 on PATH; electron spec ^43.2.0
 *      installed under clients/desktop/electron.
 *   2. Client build: `cd clients/desktop/electron && npm ci && npm run build`
 *      (one identical build serves BOTH pair members; only
 *      feature.connectivity_aware_sync off-vs-execute differs at runtime).
 *      The harness verifies/builds this when run in evidence mode.
 *   3. Workload target: gateway + seeded corpus per the profile corpus block
 *      (2 accounts x 2000 messages x 40 attachments, cold per pair) reachable
 *      on loopback; pass its base URL as --target-url. Network use is
 *      loopback-only.
 *   4. Workload driver: an executable implementing the driver event contract
 *      (search "driver event contract" below), passed as
 *      `--workload-driver-cmd <exe> [--workload-driver-arg <a>]...`.
 *      The built-in loopback reference workload is smoke-only and refuses to
 *      produce E6 evidence.
 *
 * Execution
 *   bash scripts/run-connectivity-e6-harness.sh \
 *     --profile docs/verification/connectivity-e6-profile.json \
 *     --pairs 20 --target-url http://127.0.0.1:<port> \
 *     --workload-driver-cmd <driver> [--workload-driver-arg ...]
 *   Duration: about 20 x (120 s warmup + 300 s measurement + member
 *   turnover) + client build + bootstrap statistics ~= 2.5-3.5 h wall clock
 *   (manifest core-lane timeout is 14400 s). Run serially; do not co-schedule
 *   other load on the profile host or the comparator is invalid.
 *
 * Disk and network needs
 *   < 200 MB free under test-results/ (all attempts retained, ~1-2 MB per
 *   pair document). Loopback TCP only: one ephemeral proxy port + target.
 *
 * Cleanup (TASK_EXECUTION_AND_CLEANUP discipline; automatic)
 *   Every host-scoped resource is run-named in <gen>/harness-run.json:
 *   the in-process loopback fault proxy, smoke target child, driver child
 *   PIDs and sampler timers. The harness closes all of them on success,
 *   failure, verdict-fail and SIGINT/SIGTERM, then records the cleanup
 *   receipt in the ledger. hostQosChanges is always [] — this harness never
 *   touches pf, dummynet, qdisc or any host QoS state; the profile's network
 *   fault stages (bandwidth/latency/loss + fixed-mid-measurement outage) are
 *   applied by a run-owned in-process loopback proxy instead. That is the
 *   documented mechanism choice: disposable by construction, named in the
 *   ledger, and removed in the same run. If the process is killed hard, the
 *   retained ledger lists the exact outstanding PIDs/ports for manual,
 *   exact-target reconciliation.
 *
 * Results and reruns
 *   <output-root>/<run-id>/: harness-run.json (ledger), inputs/profile.json
 *   (frozen profile copy), pairs/pair-NN.json (all attempts), aggregate.json
 *   (results document + seal). An existing generation directory is NEVER
 *   overwritten — reruns get a new dated run-id. Gate enforcement (exit 3 on
 *   overall verdict fail) can be relaxed with --no-fail-on-regression for
 *   diagnostic reruns; the recorded verdicts never change.
 *
 * Driver event contract (stdout NDJSON from the member driver process)
 *   env in : E6_DRIVER_CONTRACT=1 E6_RUN_ID E6_PAIR_INDEX E6_MEMBER
 *            E6_FLAG E6_POLICY_MODE E6_FAULT_PROXY_URL E6_TARGET_URL
 *            E6_SCHEDULE(JSON) E6_ATTEMPT_TIMEOUT_MS
 *   events : {type:'process',role,pid}       for every profile-declared
 *            measured process role the driver owns
 *            (mailserver-gateway, setjoin-desktop-electron-main,
 *            setjoin-desktop-electron-renderer)
 *            {type:'phase',phase:'warmup'|'measurement'}
 *            {type:'saturation',active,activeDuringMeasurement}
 *            {type:'attempt',seq,class,outcome,latencyMs,stage,phase}
 *              outcome in completed|failed|timedOut|networkDrop
 *            {type:'done',measurementScheduled,...}
 *   stdout must stay content-free (no mail content, bearer tokens, credentialed
 *   URLs, or high-cardinality job/account IDs); exit 0 required.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn, spawnSync } from 'node:child_process';

let ACTIVE_RESOURCES = null;
const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const HARNESS_REL = 'scripts/run-connectivity-e6-harness.mjs';
// Initialized only by the CLI; importing the production proxy is inert.
let HARNESS_SHA256;
const DEFAULT_PROFILE_REL = 'docs/verification/connectivity-e6-profile.json';
const CASE_MANIFEST_REL = 'docs/verification/connectivity-aware-sync-cases.json';
const PROFILE_CASE_ID = 'CAS-E6-PROFILE-FROZEN';
const DEFAULT_OUTPUT_ROOT_REL = 'test-results/connectivity-aware-sync/e6-harness';
const DEFAULT_SMOKE_OUTPUT_ROOT_REL =
  'test-results/connectivity-aware-sync/e6-harness-smoke';
const MEASURED_ROLE_GATEWAY = 'mailserver-gateway';
const MEASURED_ROLE_MAIN = 'setjoin-desktop-electron-main';
const MEASURED_ROLE_RENDERER = 'setjoin-desktop-electron-renderer';
const OUTCOMES = ['completed', 'failed', 'timedOut', 'networkDrop'];

function fail(tag, message) {
  const error = new Error(`E6-HARNESS-${tag}: ${message}`);
  error.e6Tag = tag;
  throw error;
}

function log(message) {
  process.stderr.write(`e6-harness: ${message}\n`);
}

function sha256String(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function isoUtcNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

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

/** Nearest-rank percentile of an ascending-sorted array. */
function nearestRankPercentile(sortedAscending, percentile) {
  if (sortedAscending.length === 0) return null;
  const rank = Math.ceil((percentile / 100) * sortedAscending.length);
  return sortedAscending[Math.min(Math.max(rank, 1), sortedAscending.length) - 1];
}

function roundMs(value) {
  return value === null || value === undefined ? null : Math.round(value * 1000) / 1000;
}

function roundPercent(value) {
  return value === null || value === undefined || !Number.isFinite(value)
    ? null
    : Math.round(value * 1e6) / 1e6;
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function stableDeepEqual(a, b) {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((item, index) => stableDeepEqual(item, b[index]));
  }
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') {
    return false;
  }
  const keysA = Object.keys(a);
  const keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;
  return keysA.every(
    (key) => Object.prototype.hasOwnProperty.call(b, key) && stableDeepEqual(a[key], b[key]),
  );
}

function assertFiniteDeep(value, where) {
  if (typeof value === 'number' && !Number.isFinite(value)) {
    fail('SCHEMA', `non-finite number at ${where}`);
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertFiniteDeep(item, `${where}[${index}]`));
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) assertFiniteDeep(item, `${where}.${key}`);
  }
}

function gitReceipt() {
  const receipt = { available: false };
  const probe = (args) => {
    const result = spawnSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8' });
    return result.status === 0 ? result.stdout.trim() : null;
  };
  const commit = probe(['rev-parse', 'HEAD']);
  if (commit === null) return receipt;
  receipt.available = true;
  receipt.commit = commit;
  const status = probe(['status', '--porcelain']);
  receipt.dirtyFingerprint = sha256String(status ?? '');
  receipt.dirtyFileCount = status === null ? null : status.split('\n').filter(Boolean).length;
  return receipt;
}

function toolVersion(command, versionArgs) {
  const result = spawnSync(command, versionArgs, { encoding: 'utf8' });
  if (result.status !== 0) return null;
  return result.stdout.split('\n')[0].trim() || null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Frozen protocol constants — pinned against the profile document exactly.
// ---------------------------------------------------------------------------

const FROZEN_PROTOCOL = {
  minimumPairs: 20,
  randomizedPairOrder: true,
  identicalWorkloadPairs: true,
  warmupSeconds: 120,
  measurementSeconds: 300,
  minimumObservationsPerCriticalClassPerRun: 1000,
  percentileMethod: 'nearest-rank',
  bootstrap: { resamples: 10000, method: 'paired', bound: 'upper-one-sided-95' },
  failureAccounting: 'separate-attempts-retained',
};

const FROZEN_CEILING_KEYS = [
  'criticalP95MaxPercent',
  'criticalP95MaxMilliseconds',
  'criticalP99MaxPercent',
  'criticalP99MaxMilliseconds',
  'peakCpuRssMaxPercent',
];

function validateFrozenProfile(selected, document_) {
  for (const [key, value] of Object.entries(FROZEN_PROTOCOL)) {
    const actual = JSON.stringify(document_.protocol?.[key]);
    const expected = JSON.stringify(value);
    if (actual !== expected) {
      fail('PROFILE', `frozen protocol field ${key} must be ${expected}, found ${actual}`);
    }
  }
  for (const key of FROZEN_CEILING_KEYS) {
    if (typeof document_.regressionCeilings?.[key] !== 'number') {
      fail('PROFILE', `frozen regression ceiling ${key} missing or not numeric`);
    }
  }
  if (document_.freezeSemantics?.postResultChangesProhibited !== true) {
    fail('PROFILE', 'freezeSemantics.postResultChangesProhibited must be true');
  }
  if (selected.status !== 'frozen') {
    fail('PROFILE', `selected profile status must be "frozen", found "${selected.status}"`);
  }
  attemptsPerClass(selected, FROZEN_PROTOCOL.minimumObservationsPerCriticalClassPerRun);
}

function attemptsPerClass(selected, floor) {
  const budget = selected.attemptsPerCriticalClassPerRun;
  // Historical v1 schedules are immutable. New comparisons freeze attempted
  // load separately from the completed-observation floor before any execution.
  if (selected.profileVersion === 1 && budget === undefined) return floor;
  if (selected.profileVersion < 2 || !Number.isSafeInteger(budget) || budget <= floor) {
    fail('PROFILE', 'a new profileVersion >= 2 must freeze attemptsPerCriticalClassPerRun above the completed-observation floor');
  }
  return budget;
}

function loadProfile(profileArg, { mode }) {
  const profilePath = path.isAbsolute(profileArg) ? profileArg : path.join(REPO_ROOT, profileArg);
  if (!fs.existsSync(profilePath)) {
    fail('PROFILE', `profile document not found: ${profileArg}`);
  }
  const profileBytes = fs.readFileSync(profilePath);
  const document_ = JSON.parse(profileBytes.toString('utf8'));
  const digest = crypto.createHash('sha256').update(profileBytes).digest('hex');
  const selected = (document_.profiles ?? []).find(
    (candidate) => candidate.platform === 'electron-macos',
  );
  if (!selected) {
    fail('PROFILE', 'no explicitly selected electron-macos profile in document');
  }
  validateFrozenProfile(selected, document_);
  const manifestBinding = readManifestBinding(digest, mode);
  return {
    document: document_,
    selected,
    digest,
    path: profilePath,
    relPath: path.relative(REPO_ROOT, profilePath),
    manifestBinding,
  };
}

function readManifestBinding(profileDigest, mode) {
  const manifestPath = path.join(REPO_ROOT, CASE_MANIFEST_REL);
  const binding = {
    manifestPath: CASE_MANIFEST_REL,
    present: fs.existsSync(manifestPath),
    caseId: PROFILE_CASE_ID,
    pinnedFixtureDigest: null,
    match: null,
  };
  if (!binding.present) {
    if (mode === 'evidence') fail('BINDING', `case manifest missing: ${CASE_MANIFEST_REL}`);
    return binding;
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const kase = (manifest.cases ?? []).find((entry) => entry.id === PROFILE_CASE_ID);
  if (!kase) {
    if (mode === 'evidence') {
      fail('BINDING', `case ${PROFILE_CASE_ID} absent from ${CASE_MANIFEST_REL}`);
    }
    return binding;
  }
  binding.pinnedFixtureDigest = kase.fixtureDigest ?? null;
  binding.match = binding.pinnedFixtureDigest === profileDigest;
  if (mode === 'evidence' && !binding.match) {
    fail(
      'BINDING',
      `profile digest ${profileDigest} does not match the manifest-pinned ` +
        `fixtureDigest ${binding.pinnedFixtureDigest}; a changed profile needs a ` +
        'new profileVersion and manifest rebinding before any results qualify',
    );
  }
  return binding;
}

// ---------------------------------------------------------------------------
// Run plan: schedule, stages, outage, class mix. Deterministic from seeds.
// ---------------------------------------------------------------------------

export function buildPlan({ selected, seeds, pairs, smoke, smokeProfile }) {
  const classes = selected.criticalRequestClasses.map((entry) => entry.class);
  const totalMix = selected.criticalRequestClasses.reduce((sum, entry) => sum + entry.mixPercent, 0);
  if (totalMix !== 100) fail('PROFILE', `critical class mix sums to ${totalMix}, not 100`);
  const protocol = smoke
    ? {
        ...FROZEN_PROTOCOL,
        warmupSeconds: smokeProfile.warmupSeconds,
        measurementSeconds: smokeProfile.measurementSeconds,
        minimumObservationsPerCriticalClassPerRun: smokeProfile.observationFloor,
      }
    : FROZEN_PROTOCOL;

  const warmupMs = protocol.warmupSeconds * 1000;
  const measurementMs = protocol.measurementSeconds * 1000;
  const floorPerClass = protocol.minimumObservationsPerCriticalClassPerRun;
  const totalAttempts = (smoke ? floorPerClass : attemptsPerClass(selected, floorPerClass)) * classes.length;
  const attemptIntervalMs = measurementMs / totalAttempts;
  if (!Number.isInteger(attemptIntervalMs) || attemptIntervalMs < 10) {
    fail('PLAN', `attempt interval ${attemptIntervalMs}ms is not an integer >= 10ms`);
  }
  const warmupAttempts = Math.floor(warmupMs / attemptIntervalMs);

  const scheduleRng = rngFromSeed(`${seeds.run}:schedule`);
  const classSequence = [];
  while (classSequence.length < totalAttempts) {
    const cycle = [...classes];
    for (let i = cycle.length - 1; i > 0; i -= 1) {
      const j = randomInt(scheduleRng, i + 1);
      [cycle[i], cycle[j]] = [cycle[j], cycle[i]];
    }
    classSequence.push(...cycle);
  }
  classSequence.length = totalAttempts;

  const stageBlocks = [];
  const stageCount = selected.networkFaults.stages.length;
  const blockMs = Math.floor(measurementMs / stageCount);
  selected.networkFaults.stages.forEach((stage, index) => {
    const startMs = index * blockMs;
    const durationMs = index === stageCount - 1 ? measurementMs - startMs : blockMs;
    stageBlocks.push({
      stage: index,
      name: stage.name,
      startMs,
      durationMs,
      bandwidthKbit: stage.bandwidthKbit,
      latencyMs: stage.latencyMs,
      lossPercent: stage.lossPercent,
    });
  });
  const outage = selected.networkFaults.outage;
  if (outage.schedule !== 'fixed-mid-measurement') {
    fail('PROFILE', `unsupported outage schedule ${outage.schedule}`);
  }
  const outagePlan = {
    startMs: Math.floor(measurementMs / 2),
    durationMs: outage.durationSeconds * 1000,
    reconnectWithinMs: outage.reconnectWithinSeconds * 1000,
  };

  const orderRng = rngFromSeed(seeds.order);
  const pairOrders = [];
  for (let index = 0; index < pairs; index += 1) {
    pairOrders.push(orderRng() < 0.5 ? 'comparator-first' : 'candidate-first');
  }

  // Built-in synthetic fault probes live only in the measurement seq range so
  // the timeout and server-failure accounting paths are always exercised.
  // They exist for the smoke reference workload only.
  const hangProbeIndexes = new Set();
  const failProbeIndexes = new Set();
  if (smoke) {
    const builtinFaultRng = rngFromSeed(`${seeds.run}:builtin-faults`);
    while (hangProbeIndexes.size < 2) {
      hangProbeIndexes.add(warmupAttempts + randomInt(builtinFaultRng, totalAttempts - warmupAttempts));
    }
    while (failProbeIndexes.size < 2) {
      failProbeIndexes.add(warmupAttempts + randomInt(builtinFaultRng, totalAttempts - warmupAttempts));
    }
  }

  const schedule = {
    attemptIntervalMs,
    warmupMs,
    warmupAttempts,
    measurementMs,
    classSequence,
    stageBlocks,
    outage: outagePlan,
    observationFloorPerClassPerRun: floorPerClass,
    classes,
    builtin: {
      hangProbeIndexes: [...hangProbeIndexes].sort((a, b) => a - b),
      failProbeIndexes: [...failProbeIndexes].sort((a, b) => a - b),
    },
  };
  const scheduleDigest = sha256String(JSON.stringify(schedule));
  return {
    protocol,
    classes,
    schedule,
    scheduleDigest,
    pairOrders,
    smoke,
    seeds,
    measuredRoles: selected.processMetricBoundaries.measuredProcesses,
    // Candidate transport seam (scheme v4 §2.3.2): the declared candidate-
    // optional population per window, read from the profile's frozen
    // harnessInstrument workload declaration when the entry carries one.
    // Null for v1/v2 — consumption asserts candidate-optional-through-proxy
    // equals it ONLY when declared, so retained generations validate
    // unchanged. Schedule construction is untouched (v1 schedule digest
    // invariance, scheme §5.3).
    declaredOptionalPopulation: declaredOptionalPopulation(selected),
  };
}

/** Read the declared candidate-optional population from a profile entry's
 *  harnessInstrument workload declaration (scheme v4 §2.3.2 consumption
 *  assertion's declared side; the checker-side schema for harnessInstrument
 *  itself is §3.6's own prerequisite). Null when the entry declares none. */
function declaredOptionalPopulation(selected) {
  const declared = selected?.harnessInstrument?.workload?.candidateOptionalRequestsPerWindow;
  if (declared === undefined) return null;
  if (!Number.isInteger(declared) || declared < 0) {
    fail(
      'PROFILE',
      `harnessInstrument.workload.candidateOptionalRequestsPerWindow must be a non-negative integer, got ${JSON.stringify(declared)}`,
    );
  }
  return declared;
}

function stageBlockAt(schedule, offsetMs) {
  const block = schedule.stageBlocks.find(
    (candidate) => offsetMs >= candidate.startMs && offsetMs < candidate.startMs + candidate.durationMs,
  );
  return block ?? schedule.stageBlocks[schedule.stageBlocks.length - 1];
}

function outageActiveAt(schedule, offsetMs) {
  const { outage } = schedule;
  return offsetMs >= outage.startMs && offsetMs < outage.startMs + outage.durationMs;
}

// ---------------------------------------------------------------------------
// In-process loopback fault proxy — the documented mechanism choice.
// Applies bandwidth / latency / loss / outage on loopback only. No host
// pf/dummynet/qdisc state is read or written (hostQosChanges stays []).
// ---------------------------------------------------------------------------

// RFC 9110 §7.6.1 (Hop-by-Hop Fields): these fields are defined to apply only
// to a single transport-level connection and MUST be removed by a proxy
// before a message is forwarded; a field named by the received `connection`
// header is stripped dynamically in stripHopByHopHeaders. `proxy-connection`
// (RFC 9112 §7.9) is included as the de-facto member of the same class. The
// upstream response's `transfer-encoding` describes the upstream connection's
// framing, never this proxy's client-facing response: re-asserting it makes
// the forwarded framing field collide with the body this proxy writes
// (instrument defect observed in the field as e6h-20260921t183646z, where
// every forwarded attempt failed the client-side body read and classified
// networkDrop while the proxy itself recorded 0 upstream errors).
const HOP_BY_HOP_HEADERS = Object.freeze([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/**
 * RFC 9110 §7.6.1: build the forwardable header object by removing every
 * hop-by-hop field (plus each field named by the received `connection`
 * header). End-to-end fields are preserved verbatim — in particular
 * `content-length` stays because the body is piped through byte-for-byte and
 * the declared length remains accurate; when `transfer-encoding` is stripped
 * and no `content-length` exists, this proxy's HTTP server applies its own
 * (single, correct) chunked framing.
 */
function stripHopByHopHeaders(headers) {
  const forwarded = { ...headers };
  for (const name of HOP_BY_HOP_HEADERS) delete forwarded[name];
  for (const token of String(headers.connection ?? '').split(',')) {
    const field = token.trim().toLowerCase();
    if (field) delete forwarded[field];
  }
  return forwarded;
}

// The ONE shared FaultProxy configuration for every member window's proxy
// (scheme v4 §2.3.2, candidate transport seam): both windows of a pair — and
// the comparator saturation instrument's v3 delivery path, which freezes onto
// the same mechanism — construct from THIS object, so every proxy in a run
// carries one config digest, recorded in both windows' receipts and asserted
// equal at consumption (E6-PROXY-SEAM). Digest computation is deliberately
// lazy (FaultProxy constructor): module import must stay inert
// (run-connectivity-e6-harness.import.test.mjs forbids import-time hashing).
const PROXY_CONFIG = Object.freeze({
  // RFC 9110 §7.6.1 request- and response-side stripping (stripHopByHopHeaders).
  hopByHopStripping: 'rfc9110-7.6.1-connection-named',
  // The serialized metered-write chain slices bodies into this many bytes per
  // takeTokens-metered write (the e6h-20260921t183646z body-drop fix).
  meteredWriteChunkBytes: 1400,
  // Per-basis attribution (scheme v4 §2.3.2 closure report): every proxied
  // request names the population that issued it on this header, and the
  // receipt's closure report breaks requestsReceived down per basis. The
  // workload driver and the internal reference simulator mark
  // `driver-attempt`; the v3 instrument marks `instrument-request`; the
  // candidate's optional-job transport (its window's proxy) marks
  // `candidate-optional`. Unattributed proxied traffic fails closed at
  // consumption — attribution by assumption is exactly what the scheme forbids.
  attributionHeader: 'x-e6-proxy-source',
  attributionBases: Object.freeze({
    'driver-attempt': 'driverAttempts',
    'instrument-request': 'instrumentRequests',
    'candidate-optional': 'candidateOptional',
  }),
  // Proxy-owned drain checks (scheme v4 proxy-drain block): stop() drains up
  // to this deadline before snapshotting pending/unsettled attempts and
  // still-registered upstreams — the quiescence protocol's inflight-at-exit
  // evidence (§2.3.1 check 7's proxy half).
  drainSettleDeadlineMs: 2000,
});

class FaultProxy {
  constructor({ schedule, seeds, targetUrl, windowOriginMonotonicMs, config = PROXY_CONFIG }) {
    this.schedule = schedule;
    this.seeds = seeds;
    this.target = new URL(targetUrl);
    this.windowOriginMonotonicMs = windowOriginMonotonicMs;
    this.config = config;
    this.configDigest = sha256String(JSON.stringify(config));
    this.server = null;
    this.sockets = new Set();
    this.upstreams = new Set();
    this.bucketTokens = 0;
    this.bucketLastRefillMs = 0;
    // Attempts received but not yet terminally settled (proxy-owned drain
    // evidence): incremented at receipt, decremented at exactly-once settle.
    this.pending = 0;
    this.drain = null;
    this.stats = {
      requestsReceived: 0,
      forwarded: 0,
      droppedLoss: 0,
      droppedOutage: 0,
      upstreamErrors: 0,
      clientAborts: 0,
    };
    this.requestsByBasis = {
      driverAttempts: 0,
      instrumentRequests: 0,
      candidateOptional: 0,
      unattributed: 0,
    };
  }

  async start() {
    this.server = http.createServer((request, response) => this.handle(request, response));
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

  elapsedWindowMs() {
    return performance.now() - this.windowOriginMonotonicMs;
  }

  currentStage() {
    const elapsed = this.elapsedWindowMs();
    const { warmupMs, measurementMs } = this.schedule;
    if (elapsed < warmupMs) {
      // Warmup cycles the same stage blocks from t=0 (never an outage); the
      // frozen outage applies only inside the measurement window.
      return stageBlockAt(this.schedule, elapsed % measurementMs);
    }
    const measurementOffset = Math.min(elapsed - warmupMs, measurementMs - 1);
    return stageBlockAt(this.schedule, measurementOffset);
  }

  outageActive() {
    const elapsed = this.elapsedWindowMs();
    if (elapsed < this.schedule.warmupMs) return false;
    return outageActiveAt(this.schedule, elapsed - this.schedule.warmupMs);
  }

  refillBucket() {
    const bytesPerMs = (this.currentStage().bandwidthKbit * 1000) / 8 / 1000;
    const now = performance.now();
    const elapsedMs = this.bucketLastRefillMs === 0 ? 25 : Math.max(now - this.bucketLastRefillMs, 0);
    this.bucketLastRefillMs = now;
    this.bucketTokens = Math.min(this.bucketTokens + bytesPerMs * elapsedMs, bytesPerMs * 1000);
  }

  async takeTokens(bytes) {
    this.refillBucket();
    const bytesPerMs = (this.currentStage().bandwidthKbit * 1000) / 8 / 1000;
    while (this.bucketTokens < bytes) {
      await sleep(5);
      this.refillBucket();
    }
    this.bucketTokens -= bytes;
  }

  handle(request, response) {
    this.stats.requestsReceived += 1;
    this.pending += 1;
    // Per-basis attribution at receipt (scheme v4 §2.3.2): classification is
    // a receipt-time fact about the request, independent of how the attempt
    // later settles — injected drops and aborts stay attributed.
    const basisToken = request.headers[this.config.attributionHeader];
    const basisKey =
      typeof basisToken === 'string' ? this.config.attributionBases[basisToken] : undefined;
    if (basisKey !== undefined) this.requestsByBasis[basisKey] += 1;
    else this.requestsByBasis.unattributed += 1;

    const stage = this.currentStage();
    response.setHeader('x-e6-fault-stage', stage.name);

    // Terminal accounting installed AT RECEIPT (scheme v4 proxy-drain block —
    // previously the accounting chain was constructed only inside the latency
    // timer, so a client that disconnected during `stage.latencyMs` returned
    // here with requestsReceived incremented and EVERY terminal counter at
    // zero, and the upstream was never even created). From this point every
    // attempt settles through exactly one terminal kind — `forwarded`,
    // `upstreamError`, `clientAbort`, or the injected `droppedLoss` /
    // `droppedOutage` — and the pending counter above returns to zero.
    let settled = false;
    let upstream = null;
    const settleOnce = () => {
      if (settled) return false;
      settled = true;
      this.pending -= 1;
      return true;
    };
    // Successful attempts settle ONLY on the response's 'finish' event — the
    // point where the response's headers and body have been handed off to the
    // operating system for transmission (the client-visible bytes are
    // committed). Invariant: proxy `forwarded` implies every declared body
    // byte was committed to the transport before settlement.
    // finishAttempt('forwarded') is reachable only from a cleanly ended,
    // well-framed upstream response (a misframed one routes to upstreamError
    // via the upstream response-'error' handler), so once 'finish' fires the
    // driver's body read can no longer fail as networkDrop on this proxy's
    // account — the proxy and driver classifications agree by ordering, with
    // no counter-before-completion window. Exactly-once with every failure
    // path via the settleOnce guard below.
    response.once('finish', () => {
      if (!settleOnce()) return;
      this.stats.forwarded += 1;
    });
    // Exactly-once terminal accounting: the guard makes the terminal increment
    // idempotent even if several failure paths fire for the same attempt — a
    // response must never be counted forwarded when a failure arm already
    // claimed it, and vice versa. The successful path settles at 'finish'
    // (above), so finishAttempt('forwarded') only initiates the downstream
    // completion; counting forwarded here — BEFORE response.end() and its
    // flush — was the classification disagreement window a round-2 review
    // found (a close during the final flush kept `forwarded` counted while
    // the driver's body read failed as networkDrop).
    const finishAttempt = (kind) => {
      if (kind === 'forwarded') {
        if (!response.socket.destroyed) response.end();
        return;
      }
      if (!settleOnce()) return;
      if (kind === 'clientAbort') {
        this.stats.clientAborts += 1;
        return;
      }
      this.stats.upstreamErrors += 1;
      if (!response.socket.destroyed) response.socket.destroy();
    };
    // The injected loss/outage drops settle at receipt, before the upstream
    // exchange exists — they are terminal kinds of the same ledger, and the
    // socket destroy below must not re-enter the cancellation route as an
    // abort.
    const finishDrop = (kind) => {
      if (!settleOnce()) return;
      this.stats[kind] += 1;
      response.socket.destroy();
    };

    // Downstream-disconnect cancellation routing (scheme v4 proxy-drain
    // block): a close before the response finished is a clientAbort — both
    // BEFORE end() (mid-response, or during the stage latency window) and
    // AFTER end() but before 'finish' (the final flush never completed: the
    // client-visible response is incomplete, so the attempt must never count
    // as forwarded — the blanket `writableEnded` early-return previously left
    // that sub-case unsettled). A completed response already settled at
    // 'finish', so its 'close' is a no-op via the exactly-once guard, and the
    // in-flight upstream exchange is destroyed with the attempt — previously
    // the upstream lifecycle handlers registered no downstream cancellation,
    // so a disconnect while upstream headers were pending left the upstream
    // registered and undestroyed.
    response.once('close', () => {
      if (!settleOnce()) return;
      this.stats.clientAborts += 1;
      if (upstream !== null && !upstream.destroyed) upstream.destroy();
    });

    if (this.outageActive()) {
      finishDrop('droppedOutage');
      return;
    }
    if (stage.lossPercent > 0) {
      const lossRng = rngFromSeed(
        `loss:${this.seeds.run}:${this.stats.requestsReceived}`,
      );
      if (lossRng() * 100 < stage.lossPercent) {
        finishDrop('droppedLoss');
        return;
      }
    }
    setTimeout(() => {
      // The client may have disconnected during this latency window: the
      // cancellation route above already settled the attempt (clientAbort)
      // and no upstream exchange may start for it.
      if (settled) return;
      upstream = http.request(
        {
          host: this.target.hostname,
          port: this.target.port,
          path: request.url,
          method: request.method,
          // Request-side RFC 9110 §7.6.1 stripping (same helper as the
          // response side below): hop-by-hop fields — `te`,
          // `proxy-authorization`, `proxy-authenticate`, `trailer`,
          // `upgrade`, and every field nominated by the request's own
          // `connection` header — describe the client-to-proxy hop only and
          // MUST NOT leak upstream. The proxy's own `host` and single-hop
          // `connection: close` are asserted after the strip; end-to-end
          // fields (content-length, custom fields) pass verbatim so the
          // piped request body keeps its declared framing.
          headers: {
            ...stripHopByHopHeaders(request.headers),
            host: this.target.host,
            connection: 'close',
          },
        },
        (upstreamResponse) => {
          response.writeHead(
            upstreamResponse.statusCode ?? 502,
            stripHopByHopHeaders(upstreamResponse.headers),
          );
          // Body forwarding is serialized through one promise chain per
          // response: each chunk's bandwidth-metered write is asynchronous
          // (takeTokens sleeps the event loop), so without the chain a small
          // single-segment upstream response emits 'data' and 'end' in the
          // same tick — 'end' then calls response.end() before the chunk's
          // write resumes, the write-after-end failure vanishes into the
          // catch below, and the client receives headers + content-length
          // with NO body (undici: ResponseContentLengthMismatchError — the
          // all-networkDrop instrument defect of e6h-20260921t183646z). The
          // chain also keeps multi-chunk bodies in order under throttling.
          //
          // The chain never rejects: a client-socket close during the
          // asynchronous takeTokens/drain waits sets `chainFailed`, so the
          // 'end' continuation routes the attempt to the failure arm
          // (clientAbort) instead of `forwarded` — a response that wrote
          // zero wire bytes must not be counted as forwarded.
          let bodyWrites = Promise.resolve();
          let chainFailed = false;
          upstreamResponse.on('data', (chunk) => {
            bodyWrites = bodyWrites.then(async () => {
              let offset = 0;
              while (offset < chunk.length && !chainFailed) {
                if (response.socket.destroyed) {
                  chainFailed = true;
                  return;
                }
                const slice = chunk.subarray(
                  offset,
                  Math.min(offset + this.config.meteredWriteChunkBytes, chunk.length),
                );
                await this.takeTokens(slice.length);
                if (response.socket.destroyed) {
                  // Close during takeTokens: the attempt is a failure
                  // (client abort), never a forwarded response.
                  chainFailed = true;
                  return;
                }
                if (!response.write(slice)) {
                  // Wait for drain, but race it against the client socket
                  // dying ('close') so the chain always settles and the
                  // terminal accounting above stays exactly-once.
                  await new Promise((resolve) => {
                    const settle = () => {
                      response.off('drain', settle);
                      response.off('close', settle);
                      resolve();
                    };
                    response.once('drain', settle);
                    response.once('close', settle);
                  });
                }
                offset += slice.length;
              }
            });
          });
          upstreamResponse.on('end', () => {
            bodyWrites.then(() => {
              if (chainFailed) {
                // The write chain ended without delivering the full body
                // (the client went away mid-body): the attempt is an
                // accounted abort, never a half-response.
                finishAttempt('clientAbort');
                return;
              }
              finishAttempt('forwarded');
            });
          });
          upstreamResponse.on('error', () => finishAttempt('upstreamError'));
        },
      );
      upstream.on('error', () => finishAttempt('upstreamError'));
      this.upstreams.add(upstream);
      request.pipe(upstream);
      upstream.on('close', () => this.upstreams.delete(upstream));
    }, stage.latencyMs);
  }

  async stop() {
    // Proxy-owned drain checks (scheme v4 proxy-drain block + §2.3.1 check 7's
    // proxy half): drain BEFORE teardown — give unsettled attempts and
    // still-registered upstreams the configured deadline to settle — then
    // snapshot the honest pre-teardown state. The snapshot is frozen evidence
    // (the window receipt carries it; runMember refuses the run when ok is
    // false, and consumption re-asserts it), so the post-snapshot forced
    // teardown below must not mutate it: values are copied, not referenced.
    const drainDeadline = performance.now() + this.config.drainSettleDeadlineMs;
    while ((this.pending > 0 || this.upstreams.size > 0) && performance.now() < drainDeadline) {
      await sleep(10);
    }
    const terminalSettled =
      this.stats.forwarded +
      this.stats.upstreamErrors +
      this.stats.clientAborts +
      this.stats.droppedLoss +
      this.stats.droppedOutage;
    this.drain = Object.freeze({
      requestsReceived: this.stats.requestsReceived,
      terminalSettled,
      pending: this.pending,
      upstreamsRegistered: this.upstreams.size,
      waitedMs: roundMs(this.config.drainSettleDeadlineMs - Math.max(drainDeadline - performance.now(), 0)),
      ok: this.pending === 0 && this.upstreams.size === 0,
    });
    for (const upstream of this.upstreams) upstream.destroy();
    this.upstreams.clear();
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    if (this.server) {
      await new Promise((resolve) => this.server.close(() => resolve()));
      this.server = null;
    }
  }
}

// Exported for scripts/run-connectivity-e6-harness.proxy.test.mjs, which
// drives the real proxy class against stub upstreams (hop-by-hop framing
// regression arms). Importing this module as a library is only safe with an
// inert CLI guard: push `--help` onto process.argv before the dynamic import
// so the module's entry guard routes to usage() and returns without touching
// the filesystem or network.
export { FaultProxy, HOP_BY_HOP_HEADERS, PROXY_CONFIG, stripHopByHopHeaders };

// ---------------------------------------------------------------------------
// Smoke loopback target — content-free synthetic workload endpoint, run as a
// child process so the smoke cross-process metric capture samples three
// genuinely distinct PIDs.
// ---------------------------------------------------------------------------

class SmokeTarget {
  constructor({ failProbeIndexes, hangProbeIndexes }) {
    this.failProbeIndexes = failProbeIndexes instanceof Set ? failProbeIndexes : new Set(failProbeIndexes);
    this.hangProbeIndexes = hangProbeIndexes instanceof Set ? hangProbeIndexes : new Set(hangProbeIndexes);
    this.server = null;
    this.sockets = new Set();
    this.stats = { requests: 0, ok: 0, failed: 0, hang: 0 };
  }

  async start() {
    this.server = http.createServer((request, response) => {
      this.stats.requests += 1;
      const url = new URL(request.url, 'http://127.0.0.1');
      const seq = Number(url.searchParams.get('seq') ?? '-1');
      this.sockets.add(response.socket);
      response.socket.on('close', () => this.sockets.delete(response.socket));
      if (url.pathname === '/hang' || this.hangProbeIndexes.has(seq)) {
        this.stats.hang += 1;
        setTimeout(() => {
          if (!response.socket.destroyed) response.end('late');
        }, 30_000).unref?.();
        return;
      }
      if (this.failProbeIndexes.has(seq)) {
        this.stats.failed += 1;
        response.writeHead(500, { 'content-type': 'application/json' });
        response.end('{"error":"e6-smoke-synthetic-failure"}');
        return;
      }
      this.stats.ok += 1;
      setTimeout(() => {
        if (!response.socket.destroyed) {
          response.writeHead(200, { 'content-type': 'application/json' });
          response.end('{"ok":true}');
        }
      }, 5);
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

function runInternalSmokeTarget() {
  const config = JSON.parse(process.env.E6_SMOKE_TARGET_CONFIG);
  const target = new SmokeTarget(config);
  target
    .start()
    .then(() => {
      process.stdout.write(`${JSON.stringify({ type: 'ready', endpoint: target.endpoint, pid: process.pid })}\n`);
    })
    .catch((error) => {
      process.stderr.write(`smoke-target: ${error.message}\n`);
      process.exit(1);
    });
  process.on('SIGTERM', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
  setInterval(() => {}, 60_000); // hold the event loop until killed
}

// ---------------------------------------------------------------------------
// Process metric sampler — ps-based CPU% / RSS peaks at the profile interval.
// ---------------------------------------------------------------------------

class ProcessSampler {
  constructor(intervalMs) {
    this.intervalMs = intervalMs;
    this.roles = new Map();
    this.timer = null;
    this.finished = false;
  }

  addRole(role, pid) {
    if (!this.roles.has(role)) {
      this.roles.set(role, { pid, samples: 0, peakCpuPercent: 0, peakRssBytes: 0, lastError: null });
    }
  }

  start() {
    if (this.timer || this.finished) return;
    this.tick();
    this.timer = setInterval(() => this.tick(), this.intervalMs);
  }

  tick() {
    if (this.finished) return;
    for (const entry of this.roles.values()) {
      const result = spawnSync('ps', ['-o', '%cpu=,rss=', '-p', String(entry.pid)], {
        encoding: 'utf8',
        env: { ...process.env, LC_ALL: 'C' },
      });
      if (result.status !== 0 || !result.stdout.trim()) {
        entry.lastError = `ps exited ${result.status}`;
        continue;
      }
      const [cpuText, rssText] = result.stdout.trim().split(/\s+/);
      const cpu = Number.parseFloat(cpuText);
      const rssKb = Number.parseFloat(rssText);
      if (!Number.isFinite(cpu) || !Number.isFinite(rssKb)) {
        entry.lastError = `unparsable ps output: ${result.stdout.trim()}`;
        continue;
      }
      entry.samples += 1;
      entry.peakCpuPercent = Math.max(entry.peakCpuPercent, cpu);
      entry.peakRssBytes = Math.max(entry.peakRssBytes, Math.round(rssKb * 1024));
    }
  }

  stop() {
    this.finished = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  result() {
    const snapshot = {};
    for (const [role, entry] of this.roles) {
      snapshot[role] = {
        pid: entry.pid,
        sampleCount: entry.samples,
        peakCpuPercent: roundPercent(entry.peakCpuPercent),
        peakRssBytes: entry.peakRssBytes,
        lastError: entry.lastError,
      };
    }
    return snapshot;
  }
}

// ---------------------------------------------------------------------------
// Built-in member simulator (reference driver-contract implementation).
// Runs as a CHILD process via --internal-member-simulator; smoke-only.
// ---------------------------------------------------------------------------

function runInternalMemberSimulator() {
  const schedule = JSON.parse(process.env.E6_SCHEDULE);
  const proxyUrl = process.env.E6_FAULT_PROXY_URL;
  const targetUrl = process.env.E6_TARGET_URL;
  const timeoutMs = Number(process.env.E6_ATTEMPT_TIMEOUT_MS);
  const isCandidate = process.env.E6_MEMBER === 'candidate';
  const hangProbeIndexes = new Set(schedule.builtin.hangProbeIndexes);
  const failProbeIndexes = new Set(schedule.builtin.failProbeIndexes);

  const emit = (event) => process.stdout.write(`${JSON.stringify(event)}\n`);
  emit({ type: 'process', role: MEASURED_ROLE_MAIN, pid: process.pid });
  emit({
    type: 'process',
    role: process.env.E6_SYNTHETIC_GATEWAY_ROLE,
    pid: Number(process.env.E6_SYNTHETIC_GATEWAY_PID),
  });
  emit({
    type: 'process',
    role: process.env.E6_SYNTHETIC_RENDER_ROLE,
    pid: Number(process.env.E6_SYNTHETIC_RENDER_PID),
  });

  async function fireAttempt({ seq, className, phase, offsetMs }) {
    const measurementOffset = phase === 'measurement' ? offsetMs : offsetMs % schedule.measurementMs;
    const stage = stageBlockAt(schedule, measurementOffset).name;
    const urlPath = hangProbeIndexes.has(seq)
      ? '/hang'
      : `/attempt?seq=${seq}&class=${className}`;
    const started = performance.now();
    try {
      const response = await fetch(`${proxyUrl}${urlPath}`, {
        method: 'POST',
        // Per-basis attribution (PROXY_CONFIG.attributionHeader): the driver
        // population marks itself so the proxy closure report attributes
        // every attempt exactly (scheme v4 §2.3.2).
        headers: { 'content-type': 'application/json', [PROXY_CONFIG.attributionHeader]: 'driver-attempt' },
        body: JSON.stringify({ class: className, phase }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      await response.arrayBuffer();
      const latencyMs = roundMs(performance.now() - started);
      if (response.ok) {
        emit({ type: 'attempt', seq, class: className, outcome: 'completed', latencyMs, stage, phase });
      } else {
        emit({ type: 'attempt', seq, class: className, outcome: 'failed', latencyMs, stage, phase });
      }
    } catch (error) {
      const latencyMs = roundMs(performance.now() - started);
      if (error.name === 'TimeoutError' || error.name === 'AbortError') {
        emit({ type: 'attempt', seq, class: className, outcome: 'timedOut', latencyMs, stage, phase });
      } else {
        emit({ type: 'attempt', seq, class: className, outcome: 'networkDrop', latencyMs, stage, phase });
      }
    }
  }

  (async () => {
    emit({ type: 'phase', phase: 'warmup' });
    if (!isCandidate) {
      emit({ type: 'saturation', active: false, activeDuringMeasurement: false, note: 'flag-off-comparator-admits-no-optional-work' });
    }
    const warmupStart = performance.now();
    const warmupInflight = [];
    for (let index = 0; index < schedule.warmupAttempts; index += 1) {
      const due = warmupStart + index * schedule.attemptIntervalMs;
      const now = performance.now();
      if (due > now) await sleep(due - now);
      warmupInflight.push(
        fireAttempt({
          seq: index,
          className: schedule.classSequence[index % schedule.classSequence.length],
          phase: 'warmup',
          offsetMs: index * schedule.attemptIntervalMs,
        }),
      );
    }
    await Promise.allSettled(warmupInflight);
    emit({ type: 'phase', phase: 'measurement' });
    emit({
      type: 'saturation',
      active: isCandidate,
      activeDuringMeasurement: isCandidate,
      note: isCandidate ? 'builtin-smoke-synthetic-saturation-marker' : 'flag-off-comparator-admits-no-optional-work',
    });
    const measurementStart = performance.now();
    const inflight = [];
    for (let index = 0; index < schedule.classSequence.length; index += 1) {
      const due = measurementStart + index * schedule.attemptIntervalMs;
      const now = performance.now();
      if (due > now) await sleep(due - now);
      inflight.push(
        fireAttempt({
          seq: index,
          className: schedule.classSequence[index],
          phase: 'measurement',
          offsetMs: index * schedule.attemptIntervalMs,
        }),
      );
    }
    await Promise.allSettled(inflight);
    emit({
      type: 'done',
      warmupScheduled: schedule.warmupAttempts,
      measurementScheduled: schedule.classSequence.length,
    });
    process.exit(0);
  })().catch((error) => {
    process.stderr.write(`member-simulator: ${error?.stack ?? error}\n`);
    process.exit(1);
  });
}

// ---------------------------------------------------------------------------
// Driver spawn + NDJSON event collection.
// ---------------------------------------------------------------------------

function memberEnv({ member, pairIndex, runId, proxyEndpoint, targetUrl, schedule, attemptTimeoutMs, extra }) {
  const env = {
    ...process.env,
    E6_DRIVER_CONTRACT: '1',
    E6_RUN_ID: runId,
    E6_PAIR_INDEX: String(pairIndex),
    E6_MEMBER: member,
    E6_FLAG: member === 'candidate' ? 'on' : 'off',
    E6_POLICY_MODE: member === 'candidate' ? 'execute' : 'off',
    E6_FAULT_PROXY_URL: proxyEndpoint,
    E6_TARGET_URL: targetUrl,
    E6_SCHEDULE: JSON.stringify(schedule),
    E6_ATTEMPT_TIMEOUT_MS: String(attemptTimeoutMs),
    ...extra,
  };
  // Candidate transport seam (scheme v4 §2.3.2): the CANDIDATE window's
  // optional-job gateway origin IS its window's FaultProxy listener — the
  // same proxy config object the comparator instrument's delivery path
  // freezes onto (PROXY_CONFIG above; config digest equality is recorded in
  // both windows' receipts). Candidate-only: the flag-off comparator admits
  // no optional work, so its child env never carries the seam. The launcher's
  // driver wrapper validates the loopback origin and forwards it as
  // E6_OPTIONAL_JOB_ORIGIN; readiness/boot traffic keeps targeting the real
  // gateway origin (E6_TARGET_URL) untouched.
  if (member === 'candidate') {
    env.E6_CANDIDATE_OPTIONAL_JOB_ORIGIN = proxyEndpoint;
  }
  return env;
}

async function spawnMemberDriver({ command, args, env, watchdogMs, onEvent, onSpawn }) {
  const child = spawn(command, args, { env, cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  if (onSpawn) onSpawn(child);
  const events = [];
  let stdoutBuffer = '';
  const stderrLines = [];
  let contractSeen = false;
  let doneEvent = null;
  let eventError = null;

  const stdoutDone = new Promise((resolve) => {
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdoutBuffer += chunk;
      let newlineIndex;
      while ((newlineIndex = stdoutBuffer.indexOf('\n')) >= 0) {
        const line = stdoutBuffer.slice(0, newlineIndex).trim();
        stdoutBuffer = stdoutBuffer.slice(newlineIndex + 1);
        if (!line) continue;
        let event;
        try {
          event = JSON.parse(line);
        } catch {
          stderrLines.push(`unparsable stdout line: ${line.slice(0, 500)}`);
          continue;
        }
        if (event?.type === 'done') doneEvent = event;
        if (['attempt', 'process', 'phase', 'saturation'].includes(event?.type)) {
          events.push(event);
          if (event.type === 'process') contractSeen = true;
          if (onEvent) {
            try {
              onEvent(event);
            } catch (error) {
              if (!eventError) eventError = error;
            }
          }
        }
      }
    });
    child.stdout.on('end', resolve);
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    for (const line of chunk.split('\n')) {
      if (line.trim()) stderrLines.push(line.trim().slice(0, 500));
    }
  });

  // A spawn-level failure (ENOENT on a mistyped --workload-driver-cmd,
  // EACCES, ...) emits ONLY 'error' — 'exit' never fires, kill() is a no-op,
  // and the child's stdout never ends, so without this the exit-code promise
  // AND the stdout drain below would each hang the whole evidence run
  // indefinitely at pair 1 member 1. Resolve both and fail fast with a
  // synthetic non-zero exit code.
  let spawnError = null;
  const spawnSettled = new Promise((resolve) => {
    child.on('error', (error) => {
      spawnError = error;
      stderrLines.push(`driver spawn failed: ${error?.message ?? error}`);
      resolve();
    });
  });
  const exitCode = await Promise.race([
    new Promise((resolve) => {
      child.on('exit', (code) => resolve(code));
      setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      }, watchdogMs).unref?.();
    }),
    spawnSettled.then(() => 127),
  ]);
  await Promise.race([stdoutDone, spawnSettled]);
  return { child, exitCode, events, stderrTail: stderrLines.slice(-20), contractSeen, doneEvent, eventError };
}

// ---------------------------------------------------------------------------
// Member + pair execution.
// ---------------------------------------------------------------------------

function emptyClassBuckets(classes) {
  const buckets = {};
  for (const className of classes) {
    buckets[className] = { scheduled: 0, completed: 0, failed: 0, timedOut: 0, networkDrop: 0, attempts: [] };
  }
  return buckets;
}

function bucketObservation(buckets, event) {
  const bucket = buckets[event.class];
  if (!bucket) fail('DRIVER', `driver emitted unknown class ${event.class}`);
  if (!OUTCOMES.includes(event.outcome)) fail('DRIVER', `driver emitted unknown outcome ${event.outcome}`);
  bucket.scheduled += 1;
  bucket.attempts.push({
    seq: event.seq,
    outcome: event.outcome,
    latencyMs: event.latencyMs ?? null,
    stage: event.stage ?? null,
  });
  bucket[event.outcome] += 1;
}

async function runMember({ member, plan, pairIndex, runId, context, resources }) {
  const proxy = new FaultProxy({
    schedule: plan.schedule,
    seeds: plan.seeds,
    targetUrl: context.targetUrl,
    windowOriginMonotonicMs: performance.now(),
  });
  const proxyEndpoint = await proxy.start();
  resources.register({
    kind: 'in-process-loopback-fault-proxy',
    name: `e6-fault-proxy/${runId}/pair-${pairIndex}/${member}`,
    pid: process.pid,
    endpoint: proxyEndpoint,
  });

  const sampler = new ProcessSampler(context.sampleIntervalMs);
  const extraEnv = {};
  let command;
  let args;
  if (context.workloadDriver === 'builtin') {
    command = process.execPath;
    args = [path.join(REPO_ROOT, HARNESS_REL), '--internal-member-simulator'];
    extraEnv.E6_SYNTHETIC_GATEWAY_ROLE = MEASURED_ROLE_GATEWAY;
    extraEnv.E6_SYNTHETIC_GATEWAY_PID = String(context.smokeTargetPid);
    extraEnv.E6_SYNTHETIC_RENDER_ROLE = MEASURED_ROLE_RENDERER;
    extraEnv.E6_SYNTHETIC_RENDER_PID = String(process.pid);
  } else {
    // The description object (recorded in the run ledger / results seal) is
    // the single carrier of the external driver command+args — reading
    // cli-level fields here would spawn `undefined` at pair 1 member 1.
    command = context.workloadDriverDescription.command;
    args = context.workloadDriverDescription.args ?? [];
  }

  const env = memberEnv({
    member,
    pairIndex,
    runId,
    proxyEndpoint,
    targetUrl: context.targetUrl,
    schedule: plan.schedule,
    attemptTimeoutMs: context.attemptTimeoutMs,
    extra: extraEnv,
  });
  const startedAtUtc = isoUtcNow();
  const windowOriginMonotonicMs = performance.now();
  const watchdogMs =
    context.attemptTimeoutMs * 4 +
    (plan.schedule.warmupMs + plan.schedule.measurementMs) * 1.5 +
    120_000;

  const warmupBuckets = emptyClassBuckets(plan.classes);
  const measurementBuckets = emptyClassBuckets(plan.classes);
  let saturationEvent = null;
  const rolePids = new Map();

  // Events are handled as they stream: the sampler must run concurrently with
  // the member window, not after child exit.
  const onEvent = (event) => {
    if (event.type === 'phase') {
      if (event.phase === 'measurement') sampler.start();
      return;
    }
    if (event.type === 'process') {
      if (typeof event.pid !== 'number' || !event.role) {
        fail('DRIVER', `malformed process event ${JSON.stringify(event)}`);
      }
      rolePids.set(event.role, event.pid);
      sampler.addRole(event.role, event.pid);
      return;
    }
    if (event.type === 'saturation') {
      saturationEvent = event;
      return;
    }
    if (event.type === 'attempt') {
      bucketObservation(event.phase === 'measurement' ? measurementBuckets : warmupBuckets, event);
    }
  };

  const driver = await spawnMemberDriver({
    command,
    args,
    env,
    watchdogMs,
    onEvent,
    onSpawn: (child) => {
      // Registered at spawn so an in-run SIGINT can target this exact PID.
      resources.register({
        kind: 'workload-driver-child',
        name: `e6-driver/${runId}/pair-${pairIndex}/${member}`,
        pid: child.pid,
        command,
      });
    },
  });
  const finalizeProxyAndSampler = async () => {
    sampler.stop();
    await proxy.stop();
  };
  if (driver.eventError) {
    await finalizeProxyAndSampler();
    throw driver.eventError;
  }

  if (!driver.contractSeen) {
    await finalizeProxyAndSampler();
    // Surface WHY the driver produced nothing: the stderr tail + exit code are
    // the only forensic record of a pre-traffic refusal (named wrapper arms,
    // env/usage failures) — without them a mid-run contract abort is
    // undebuggable. Also persist to the pair dir for the retained generation.
    const why = driver.stderrTail.length
      ? `driver stderr tail: ${driver.stderrTail.join(' | ')}`
      : `driver exit ${driver.exitCode ?? 'null'} with empty stderr`;
    try {
      fs.writeFileSync(path.join(path.dirname(pairPath ?? generation), `pair-driver-refusal.log`),
        `${new Date().toISOString()} exit=${driver.exitCode ?? 'null'}\n${driver.stderrTail.join('\n')}\n`);
    } catch {}
    fail('DRIVER', `driver emitted no {type:"process"} event; driver event contract violated (${why})`);
  }
  for (const role of plan.measuredRoles) {
    if (!rolePids.has(role)) {
      await finalizeProxyAndSampler();
      fail('DRIVER', `driver never reported measured process role "${role}"; cross-process capture would be incomplete`);
    }
  }
  if (driver.exitCode !== 0) {
    await finalizeProxyAndSampler();
    fail('DRIVER', `driver exited ${driver.exitCode}; stderr tail: ${driver.stderrTail.join(' | ') || '(empty)'}`);
  }
  await finalizeProxyAndSampler();

  // Proxy drain invariant (scheme v4 proxy-drain block): the window refuses
  // unless every proxied attempt settled through exactly one terminal kind
  // (requestsReceived == terminal ledger) and nothing survived at teardown
  // (no unsettled attempt, no registered upstream after the drain deadline).
  // A breach means the attempt population is not exactly-attributable —
  // machinery failure, run refused before any results document exists.
  if (proxy.drain === null || !proxy.drain.ok) {
    fail(
      'ACCOUNTING',
      `${member}: proxy drain invariant breached at teardown — ` +
        `pending ${proxy.drain?.pending ?? 'n/a'} attempt(s), ` +
        `${proxy.drain?.upstreamsRegistered ?? 'n/a'} registered upstream(s) ` +
        `after a ${proxy.drain?.waitedMs ?? 'n/a'}ms drain wait; ` +
        'the instrument-quiescence protocol cannot assert proxy quiescence over an undrained proxy',
    );
  }

  const warmupScheduled = plan.schedule.warmupAttempts;
  const warmupObserved = Object.values(warmupBuckets).reduce((sum, bucket) => sum + bucket.scheduled, 0);
  const measurementScheduled = plan.schedule.classSequence.length;
  const measurementObserved = Object.values(measurementBuckets).reduce((sum, bucket) => sum + bucket.scheduled, 0);
  if (warmupObserved !== warmupScheduled || measurementObserved !== measurementScheduled) {
    fail(
      'ACCOUNTING',
      `${member}: attempt accounting mismatch — scheduled ` +
        `${warmupScheduled}+${measurementScheduled}, observed ${warmupObserved}+${measurementObserved}; ` +
        'dropped attempts can never produce a results document',
    );
  }
  if (driver.doneEvent && driver.doneEvent.measurementScheduled !== measurementScheduled) {
    fail('DRIVER', 'driver done-event count disagrees with the schedule');
  }

  return {
    role: member,
    flag: member === 'candidate' ? 'on' : 'off',
    policyMode: member === 'candidate' ? 'execute' : 'off',
    syntheticIdentity: context.workloadDriver === 'builtin' ? 'smoke-synthetic-child-processes' : null,
    childCommand: command === process.execPath ? `${command} ${args.join(' ')}` : command,
    childPid: driver.child.pid,
    exitCode: driver.exitCode,
    attemptTimeoutMs: context.attemptTimeoutMs,
    faultProxy: {
      endpoint: proxyEndpoint,
      stats: proxy.stats,
      // Per-basis closure report + shared config evidence + proxy-owned drain
      // checks (scheme v4 §2.3.2 and the proxy-drain block). `config.digest`
      // is asserted EQUAL across both windows of every pair at consumption
      // (one shared proxy config object); `attribution.declaredCandidate-
      // Optional` is the declared population the candidate-optional basis is
      // asserted against (null until a v3 profile declares it).
      requestsByBasis: proxy.requestsByBasis,
      config: {
        digest: proxy.configDigest,
        attributionHeader: proxy.config.attributionHeader,
        attributionBases: proxy.config.attributionBases,
      },
      attribution: { declaredCandidateOptional: plan.declaredOptionalPopulation ?? null },
      drain: proxy.drain,
    },
    window: {
      startedAtUtc,
      endedAtUtc: isoUtcNow(),
      elapsedSeconds: roundMs((performance.now() - windowOriginMonotonicMs) / 1000),
      warmupMs: plan.schedule.warmupMs,
      measurementMs: plan.schedule.measurementMs,
    },
    saturation: saturationEvent,
    processSamples: sampler.result(),
    measuredRolesReported: [...rolePids.keys()].sort(),
    warmup: {
      scheduled: warmupScheduled,
      observed: warmupObserved,
      attemptsRetained: true,
      perClass: classBucketView(warmupBuckets),
    },
    classes: classBucketView(measurementBuckets),
  };
}

function classBucketView(buckets) {
  return Object.fromEntries(
    Object.entries(buckets).map(([className, bucket]) => [
      className,
      {
        scheduled: bucket.scheduled,
        completed: bucket.completed,
        failed: bucket.failed,
        timedOut: bucket.timedOut,
        networkDrop: bucket.networkDrop,
        attempts: bucket.attempts,
      },
    ]),
  );
}

async function runPair({ pairNumber, plan, runId, context, resources }) {
  const order = plan.pairOrders[pairNumber];
  const firstMember = order === 'comparator-first' ? 'comparator' : 'candidate';
  const secondMember = firstMember === 'comparator' ? 'candidate' : 'comparator';
  const members = {};
  for (const member of [firstMember, secondMember]) {
    members[member] = await runMember({ member, plan, pairIndex: pairNumber, runId, context, resources });
  }
  const pairDoc = {
    schemaVersion: 1,
    kind: 'e6-pair-result',
    runId,
    pairIndex: pairNumber,
    order: { first: firstMember, sequence: order },
    profileDigest: context.profileDigest,
    profileId: context.profileId,
    scheduleDigest: plan.scheduleDigest,
    seeds: plan.seeds,
    members,
  };
  assertFiniteDeep(pairDoc, `pair-${pairNumber}`);
  return pairDoc;
}

// ---------------------------------------------------------------------------
// Statistics: pooled nearest-rank percentiles + seeded cluster-paired
// bootstrap (resampling pair indices) with upper-one-sided-95% bounds.
// ---------------------------------------------------------------------------

function completedLatencies(memberRun, className) {
  const latencies = [];
  for (const attempt of memberRun.classes[className].attempts) {
    if (attempt.outcome === 'completed' && attempt.latencyMs !== null) latencies.push(attempt.latencyMs);
  }
  return latencies;
}

function sortedCopy(values) {
  return [...values].sort((a, b) => a - b);
}

/** Globally sorted pooled values carrying their pair of origin so the
 *  bootstrap can reweight pairs with a single O(n) prefix scan. */
function pooledWithOrigin(latenciesPerPair) {
  const indices = [];
  latenciesPerPair.forEach((values, pairIndex) => {
    for (let index = 0; index < values.length; index += 1) indices.push([values[index], pairIndex]);
  });
  indices.sort((a, b) => a[0] - b[0]);
  const values = new Float64Array(indices.length);
  const origin = new Int32Array(indices.length);
  indices.forEach(([value, pairIndex], index) => {
    values[index] = value;
    origin[index] = pairIndex;
  });
  return {
    values,
    origin,
    lengths: latenciesPerPair.map((values_) => values_.length),
    pairs: latenciesPerPair.length,
  };
}

function quantileUnderCounts(pool, counts, quantiles) {
  let total = 0;
  for (let index = 0; index < pool.pairs; index += 1) total += pool.lengths[index] * counts[index];
  if (total === 0) return quantiles.map(() => null);
  const ranks = quantiles.map((q) => Math.max(1, Math.ceil(q * total)));
  const result = new Array(quantiles.length).fill(null);
  const { values, origin } = pool;
  let cumulative = 0;
  let resultIndex = 0;
  for (let index = 0; index < values.length && resultIndex < ranks.length; index += 1) {
    cumulative += counts[origin[index]];
    while (resultIndex < ranks.length && cumulative >= ranks[resultIndex]) {
      result[resultIndex] = values[index];
      resultIndex += 1;
    }
  }
  return result;
}

function pooledQuantilePair({ candidateLatencies, comparatorLatencies, resamples, seed, className }) {
  const point = (values) => {
    const sorted = sortedCopy(values);
    return {
      p50: roundMs(nearestRankPercentile(sorted, 50)),
      p95: roundMs(nearestRankPercentile(sorted, 95)),
      p99: roundMs(nearestRankPercentile(sorted, 99)),
    };
  };
  const candidatePoint = point(candidateLatencies.flat());
  const comparatorPoint = point(comparatorLatencies.flat());
  const candidatePool = pooledWithOrigin(candidateLatencies);
  const comparatorPool = pooledWithOrigin(comparatorLatencies);
  const pairs = candidateLatencies.length;
  const counts = new Int32Array(pairs);
  const diffs = { 95: { abs: [], rel: [] }, 99: { abs: [], rel: [] } };
  let comparatorZeroSeen = false;
  const rng = rngFromSeed(`${seed}:class:${className}`);
  for (let resample = 0; resample < resamples; resample += 1) {
    counts.fill(0);
    for (let index = 0; index < pairs; index += 1) counts[randomInt(rng, pairs)] += 1;
    const [candidateP95, candidateP99] = quantileUnderCounts(candidatePool, counts, [0.95, 0.99]);
    const [comparatorP95, comparatorP99] = quantileUnderCounts(comparatorPool, counts, [0.95, 0.99]);
    for (const [quantile, candidateValue, comparatorValue] of [
      [95, candidateP95, comparatorP95],
      [99, candidateP99, comparatorP99],
    ]) {
      if (candidateValue === null || comparatorValue === null) continue;
      const abs = candidateValue - comparatorValue;
      diffs[quantile].abs.push(abs);
      if (comparatorValue === 0) {
        comparatorZeroSeen = true;
      } else {
        diffs[quantile].rel.push(abs / comparatorValue);
      }
    }
  }
  const bound = (quantile) => ({
    pointAbsMs: roundMs(candidatePoint[`p${quantile}`] - comparatorPoint[`p${quantile}`]),
    pointRelPercent:
      comparatorPoint[`p${quantile}`] === 0
        ? null
        : roundPercent(((candidatePoint[`p${quantile}`] - comparatorPoint[`p${quantile}`]) / comparatorPoint[`p${quantile}`]) * 100),
    upper95AbsMs: roundMs(nearestRankPercentile(sortedCopy(diffs[quantile].abs), 95)),
    upper95RelPercent: roundPercent(nearestRankPercentile(sortedCopy(diffs[quantile].rel), 95) * 100),
    comparatorBaselineZero: comparatorZeroSeen,
    resamples,
  });
  return {
    comparator: comparatorPoint,
    candidate: candidatePoint,
    bounds: { p95: bound(95), p99: bound(99) },
  };
}

function peakBootstrapBound({ candidatePeaks, comparatorPeaks, resamples, seed, role }) {
  const rng = rngFromSeed(`${seed}:role:${role}`);
  const diffRel = [];
  let comparatorZeroSeen = false;
  for (let resample = 0; resample < resamples; resample += 1) {
    let candidatePeak = Number.NEGATIVE_INFINITY;
    let comparatorPeak = Number.NEGATIVE_INFINITY;
    for (let index = 0; index < candidatePeaks.length; index += 1) {
      const picked = randomInt(rng, candidatePeaks.length);
      if (candidatePeaks[picked] > candidatePeak) candidatePeak = candidatePeaks[picked];
      if (comparatorPeaks[picked] > comparatorPeak) comparatorPeak = comparatorPeaks[picked];
    }
    if (comparatorPeak === 0) {
      comparatorZeroSeen = true;
      if (candidatePeak === 0) diffRel.push(0);
    } else {
      diffRel.push((candidatePeak - comparatorPeak) / comparatorPeak);
    }
  }
  return {
    // Percent units: 5 means 5%, matching the profile ceiling units.
    upper95RelPercent: roundPercent(nearestRankPercentile(sortedCopy(diffRel), 95) * 100),
    comparatorBaselineZero: comparatorZeroSeen,
    resamples,
  };
}

// ---------------------------------------------------------------------------
// Aggregate assembly + verdict computation (pure; shared with --self-test).
// ---------------------------------------------------------------------------

function pooledCounts(pairDocs, role, className) {
  return pairDocs.reduce(
    (sum, doc) => {
      const bucket = doc.members[role].classes[className];
      return {
        scheduled: sum.scheduled + bucket.scheduled,
        completed: sum.completed + bucket.completed,
        failed: sum.failed + bucket.failed,
        timedOut: sum.timedOut + bucket.timedOut,
        networkDrop: sum.networkDrop + bucket.networkDrop,
      };
    },
    { scheduled: 0, completed: 0, failed: 0, timedOut: 0, networkDrop: 0 },
  );
}

function assembleAggregate({ pairDocs, plan, profile, context }) {
  const { selected } = profile;
  const classes = {};
  for (const className of plan.classes) {
    const candidateLatencies = pairDocs.map((doc) => completedLatencies(doc.members.candidate, className));
    const comparatorLatencies = pairDocs.map((doc) => completedLatencies(doc.members.comparator, className));
    const stats = pooledQuantilePair({
      candidateLatencies,
      comparatorLatencies,
      resamples: plan.protocol.bootstrap.resamples,
      seed: plan.seeds.bootstrap,
      className,
    });
    const counts = {
      comparator: pooledCounts(pairDocs, 'comparator', className),
      candidate: pooledCounts(pairDocs, 'candidate', className),
    };
    const attempted = (roleCounts) => roleCounts.completed + roleCounts.failed + roleCounts.timedOut + roleCounts.networkDrop;
    const failureRate = (roleCounts) =>
      attempted(roleCounts) === 0
        ? null
        : (roleCounts.failed + roleCounts.timedOut + roleCounts.networkDrop) / attempted(roleCounts);
    const comparatorRate = failureRate(counts.comparator);
    const candidateRate = failureRate(counts.candidate);
    classes[className] = {
      mixPercent: selected.criticalRequestClasses.find((entry) => entry.class === className)?.mixPercent ?? null,
      counts,
      failureRates: {
        comparator: comparatorRate,
        candidate: candidateRate,
        regression: comparatorRate === null || candidateRate === null ? null : candidateRate > comparatorRate,
      },
      ...stats,
    };
  }

  const processMetrics = buildProcessMetrics({ pairDocs, plan, profile });
  const candidateSaturationEvents = pairDocs.map((doc) => doc.members.candidate.saturation);
  const optionalSaturationObserved = {
    candidateEvents: candidateSaturationEvents,
    candidateActiveDuringMeasurement: candidateSaturationEvents.every(
      (event) => event?.activeDuringMeasurement === true,
    ),
  };

  const aggregate = {
    schemaVersion: 1,
    kind: plan.smoke ? 'e6-harness-smoke' : 'e6-paired-run-results',
    runId: context.runId,
    createdAtUtc: isoUtcNow(),
    smoke: plan.smoke,
    ...(plan.smoke ? { notAnE6ResultsDoc: true, smokeScope: 'machinery-validation-only' } : {}),
    profile: {
      profileId: selected.profileId,
      profileVersion: selected.profileVersion,
      status: selected.status,
      frozenAtUtc: selected.frozenAtUtc,
      platform: selected.platform,
      digest: profile.digest,
      path: profile.relPath,
      shell: selected.shell,
    },
    binding: {
      manifest: profile.manifestBinding,
      git: context.git,
      harness: { path: HARNESS_REL, sha256: HARNESS_SHA256 },
      host: context.hostIdentity ?? { os: `${os.type()} ${os.release()}`, arch: os.arch() },
      toolVersions: context.toolVersions,
      workloadDriver: context.workloadDriverDescription,
    },
    seeds: plan.seeds,
    protocolEcho: {
      ...plan.protocol,
      pairs: pairDocs.length,
      percentileMethod: FROZEN_PROTOCOL.percentileMethod,
      bootstrap: plan.protocol.bootstrap,
      scheduleDigest: plan.scheduleDigest,
      classMix: selected.criticalRequestClasses,
      optionalSaturation: selected.optionalSaturation,
      attemptIntervalMs: plan.schedule.attemptIntervalMs,
    },
    ceilings: profile.document.regressionCeilings,
    networkFaults: {
      mechanism: 'in-process-loopback-fault-proxy',
      mechanismRationale:
        'loopback-only fault application by a run-owned proxy; zero host pf/dummynet/qdisc changes (NETEM-CLEANUP satisfied by construction)',
      hostQosChanges: [],
      stages: selected.networkFaults.stages,
      outage: selected.networkFaults.outage,
      scheduleDescription: 'three contiguous stage blocks; outage fixed-mid-measurement overlays them',
      warmupStaging: 'warmup cycles the same stage blocks from t=0 without outage',
    },
    optionalSaturationObserved,
    classes,
    processMetrics,
    pairs: pairDocs.map((doc, index) => ({
      pairIndex: doc.pairIndex,
      order: doc.order.sequence,
      docPath: `pairs/pair-${String(index + 1).padStart(2, '0')}.json`,
    })),
    accounting: {
      failureAccounting: FROZEN_PROTOCOL.failureAccounting,
      warmupRetained: true,
      measurementAttemptsRetained: true,
    },
    postResultChangesProhibited: true,
    seal: null,
  };
  if (!plan.smoke) {
    aggregate.verdict = computeVerdicts({
      aggregate: { classes, processMetrics, optionalSaturationObserved },
      pairDocs,
      plan,
      profile,
    });
  }
  assertFiniteDeep(aggregate, 'aggregate');
  return aggregate;
}

function buildProcessMetrics({ pairDocs, plan, profile }) {
  const roles = profile.selected.processMetricBoundaries.measuredProcesses;
  const perPair = pairDocs.map((doc) => ({
    pairIndex: doc.pairIndex,
    roles: Object.fromEntries(
      roles.map((role) => {
        const comparator = doc.members.comparator.processSamples[role] ?? null;
        const candidate = doc.members.candidate.processSamples[role] ?? null;
        return [
          role,
          {
            comparator,
            candidate,
            captureComplete: Boolean(comparator?.sampleCount >= 2 && candidate?.sampleCount >= 2),
          },
        ];
      }),
    ),
  }));
  const captureCompleteEverywhere = (pickRole) =>
    pairDocs.every((doc) => {
      const comparator = doc.members.comparator.processSamples[pickRole];
      const candidate = doc.members.candidate.processSamples[pickRole];
      return Boolean(comparator?.sampleCount >= 2 && candidate?.sampleCount >= 2);
    });
  const regression = {};
  for (const role of roles) {
    const boundFor = (metric) => {
      if (!captureCompleteEverywhere(role)) return null;
      const candidatePeaks = pairDocs.map((doc) => doc.members.candidate.processSamples[role][metric]);
      const comparatorPeaks = pairDocs.map((doc) => doc.members.comparator.processSamples[role][metric]);
      return peakBootstrapBound({
        candidatePeaks,
        comparatorPeaks,
        resamples: plan.protocol.bootstrap.resamples,
        seed: plan.seeds.bootstrap,
        role: `${role}:${metric}`,
      });
    };
    regression[role] = { cpu: boundFor('peakCpuPercent'), rss: boundFor('peakRssBytes') };
  }
  return {
    sampleIntervalMs: profile.selected.processMetricBoundaries.sampleIntervalMs,
    measuredProcessRoles: roles,
    perPair,
    regression,
    ceilingPercent: profile.document.regressionCeilings.peakCpuRssMaxPercent,
  };
}

function floorMet(plan, pairDocs, className) {
  return pairDocs.every(
    (doc) =>
      doc.members.comparator.classes[className].completed >=
        plan.schedule.observationFloorPerClassPerRun &&
      doc.members.candidate.classes[className].completed >=
        plan.schedule.observationFloorPerClassPerRun,
  );
}

function computeVerdicts({ aggregate, pairDocs, plan, profile }) {
  const ceilings = profile.document.regressionCeilings;
  const perClass = {};
  const claimsUnavailableClasses = [];
  for (const className of plan.classes) {
    const entry = aggregate.classes[className];
    const floor = floorMet(plan, pairDocs, className);
    if (!floor) claimsUnavailableClasses.push(className);
    const within = (bound, maxPercent, maxMs) => ({
      withinPercent:
        !bound.comparatorBaselineZero &&
        bound.upper95RelPercent !== null &&
        bound.upper95RelPercent <= maxPercent,
      withinMs: bound.upper95AbsMs !== null && bound.upper95AbsMs <= maxMs,
      ceilingPercent: maxPercent,
      ceilingMs: maxMs,
    });
    const p95 = within(entry.bounds.p95, ceilings.criticalP95MaxPercent, ceilings.criticalP95MaxMilliseconds);
    const p99 = within(entry.bounds.p99, ceilings.criticalP99MaxPercent, ceilings.criticalP99MaxMilliseconds);
    perClass[className] = {
      claimsAvailable: floor,
      observationFloorMet: floor,
      minimumObservationsPerCriticalClassPerRun: plan.schedule.observationFloorPerClassPerRun,
      regressionCeilingsMet: floor && p95.withinPercent && p95.withinMs && p99.withinPercent && p99.withinMs,
      p95,
      p99,
    };
  }

  // The pair floor comes from the bound profile's frozen protocol (pinned to
  // FROZEN_PROTOCOL.minimumPairs by validateFrozenProfile for real profiles).
  const requiredPairs = profile.document.protocol.minimumPairs ?? FROZEN_PROTOCOL.minimumPairs;
  const minimumPairsMet = pairDocs.length >= requiredPairs;
  const pairedRegressionPass =
    minimumPairsMet && plan.classes.every((className) => perClass[className].regressionCeilingsMet);

  const accountingComplete = pairDocs.every((doc) =>
    ['comparator', 'candidate'].every((role) => {
      const memberRun = doc.members[role];
      const warmupSum = Object.values(memberRun.warmup.perClass).reduce((sum, bucket) => sum + bucket.scheduled, 0);
      const measurementSum = Object.values(memberRun.classes).reduce((sum, bucket) => sum + bucket.scheduled, 0);
      const attemptsConsistent = Object.values(memberRun.classes).every(
        (bucket) =>
          bucket.scheduled === bucket.attempts.length &&
          bucket.attempts.every((attempt) => OUTCOMES.includes(attempt.outcome)),
      );
      return (
        warmupSum === memberRun.warmup.scheduled &&
        measurementSum === plan.schedule.classSequence.length &&
        attemptsConsistent
      );
    }),
  );

  const roles = aggregate.processMetrics.measuredProcessRoles;
  const captureComplete = pairDocs.every((doc) =>
    roles.every(
      (role) =>
        aggregate.processMetrics.perPair.find((entry) => entry.pairIndex === doc.pairIndex)?.roles[role]
          ?.captureComplete,
    ),
  );
  const saturationOk =
    aggregate.optionalSaturationObserved.candidateEvents.length === pairDocs.length &&
    aggregate.optionalSaturationObserved.candidateActiveDuringMeasurement;
  const withinCeilingPercent = (bound) =>
    bound !== null &&
    !bound.comparatorBaselineZero &&
    bound.upper95RelPercent !== null &&
    bound.upper95RelPercent <= aggregate.processMetrics.ceilingPercent;
  const processPass =
    captureComplete &&
    saturationOk &&
    roles.every((role) => {
      const bound = aggregate.processMetrics.regression[role];
      return withinCeilingPercent(bound.cpu) && withinCeilingPercent(bound.rss);
    });

  const criticalSampleFloorPass = plan.classes.every((className) => perClass[className].observationFloorMet);
  return {
    criticalSampleFloor: {
      pass: criticalSampleFloorPass,
      perClass: Object.fromEntries(plan.classes.map((className) => [className, perClass[className].observationFloorMet])),
      note: criticalSampleFloorPass
        ? 'every claimed Critical class met the completed-observation floor in every member run'
        : 'a class below the floor cannot make any claim; insufficient observations mean unavailable claims, never interpolated or borrowed evidence',
    },
    pairedRegression: {
      pass: pairedRegressionPass,
      minimumPairsMet,
      independentPairs: pairDocs.length,
      requiredPairs,
      perClass: Object.fromEntries(plan.classes.map((className) => [className, perClass[className].regressionCeilingsMet])),
    },
    failedRequestAccounting: {
      pass: accountingComplete,
      accountingComplete,
      failuresAndTimeoutsReportedSeparately: true,
      allAttemptsRetained: true,
    },
    crossprocessCriticalSaturation: {
      pass: processPass,
      captureComplete,
      saturationAdmitted: profile.selected.optionalSaturation?.admitted === true,
      candidateActiveDuringMeasurement: Boolean(saturationOk),
      ceilingPercent: aggregate.processMetrics.ceilingPercent,
      perRole: Object.fromEntries(
        roles.map((role) => {
          const bound = aggregate.processMetrics.regression[role];
          return [
            role,
            {
              pass: withinCeilingPercent(bound.cpu) && withinCeilingPercent(bound.rss),
              comparatorBaselineZero: Boolean(bound.cpu?.comparatorBaselineZero || bound.rss?.comparatorBaselineZero),
            },
          ];
        }),
      ),
    },
    claimsUnavailableClasses,
    overallPass: criticalSampleFloorPass && pairedRegressionPass && accountingComplete && processPass,
  };
}

// ---------------------------------------------------------------------------
// Embedded results-doc validation — the four E6 case acceptance checks as
// schema assertions. A results document missing or contradicting any
// dimension is refused before write; a valid document whose MEASURED verdict
// fails still writes (results documents record reality; the gate reads the
// recorded verdict, which is itself recomputation-checked below).
// ---------------------------------------------------------------------------

const sha256Bytes = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

export const E6_RUNTIME_CASE_GATES = new Map([
  ['CAS-E6-CRITICAL-SAMPLE-FLOOR', 'criticalSampleFloor'],
  ['CAS-E6-PAIRED-REGRESSION', 'pairedRegression'],
  ['CAS-E6-FAILED-REQUEST-ACCOUNTING', 'failedRequestAccounting'],
  ['CAS-E6-CROSSPROCESS-CRITICAL-SATURATION', 'crossprocessCriticalSaturation'],
]);

export function hasRetainedE6Generation(root) {
  // A real retained generation carries the canonical aggregate layout the
  // consumer writes; lane scratch run directories (run.txt, logs) do not.
  // An absent or unreadable root counts as absent.
  try {
    return fs.readdirSync(root, { withFileTypes: true }).some((child) =>
      child.isDirectory() && fs.existsSync(path.join(root, child.name, 'e6', 'generation', 'aggregate.json')));
  } catch {
    return false;
  }
}

export function readRetainedE6Generation(generation, expectedDigest) {
  assert.match(expectedDigest ?? '', /^[0-9a-f]{64}$/, 'an independently recorded aggregate SHA-256 is required');
  const bytes = fs.readFileSync(path.join(generation, 'aggregate.json'));
  assert.equal(sha256Bytes(bytes), expectedDigest, 'aggregate does not match the supplied retained digest');
  const aggregate = JSON.parse(bytes);
  assert.match(aggregate.runId, /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/, 'unsafe run ID');
  assert.equal(aggregate.kind, 'e6-paired-run-results', 'smoke/partial results are not E6 evidence');
  assert.equal(aggregate.smoke, false);
  const profileBytes = fs.readFileSync(path.join(generation, 'inputs/profile.json'));
  const document = JSON.parse(profileBytes);
  const selected = document.profiles.find(item => item.profileId === aggregate.profile.profileId);
  assert.ok(selected, 'aggregate profile is absent from its frozen input');
  validateFrozenProfile(selected, document);
  assert.equal(aggregate.profile.profileVersion, selected.profileVersion);
  assert.equal(sha256Bytes(profileBytes), aggregate.profile.digest);
  assert.equal(sha256Bytes(profileBytes), aggregate.seal.profileDigest);
  assert.equal(aggregate.seal.manifestBinding.match, true);
  assert.equal(aggregate.seal.manifestBinding.pinnedFixtureDigest, sha256Bytes(profileBytes));
  assert.deepEqual(aggregate.binding.harness, aggregate.seal.harness);
  assert.deepEqual(aggregate.binding.git, aggregate.seal.git);
  const seeds = { run: selected.clockAndSeeds.runSeed, order: selected.clockAndSeeds.orderSeed, bootstrap: selected.clockAndSeeds.bootstrapSeed };
  assert.deepEqual(aggregate.seeds, seeds);
  assert.deepEqual(aggregate.seal.seeds, seeds);
  assert.ok(aggregate.pairs.length >= document.protocol.minimumPairs, 'incomplete pair population');
  const plan = buildPlan({ selected, seeds, pairs: aggregate.pairs.length, smoke: false });
  assert.equal(aggregate.seal.scheduleDigest, plan.scheduleDigest);
  assert.equal(aggregate.protocolEcho.scheduleDigest, plan.scheduleDigest);
  const pairFiles = aggregate.pairs.map((entry, index) => {
    const relative = `pairs/pair-${String(index + 1).padStart(2, '0')}.json`;
    assert.equal(entry.pairIndex, index);
    assert.equal(entry.docPath, relative, 'pair path must be the canonical in-generation path');
    assert.equal(entry.order, plan.pairOrders[index]);
    const bytes = fs.readFileSync(path.join(generation, relative), 'utf8');
    assert.equal(sha256Bytes(bytes), entry.sha256);
    const doc = JSON.parse(bytes);
    assert.equal(doc.kind, 'e6-pair-result');
    assert.equal(doc.runId, aggregate.runId);
    assert.equal(doc.pairIndex, index);
    assert.equal(doc.profileId, selected.profileId);
    assert.equal(doc.order.sequence, plan.pairOrders[index]);
    assert.deepEqual(doc.seeds, seeds);
    return { path: relative, bytes, doc };
  });
  const profile = { selected, document, digest: sha256Bytes(profileBytes) };
  const checks = validateResultsDoc({ aggregate, pairFiles, plan, profile });
  // Legacy aggregates recorded only Darwin release, which cannot establish
  // equality with a macOS product/build pin. Keep that gap explicit.
  const profileQualified = aggregate.binding.host.arch === selected.host.arch && aggregate.binding.host.profileOS === selected.host.os;
  return { aggregate, profile, checks: checks.length, profileQualified, evidenceFiles: [
    ['aggregate.json', bytes], ['inputs/profile.json', profileBytes],
    ...pairFiles.map(file => [file.path, file.bytes]),
  ] };
}


export function validateResultsDoc({ aggregate, pairFiles, plan, profile }) {
  const checks = [];
  const check = (id, condition, detail) => {
    if (!condition) fail('SCHEMA', `[${id}] ${detail}`);
    checks.push(id);
  };

  check('E6-KIND', aggregate.kind === 'e6-paired-run-results', 'kind must be exactly e6-paired-run-results');
  check('E6-KIND', aggregate.smoke === false, 'an E6 results document is never smoke');
  check('E6-KIND', aggregate.notAnE6ResultsDoc === undefined, 'an E6 results document never carries smoke markers');
  check('E6-KIND', aggregate.verdict && typeof aggregate.verdict === 'object', 'an E6 results document carries the case verdicts');
  check('E6-PROTOCOL', aggregate.protocolEcho.percentileMethod === FROZEN_PROTOCOL.percentileMethod, 'percentile method must be nearest-rank');
  check('E6-PROTOCOL', stableDeepEqual(aggregate.protocolEcho.bootstrap, FROZEN_PROTOCOL.bootstrap), 'bootstrap echo must equal the frozen protocol');
  check('E6-PROTOCOL', aggregate.protocolEcho.identicalWorkloadPairs === true, 'identicalWorkloadPairs must be pinned');
  check('E6-PROTOCOL', aggregate.protocolEcho.randomizedPairOrder === true, 'randomizedPairOrder must be pinned');
  check('E6-SEAL', aggregate.postResultChangesProhibited === true, 'postResultChangesProhibited must be true');
  check('E6-SEAL', aggregate.seal !== null && typeof aggregate.seal === 'object', 'seal required');
  check('E6-SEAL', isFiniteDigest(aggregate.seal.profileDigest), 'seal.profileDigest required');
  check('E6-SEAL', isFiniteDigest(aggregate.seal.scheduleDigest), 'seal.scheduleDigest required');
  check('E6-SEAL', Boolean(aggregate.seal.toolVersions) && Object.keys(aggregate.seal.toolVersions).length > 0, 'seal.toolVersions required');
  check('E6-BINDING', pairFiles.every((file) => file.doc.profileDigest === aggregate.profile.digest), 'every pair document must bind the aggregate profile digest');
  check('E6-BINDING', pairFiles.every((file) => file.doc.scheduleDigest === aggregate.protocolEcho.scheduleDigest), 'identical workloads require one scheduleDigest across all pair documents');
  check('E6-BINDING', pairFiles.every((file) => sha256String(file.bytes) === (aggregate.seal?.pairDocDigests?.[file.doc.pairIndex] ?? null)), 'pair document digest mismatch: results were modified after sealing');
  check('E6-SEAL', aggregate.postResultChangesProhibited === true, 'postResultChangesProhibited must be true');
  check('E6-SEAL', aggregate.seal !== null && typeof aggregate.seal === 'object', 'seal required');
  check('E6-SEAL', isFiniteDigest(aggregate.seal.profileDigest), 'seal.profileDigest required');
  check('E6-SEAL', isFiniteDigest(aggregate.seal.scheduleDigest), 'seal.scheduleDigest required');
  check('E6-SEAL', Boolean(aggregate.seal.toolVersions) && Object.keys(aggregate.seal.toolVersions).length > 0, 'seal.toolVersions required');

  // CAS-E6-FAILED-REQUEST-ACCOUNTING as schema: every attempt present, exact
  // outcome partition, warmup retained, counts consistent everywhere.
  for (const file of pairFiles) {
    for (const role of ['comparator', 'candidate']) {
      const memberRun = file.doc.members[role];
      let measurementScheduled = 0;
      for (const [className, bucket] of Object.entries(memberRun.classes)) {
        check('E6-ACCOUNTING', bucket.scheduled === bucket.attempts.length, `${file.path} ${role} ${className}: scheduled != retained attempts`);
        const partition = bucket.attempts.reduce(
          (counts, attempt) => {
            counts[attempt.outcome] += 1;
            return counts;
          },
          { completed: 0, failed: 0, timedOut: 0, networkDrop: 0 },
        );
        check(
          'E6-ACCOUNTING',
          partition.completed === bucket.completed &&
            partition.failed === bucket.failed &&
            partition.timedOut === bucket.timedOut &&
            partition.networkDrop === bucket.networkDrop,
          `${file.path} ${role} ${className}: outcome partition contradicts counts`,
        );
        measurementScheduled += bucket.scheduled;
      }
      const warmupSum = Object.values(memberRun.warmup.perClass).reduce((sum, bucket) => sum + bucket.scheduled, 0);
      check('E6-ACCOUNTING', warmupSum === memberRun.warmup.scheduled, `${file.path} ${role}: warmup attempt accounting mismatch`);
      check('E6-ACCOUNTING', memberRun.warmup.attemptsRetained !== false, `${file.path} ${role}: warmup retention refused`);
      check('E6-ACCOUNTING', measurementScheduled === plan.schedule.classSequence.length, `${file.path} ${role}: measurement attempts != schedule`);
    }
  }

  // Aggregate class counts must equal the pooled pair documents exactly, and
  // recorded point percentiles / bootstrap bounds must equal recomputation.
  for (const className of plan.classes) {
    const entry = aggregate.classes[className];
    check('E6-SAMPLE-FLOOR', Boolean(entry) && typeof entry === 'object', `class ${className} missing from aggregate`);
    for (const role of ['comparator', 'candidate']) {
      const pooled = pooledCounts(pairFiles.map((file) => file.doc), role, className);
      check('E6-CONSISTENCY', stableDeepEqual(entry.counts[role], pooled), `${className}/${role}: aggregate counts != pooled pair counts`);
      const latencies = pairFiles.map((file) => completedLatencies(file.doc.members[role], className));
      const flat = sortedCopy(latencies.flat());
      for (const percentile of [50, 95, 99]) {
        check(
          'E6-PERCENTILE',
          entry[role]?.[`p${percentile}`] === roundMs(nearestRankPercentile(flat, percentile)),
          `${className}/${role}: recorded p${percentile} != nearest-rank recomputation`,
        );
      }
    }
    const recomputed = pooledQuantilePair({
      candidateLatencies: pairFiles.map((file) => completedLatencies(file.doc.members.candidate, className)),
      comparatorLatencies: pairFiles.map((file) => completedLatencies(file.doc.members.comparator, className)),
      resamples: plan.protocol.bootstrap.resamples,
      seed: plan.seeds.bootstrap,
      className,
    });
    check('E6-BOOTSTRAP', stableDeepEqual(entry.bounds, recomputed.bounds), `${className}: recorded bootstrap bounds != seeded recomputation`);
  }

  // CAS-E6-CROSSPROCESS-CRITICAL-SATURATION as schema: every declared
  // measured process role captured in both members of every pair.
  for (const file of pairFiles) {
    for (const role of profile.selected.processMetricBoundaries.measuredProcesses) {
      for (const memberRole of ['comparator', 'candidate']) {
        const sample = file.doc.members[memberRole].processSamples[role];
        check(
          'E6-CROSSPROCESS',
          Boolean(sample) && sample.sampleCount >= 2 && isFiniteNumber(sample.peakCpuPercent) && isFiniteNumber(sample.peakRssBytes),
          `${file.path} ${memberRole}: measured process role ${role} not captured (declared process metric boundary)`,
        );
      }
    }
  }

  // Proxy drain invariant + candidate transport seam (scheme v4). Vacuous for
  // pre-v4 pair documents by construction: every check below arms only when
  // the window receipt carries the v4 proxy evidence blocks, so the retained
  // v1 generation (whose faultProxy blocks carry endpoint+stats only)
  // validates with an unchanged schema-assertion count.
  for (const file of pairFiles) {
    const proxyBlockOf = (role) => file.doc.members[role].faultProxy ?? null;
    const comparatorProxy = proxyBlockOf('comparator');
    const candidateProxy = proxyBlockOf('candidate');
    if (comparatorProxy?.config !== undefined || candidateProxy?.config !== undefined) {
      check(
        'E6-PROXY-SEAM',
        typeof comparatorProxy?.config?.digest === 'string' &&
          comparatorProxy.config.digest === candidateProxy?.config?.digest,
        `${file.path}: both windows must record the SAME proxy config digest (one shared proxy config object, scheme v4 §2.3.2)`,
      );
    }
    for (const [role, proxyBlock] of [['comparator', comparatorProxy], ['candidate', candidateProxy]]) {
      if (proxyBlock?.drain !== undefined) {
        check(
          'E6-PROXY-DRAIN',
          proxyBlock.drain.ok === true,
          `${file.path} ${role}: proxy drain invariant breached at teardown (pending ${proxyBlock.drain.pending}, upstreams ${proxyBlock.drain.upstreamsRegistered})`,
        );
        check(
          'E6-PROXY-DRAIN',
          proxyBlock.drain.terminalSettled === proxyBlock.drain.requestsReceived && proxyBlock.drain.pending === 0,
          `${file.path} ${role}: proxy terminal accounting must reconcile with requestsReceived at teardown`,
        );
      }
      if (proxyBlock?.requestsByBasis !== undefined) {
        const basis = proxyBlock.requestsByBasis;
        const basisSum =
          (basis.driverAttempts ?? 0) + (basis.instrumentRequests ?? 0) + (basis.candidateOptional ?? 0) + (basis.unattributed ?? 0);
        check(
          'E6-PROXY-ATTRIBUTION',
          basisSum === proxyBlock.stats.requestsReceived,
          `${file.path} ${role}: per-basis closure report must reconcile with requestsReceived`,
        );
        check(
          'E6-PROXY-ATTRIBUTION',
          basis.unattributed === 0,
          `${file.path} ${role}: unattributed proxied traffic fails closed (every population must carry its attribution basis)`,
        );
        const declared = proxyBlock.attribution?.declaredCandidateOptional;
        if (role === 'candidate' && declared !== null && declared !== undefined) {
          check(
            'E6-PROXY-ATTRIBUTION',
            basis.candidateOptional === declared,
            `${file.path} candidate: candidate-optional-through-proxy (${basis.candidateOptional}) != the declared population (${declared})`,
          );
        }
      }
    }
  }

  // Verdict integrity: the recorded verdict must equal recomputation from the
  // document's own numbers — a tampered "pass" is refused.
  const recomputedVerdict = computeVerdicts({
    aggregate,
    pairDocs: pairFiles.map((file) => file.doc),
    plan,
    profile,
  });
  check(
    'E6-VERDICT',
    stableDeepEqual(aggregate.verdict, recomputedVerdict),
    `recorded verdict != recomputed verdict (${JSON.stringify(aggregate.verdict.overallPass)} vs ${JSON.stringify(recomputedVerdict.overallPass)})`,
  );
  assertFiniteDeep(aggregate, 'aggregate(final)');
  return checks;
}

function validateSmokeDoc({ aggregate, pairFiles, plan }) {
  const checks = [];
  const check = (id, condition, detail) => {
    if (!condition) fail('SCHEMA', `[SMOKE-${id}] ${detail}`);
    checks.push(id);
  };
  check('KIND', aggregate.kind === 'e6-harness-smoke', 'smoke kind must be e6-harness-smoke');
  check('KIND', aggregate.smoke === true && aggregate.notAnE6ResultsDoc === true, 'smoke output must be explicitly marked not-an-E6-results-doc');
  check('KIND', aggregate.verdict === undefined && aggregate.e6GateVerdicts === undefined, 'smoke output must not carry E6 gate verdicts');
  check('MACHINERY', pairFiles.length >= 1, 'at least one pair executed');
  check('MACHINERY', pairFiles.every((file) => file.doc.scheduleDigest === plan.scheduleDigest), 'pair documents must bind the smoke schedule');
  for (const file of pairFiles) {
    for (const role of ['comparator', 'candidate']) {
      const memberRun = file.doc.members[role];
      const measurementObserved = Object.values(memberRun.classes).reduce((sum, bucket) => sum + bucket.scheduled, 0);
      check('MACHINERY', measurementObserved === plan.schedule.classSequence.length, `${role}: schedule not fully executed`);
      check('MACHINERY', plan.classes.every((className) => memberRun.classes[className]), `${role}: class buckets incomplete`);
      const outcomes = new Set();
      const stagesSeen = new Set();
      let completedCount = 0;
      for (const bucket of Object.values(memberRun.classes)) {
        for (const attempt of bucket.attempts) {
          outcomes.add(attempt.outcome);
          if (attempt.stage) stagesSeen.add(attempt.stage);
          if (attempt.outcome === 'completed') completedCount += 1;
        }
      }
      check('MACHINERY', completedCount > 0, `${role}: no completed observations`);
      check('MACHINERY', outcomes.size >= 2, `${role}: single outcome class; fault/accounting paths not exercised`);
      for (const block of plan.schedule.stageBlocks) {
        check('MACHINERY', stagesSeen.has(block.name), `${role}: fault stage ${block.name} never applied`);
      }
      check('MACHINERY', Object.keys(memberRun.processSamples).length >= 3, `${role}: fewer than three measured process roles sampled`);
      for (const [sampledRole, sample] of Object.entries(memberRun.processSamples)) {
        check('MACHINERY', sample.sampleCount >= 2, `${role}/${sampledRole}: insufficient process samples`);
        check('MACHINERY', isFiniteNumber(sample.peakRssBytes) && sample.peakRssBytes > 0, `${role}/${sampledRole}: peak RSS not captured`);
        check('MACHINERY', isFiniteNumber(sample.peakCpuPercent), `${role}/${sampledRole}: peak CPU not captured`);
      }
    }
  }
  check(
    'MACHINERY',
    plan.classes.every((className) => aggregate.classes[className]?.bounds?.p95?.upper95AbsMs !== null),
    'bootstrap bounds not computed for every class',
  );
  check('MACHINERY', Boolean(aggregate.seal?.profileDigest), 'smoke seal missing profile digest');
  return checks;
}

function isFiniteDigest(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

// ---------------------------------------------------------------------------
// Resource ledger + cleanup (TASK_EXECUTION_AND_CLEANUP discipline).
// ---------------------------------------------------------------------------

class ResourceLedger {
  constructor(runDir) {
    this.runDir = runDir;
    this.entries = [];
  }

  register(entry) {
    this.entries.push({ ...entry, registeredAtUtc: isoUtcNow(), closedAtUtc: null, closeStatus: 'open' });
    this.write();
  }

  closeAll() {
    for (const entry of this.entries) {
      if (entry.closeStatus === 'open') {
        entry.closeStatus = 'removed';
        entry.closedAtUtc = isoUtcNow();
      }
    }
    this.write();
  }

  killOwnedProcesses() {
    for (const entry of this.entries) {
      if (entry.kind === 'workload-driver-child' && entry.closeStatus === 'open') {
        try {
          process.kill(entry.pid, 'SIGTERM');
        } catch {
          // already gone
        }
      }
    }
  }

  write() {
    if (!this.runDir) return;
    const payload = {
      schemaVersion: 1,
      kind: 'e6-harness-run-ledger',
      taskLabel: 'run-connectivity-e6-harness',
      entries: this.entries,
      hostQosChanges: [],
      updatedAtUtc: isoUtcNow(),
    };
    fs.writeFileSync(path.join(this.runDir, 'harness-run.json'), `${JSON.stringify(payload, null, 2)}\n`);
  }
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------

function usage() {
  process.stdout.write(`Usage:
  bash scripts/run-connectivity-e6-harness.sh --profile <profile.json> [options]

Modes:
  --self-test            In-memory schema/verdict assertion suite; writes nothing.
  --smoke                Short-circuit machinery validation (1 pair, reduced
                         floors/windows). Output is marked smoke:true and is
                         structurally NOT an E6 results document.

Options:
  --profile <path>       Frozen E6 profile document (default:
                         ${DEFAULT_PROFILE_REL}).
  --pairs <n>            Pair count. Evidence mode requires >= 20 (default 20);
                         smoke defaults to 1.
  --output-root <dir>    Results root (default ${DEFAULT_OUTPUT_ROOT_REL},
                         smoke: ${DEFAULT_SMOKE_OUTPUT_ROOT_REL}).
  --run-id <id>          Explicit run id [A-Za-z0-9._-]; an existing generation
                         directory is never overwritten.
  --workload-driver builtin        Built-in loopback reference workload
                                   (smoke default; refuses E6 evidence).
  --workload-driver-cmd <exe>      Evidence-mode external driver command.
  --workload-driver-arg <a>        Repeatable external driver argument.
  --target-url <url>     Loopback workload target (evidence mode; required).
  --client-dir <dir>     Desktop electron client dir (default
                         clients/desktop/electron; built/located in evidence mode).
  --rebuild-clients      Force npm run build in the client dir (evidence mode).
  --attempt-timeout-ms <n>  Per-attempt client timeout (default 30000; smoke 1500).
  --no-fail-on-regression   Exit 0 even when measured verdicts fail (evidence
                         mode otherwise exits 3 on overall fail).
  --dry-run              Validate bindings and print the plan; execute nothing.
  --json                 Print a one-line JSON summary on stdout at the end.
  -h, --help             Show this text.
`);
}

function parseCli(argv) {
  const cli = {
    help: false,
    selfTest: false,
    smoke: false,
    dryRun: false,
    json: false,
    profile: DEFAULT_PROFILE_REL,
    pairs: null,
    outputRoot: null,
    runId: null,
    workloadDriver: null,
    workloadDriverCommand: null,
    workloadDriverArgs: [],
    targetUrl: null,
    clientDir: 'clients/desktop/electron',
    rebuildClients: false,
    attemptTimeoutMs: null,
    failOnRegression: true,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) fail('USAGE', `${arg} requires a value`);
      return argv[index];
    };
    switch (arg) {
      case '-h':
      case '--help':
        cli.help = true;
        break;
      case '--self-test':
        cli.selfTest = true;
        break;
      case '--smoke':
        cli.smoke = true;
        break;
      case '--dry-run':
        cli.dryRun = true;
        break;
      case '--json':
        cli.json = true;
        break;
      case '--profile':
        cli.profile = next();
        break;
      case '--pairs':
        cli.pairs = Number(next());
        if (!Number.isInteger(cli.pairs) || cli.pairs < 1) fail('USAGE', '--pairs must be an integer >= 1');
        break;
      case '--output-root':
        cli.outputRoot = next();
        break;
      case '--run-id':
        cli.runId = next();
        if (!/^[A-Za-z0-9._-]+$/.test(cli.runId)) fail('USAGE', '--run-id allows only [A-Za-z0-9._-]');
        break;
      case '--workload-driver':
        cli.workloadDriver = next();
        if (cli.workloadDriver !== 'builtin') fail('USAGE', '--workload-driver only accepts "builtin"');
        break;
      case '--workload-driver-cmd':
        cli.workloadDriverCommand = next();
        break;
      case '--workload-driver-arg':
        cli.workloadDriverArgs.push(next());
        break;
      case '--target-url':
        cli.targetUrl = next();
        break;
      case '--client-dir':
        cli.clientDir = next();
        break;
      case '--rebuild-clients':
        cli.rebuildClients = true;
        break;
      case '--attempt-timeout-ms':
        cli.attemptTimeoutMs = Number(next());
        if (!Number.isInteger(cli.attemptTimeoutMs) || cli.attemptTimeoutMs < 100) {
          fail('USAGE', '--attempt-timeout-ms must be an integer >= 100');
        }
        break;
      case '--no-fail-on-regression':
        cli.failOnRegression = false;
        break;
      default:
        fail('USAGE', `unknown argument: ${arg}`);
    }
  }
  return cli;
}

// ---------------------------------------------------------------------------
// Evidence-mode environment verification.
// ---------------------------------------------------------------------------

function verifyEvidenceEnvironment({ cli, profile }) {
  const selected = profile.selected;
  const hostIdentity = {
    os: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    profileOS: `macOS ${toolVersion('sw_vers', ['-productVersion'])} (${toolVersion('sw_vers', ['-buildVersion'])})`,
  };
  assertProfileHost(selected.host, hostIdentity, os.platform());
  const toolVersions = {
    node: toolVersion('node', ['--version']),
    go: toolVersion('go', ['version']),
    rustc: toolVersion('rustc', ['--version']),
  };
  const pinned = selected.toolchain;
  const mismatches = [];
  if (toolVersions.node !== pinned.node) mismatches.push(`node ${toolVersions.node} != pinned ${pinned.node}`);
  if (!toolVersions.go?.includes('go1.')) mismatches.push(`go "${toolVersions.go}" missing`);
  if (!toolVersions.go?.includes(pinned.go)) mismatches.push(`go "${toolVersions.go}" != pinned ${pinned.go}`);
  if (!toolVersions.rustc?.includes(pinned.rust.replace('rustc ', ''))) {
    mismatches.push(`rustc "${toolVersions.rustc}" != pinned ${pinned.rust}`);
  }
  if (mismatches.length > 0) {
    fail(
      'ENVIRONMENT',
      `toolchain does not match the frozen profile (${mismatches.join('; ')}); ` +
        'results qualify only the exact frozen profile — a changed toolchain needs a new profileVersion',
    );
  }
  const clientDir = path.isAbsolute(cli.clientDir) ? cli.clientDir : path.join(REPO_ROOT, cli.clientDir);
  const packageJsonPath = path.join(clientDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) fail('ENVIRONMENT', `client dir has no package.json: ${cli.clientDir}`);
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const electronSpec = packageJson.devDependencies?.electron ?? null;
  const electronInstalled = (() => {
    try {
      return JSON.parse(fs.readFileSync(path.join(clientDir, 'node_modules', 'electron', 'package.json'), 'utf8')).version ?? null;
    } catch {
      return null;
    }
  })();
  const distMain = path.join(clientDir, 'dist', 'main.js');
  const needsBuild = cli.rebuildClients || !fs.existsSync(distMain);
  let clientBuild;
  if (needsBuild) {
    log('building desktop electron client (one identical build for both pair members)...');
    const result = spawnSync('npm', ['run', 'build'], { cwd: clientDir, encoding: 'utf8', stdio: 'inherit' });
    if (result.status !== 0) fail('ENVIRONMENT', 'client build failed');
    clientBuild = { built: true, rebuilt: true, distMain: path.relative(REPO_ROOT, distMain), sha256: sha256File(distMain) };
  } else {
    clientBuild = { built: true, rebuilt: false, distMain: path.relative(REPO_ROOT, distMain), sha256: sha256File(distMain) };
  }
  return {
    hostIdentity,
    toolVersions,
    clientBuild,
    clientDirRel: path.relative(REPO_ROOT, clientDir),
    electronSpec,
    electronInstalled,
  };
}

export function assertProfileHost(expected, actual, platform) {
  if (platform !== 'darwin' || actual.arch !== expected.arch || actual.profileOS !== expected.os) {
    fail('ENVIRONMENT', `frozen profile host is ${expected.os} ${expected.arch}; this host is ${actual.profileOS} ${actual.arch}; freeze a new profile version before running on a changed host`);
  }
}

// ---------------------------------------------------------------------------
// Self-test — embedded schema/verdict assertions over synthetic documents.
// Pure in-memory; writes nothing, touches no network.
// ---------------------------------------------------------------------------

function buildSyntheticDoc({ pairs, completedPerClass, candidatePenaltyMs = 0, candidatePeakCpuPercent = 4, comparatorPeakCpuPercent = 4 }) {
  const classes = ['queued-send', 'draft-commit', 'auth-revocation', 'security-state', 'delivery-receipt'];
  const schedule = {
    attemptIntervalMs: 60,
    warmupMs: 2000,
    warmupAttempts: 33,
    measurementMs: 6000,
    classSequence: [],
    stageBlocks: [
      { stage: 0, name: 'broadband-unmetered', startMs: 0, durationMs: 2000, bandwidthKbit: 50000, latencyMs: 20, lossPercent: 0 },
      { stage: 1, name: 'metered-lte', startMs: 2000, durationMs: 2000, bandwidthKbit: 10000, latencyMs: 60, lossPercent: 1 },
      { stage: 2, name: 'weak-constrained', startMs: 4000, durationMs: 2000, bandwidthKbit: 1000, latencyMs: 200, lossPercent: 2 },
    ],
    outage: { startMs: 3000, durationMs: 1000, reconnectWithinMs: 5000 },
    observationFloorPerClassPerRun: 1000,
    classes,
    builtin: { hangProbeIndexes: [], failProbeIndexes: [] },
  };
  const seeds = { run: 'e6-pair-runbook-v1', order: 'e6-order-v1', bootstrap: 'e6-bootstrap-v1' };
  const failed = 2;
  const timedOut = 1;
  const networkDrop = 3;
  const warmupPerClass = [7, 7, 7, 6, 6];
  const perMember = completedPerClass + failed + timedOut + networkDrop;
  schedule.classSequence = Array.from({ length: perMember * classes.length }, (_, index) => classes[index % classes.length]);
  const buildMember = (role) => ({
    role,
    flag: role === 'candidate' ? 'on' : 'off',
    policyMode: role === 'candidate' ? 'execute' : 'off',
    syntheticIdentity: 'self-test',
    childCommand: 'self-test',
    childPid: 1,
    exitCode: 0,
    attemptTimeoutMs: 1500,
    faultProxy: { endpoint: 'http://127.0.0.1:0', stats: { requestsReceived: 0, forwarded: 0, droppedLoss: 0, droppedOutage: 0, upstreamErrors: 0, clientAborts: 0 } },
    window: { startedAtUtc: '2026-09-19T00:00:00Z', endedAtUtc: '2026-09-19T00:00:10Z', elapsedSeconds: 10, warmupMs: 2000, measurementMs: 6000 },
    saturation: { type: 'saturation', active: role === 'candidate', activeDuringMeasurement: role === 'candidate' },
    processSamples: {
      [MEASURED_ROLE_GATEWAY]: { pid: 2, sampleCount: 8, peakCpuPercent: comparatorPeakCpuPercent, peakRssBytes: 1048576, lastError: null },
      [MEASURED_ROLE_MAIN]: { pid: 3, sampleCount: 8, peakCpuPercent: role === 'candidate' ? candidatePeakCpuPercent : comparatorPeakCpuPercent, peakRssBytes: 2097152, lastError: null },
      [MEASURED_ROLE_RENDERER]: { pid: 4, sampleCount: 8, peakCpuPercent: 2, peakRssBytes: 524288, lastError: null },
    },
    measuredRolesReported: [MEASURED_ROLE_GATEWAY, MEASURED_ROLE_MAIN, MEASURED_ROLE_RENDERER],
    warmup: {
      scheduled: warmupPerClass.reduce((sum, value) => sum + value, 0),
      observed: warmupPerClass.reduce((sum, value) => sum + value, 0),
      attemptsRetained: true,
      perClass: Object.fromEntries(
        classes.map((className, index) => [
          className,
          { scheduled: warmupPerClass[index], completed: warmupPerClass[index], failed: 0, timedOut: 0, networkDrop: 0, attempts: [] },
        ]),
      ),
    },
    classes: Object.fromEntries(
      classes.map((className, classIndex) => {
        const attempts = [];
        const baseLatency = 10 + classIndex * 3;
        for (let seq = 0; seq < completedPerClass + failed + timedOut + networkDrop; seq += 1) {
          if (seq < completedPerClass) {
            const latency = role === 'candidate' ? baseLatency + candidatePenaltyMs : baseLatency;
            attempts.push({ seq, outcome: 'completed', latencyMs: latency + (seq % 5) * 0.5, stage: 'broadband-unmetered' });
          } else if (seq === completedPerClass) {
            attempts.push({ seq, outcome: 'failed', latencyMs: 5, stage: 'metered-lte' });
          } else if (seq === completedPerClass + 1) {
            attempts.push({ seq, outcome: 'timedOut', latencyMs: 1500, stage: 'metered-lte' });
          } else {
            attempts.push({ seq, outcome: 'networkDrop', latencyMs: 1, stage: 'weak-constrained' });
          }
        }
        const counts = attempts.reduce(
          (accumulator, attempt) => {
            accumulator[attempt.outcome] += 1;
            return accumulator;
          },
          { completed: 0, failed: 0, timedOut: 0, networkDrop: 0 },
        );
        return [
          className,
          {
            scheduled: attempts.length,
            completed: counts.completed,
            failed: counts.failed,
            timedOut: counts.timedOut,
            networkDrop: counts.networkDrop,
            attempts,
          },
        ];
      }),
    ),
  });
  const pairDocs = [];
  for (let index = 0; index < pairs; index += 1) {
    pairDocs.push({
      schemaVersion: 1,
      kind: 'e6-pair-result',
      runId: 'self-test',
      pairIndex: index,
      order: { first: index % 2 === 0 ? 'comparator' : 'candidate', sequence: index % 2 === 0 ? 'comparator-first' : 'candidate-first' },
      profileDigest: 'a'.repeat(64),
      profileId: 'e6-electron-macos-arm64-v1',
      scheduleDigest: sha256String(JSON.stringify(schedule)),
      seeds,
      members: { comparator: buildMember('comparator'), candidate: buildMember('candidate') },
    });
  }
  return { pairDocs, schedule, seeds, classes };
}

function syntheticProfileAndPlan({ schedule, seeds, classes }) {
  const selected = {
    profileId: 'e6-electron-macos-arm64-v1',
    profileVersion: 1,
    status: 'frozen',
    frozenAtUtc: '2026-09-18T00:00:00Z',
    platform: 'electron-macos',
    host: { os: 'macOS 26.6.2 (25G83)', arch: 'arm64', selection: 'explicit' },
    shell: { name: 'electron', build: '43.4.1 (clients/desktop/electron, package spec ^43.2.0)', contractVersion: 1 },
    toolchain: { node: 'v26.8.1', go: 'go1.27.1', rust: 'rustc 1.97.1' },
    criticalRequestClasses: classes.map((className) => ({ class: className, mixPercent: 20 })),
    optionalSaturation: { admitted: true, description: 'self-test' },
    networkFaults: {
      stages: schedule.stageBlocks.map(({ name, bandwidthKbit, latencyMs, lossPercent }) => ({ name, bandwidthKbit, latencyMs, lossPercent })),
      outage: { countPerMeasurement: 1, durationSeconds: 1, reconnectWithinSeconds: 5, schedule: 'fixed-mid-measurement' },
    },
    processMetricBoundaries: {
      measuredProcesses: [MEASURED_ROLE_GATEWAY, MEASURED_ROLE_MAIN, MEASURED_ROLE_RENDERER],
      sampleIntervalMs: 1000,
    },
    clockAndSeeds: seeds,
  };
  const document_ = {
    schemaVersion: 1,
    freezeSemantics: { postResultChangesProhibited: true },
    // Verdict-composition scenario: the synthetic frozen profile binds a
    // two-pair floor so the overall-pass rule is exercisable in memory. The
    // real profile's 20-pair floor is pinned by validateFrozenProfile.
    protocol: { ...FROZEN_PROTOCOL, minimumPairs: 2 },
    regressionCeilings: {
      criticalP95MaxPercent: 5,
      criticalP95MaxMilliseconds: 50,
      criticalP99MaxPercent: 10,
      criticalP99MaxMilliseconds: 100,
      peakCpuRssMaxPercent: 10,
    },
    profiles: [selected],
  };
  const plan = {
    protocol: FROZEN_PROTOCOL,
    classes,
    schedule,
    scheduleDigest: sha256String(JSON.stringify(schedule)),
    pairOrders: [],
    smoke: false,
    seeds,
    measuredRoles: selected.processMetricBoundaries.measuredProcesses,
  };
  return {
    profile: {
      document: document_,
      selected,
      digest: 'a'.repeat(64),
      path: 'self-test',
      relPath: 'self-test',
      manifestBinding: { present: false, match: null, pinnedFixtureDigest: null, caseId: PROFILE_CASE_ID },
    },
    plan,
  };
}

function serializePairFile(doc) {
  const bytes = JSON.stringify(doc);
  return { path: `pairs/pair-${String(doc.pairIndex + 1).padStart(2, '0')}.json`, bytes, doc };
}

function sealAggregate({ aggregate, pairFiles, plan, profile, context }) {
  aggregate.pairs = aggregate.pairs.map((pair, index) => ({
    ...pair,
    sha256: sha256String(pairFiles[index].bytes),
  }));
  aggregate.seal = {
    profileDigest: profile.digest,
    profilePath: profile.relPath,
    manifestBinding: profile.manifestBinding,
    scheduleDigest: plan.scheduleDigest,
    seeds: plan.seeds,
    toolVersions: context.toolVersions,
    harness: { path: HARNESS_REL, sha256: HARNESS_SHA256 },
    git: context.git,
    pairDocDigests: Object.fromEntries(pairFiles.map((file) => [file.doc.pairIndex, sha256String(file.bytes)])),
    createdAtUtc: isoUtcNow(),
  };
}

function runSelfTest() {
  const failures = [];
  const expectPass = (label, fn) => {
    try {
      fn();
      log(`self-test PASS: ${label}`);
    } catch (error) {
      failures.push(`${label}: unexpected failure ${error.message}`);
    }
  };
  const expectFail = (label, expectedTag, fn) => {
    try {
      fn();
      failures.push(`${label}: expected refusal (${expectedTag}) but validation passed`);
    } catch (error) {
      if (error.e6Tag === 'SCHEMA' && error.message.includes(expectedTag)) {
        log(`self-test PASS: ${label}`);
      } else {
        failures.push(`${label}: refused with wrong error: ${error.message}`);
      }
    }
  };

  const context = {
    runId: 'self-test',
    git: { available: false },
    toolVersions: { node: 'v26.8.1', go: 'go1.27.1', rustc: 'rustc 1.97.1' },
    workloadDriverDescription: { kind: 'builtin', synthetic: true },
  };

  // Baseline: floor NOT met (synthetic counts are far below 1000/class) — a
  // VALID document whose claims are unavailable.
  const base = buildSyntheticDoc({ pairs: 2, completedPerClass: 6 });
  const { profile, plan } = syntheticProfileAndPlan({ schedule: base.schedule, seeds: base.seeds, classes: base.classes });
  plan.pairOrders = base.pairDocs.map((doc) => doc.order.sequence);
  const pairFiles = base.pairDocs.map(serializePairFile);
  const aggregate = assembleAggregate({ pairDocs: base.pairDocs, plan, profile, context });
  sealAggregate({ aggregate, pairFiles, plan, profile, context });

  expectPass('valid below-floor document validates with claims unavailable', () => {
    validateResultsDoc({ aggregate, pairFiles, plan, profile });
    if (aggregate.verdict.criticalSampleFloor.pass !== false) fail('SELFTEST', 'floor verdict should be false');
    if (aggregate.verdict.overallPass !== false) fail('SELFTEST', 'overall should be false below floor');
    if (aggregate.verdict.claimsUnavailableClasses.length !== base.classes.length) fail('SELFTEST', 'all classes should be claims-unavailable');
  });

  // Doc-content mutations deep-clone the synthetic docs (so shared fixtures
  // stay pristine), re-serialize bytes and re-stamp the seal digests so the
  // tamper-after-seal guard is not the failure under test.
  const withMutatedDoc = (mutate) => {
    const mutated = base.pairDocs.map((doc) => serializePairFile(structuredClone(doc)));
    mutate(mutated);
    for (const file of mutated) file.bytes = JSON.stringify(file.doc);
    const cloned = structuredClone(aggregate);
    cloned.seal.pairDocDigests = Object.fromEntries(
      mutated.map((file) => [file.doc.pairIndex, sha256String(file.bytes)]),
    );
    return { cloned, mutated };
  };

  expectFail('dropped attempt refused', 'E6-ACCOUNTING', () => {
    const { cloned, mutated } = withMutatedDoc((files) => {
      files[0].doc.members.candidate.classes['queued-send'].attempts.pop();
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('outcome partition contradiction refused', 'E6-ACCOUNTING', () => {
    const { cloned, mutated } = withMutatedDoc((files) => {
      files[0].doc.members.candidate.classes['queued-send'].failed -= 1;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('warmup under-accounting refused', 'E6-ACCOUNTING', () => {
    const { cloned, mutated } = withMutatedDoc((files) => {
      files[1].doc.members.comparator.warmup.scheduled -= 1;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('tampered pair bytes refused', 'E6-BINDING', () => {
    const mutated = base.pairDocs.map(serializePairFile);
    mutated[1].bytes = `${mutated[1].bytes} `;
    validateResultsDoc({ aggregate, pairFiles: mutated, plan, profile });
  });

  expectFail('aggregate count drift refused', 'E6-CONSISTENCY', () => {
    const cloned = structuredClone(aggregate);
    cloned.classes['queued-send'].counts.candidate.completed += 1;
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('tampered point percentile refused', 'E6-PERCENTILE', () => {
    const cloned = structuredClone(aggregate);
    cloned.classes['queued-send'].comparator.p95 += 0.001;
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('tampered bootstrap bound refused', 'E6-BOOTSTRAP', () => {
    const cloned = structuredClone(aggregate);
    cloned.classes['draft-commit'].bounds.p95.upper95AbsMs += 0.5;
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('missing measured process role refused', 'E6-CROSSPROCESS', () => {
    const { cloned, mutated } = withMutatedDoc((files) => {
      delete files[0].doc.members.comparator.processSamples[MEASURED_ROLE_RENDERER];
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  // Proxy drain invariant + candidate transport seam (scheme v4): the
  // conditional E6-PROXY-* checks arm ONLY when the v4 proxy evidence blocks
  // are present (pre-v4 documents — the fixture above, the retained v1
  // generation — validate unchanged), and each block's contradictions fail
  // closed. The valid-blocks arm also proves the checks are vacuous-when-
  // absent: the baseline fixture carries no v4 blocks and still passes.
  const withV4ProxyBlocks = (mutate) =>
    withMutatedDoc((files) => {
      for (const file of files) {
        for (const role of ['comparator', 'candidate']) {
          const proxyBlock = file.doc.members[role].faultProxy;
          const received = proxyBlock.stats.requestsReceived;
          proxyBlock.config = {
            digest: sha256String('v4-selftest-shared-proxy-config'),
            attributionHeader: PROXY_CONFIG.attributionHeader,
            attributionBases: PROXY_CONFIG.attributionBases,
          };
          proxyBlock.requestsByBasis = {
            driverAttempts: received,
            instrumentRequests: 0,
            candidateOptional: 0,
            unattributed: 0,
          };
          proxyBlock.attribution = { declaredCandidateOptional: null };
          proxyBlock.drain = {
            requestsReceived: received,
            terminalSettled: received,
            pending: 0,
            upstreamsRegistered: 0,
            waitedMs: 0,
            ok: true,
          };
        }
      }
      mutate(files);
    });

  expectPass('valid v4 proxy evidence blocks validate', () => {
    const { cloned, mutated } = withV4ProxyBlocks(() => {});
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('breached proxy drain refused', 'E6-PROXY-DRAIN', () => {
    const { cloned, mutated } = withV4ProxyBlocks((files) => {
      files[0].doc.members.candidate.faultProxy.drain.ok = false;
      files[0].doc.members.candidate.faultProxy.drain.pending = 1;
      files[0].doc.members.candidate.faultProxy.drain.terminalSettled -= 1;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('proxy terminal ledger not reconciling refused', 'E6-PROXY-DRAIN', () => {
    const { cloned, mutated } = withV4ProxyBlocks((files) => {
      files[1].doc.members.comparator.faultProxy.drain.terminalSettled -= 1;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('proxy config digest mismatch between windows refused', 'E6-PROXY-SEAM', () => {
    const { cloned, mutated } = withV4ProxyBlocks((files) => {
      files[0].doc.members.candidate.faultProxy.config.digest = sha256String('a-different-proxy-config');
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('unattributed proxied traffic refused', 'E6-PROXY-ATTRIBUTION', () => {
    const { cloned, mutated } = withV4ProxyBlocks((files) => {
      // Keep the breakdown summing to requestsReceived so the reconciliation
      // check passes and the UNATTRIBUTED check is the one that fires.
      const proxyBlock = files[0].doc.members.candidate.faultProxy;
      proxyBlock.stats.requestsReceived = 3;
      proxyBlock.drain.requestsReceived = 3;
      proxyBlock.drain.terminalSettled = 3;
      proxyBlock.requestsByBasis.driverAttempts = 0;
      proxyBlock.requestsByBasis.unattributed = 3;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('per-basis breakdown not reconciling refused', 'E6-PROXY-ATTRIBUTION', () => {
    const { cloned, mutated } = withV4ProxyBlocks((files) => {
      files[1].doc.members.comparator.faultProxy.requestsByBasis.driverAttempts += 3;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('candidate optional through proxy != declared population refused', 'E6-PROXY-ATTRIBUTION', () => {
    const { cloned, mutated } = withV4ProxyBlocks((files) => {
      const candidate = files[0].doc.members.candidate.faultProxy;
      candidate.attribution.declaredCandidateOptional = 12;
      candidate.requestsByBasis.candidateOptional = 11;
      candidate.requestsByBasis.driverAttempts -= 11;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectPass('candidate optional through proxy == declared population validates', () => {
    const { cloned, mutated } = withV4ProxyBlocks((files) => {
      const candidate = files[0].doc.members.candidate.faultProxy;
      candidate.attribution.declaredCandidateOptional = 12;
      candidate.requestsByBasis.candidateOptional = 12;
      candidate.requestsByBasis.driverAttempts -= 12;
    });
    validateResultsDoc({ aggregate: cloned, pairFiles: mutated, plan, profile });
  });

  expectFail('seal removal refused', 'E6-SEAL', () => {
    const cloned = structuredClone(aggregate);
    cloned.seal = null;
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('postResultChangesProhibited=false refused', 'E6-SEAL', () => {
    const cloned = structuredClone(aggregate);
    cloned.postResultChangesProhibited = false;
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('smoke-marked e6 results doc refused', 'E6-KIND', () => {
    const cloned = structuredClone(aggregate);
    cloned.smoke = true;
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('verdict tampering refused', 'E6-VERDICT', () => {
    const cloned = structuredClone(aggregate);
    cloned.verdict.overallPass = true;
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('percentile-method drift refused', 'E6-PROTOCOL', () => {
    const cloned = structuredClone(aggregate);
    cloned.protocolEcho.percentileMethod = 'linear-interpolation';
    validateResultsDoc({ aggregate: cloned, pairFiles, plan, profile });
  });

  expectFail('schedule digest drift across pairs refused', 'E6-BINDING', () => {
    const mutated = base.pairDocs.map(serializePairFile);
    mutated[1].doc.scheduleDigest = 'b'.repeat(64);
    validateResultsDoc({ aggregate, pairFiles: mutated, plan, profile });
  });

  // Scenario variants each bind their own schedule and schedule digest.
  const variantPlan = (scenario) => ({
    ...plan,
    schedule: scenario.schedule,
    scheduleDigest: sha256String(JSON.stringify(scenario.schedule)),
    pairOrders: scenario.pairDocs.map((doc) => doc.order.sequence),
  });

  // Verdict rules: floor met + ceilings respected -> overall pass. The
  // candidate penalty (0.5ms on a 12ms p95 baseline) stays inside BOTH the
  // 5% and 50ms p95 ceilings and the 10%/100ms p99 ceilings.
  const met = buildSyntheticDoc({ pairs: 2, completedPerClass: 1000, candidatePenaltyMs: 0.5, candidatePeakCpuPercent: 4.2, comparatorPeakCpuPercent: 4 });
  const metPlan = variantPlan(met);
  const metFiles = met.pairDocs.map(serializePairFile);
  const metAggregate = assembleAggregate({ pairDocs: met.pairDocs, plan: metPlan, profile, context });
  sealAggregate({ aggregate: metAggregate, pairFiles: metFiles, plan: metPlan, profile, context });
  expectPass('floor-met within-ceiling document passes overall', () => {
    validateResultsDoc({ aggregate: metAggregate, pairFiles: metFiles, plan: metPlan, profile });
    if (metAggregate.verdict.overallPass !== true) {
      fail('SELFTEST', `expected overall pass, got ${JSON.stringify(metAggregate.verdict)}`);
    }
  });

  // Verdict rules: a real regression (candidate +40ms on a ~12ms p95) must
  // fail the ceiling verdict while remaining a VALID document.
  const regressed = buildSyntheticDoc({ pairs: 2, completedPerClass: 1000, candidatePenaltyMs: 40, candidatePeakCpuPercent: 4.2, comparatorPeakCpuPercent: 4 });
  const regressedPlan = variantPlan(regressed);
  const regressedFiles = regressed.pairDocs.map(serializePairFile);
  const regressedAggregate = assembleAggregate({ pairDocs: regressed.pairDocs, plan: regressedPlan, profile, context });
  sealAggregate({ aggregate: regressedAggregate, pairFiles: regressedFiles, plan: regressedPlan, profile, context });
  expectPass('breached ceiling records fail verdict in a valid document', () => {
    validateResultsDoc({ aggregate: regressedAggregate, pairFiles: regressedFiles, plan: regressedPlan, profile });
    if (regressedAggregate.verdict.pairedRegression.pass !== false) fail('SELFTEST', 'regression must fail pairedRegression');
    if (regressedAggregate.verdict.overallPass !== false) fail('SELFTEST', 'regression must fail overall');
  });

  // Verdict rules: comparator baseline zero is never evaluable, never pass.
  const zeroBase = buildSyntheticDoc({ pairs: 2, completedPerClass: 1000, comparatorPeakCpuPercent: 0, candidatePeakCpuPercent: 3 });
  const zeroPlan = variantPlan(zeroBase);
  const zeroFiles = zeroBase.pairDocs.map(serializePairFile);
  const zeroAggregate = assembleAggregate({ pairDocs: zeroBase.pairDocs, plan: zeroPlan, profile, context });
  sealAggregate({ aggregate: zeroAggregate, pairFiles: zeroFiles, plan: zeroPlan, profile, context });
  expectPass('comparator-baseline-zero CPU refuses the crossprocess verdict', () => {
    validateResultsDoc({ aggregate: zeroAggregate, pairFiles: zeroFiles, plan: zeroPlan, profile });
    if (zeroAggregate.verdict.crossprocessCriticalSaturation.pass !== false) {
      fail('SELFTEST', 'comparator-zero peaks must not pass the crossprocess verdict');
    }
  });

  if (failures.length > 0) {
    for (const failure of failures) process.stderr.write(`e6-harness self-test FAIL: ${failure}\n`);
    process.stderr.write('e6-harness self-test: FAIL\n');
    process.exit(1);
  }
  process.stdout.write('e6-harness self-test: PASS (schema refusals + verdict rules + recomputation integrity)\n');
}

// ---------------------------------------------------------------------------
// Main driver.
// ---------------------------------------------------------------------------

const SMOKE_PROFILE = {
  warmupSeconds: 2,
  measurementSeconds: 6,
  observationFloor: 12,
  attemptTimeoutMs: 1500,
};

class Cleanup {
  constructor() {
    this.tasks = [];
    this.done = false;
  }

  register(fn, label) {
    this.tasks.push({ fn, label, done: false });
  }

  async run({ interrupted = false } = {}) {
    if (this.done) return;
    this.done = true;
    for (const task of [...this.tasks].reverse()) {
      if (task.done) continue;
      task.done = true;
      try {
        await task.fn({ interrupted });
      } catch (error) {
        log(`cleanup task ${task.label} failed: ${error.message}`);
      }
    }
  }
}

async function startSmokeTargetChild({ plan }) {
  const child = spawn(process.execPath, [path.join(REPO_ROOT, HARNESS_REL), '--internal-smoke-target'], {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      E6_SMOKE_TARGET_CONFIG: JSON.stringify({
        failProbeIndexes: plan.schedule.builtin.failProbeIndexes,
        hangProbeIndexes: plan.schedule.builtin.hangProbeIndexes,
      }),
    },
  });
  const ready = await new Promise((resolve, reject) => {
    const timeout_ = setTimeout(() => reject(new Error('smoke target child did not become ready')), 10_000);
    child.stdout.setEncoding('utf8');
    child.stdout.once('data', (chunk) => {
      clearTimeout(timeout_);
      const line = chunk.split('\n')[0];
      try {
        resolve(JSON.parse(line));
      } catch {
        reject(new Error(`unparsable smoke target ready line: ${line}`));
      }
    });
    child.once('exit', (code) => reject(new Error(`smoke target child exited early (${code})`)));
  });
  return { child, endpoint: ready.endpoint, pid: ready.pid };
}

async function main() {
  HARNESS_SHA256 = sha256File(path.join(REPO_ROOT, HARNESS_REL));
  const cli = parseCli(process.argv.slice(2));
  if (cli.help) {
    usage();
    return;
  }
  if (cli.selfTest) {
    runSelfTest();
    return;
  }

  const mode = cli.smoke ? 'smoke' : 'evidence';
  const profile = loadProfile(cli.profile, { mode });
  const selected = profile.selected;

  if (mode === 'evidence' && !cli.dryRun && !cli.workloadDriverCommand) {
    fail(
      'USAGE',
      'evidence mode requires --workload-driver-cmd <exe> (the built-in loopback reference workload cannot produce E6 evidence)',
    );
  }
  if (mode === 'smoke' && (cli.workloadDriverCommand || cli.targetUrl)) {
    fail('USAGE', '--smoke uses the built-in reference workload and loopback target only');
  }

  const pairs = cli.pairs ?? (mode === 'smoke' ? 1 : FROZEN_PROTOCOL.minimumPairs);
  if (mode === 'evidence' && pairs < FROZEN_PROTOCOL.minimumPairs) {
    fail('USAGE', `evidence mode requires at least ${FROZEN_PROTOCOL.minimumPairs} pairs (profile.protocol.minimumPairs); got ${pairs}`);
  }
  if (mode === 'evidence') {
    if (cli.targetUrl) {
      // Loopback-only is a hard rule, dry-run included: this harness never
      // addresses non-loopback network targets.
      const target = new URL(cli.targetUrl);
      if (!['127.0.0.1', 'localhost', '::1'].includes(target.hostname)) {
        fail('USAGE', 'network use is loopback-only; --target-url must address loopback');
      }
    } else if (!cli.dryRun) {
      fail('USAGE', 'evidence mode requires --target-url (loopback workload target base URL)');
    }
  }

  const seeds = {
    run: selected.clockAndSeeds.runSeed,
    order: selected.clockAndSeeds.orderSeed,
    bootstrap: selected.clockAndSeeds.bootstrapSeed,
  };
  const smokeProfile = { ...SMOKE_PROFILE };
  const plan = buildPlan({ selected, seeds, pairs, smoke: mode === 'smoke', smokeProfile });
  const attemptTimeoutMs = cli.attemptTimeoutMs ?? (mode === 'smoke' ? SMOKE_PROFILE.attemptTimeoutMs : 30_000);

  const evidence = mode === 'evidence' && !cli.dryRun ? verifyEvidenceEnvironment({ cli, profile }) : null;
  const toolVersions =
    evidence?.toolVersions ??
    {
      node: toolVersion('node', ['--version']),
      go: toolVersion('go', ['version']),
      rustc: toolVersion('rustc', ['--version']),
    };

  const runId =
    cli.runId ??
    `${mode === 'smoke' ? 'e6hsmoke' : 'e6h'}-${isoUtcNow().replace(/[-:]/g, '').toLowerCase()}-${shortCommit()}`;
  const outputRootRel =
    cli.outputRoot ?? (mode === 'smoke' ? DEFAULT_SMOKE_OUTPUT_ROOT_REL : DEFAULT_OUTPUT_ROOT_REL);
  const outputRoot = path.isAbsolute(outputRootRel) ? outputRootRel : path.join(REPO_ROOT, outputRootRel);
  const runDir = path.join(outputRoot, runId);

  if (cli.dryRun) {
    process.stdout.write(
      `${JSON.stringify(
        {
          dryRun: true,
          mode,
          profileId: selected.profileId,
          profileDigest: profile.digest,
          manifestBinding: profile.manifestBinding,
          pairs,
          scheduleDigest: plan.scheduleDigest,
          attemptIntervalMs: plan.schedule.attemptIntervalMs,
          warmupMs: plan.schedule.warmupMs,
          measurementMs: plan.schedule.measurementMs,
          observationFloorPerClassPerRun: plan.schedule.observationFloorPerClassPerRun,
          outage: plan.schedule.outage,
          stageBlocks: plan.schedule.stageBlocks.map(({ name, startMs, durationMs }) => ({ name, startMs, durationMs })),
          pairOrders: plan.pairOrders,
          runIdWouldBe: runId,
          runDirWouldBe: path.relative(REPO_ROOT, runDir),
        },
        null,
        2,
      )}\n`,
    );
    return;
  }

  // Generation directory is created exclusively — never overwrite a rerun.
  fs.mkdirSync(outputRoot, { recursive: true });
  try {
    fs.mkdirSync(runDir, { recursive: false });
  } catch {
    fail('RUNID', `generation directory already exists: ${path.relative(REPO_ROOT, runDir)} — reruns write new dated generations and never overwrite`);
  }
  const generation = runDir;
  fs.mkdirSync(path.join(generation, 'pairs'), { recursive: true });
  fs.mkdirSync(path.join(generation, 'inputs'), { recursive: true });
  fs.copyFileSync(profile.path, path.join(generation, 'inputs', 'profile.json'));
  log(`generation: ${path.relative(REPO_ROOT, generation)}`);

  const resources = new ResourceLedger(generation);
  ACTIVE_RESOURCES = resources;
  const cleanup = new Cleanup();
  let interrupted = false;
  const onSignal = (signal) => {
    if (interrupted) return;
    interrupted = true;
    log(`received ${signal}; killing owned children and closing owned resources`);
    resources.killOwnedProcesses();
    // An in-flight await (spawn error, refused target) can hold the event
    // loop open long after the children are dead — exit instead of lingering
    // as a half-alive run. 130 = terminated by SIGINT convention.
    process.exit(130);
  };
  process.on('SIGINT', () => onSignal('SIGINT'));
  process.on('SIGTERM', () => onSignal('SIGTERM'));

  resources.write();
  const context = {
    runId,
    profileDigest: profile.digest,
    profileId: selected.profileId,
    hostIdentity: evidence?.hostIdentity,
    git: gitReceipt(),
    toolVersions,
    workloadDriver: mode === 'smoke' ? 'builtin' : 'external',
    workloadDriverDescription:
      mode === 'smoke'
        ? { kind: 'builtin', synthetic: true, note: 'built-in loopback reference workload; machinery validation only' }
        : { kind: 'external', command: cli.workloadDriverCommand, args: cli.workloadDriverArgs },
    targetUrl: mode === 'smoke' ? null : cli.targetUrl,
    attemptTimeoutMs,
    sampleIntervalMs: selected.processMetricBoundaries.sampleIntervalMs,
    smokeTargetPid: null,
  };

  let exitCode = 0;
  try {
    if (mode === 'smoke') {
      const target = await startSmokeTargetChild({ plan });
      context.targetUrl = target.endpoint;
      context.smokeTargetPid = target.pid;
      resources.register({ kind: 'loopback-smoke-target-child', name: `e6-smoke-target/${runId}`, pid: target.pid, endpoint: target.endpoint });
      cleanup.register(async () => {
        target.child.kill('SIGTERM');
      }, 'smoke-target-child');
    }

    const pairFiles = [];
    for (let pairNumber = 0; pairNumber < pairs && !interrupted; pairNumber += 1) {
      log(`pair ${pairNumber + 1}/${pairs} (${plan.pairOrders[pairNumber]}) starting`);
      const pairDoc = await runPair({ pairNumber, plan, runId, context, resources });
      const pairPath = path.join(generation, 'pairs', `pair-${String(pairNumber + 1).padStart(2, '0')}.json`);
      fs.writeFileSync(pairPath, JSON.stringify(pairDoc));
      pairFiles.push({ path: path.relative(generation, pairPath), bytes: fs.readFileSync(pairPath, 'utf8'), doc: pairDoc });
      log(`pair ${pairNumber + 1}/${pairs} complete`);
    }
    if (interrupted) {
      fs.writeFileSync(
        path.join(generation, 'interrupted.json'),
        `${JSON.stringify({ interrupted: true, atUtc: isoUtcNow(), completedPairs: pairFiles.length }, null, 2)}\n`,
      );
      log('run interrupted; partial generation retained with interrupted.json');
      exitCode = 130;
      return;
    }

    const aggregate = assembleAggregate({ pairDocs: pairFiles.map((file) => file.doc), plan, profile, context });
    sealAggregate({ aggregate, pairFiles, plan, profile, context });
    if (mode === 'evidence') {
      const checked = validateResultsDoc({ aggregate, pairFiles, plan, profile });
      log(`results-doc validation: ${checked.length} assertions enforced`);
    } else {
      const checked = validateSmokeDoc({ aggregate, pairFiles, plan });
      log(`smoke-doc validation: ${checked.length} machinery assertions enforced`);
    }

    fs.writeFileSync(path.join(generation, 'aggregate.json'), `${JSON.stringify(aggregate, null, 2)}\n`);
    resources.closeAll();

    printSummary({ aggregate, generation, mode });
    if (cli.json) {
      process.stdout.write(
        `${JSON.stringify({
          runId,
          generation: path.relative(REPO_ROOT, generation),
          mode,
          pairs: pairFiles.length,
          overallPass: aggregate.verdict?.overallPass ?? null,
          smoke: aggregate.smoke,
        })}\n`,
      );
    }
    if (mode === 'evidence' && cli.failOnRegression && aggregate.verdict?.overallPass === false) {
      log('overall verdict FAIL — exiting 3 (gate enforcement; use --no-fail-on-regression for diagnostic reruns)');
      exitCode = 3;
    }
  } catch (error) {
    log(`ERROR ${error.message}`);
    process.exitCode = interrupted ? 130 : 1;
    throw error;
  } finally {
    await cleanup.run({ interrupted });
    resources.closeAll();
  }
  if (exitCode !== 0) process.exitCode = exitCode;
}

function shortCommit() {
  const result = spawnSync('git', ['rev-parse', '--short=12', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : 'nogit';
}

function printSummary({ aggregate, generation, mode }) {
  const lines = [];
  lines.push(`E6 ${mode === 'smoke' ? 'SMOKE (machinery validation only — NOT E6 evidence)' : 'paired-run results'}`);
  lines.push(`  generation : ${path.relative(REPO_ROOT, generation)}`);
  lines.push(`  profile    : ${aggregate.profile.profileId} v${aggregate.profile.profileVersion} digest=${aggregate.profile.digest.slice(0, 12)}...`);
  lines.push(`  pairs      : ${aggregate.pairs.length} orders=${aggregate.pairs.map((pair) => pair.order).join(',') || 'n/a'}`);
  for (const [className, entry] of Object.entries(aggregate.classes)) {
    lines.push(
      `  ${className.padEnd(18)} completed off/on=${entry.counts.comparator.completed}/${entry.counts.candidate.completed}` +
        ` p95=${entry.comparator.p95}->${entry.candidate.p95}ms` +
        ` bound95=+${entry.bounds.p95.upper95AbsMs}ms/${entry.bounds.p95.upper95RelPercent === null ? 'n/e' : `${entry.bounds.p95.upper95RelPercent}%`}` +
        ` failed/timedOut/dropped off=${entry.counts.comparator.failed}/${entry.counts.comparator.timedOut}/${entry.counts.comparator.networkDrop}` +
        ` on=${entry.counts.candidate.failed}/${entry.counts.candidate.timedOut}/${entry.counts.candidate.networkDrop}`,
    );
  }
  if (aggregate.verdict) {
    lines.push(
      `  verdict    : floor=${aggregate.verdict.criticalSampleFloor.pass} regression=${aggregate.verdict.pairedRegression.pass} ` +
        `accounting=${aggregate.verdict.failedRequestAccounting.pass} crossprocess=${aggregate.verdict.crossprocessCriticalSaturation.pass} ` +
        `overall=${aggregate.verdict.overallPass}`,
    );
    if (aggregate.verdict.claimsUnavailableClasses.length > 0) {
      lines.push(`  claims unavailable (below observation floor): ${aggregate.verdict.claimsUnavailableClasses.join(', ')}`);
    }
  }
  process.stdout.write(`${lines.join('\n')}\n`);
}

if (import.meta.main) {
  if (process.argv.includes('--internal-smoke-target')) {
    runInternalSmokeTarget();
  } else if (process.argv.includes('--internal-member-simulator')) {
    runInternalMemberSimulator();
  } else {
    main().catch((error) => {
      process.stderr.write(`e6-harness: fatal ${error.message}\n`);
      if (process.env.E6_DEBUG) process.stderr.write(`${error.stack ?? ''}\n`);
      // A fatal (e.g. the driver spawn throwing) leaves owned handles alive —
      // the fault-proxy listener and ledger timers keep the event loop spinning
      // forever, so the process would hang instead of exiting. Kill owned
      // processes and exit hard; a fatal run has no results worth flushing.
      try {
        ACTIVE_RESOURCES?.killOwnedProcesses();
      } catch {}
      process.exit(1);
    });
  }
}
