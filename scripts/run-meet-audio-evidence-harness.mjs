#!/usr/bin/env node
/**
 * MEET MP-AUDIO-001 pinned-Egress audio evidence harness — receipt-only
 * driver for the pinned LiveKit/Egress audio path (test-contract row 32,
 * wave-1 unit B4; plan
 * `retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-recording.md`
 * M4 bullet 1: "Freeze its exact supported Egress/API/container/codec
 * behavior with real pinned service evidence before implementing the public
 * recording contract").
 *
 * CONTRACT: meet-audio-evidence-harness
 * Authority: retired-docs:verification/2026-09-05-meet-document-presentation-test-contract.md
 * row MP-AUDIO-001 (amended 2026-09-23). The three binding rules:
 *
 *  (a) RECEIPT-ONLY, NO PROMOTION. Everything this harness writes is an
 *      observed-facts receipt under test-results/. It NEVER promotes or
 *      pins a CaptureProfile; no promotion path exists in this repo and
 *      building one would change admission. A receipt alone can never turn
 *      `evidence_pending` into `qualified` — a qualification decision is an
 *      explicit owner/review admission binding a digest-bearing EvidenceRef
 *      (`<receipt-path>#sha256=<64 hex>`, enforced by acquisition.go
 *      Validate() and the BZ276 reducer shape belt). The receipt schema
 *      itself refuses a promotion claim.
 *
 *  (b) MISSING SERVICE = EVIDENCE_PENDING FAILURE, NEVER A SKIP. When the
 *      pinned LiveKit/Egress services are absent or cannot start (no
 *      Docker, unpinned image refused, pull/health failure, Linux-only
 *      binary on darwin, port conflict), the harness writes an
 *      `evidence_pending` receipt naming the exact missing piece and exits
 *      NON-ZERO. A skip must never surface as green.
 *
 *  (c) NEVER A REQUIRED CI LANE. The live mode is a manual operator run.
 *      Nothing in .github/workflows, scripts/verify-all.sh or any other
 *      required lane invokes this harness. `--self-test` / `--dry-run` are
 *      offline and write nothing; they exist so the machinery can be
 *      checked anywhere WITHOUT starting services — they still must not be
 *      wired into a required lane.
 *
 * ---------------------------------------------------------------------------
 * Pins (single source of truth — nothing here invents a value)
 * ---------------------------------------------------------------------------
 * The harness parses `mailserver/deploy/scripts/lib-livekit.sh` and refuses
 * to run if the pins are missing or malformed:
 *   EGRESS_IMAGE        docker.io/livekit/egress:v1.13.0@sha256:980ff439...
 *   LIVEKIT_VERSION     1.13.5 (+ LIVEKIT_SHA256_AMD64 / _ARM64 release
 *                       archive digests — Linux release binaries)
 * The pinned egress image is also the only tool allowed to probe produced
 * media (its bundled ffprobe), so every harness-chosen image is pinned.
 * livekit-server runs from:
 *   1. `--livekit-binary <p>` — sha256-verified against the pinned release
 *      digests (Linux builds; the linux-ci-host path), or
 *   2. `--livekit-image name@sha256:<64hex>` — an OPERATOR-verified image
 *      digest (the repo publishes no livekit-server image digest; the
 *      operator owns that trust decision and the receipt records it), or
 *   3. the repo's own `install_livekit_binary` (sha256-verified release
 *      archive) — Linux hosts only; on darwin this refuses with rule-32b
 *      honesty instead of pretending a Linux binary can run.
 * Sinks/buses: an operator S3 endpoint, or a digest-pinned `--sink-image`
 * (the harness creates the bucket via SigV4 — the official MinIO image
 * ships no mc CLI and no unpinned tool may run); the egress config's
 * redis/valkey pipeline bus may be run via a digest-pinned `--bus-image`
 * (else the harness records whatever the pinned egress actually does
 * without one). Tag-only image refs are refused everywhere — no unpinned
 * or untrust-rooted image ever executes.
 *
 * ---------------------------------------------------------------------------
 * Modes and exit codes (e6-harness conventions)
 * ---------------------------------------------------------------------------
 *   --self-test   In-memory receipt-schema/pin-parser/verdict assertions.
 *                 Writes nothing. Exit 0/1.
 *   --dry-run     Validates the real pins + CLI bindings + receipt schema
 *                 and prints the execution plan + the exact operator
 *                 command. Writes nothing, starts nothing, needs no Docker.
 *                 Exit 0/1.
 *   live (default) Provisions the pinned stack, drives the existing B2
 *                 RoomComposite audio path end-to-end (start/stop + the
 *                 named `MP-AUDIO-001/start-failure-visible` arm), probes
 *                 the produced bytes with the pinned image's ffprobe, and
 *                 writes test-results/meet-audio-evidence/<run-id>/
 *                 receipt.json (+ logs/, media/). Never overwrites a run
 *                 directory.
 * Exit codes: 0 evidence run completed with disposition `observed`;
 * 3 evidence run completed with disposition `evidence_pending` (services
 * missing/failed — NON-ZERO, never green); 1 machinery/validation/usage
 * failure (usage exits 1, never 2; disposition `failed` also exits 1);
 * 130 interrupted. Interrupts and failures clean up every run-owned
 * resource (processes, containers) and record the cleanup steps; the
 * receipt lists every owned resource with its runtime name for exact-target
 * manual reconciliation if the process is killed hard.
 *
 * Honesty limits: the implemented probes cover producer/API/container/
 * codec identity and start/stop. Clock-alignment quantification, gap
 * injection, duplicate/lost-ack, crash-recovery and revoke/end arms are
 * DECLARED in every receipt's `unimplementedProbes` and are NOT claimed by
 * a receipt. Secrets are never written to the receipt (only sha256
 * fingerprints; sink keys are per-request, run-scoped values are random
 * per run, and download URLs are presigned — file results are recorded
 * with credentials stripped).
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const DEPLOY_LIB_REL = 'mailserver/deploy/scripts/lib-livekit.sh';
const DEFAULT_OUTPUT_ROOT_REL = 'test-results/meet-audio-evidence';
const HARNESS_REL = 'scripts/run-meet-audio-evidence-harness.mjs';

// The EvidenceRef rule a future owner admission must satisfy when binding
// this receipt (mirrors acquisition.go `evidenceRefDigest` and the BZ276
// SQL shape belt — kept in lockstep by test-contract row 32).
const EVIDENCE_REF_DIGEST = /^[^#\s]+#sha256=[0-9a-f]{64}$/;
const DISPOSITIONS = ['observed', 'evidence_pending', 'failed'];
const DIGEST_PINNED_IMAGE = /^[^@\s]+@sha256:[0-9a-f]{64}$/;

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
function sha256File(file) {
  return sha256(fs.readFileSync(file));
}
function isoUtcNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}
function fingerprint(value) {
  // Secret fingerprint: proves which secret ran without recording it.
  return `sha256:${sha256(String(value)).slice(0, 16)}`;
}
function log(msg) {
  process.stderr.write(`meet-audio-evidence: ${msg}\n`);
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class UsageError extends Error {}
class MachineryError extends Error {}

function usage() {
  process.stdout.write(`Usage:
  bash scripts/run-meet-audio-evidence-harness.sh --self-test
  bash scripts/run-meet-audio-evidence-harness.sh --dry-run
  bash scripts/run-meet-audio-evidence-harness.sh [live options]

Modes:
  --self-test            In-memory schema/pin/verdict assertions; writes nothing.
  --dry-run              Validate pins/bindings and print the plan; starts
                         nothing, writes nothing.
  (default)              LIVE evidence run (manual operator lane; NEVER a
                         required CI lane). Writes a run-scoped receipt.

Live options:
  --output-root <dir>    Results root (default ${DEFAULT_OUTPUT_ROOT_REL}).
  --run-id <id>          Explicit run id [A-Za-z0-9._-]; an existing run
                         directory is never overwritten.
  --livekit-binary <p>   livekit-server binary; sha256-verified against the
                         pinned release digests (Linux builds).
  --livekit-image <ref>  ALTERNATIVE digest-pinned livekit-server image
                         (name@sha256:<64hex>); operator-verified digest,
                         recorded in the receipt.
  --sink-endpoint <url>  S3-compatible sink endpoint (env
                         MEET_AUDIO_SINK_ENDPOINT). Required for live.
  --sink-bucket <b>      Sink bucket (env MEET_AUDIO_SINK_BUCKET).
  --sink-region <r>      Sink region (default us-east-1).
  --sink-access-key <k>  Sink access key (env MEET_AUDIO_SINK_ACCESS_KEY).
  --sink-secret-key <k>  Sink secret key (env MEET_AUDIO_SINK_SECRET_KEY).
                         Never recorded (fingerprint only).
  --sink-image <ref>     OPTIONAL digest-pinned image (name@sha256:<64hex>,
                         e.g. MinIO) for the harness to run the sink itself;
                         the harness creates the bucket via SigV4.
  --bus-image <ref>      OPTIONAL digest-pinned redis/valkey image for the
                         egress pipeline bus. Without it the harness records
                         what the pinned egress does without a bus.
  --ports-http <n>       LiveKit HTTP/signal port (default 7880).
  --keep-services        Diagnostics only: do not tear the stack down at the
                         end (every owned resource is still listed in the
                         receipt for exact-target manual cleanup).
  -h, --help             Show this text.

Exit codes: 0 observed evidence; 3 evidence_pending (missing/failed pinned
services — non-zero, never a green skip); 1 machinery/validation/usage;
130 interrupted.
`);
}

function parseCli(argv) {
  const cli = {
    help: false,
    selfTest: false,
    dryRun: false,
    outputRoot: null,
    runId: null,
    livekitBinary: null,
    livekitImage: null,
    sinkEndpoint: process.env.MEET_AUDIO_SINK_ENDPOINT || null,
    sinkBucket: process.env.MEET_AUDIO_SINK_BUCKET || null,
    sinkRegion: process.env.MEET_AUDIO_SINK_REGION || 'us-east-1',
    sinkAccessKey: process.env.MEET_AUDIO_SINK_ACCESS_KEY || null,
    sinkSecretKey: process.env.MEET_AUDIO_SINK_SECRET_KEY || null,
    sinkImage: null,
    busImage: null,
    portsHttp: 7880,
    keepServices: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) throw new UsageError(`${arg} requires a value`);
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
      case '--dry-run':
        cli.dryRun = true;
        break;
      case '--output-root':
        cli.outputRoot = next();
        break;
      case '--run-id':
        cli.runId = next();
        if (!/^[A-Za-z0-9._-]+$/.test(cli.runId)) throw new UsageError('--run-id allows only [A-Za-z0-9._-]');
        break;
      case '--livekit-binary':
        cli.livekitBinary = next();
        break;
      case '--livekit-image':
        cli.livekitImage = next();
        break;
      case '--sink-endpoint':
        cli.sinkEndpoint = next();
        break;
      case '--sink-bucket':
        cli.sinkBucket = next();
        break;
      case '--sink-region':
        cli.sinkRegion = next();
        break;
      case '--sink-access-key':
        cli.sinkAccessKey = next();
        break;
      case '--sink-secret-key':
        cli.sinkSecretKey = next();
        break;
      case '--sink-image':
        cli.sinkImage = next();
        break;
      case '--bus-image':
        cli.busImage = next();
        break;
      case '--ports-http':
        cli.portsHttp = Number(next());
        if (!Number.isInteger(cli.portsHttp) || cli.portsHttp <= 0 || cli.portsHttp > 65535) {
          throw new UsageError('--ports-http must be a TCP port');
        }
        break;
      case '--keep-services':
        cli.keepServices = true;
        break;
      default:
        throw new UsageError(`unknown argument: ${arg}`);
    }
  }
  return cli;
}

// ---------------------------------------------------------------------------
// Pin parsing — lib-livekit.sh is the single source of truth.
// ---------------------------------------------------------------------------

export function parsePins(libSource) {
  const pins = {};
  const scalars = {
    egressImage: 'EGRESS_IMAGE',
    livekitVersion: 'LIVEKIT_VERSION',
    livekitSha256Amd64: 'LIVEKIT_SHA256_AMD64',
    livekitSha256Arm64: 'LIVEKIT_SHA256_ARM64',
  };
  for (const [field, name] of Object.entries(scalars)) {
    const match = libSource.match(new RegExp(`^${name}="([^"]*)"`, 'm'));
    if (!match || match[1] === '') return { ok: false, reason: `${name} missing or empty in ${DEPLOY_LIB_REL}` };
    pins[field] = match[1];
  }
  if (!DIGEST_PINNED_IMAGE.test(pins.egressImage)) {
    return { ok: false, reason: `EGRESS_IMAGE ${JSON.stringify(pins.egressImage)} is not a digest-pinned image reference (a tag alone is mutable — refused)` };
  }
  if (!/^\d+\.\d+\.\d+$/.test(pins.livekitVersion)) {
    return { ok: false, reason: `LIVEKIT_VERSION ${JSON.stringify(pins.livekitVersion)} is not a plain semver` };
  }
  for (const field of ['livekitSha256Amd64', 'livekitSha256Arm64']) {
    if (!/^[0-9a-f]{64}$/.test(pins[field])) {
      return { ok: false, reason: `${scalars[field]} is not a 64-hex digest` };
    }
  }
  return { ok: true, pins };
}

function loadPins() {
  const libPath = path.join(ROOT, DEPLOY_LIB_REL);
  if (!fs.existsSync(libPath)) {
    throw new MachineryError(`pin source missing: ${DEPLOY_LIB_REL}`);
  }
  const parsed = parsePins(fs.readFileSync(libPath, 'utf8'));
  if (!parsed.ok) throw new MachineryError(parsed.reason);
  return parsed.pins;
}

// ---------------------------------------------------------------------------
// Receipt schema (v1) — the only output shape this harness may produce.
// ---------------------------------------------------------------------------

export function validateReceipt(receipt) {
  const problems = [];
  const need = (cond, msg) => { if (!cond) problems.push(msg); };

  need(receipt && typeof receipt === 'object', 'receipt is not an object');
  if (problems.length) return problems;
  need(receipt.schema === 'meet-audio-evidence-receipt/v1', 'receipt.schema must be meet-audio-evidence-receipt/v1');
  need(/^[A-Za-z0-9._-]+$/.test(String(receipt.runId)), 'receipt.runId missing/malformed');
  need(DISPOSITIONS.includes(receipt.disposition), `receipt.disposition must be one of ${DISPOSITIONS.join('|')}`);

  // Rule (a): receipt-only. A receipt claiming promotion is invalid BY
  // SCHEMA, not just by policy.
  need(receipt.promotion && receipt.promotion.permitted === false, 'receipt.promotion.permitted must be false — receipts never promote (row 32a)');
  need(typeof receipt.promotion?.note === 'string' && receipt.promotion.note.includes('receipt-only'), 'receipt.promotion.note must state the receipt-only boundary');

  // Pins: the egress image pin and livekit version are mandatory in every
  // receipt; full resolution is mandatory once services actually ran.
  need(receipt.pins && typeof receipt.pins === 'object', 'receipt.pins missing');
  if (receipt.pins) {
    need(DIGEST_PINNED_IMAGE.test(String(receipt.pins.egressImage)), 'receipt.pins.egressImage must be name@sha256:<64hex>');
    need(/^\d+\.\d+\.\d+$/.test(String(receipt.pins.livekitVersion)), 'receipt.pins.livekitVersion must be semver');
    if (receipt.disposition !== 'evidence_pending') {
      need(/^[0-9a-f]{64}$/.test(String(receipt.pins.livekitSha256)), 'receipt.pins.livekitSha256 must be a 64-hex digest');
      need(typeof receipt.pins.livekitBinaryPath === 'string' && receipt.pins.livekitBinaryPath !== '', 'receipt.pins.livekitBinaryPath required once services ran');
      need(typeof receipt.pins.egressImageResolvedDigest === 'string' && /^sha256:[0-9a-f]{64}$/.test(receipt.pins.egressImageResolvedDigest), 'receipt.pins.egressImageResolvedDigest must record the pulled digest once services ran');
    }
  }

  need(typeof receipt.host === 'object' && receipt.host !== null, 'receipt.host missing');
  need(Array.isArray(receipt.commands), 'receipt.commands must be an array');
  for (const command of receipt.commands) {
    need(command && typeof command.command === 'string', 'each receipt.commands[] entry needs a command string');
    need(Number.isInteger(command.exitCode), 'each receipt.commands[] entry needs an integer exitCode');
  }
  need(Array.isArray(receipt.probes), 'receipt.probes must be an array');
  for (const probe of receipt.probes) {
    need(probe && typeof probe.name === 'string', 'each probe needs a name');
    need(typeof probe.outcome === 'string', 'each probe needs an outcome');
    if (probe.media) {
      need(/^[0-9a-f]{64}$/.test(String(probe.media.contentSha256)), 'probe.media.contentSha256 must be a 64-hex digest');
      need(Number.isInteger(probe.media.byteSize) && probe.media.byteSize > 0, 'probe.media.byteSize must be positive');
      need(typeof probe.media.mimeType === 'string' && probe.media.mimeType !== '', 'probe.media.mimeType required');
      need(typeof probe.media.container === 'string' && probe.media.container !== '', 'probe.media.container required');
      need(typeof probe.media.codec === 'string' && probe.media.codec !== '', 'probe.media.codec required');
    }
  }
  need(Array.isArray(receipt.unimplementedProbes)
    && receipt.unimplementedProbes.every((p) => typeof p === 'string')
    && receipt.unimplementedProbes.length > 0,
  'receipt.unimplementedProbes must be a non-empty string array (honest scope declaration)');

  // Rule (b) discipline: evidence_pending must name what was missing;
  // failed must name its failure; observed must have evidence.
  if (receipt.disposition === 'evidence_pending') {
    need(typeof receipt.pendingReason === 'string' && receipt.pendingReason !== '', 'an evidence_pending receipt must name pendingReason');
  }
  if (receipt.disposition === 'failed') {
    need(typeof receipt.failureReason === 'string' && receipt.failureReason !== '', 'a failed receipt must name failureReason');
  }
  if (receipt.disposition === 'observed') {
    need(Array.isArray(receipt.probes) && receipt.probes.some((p) => p.outcome === 'produced'), 'an observed receipt needs at least one produced probe');
  }

  // Secrets and credentialed URLs must never be recorded.
  const serialized = JSON.stringify(receipt);
  need(!/MEET_AUDIO_SINK_SECRET_KEY=/.test(serialized), 'receipts must never embed sink secret env assignments');
  need(!/downloadUrl|download_url/.test(serialized), 'receipts must never embed presigned download URLs');
  return problems;
}

function baseReceipt({ runId }) {
  return {
    schema: 'meet-audio-evidence-receipt/v1',
    runId,
    startedAtUtc: isoUtcNow(),
    completedAtUtc: null,
    disposition: null, // observed | evidence_pending | failed
    pendingReason: null,
    failureReason: null,
    // Row 32(a): receipt-only, no promotion path.
    promotion: {
      permitted: false,
      note: 'receipt-only: this document records observed pinned-service facts and NEVER promotes or pins a CaptureProfile; no promotion path exists — admission changes only via an explicit owner/review decision binding a digest-bearing EvidenceRef',
    },
    harness: {
      path: HARNESS_REL,
      sha256: null,
      contractRow: 'MP-AUDIO-001 (test contract 2026-09-05, row amended 2026-09-23)',
      ciLane: 'none — required CI lanes must never invoke this harness (row 32c)',
    },
    pins: null,
    host: null,
    sink: null,
    bus: null,
    commands: [],
    probes: [],
    unimplementedProbes: [
      'clock-alignment quantification against the plan <=100ms ceiling',
      'gap injection / discontinuous-sequence arms',
      'duplicate and lost acknowledgement arms',
      'crash-recovery (producer kill mid-segment) arm',
      'revoke/end mid-capture arms',
    ],
    resources: [],
    cleanup: null,
    receiptSha256: null,
  };
}

function exitCodeForDisposition(disposition) {
  switch (disposition) {
    case 'observed': return 0;
    case 'evidence_pending': return 3;
    case 'failed': return 1;
    default: return 1;
  }
}

// ---------------------------------------------------------------------------
// Self-test — in-memory only; writes nothing (row 32c: CI-safe by construction).
// ---------------------------------------------------------------------------

function selfTest() {
  const failures = [];
  const check = (label, fn) => {
    try {
      fn();
      log(`self-test PASS: ${label}`);
    } catch (err) {
      failures.push(`${label}: ${err.message}`);
    }
  };

  const validPinSource = [
    'LIVEKIT_VERSION="1.13.5"',
    'LIVEKIT_SHA256_AMD64="c020fac437b7cc9b776eef1ad5ea8af77be9acfa07602eca20a3a44930dfbc70"',
    'LIVEKIT_SHA256_ARM64="332015305518765fe05bad74fc3a9d9583e635e7dd130de3c4fc563d69c550f3"',
    'EGRESS_IMAGE="docker.io/livekit/egress:v1.13.0@sha256:980ff439431df2c773573721ab6da19e15bdc1f049ab7cb80e87470bf174c12f"',
  ].join('\n');

  check('pin parser accepts the deployed pin shape', () => {
    const parsed = parsePins(validPinSource);
    assert.equal(parsed.ok, true, parsed.reason ?? '');
    assert.equal(parsed.pins.egressImage.includes('@sha256:980ff439'), true);
    assert.equal(parsed.pins.livekitVersion, '1.13.5');
  });

  check('pin parser refuses a tag-only egress image (a mutable tag is not a pin)', () => {
    const source = validPinSource.replace(
      'EGRESS_IMAGE="docker.io/livekit/egress:v1.13.0@sha256:980ff439431df2c773573721ab6da19e15bdc1f049ab7cb80e87470bf174c12f"',
      'EGRESS_IMAGE="docker.io/livekit/egress:v1.13.0"',
    );
    const parsed = parsePins(source);
    assert.equal(parsed.ok, false);
    assert.match(parsed.reason, /digest-pinned/);
  });

  check('pin parser refuses missing or malformed entries', () => {
    assert.equal(parsePins('').ok, false);
    assert.equal(parsePins(validPinSource.replace('LIVEKIT_VERSION="1.13.5"', 'LIVEKIT_VERSION="not-semver"')).ok, false);
    assert.equal(parsePins(validPinSource.replace(/LIVEKIT_SHA256_ARM64="[0-9a-f]{64}"/, 'LIVEKIT_SHA256_ARM64="nothex"')).ok, false);
  });

  const goodReceipt = {
    schema: 'meet-audio-evidence-receipt/v1',
    runId: 'run-1',
    startedAtUtc: '2026-09-23T00:00:00Z',
    completedAtUtc: '2026-09-23T00:01:00Z',
    disposition: 'observed',
    pendingReason: null,
    failureReason: null,
    promotion: {
      permitted: false,
      note: 'receipt-only: never promotes or pins a CaptureProfile',
    },
    harness: { path: HARNESS_REL, sha256: 'x', contractRow: 'MP-AUDIO-001', ciLane: 'none' },
    pins: {
      egressImage: `docker.io/livekit/egress:v1.13.0@sha256:${'9'.repeat(64)}`,
      egressImageResolvedDigest: `sha256:${'8'.repeat(64)}`,
      livekitVersion: '1.13.5',
      livekitSha256: `${'7'.repeat(64)}`,
      livekitBinaryPath: '/usr/local/bin/livekit-server',
    },
    host: { platform: 'linux', arch: 'arm64' },
    sink: { endpoint: 'http://127.0.0.1:9000', bucket: 'evidence', region: 'us-east-1', secretFingerprint: 'sha256:abcd' },
    commands: [{ atUtc: '2026-09-23T00:00:01Z', command: 'docker version --format {{.Server.Version}}', exitCode: 0 }],
    probes: [
      {
        name: 'audio-only-default-container',
        outcome: 'produced',
        request: { roomName: 'r', audioOnly: true, fileOutputs: [{ fileType: 'MP4' }] },
        media: { contentSha256: `${'a'.repeat(64)}`, byteSize: 1024, mimeType: 'audio/mp4', container: 'mp4', codec: 'aac', sampleRateHz: 48000 },
      },
      { name: 'start-failure-visible', outcome: 'failed-as-expected' },
    ],
    unimplementedProbes: ['crash-recovery arm'],
    resources: [],
    cleanup: { completedUtc: '2026-09-23T00:01:00Z', steps: [] },
    receiptSha256: null,
  };

  check('receipt schema accepts a well-formed observed receipt', () => {
    assert.deepEqual(validateReceipt(goodReceipt), []);
  });

  check('receipt schema accepts an evidence_pending receipt with partial pins', () => {
    const pending = JSON.parse(JSON.stringify(goodReceipt));
    pending.disposition = 'evidence_pending';
    pending.pendingReason = 'docker unavailable';
    delete pending.pins.egressImageResolvedDigest;
    delete pending.pins.livekitBinaryPath;
    delete pending.pins.livekitSha256;
    pending.probes = [];
    assert.deepEqual(validateReceipt(pending), []);
  });

  const rejects = (label, mutate) => {
    check(`receipt schema rejects ${label}`, () => {
      const receipt = JSON.parse(JSON.stringify(goodReceipt));
      mutate(receipt);
      assert.notDeepEqual(validateReceipt(receipt), []);
    });
  };
  rejects('a missing digest on probed media', (r) => { r.probes[0].media.contentSha256 = 'nothex'; });
  rejects('an unknown disposition', (r) => { r.disposition = 'qualified'; });
  rejects('a promotion claim (row 32a)', (r) => { r.promotion.permitted = true; });
  rejects('a promotion note without the receipt-only boundary', (r) => { r.promotion.note = 'auto-promoted'; });
  rejects('a tag-only egress pin', (r) => { r.pins.egressImage = 'docker.io/livekit/egress:v1.13.0'; });
  rejects('an unresolved egress digest on an observed run', (r) => { r.pins.egressImageResolvedDigest = 'unresolved'; });
  rejects('an evidence_pending receipt without a pendingReason (row 32b)', (r) => {
    r.disposition = 'evidence_pending';
    r.pendingReason = null;
    r.probes = [];
  });
  rejects('an observed receipt with no produced probe', (r) => { r.probes = [r.probes[1]]; });
  rejects('embedded sink secret material', (r) => { r.commands.push({ atUtc: 'x', command: 'env', exitCode: 0, env: 'MEET_AUDIO_SINK_SECRET_KEY=hunter2' }); });
  rejects('an embedded presigned download URL', (r) => {
    r.probes[0].stopResult = { fileResults: [{ downloadUrl: 'http://sink/bucket/file?X-Amz-Signature=secret' }] };
  });
  rejects('a malformed run id', (r) => { r.runId = '../escape'; });
  rejects('an empty unimplemented-probes declaration (dishonest scope)', (r) => { r.unimplementedProbes = []; });

  check('evidence-ref digest rule mirrors acquisition.go/SQL shape belt', () => {
    assert.equal(EVIDENCE_REF_DIGEST.test(`test-results/meet-audio-evidence/run-1/receipt.json#sha256=${'a'.repeat(64)}`), true);
    assert.equal(EVIDENCE_REF_DIGEST.test('mp-audio-001-run-1'), false);
    assert.equal(EVIDENCE_REF_DIGEST.test(`receipt.json#sha256=${'a'.repeat(63)}`), false);
  });

  check('disposition exit-code mapping is fail-closed (a skip is never green)', () => {
    assert.equal(exitCodeForDisposition('observed'), 0);
    assert.equal(exitCodeForDisposition('evidence_pending') !== 0, true);
    assert.equal(exitCodeForDisposition('failed') !== 0, true);
  });

  if (failures.length) {
    for (const failure of failures) process.stderr.write(`meet-audio-evidence self-test FAIL: ${failure}\n`);
    process.stderr.write('meet-audio-evidence self-test: FAIL\n');
    return 1;
  }
  process.stdout.write('meet-audio-evidence self-test: PASS (pin parser + receipt schema + promotion boundary + verdict rules)\n');
  return 0;
}

// ---------------------------------------------------------------------------
// Process / HTTP helpers (commands recorded into the receipt; secrets never).
// ---------------------------------------------------------------------------

function recordCommand(receipt, command, exitCode, note) {
  receipt.commands.push({ atUtc: isoUtcNow(), command, exitCode, ...(note ? { note } : {}) });
}

function runCapture(cmd, args, { timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ code: 127, stdout, stderr: `${stderr}${err.message}` });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function waitForHttp(url, { timeoutMs = 60000, intervalMs = 500 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'unknown';
  while (Date.now() < deadline) {
    try {
      const response = await fetchWithTimeout(url, {}, 3000);
      await response.arrayBuffer().catch(() => {});
      if (response.status < 500) return { ok: true };
      lastError = `HTTP ${response.status}`;
    } catch (err) {
      lastError = err?.cause?.code ?? err?.message ?? 'fetch failed';
    }
    await sleep(intervalMs);
  }
  return { ok: false, reason: lastError };
}

function waitForTcp(port, { timeoutMs = 20000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  const attempt = () => new Promise((resolve) => {
    const socket = net.connect({ port, host: '127.0.0.1', timeout: 2000 }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('error', () => resolve(false));
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
  });
  return (async () => {
    while (Date.now() < deadline) {
      if (await attempt()) return true;
      await sleep(500);
    }
    return false;
  })();
}

// Twirp JSON POST — the same wire surface lkEgress reaches through
// server-sdk-go's twirp client (basic auth key:secret). Any HTTP response
// proves endpoint liveness.
async function twirpCall(url, action, body, apiKey, apiSecret) {
  const payload = JSON.stringify(body);
  try {
    const response = await fetchWithTimeout(`${url}/twirp/livekit.Egress/${action}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Basic ${Buffer.from(`${apiKey}:${apiSecret}`).toString('base64')}`,
      },
      body: payload,
    }, 20000);
    const text = await response.text();
    if (response.status !== 200) {
      return { ok: false, status: response.status, error: `twirp ${response.status}: ${text.slice(0, 400)}` };
    }
    return { ok: true, status: response.status, result: JSON.parse(text) };
  } catch (err) {
    return { ok: false, status: 0, error: err?.cause?.code ?? err?.message ?? 'fetch failed' };
  }
}

async function downloadTo(url, dest) {
  try {
    const response = await fetchWithTimeout(url, {}, 60000);
    if (!response.ok) {
      await response.arrayBuffer().catch(() => {});
      return { ok: false, error: `download HTTP ${response.status}` };
    }
    fs.writeFileSync(dest, Buffer.from(await response.arrayBuffer()));
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err?.message ?? 'download failed' };
  }
}

// Minimal AWS SigV4 PUT (bucket creation against the run-owned sink) — the
// official MinIO image ships no mc CLI, and no unpinned tool may run.
async function sigv4PutBucket(endpoint, bucket, { accessKey, secretKey, region }) {
  const url = new URL(`${endpoint.replace(/\/$/, '')}/${bucket}`);
  const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = crypto.createHash('sha256').update('').digest('hex');
  const canonicalHeaders = `host:${url.host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = ['PUT', url.pathname, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, crypto.createHash('sha256').update(canonicalRequest).digest('hex')].join('\n');
  const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretKey}`, dateStamp), region), 's3'), 'aws4_request');
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  try {
    const response = await fetchWithTimeout(url.toString(), {
      method: 'PUT',
      headers: {
        Authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
        'x-amz-content-sha256': payloadHash,
        'x-amz-date': amzDate,
      },
    }, 15000);
    const body = (await response.text()).slice(0, 200);
    return { ok: response.ok, status: response.status, body };
  } catch (err) {
    return { ok: false, status: 0, body: err?.message ?? 'sink request failed' };
  }
}

// ---------------------------------------------------------------------------
// Receipt finalization.
// ---------------------------------------------------------------------------

function finishReceipt(runDir, receipt) {
  const receiptPath = path.join(runDir, 'receipt.json');
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  const digest = sha256File(receiptPath);
  receipt.receiptSha256 = digest;
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  const problems = validateReceipt(receipt);
  if (problems.length) {
    // A receipt that fails its own schema is a machinery defect, recorded
    // loudly — never silently patched into validity.
    log(`RECEIPT SCHEMA DEFECTS: ${problems.join('; ')}`);
  }
  log(`receipt: ${receiptPath}`);
  log(`receipt sha256: ${digest}`);
  log(`evidence ref form (for a future owner admission): ${path.relative(ROOT, receiptPath)}#sha256=${digest}`);
  log(`disposition: ${receipt.disposition} — this receipt does NOT promote or pin any profile (row 32a)`);
  return exitCodeForDisposition(receipt.disposition);
}

// ---------------------------------------------------------------------------
// Live run.
// ---------------------------------------------------------------------------

async function liveRun(cli) {
  const pins = loadPins();
  const outputRoot = path.join(ROOT, cli.outputRoot ?? DEFAULT_OUTPUT_ROOT_REL);
  const runId = cli.runId ?? `mpaudio-${new Date().toISOString().replace(/[-:]/g, '').replace(/\..*$/, 'Z')}`;
  const runDir = path.join(outputRoot, runId);
  if (fs.existsSync(runDir)) throw new MachineryError(`run directory exists — a run is never overwritten: ${runDir}`);
  fs.mkdirSync(path.join(runDir, 'logs'), { recursive: true });

  const receipt = baseReceipt({ runId });
  receipt.harness.sha256 = sha256(fs.readFileSync(path.join(ROOT, HARNESS_REL)));
  receipt.host = {
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    docker: null,
  };
  receipt.pins = {
    egressImage: pins.egressImage,
    livekitVersion: pins.livekitVersion,
    livekitSha256: process.arch === 'arm64' ? pins.livekitSha256Arm64 : pins.livekitSha256Amd64,
    livekitBinaryPath: null,
    livekitImage: null,
    egressImageResolvedDigest: null,
  };
  const writeLog = (name, data) => fs.writeFileSync(path.join(runDir, 'logs', name), data);

  // Rule 32b: every "cannot proceed" writes an evidence_pending receipt
  // naming the exact missing piece and exits NON-ZERO (never a green skip).
  const pending = async (reason) => {
    receipt.disposition = 'evidence_pending';
    receipt.pendingReason = reason;
    receipt.completedAtUtc = isoUtcNow();
    log(`NOTICE: ${reason}`);
    log('NOTICE: pinned services unavailable — disposition evidence_pending, exiting NON-ZERO (a skip never surfaces as green; row 32b).');
    return finishReceipt(runDir, receipt);
  };

  // -- 0a. Fail-fast configuration pre-validation (no services started, no
  // image pulled): a run whose sink or livekit runtime cannot exist on this
  // host ends evidence_pending WITHOUT pulling gigabytes first (rule 32b).
  const archPin = process.arch === 'arm64' ? pins.livekitSha256Arm64 : pins.livekitSha256Amd64;
  let livekitBin = null;
  if (cli.livekitBinary) {
    if (!fs.existsSync(cli.livekitBinary)) {
      return pending(`--livekit-binary not found: ${cli.livekitBinary}`);
    }
    const got = sha256File(cli.livekitBinary);
    recordCommand(receipt, `sha256(${path.basename(cli.livekitBinary)})`, 0, `expected pinned ${process.arch} release digest ${archPin.slice(0, 16)}…`);
    if (got !== archPin) {
      return pending(`livekit-server binary sha256 ${got} does not match the pinned ${process.arch} release digest — refusing to qualify against an unpinned binary`);
    }
    livekitBin = cli.livekitBinary;
    receipt.pins.livekitBinaryPath = path.relative(ROOT, path.resolve(livekitBin));
  } else if (cli.livekitImage) {
    if (!DIGEST_PINNED_IMAGE.test(cli.livekitImage)) {
      return pending(`--livekit-image ${cli.livekitImage} is not digest-pinned (name@sha256:<64hex>) — tag-only refs are refused`);
    }
    receipt.pins.livekitImage = cli.livekitImage;
  } else if (process.platform !== 'linux') {
    return pending(`the pinned livekit-server ${pins.livekitVersion} release binaries are Linux builds and this host is ${process.platform} — pass --livekit-image name@sha256:<digest> (a digest you verified) or run on a Linux host`);
  }
  const sink = {
    endpoint: cli.sinkEndpoint,
    bucket: cli.sinkBucket,
    region: cli.sinkRegion,
    accessKey: cli.sinkAccessKey,
    secretKey: cli.sinkSecretKey,
    image: cli.sinkImage,
    container: null,
    port: null,
  };
  if (sink.image && !DIGEST_PINNED_IMAGE.test(sink.image)) {
    return pending(`--sink-image ${sink.image} is not digest-pinned (name@sha256:<64hex>) — the harness never runs an unpinned image`);
  }
  const sinkComplete = Boolean(sink.endpoint && sink.bucket && sink.accessKey && sink.secretKey);
  if (!sinkComplete && !sink.image) {
    return pending('no S3-compatible sink configured: pass --sink-endpoint/--sink-bucket/--sink-access-key/--sink-secret-key (or MEET_AUDIO_SINK_*), or --sink-image name@sha256:<digest> to run a digest-pinned sink');
  }

  // -- 0b. Docker presence (missing machinery is evidence_pending).
  const dockerProbe = await runCapture('docker', ['version', '--format', '{{.Server.Version}}']);
  recordCommand(receipt, 'docker version --format {{.Server.Version}}', dockerProbe.code);
  if (dockerProbe.code !== 0) {
    writeLog('docker-version.err', dockerProbe.stderr);
    return pending(`docker unavailable (exit ${dockerProbe.code}): ${dockerProbe.stderr.trim().slice(0, 200)}`);
  }
  receipt.host.docker = dockerProbe.stdout.trim();

  // -- 1. Pull the pinned egress image; record the RESOLVED manifest digest.
  const pull = await runCapture('docker', ['pull', pins.egressImage], { timeoutMs: 600000 });
  recordCommand(receipt, `docker pull ${pins.egressImage}`, pull.code);
  if (pull.code !== 0) {
    writeLog('docker-pull.err', pull.stderr);
    return pending(`pinned egress image pull failed (exit ${pull.code}) — the pinned service could not start`);
  }
  const inspect = await runCapture('docker', ['inspect', '--format', '{{index .RepoDigests 0}}', pins.egressImage.split('@')[0]]);
  recordCommand(receipt, 'docker inspect --format {{index .RepoDigests 0}} <egress-image>', inspect.code);
  if (inspect.code === 0) {
    const resolved = inspect.stdout.trim().split('@')[1];
    if (resolved) receipt.pins.egressImageResolvedDigest = resolved;
  }
  if (!receipt.pins.egressImageResolvedDigest) {
    return pending('could not resolve the pulled egress manifest digest — the pin is unverified');
  }

  // -- 2. Run-owned resource registry + interrupt cleanup, then the
  // deferred livekit-server install (Linux hosts; the sha256-verified
  // release archive via the repo's own installer).
  const owned = { processes: [], containers: [] };
  const cleanup = buildCleanup(receipt, owned, cli.keepServices);
  process.on('SIGINT', () => { cleanup().then(() => process.exit(130)); });
  process.on('SIGTERM', () => { cleanup().then(() => process.exit(130)); });
  if (!livekitBin) {
    const binDir = path.join(runDir, 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    const install = await runCapture('bash', ['-c',
      `source '${path.join(ROOT, DEPLOY_LIB_REL)}' && install_livekit_binary '${binDir}/livekit-server'`], { timeoutMs: 300000 });
    recordCommand(receipt, `source ${DEPLOY_LIB_REL} && install_livekit_binary <runDir>/bin/livekit-server`, install.code);
    writeLog('livekit-install.log', `${install.stdout}\n${install.stderr}`);
    livekitBin = path.join(binDir, 'livekit-server');
    if (install.code !== 0 || !fs.existsSync(livekitBin)) {
      await cleanup();
      return pending(`pinned livekit-server ${pins.livekitVersion} install failed (network/release unavailable?) — exit ${install.code}`);
    }
    receipt.pins.livekitBinaryPath = path.relative(ROOT, livekitBin);
  }
  if (livekitBin) {
    const versionOut = await runCapture(livekitBin, ['--version']);
    recordCommand(receipt, 'livekit-server --version', versionOut.code);
    if (versionOut.code === 0) receipt.pins.livekitReportedVersion = versionOut.stdout.trim().split(/\s+/).pop();
  }

  // -- 4. Resolve the container→host gateway address with the pinned image,
  // BEFORE anything starts, so the SFU can advertise a reachable node_ip.
  const gatewayProbe = await runCapture('docker', ['run', '--rm', '--add-host', 'host.docker.internal:host-gateway',
    '--entrypoint', '/bin/sh', pins.egressImage, '-c', 'getent hosts host.docker.internal | awk \'{print $1}\''], { timeoutMs: 120000 });
  recordCommand(receipt, 'docker run --rm --add-host host.docker.internal:host-gateway <pinned-egress> getent hosts host.docker.internal', gatewayProbe.code);
  if (gatewayProbe.code !== 0 || !gatewayProbe.stdout.trim()) {
    writeLog('gateway-probe.err', gatewayProbe.stderr);
    return pending('could not resolve the container→host gateway address with the pinned image — RTC reachability unverifiable');
  }
  const gatewayIp = gatewayProbe.stdout.trim().split('\n')[0];

  // -- 5. Start the SFU (binary child or pinned operator image).
  const apiKey = 'setjoin';
  const apiSecret = crypto.randomBytes(24).toString('hex'); // run-scoped, never recorded
  const rtcUdpStart = 50100;
  const rtcUdpEnd = 50120;
  const livekitConfig = {
    port: cli.portsHttp,
    bind_addresses: ['0.0.0.0'],
    rtc: {
      tcp_port: cli.portsHttp + 1,
      port_range_start: rtcUdpStart,
      port_range_end: rtcUdpEnd,
      use_external_ip: false,
      node_ip: gatewayIp,
    },
    room: { auto_create: true },
    keys: { [apiKey]: apiSecret },
    logging: { level: 'info' },
  };
  const livekitConfigPath = path.join(runDir, 'livekit.yaml');
  fs.writeFileSync(livekitConfigPath, JSON.stringify(livekitConfig, null, 2));
  const livekitLog = fs.openSync(path.join(runDir, 'logs', 'livekit.log'), 'a');
  if (livekitBin) {
    const livekitChild = spawn(livekitBin, ['--config', livekitConfigPath], { stdio: ['ignore', livekitLog, livekitLog] });
    owned.processes.push({ role: 'livekit-server', pid: livekitChild.pid });
    receipt.resources.push({ kind: 'process', role: 'livekit-server', pid: livekitChild.pid, runOwned: true });
  } else {
    const sfuName = `setjoin-meet-audio-sfu-${runId}`;
    const sfuRun = await runCapture('docker', ['run', '-d', '--name', sfuName,
      '--add-host', 'host.docker.internal:host-gateway',
      '-p', `${cli.portsHttp}:${cli.portsHttp}`,
      '-p', `${cli.portsHttp + 1}:${cli.portsHttp + 1}`,
      '-p', `${rtcUdpStart}-${rtcUdpEnd}:${rtcUdpStart}-${rtcUdpEnd}/udp`,
      '-v', `${livekitConfigPath}:/etc/livekit.yaml:ro`,
      cli.livekitImage, '--config', '/etc/livekit.yaml']);
    recordCommand(receipt, `docker run -d --name ${sfuName} -v <runDir>/livekit.yaml:/etc/livekit.yaml:ro -p <http/tcp/rtc-udp ports> <pinned-livekit-image> --config /etc/livekit.yaml`, sfuRun.code);
    if (sfuRun.code !== 0) {
      writeLog('sfu-run.err', sfuRun.stderr);
      await cleanup();
      return pending(`digest-pinned livekit-server image failed to start (exit ${sfuRun.code})`);
    }
    owned.containers.push(sfuName);
    receipt.resources.push({ kind: 'container', role: 'livekit-server', name: sfuName, runOwned: true });
  }
  const signalUrl = `http://127.0.0.1:${cli.portsHttp}/`;
  const livekitHealth = await waitForHttp(signalUrl, { timeoutMs: 45000 });
  recordCommand(receipt, `GET ${signalUrl} (SFU health wait)`, livekitHealth.ok ? 0 : 1);
  if (!livekitHealth.ok) {
    await cleanup();
    return pending(`livekit-server ${pins.livekitVersion} did not become healthy: ${livekitHealth.reason ?? 'unknown'}`);
  }

  // -- 6. Sink: start the digest-pinned image if requested, then ensure the bucket.
  if (sink.image) {
    sink.container = `setjoin-meet-audio-sink-${runId}`;
    sink.accessKey = crypto.randomBytes(12).toString('hex'); // run-scoped
    sink.secretKey = crypto.randomBytes(24).toString('hex');
    sink.port = 9100 + (process.pid % 500);
    const sinkRun = await runCapture('docker', ['run', '-d', '--name', sink.container, '-p', `${sink.port}:9000`,
      '-e', `MINIO_ROOT_USER=${sink.accessKey}`, '-e', `MINIO_ROOT_PASSWORD=${sink.secretKey}`,
      sink.image, 'server', '/data']);
    recordCommand(receipt, `docker run -d --name ${sink.container} -p ${sink.port}:9000 -e MINIO_ROOT_USER=... -e MINIO_ROOT_PASSWORD=<redacted> ${sink.image} server /data`, sinkRun.code);
    if (sinkRun.code !== 0) {
      writeLog('sink-run.err', sinkRun.stderr);
      await cleanup();
      return pending(`digest-pinned sink image failed to start (exit ${sinkRun.code})`);
    }
    owned.containers.push(sink.container);
    receipt.resources.push({ kind: 'container', role: 'sink', name: sink.container, runOwned: true });
    sink.endpoint = `http://127.0.0.1:${sink.port}`;
    const sinkHealth = await waitForHttp(`${sink.endpoint}/minio/health/live`, { timeoutMs: 30000 });
    recordCommand(receipt, `GET ${sink.endpoint}/minio/health/live`, sinkHealth.ok ? 0 : 1);
    if (!sinkHealth.ok) {
      await cleanup();
      return pending('digest-pinned sink never became healthy');
    }
    const bucket = await sigv4PutBucket(sink.endpoint, sink.bucket, sink);
    recordCommand(receipt, `SigV4 PUT ${sink.endpoint}/${sink.bucket} (bucket create)`, bucket.ok ? 0 : 1, bucket.ok ? undefined : `HTTP ${bucket.status}: ${bucket.body}`);
    if (!bucket.ok) {
      await cleanup();
      return pending(`sink bucket ${sink.bucket} could not be created (HTTP ${bucket.status})`);
    }
  } else {
    // Operator sink: probe the bucket with an anonymous HEAD; a failure is
    // not fatal here — the per-request S3 upload surfaces exact errors.
    const probeStatus = await fetchWithTimeout(`${sink.endpoint.replace(/\/$/, '')}/${sink.bucket}`, { method: 'HEAD' }, 8000).then((r) => r.status).catch(() => 0);
    recordCommand(receipt, `HEAD ${sink.endpoint}/${sink.bucket}`, probeStatus === 200 ? 0 : 1, 'operator sink reachability probe');
  }
  receipt.sink = {
    endpoint: sink.endpoint,
    bucket: sink.bucket,
    region: sink.region,
    image: sink.image,
    accessKeyFingerprint: fingerprint(sink.accessKey),
    secretFingerprint: fingerprint(sink.secretKey),
  };
  const sinkEndpointForContainer = sink.image
    ? `http://host.docker.internal:${sink.port}`
    : sink.endpoint;

  // -- 7. Optional run-owned pipeline bus (egress requires redis in most
  // deployments); without it, the pinned egress's actual behavior is the
  // observation.
  let busAddress = null;
  let busPassword = null; // run-scoped; only a fingerprint reaches the receipt
  if (cli.busImage) {
    if (!DIGEST_PINNED_IMAGE.test(cli.busImage)) {
      await cleanup();
      return pending(`--bus-image ${cli.busImage} is not digest-pinned (name@sha256:<64hex>) — the harness never runs an unpinned image`);
    }
    busPassword = crypto.randomBytes(16).toString('hex');
    const busName = `setjoin-meet-audio-bus-${runId}`;
    const busPort = 9600 + (process.pid % 300);
    const busRun = await runCapture('docker', ['run', '-d', '--name', busName, '-p', `${busPort}:6379`,
      cli.busImage, 'redis-server', '--requirepass', busPassword]);
    recordCommand(receipt, `docker run -d --name ${busName} -p ${busPort}:6379 <bus-image> redis-server --requirepass <redacted>`, busRun.code);
    if (busRun.code !== 0) {
      writeLog('bus-run.err', busRun.stderr);
      await cleanup();
      return pending(`digest-pinned bus image failed to start (exit ${busRun.code})`);
    }
    owned.containers.push(busName);
    receipt.resources.push({ kind: 'container', role: 'bus', name: busName, runOwned: true });
    busAddress = `host.docker.internal:${busPort}`;
    receipt.bus = { image: cli.busImage, address: busAddress, passwordFingerprint: fingerprint(busPassword) };
    const busHealth = await waitForTcp(busPort);
    recordCommand(receipt, `TCP connect 127.0.0.1:${busPort} (bus health wait)`, busHealth ? 0 : 1);
    if (!busHealth) {
      await cleanup();
      return pending('digest-pinned bus never became reachable');
    }
    await sleep(1000);
  }

  // -- 8. Start the pinned egress container (unit-template shape: pinned
  // image, EGRESS_CONFIG_FILE, SYS_ADMIN for the headless-Chromium sandbox).
  const egressName = `setjoin-meet-audio-egress-${runId}`;
  const egressConfigLines = [
    'log_level: info',
    `api_key: ${apiKey}`,
    `api_secret: ${apiSecret}`,
    `ws_url: ws://host.docker.internal:${cli.portsHttp}`,
    'insecure: true',
    'cpu_cost:',
    '  room_composite_cpu_cost: 3',
  ];
  if (busAddress) {
    egressConfigLines.push('redis:', `  address: ${busAddress}`, `  password: ${busPassword}`);
  }
  const egressConfigPath = path.join(runDir, 'egress.yaml');
  fs.writeFileSync(egressConfigPath, `${egressConfigLines.join('\n')}\n`);
  const rpcPort = 9200 + (process.pid % 300);
  const egressRun = await runCapture('docker', ['run', '-d', '--name', egressName,
    '--add-host', 'host.docker.internal:host-gateway',
    '--cap-add', 'SYS_ADMIN',
    '-e', 'EGRESS_CONFIG_FILE=/etc/egress.yaml',
    '-v', `${egressConfigPath}:/etc/egress.yaml:ro`,
    '-p', `${rpcPort}:8888`,
    pins.egressImage]);
  recordCommand(receipt, `docker run -d --name ${egressName} --add-host host.docker.internal:host-gateway --cap-add SYS_ADMIN -e EGRESS_CONFIG_FILE=/etc/egress.yaml -v <runDir>/egress.yaml:/etc/egress.yaml:ro -p ${rpcPort}:8888 ${pins.egressImage}`, egressRun.code);
  if (egressRun.code !== 0) {
    writeLog('egress-run.err', egressRun.stderr);
    await cleanup();
    return pending(`pinned egress container failed to start (exit ${egressRun.code})`);
  }
  owned.containers.push(egressName);
  receipt.resources.push({ kind: 'container', role: 'egress', name: egressName, runOwned: true });

  const egressRpc = `http://127.0.0.1:${rpcPort}`;
  // Health = the twirp RPC endpoint answering (any HTTP status proves the
  // service is up); a container that dies while waiting ends the wait.
  let egressHealthy = false;
  let lastRpcError = '';
  for (let waited = 0; waited < 45000 && !egressHealthy; waited += 2000) {
    const probe = await twirpCall(egressRpc, 'ListEgress', { room_name: 'health-probe' }, apiKey, apiSecret);
    if (probe.status > 0) {
      egressHealthy = true;
      break;
    }
    lastRpcError = probe.error;
    const running = await runCapture('docker', ['inspect', '--format', '{{.State.Running}}', egressName]);
    if (running.stdout.trim() === 'false') break;
    await sleep(2000);
  }
  recordCommand(receipt, `POST ${egressRpc}/twirp/livekit.Egress/ListEgress (egress health wait)`, egressHealthy ? 0 : 1);
  if (!egressHealthy) {
    const logs = await runCapture('docker', ['logs', egressName]);
    writeLog('egress.log', `${logs.stdout}\n${logs.stderr}`);
    await cleanup();
    const redisHint = /redis/i.test(`${logs.stdout}${logs.stderr}`)
      ? ' (egress logs name redis — rerun with --bus-image name@sha256:<digest>)'
      : '';
    return pending(`pinned egress service did not become healthy: ${lastRpcError}${redisHint} (container logs retained under logs/egress.log)`);
  }

  // -- 9. Drive the existing audio path (the B2 RoomComposite shape,
  // lkEgress's wire surface) end-to-end.
  const roomName = `mpaudio-${runId}`;
  const downloadDir = path.join(runDir, 'media');
  fs.mkdirSync(downloadDir, { recursive: true });

  const probesPlan = [
    {
      // The admission-critical observation: what an audio-only RoomComposite
      // file request ACTUALLY produces on the pinned service.
      name: 'audio-only-default-container',
      request: { roomName, audioOnly: true, fileOutputs: [{ fileType: 'MP4', filepath: `default-{room_name}-{time}` }] },
      expectFailure: false,
    },
    {
      // The unproven non-MP4 path: whatever the pinned service does with a
      // non-MP4 file request under audio_only is OBSERVED, never assumed
      // (egress.go documents DEFAULT_FILETYPE's upstream-forced MP4 table).
      name: 'audio-only-ogg-container',
      request: { roomName, audioOnly: true, fileOutputs: [{ fileType: 'OGG', filepath: `ogg-{room_name}-{time}` }] },
      expectFailure: false,
    },
    {
      // Named contract case MP-AUDIO-001/start-failure-visible: a broken
      // request must produce an observable, typed failure — never silence.
      name: 'start-failure-visible',
      request: { roomName, audioOnly: true, fileOutputs: [] },
      expectFailure: true,
    },
  ];

  const probes = [];
  for (const plan of probesPlan) {
    const probe = {
      name: plan.name,
      request: plan.request,
      outcome: null,
      startedAtUtc: isoUtcNow(),
      egressId: null,
      startError: null,
      stopResult: null,
      media: null,
      ffprobe: null,
      commands: [],
    };
    const started = await twirpCall(egressRpc, 'StartRoomCompositeEgress', {
      room_name: plan.request.roomName,
      audio_only: plan.request.audioOnly,
      file_outputs: plan.request.fileOutputs.map((o) => ({
        file_type: o.fileType,
        filepath: o.filepath,
        s3: {
          access_key: sink.accessKey,
          secret: sink.secretKey,
          region: sink.region,
          endpoint: sinkEndpointForContainer,
          bucket: sink.bucket,
        },
      })),
    });
    probe.commands.push({ command: `POST /twirp/livekit.Egress/StartRoomCompositeEgress (${plan.name})`, exitCode: started.ok ? 0 : 1 });
    if (!started.ok) {
      probe.startError = started.error;
      probe.outcome = plan.expectFailure ? 'failed-as-expected' : 'start-failed';
      probes.push(probe);
      continue;
    }
    probe.egressId = started.result?.egressId ?? null;
    if (plan.expectFailure) {
      probe.outcome = 'unexpected-start (should have failed)';
      probes.push(probe);
      continue;
    }

    await sleep(4000); // let the composite produce measurable bytes
    const stopped = await twirpCall(egressRpc, 'StopEgress', { egress_id: probe.egressId }, apiKey, apiSecret);
    probe.commands.push({ command: `POST /twirp/livekit.Egress/StopEgress (${plan.name})`, exitCode: stopped.ok ? 0 : 1 });
    const result = await pollEgressResult(egressRpc, plan.request.roomName, probe.egressId, apiKey, apiSecret, { timeoutMs: 90000 });
    const rawFiles = result.item?.fileResults ?? result.item?.file_results ?? [];
    // Presigned download URLs carry sink credentials — record the file
    // facts, never the URLs; download happens immediately from the live URL.
    probe.stopResult = {
      status: result.item?.status ?? 'observation-timeout',
      files: rawFiles.map((f) => ({
        location: sanitizeFileRef(f.location ?? f.filename),
        size: f.size ?? null,
        startedAt: f.startedAt ?? null,
        endedAt: f.endedAt ?? null,
        duration: f.duration ?? null,
      })),
    };
    probe.outcome = rawFiles.some((f) => Number(f.size) > 0 && (f.downloadUrl || f.download_url)) ? 'produced' : 'no-durable-output';

    // Download + verify the produced bytes; probe identity with the SAME
    // pinned egress image's ffprobe — no unpinned tool runs.
    let fileIndex = 0;
    for (const file of rawFiles) {
      const downloadUrl = file.downloadUrl ?? file.download_url;
      if (!downloadUrl || !Number(file.size)) continue;
      const localName = `${plan.name}-${fileIndex}`;
      fileIndex += 1;
      const localPath = path.join(downloadDir, localName);
      const downloaded = await downloadTo(downloadUrl, localPath);
      probe.commands.push({ command: `GET <sink-download-url> -> media/${localName}`, exitCode: downloaded.ok ? 0 : 1, note: downloaded.ok ? undefined : downloaded.error });
      if (!downloaded.ok) continue;
      probe.media = {
        contentSha256: sha256File(localPath),
        byteSize: fs.statSync(localPath).size,
        mimeType: null,
        container: null,
        codec: null,
        sampleRateHz: null,
        localPath: `media/${localName}`,
      };
      const probed = await runCapture('docker', ['run', '--rm', '--entrypoint', 'ffprobe',
        '-v', `${downloadDir}:/probe:ro`, pins.egressImage,
        '-v', 'error', '-print_format', 'json', '-show_format', '-show_streams', `/probe/${localName}`], { timeoutMs: 120000 });
      probe.commands.push({ command: `docker run --rm --entrypoint ffprobe <pinned-egress> ... /probe/${localName}`, exitCode: probed.code });
      if (probed.code === 0) {
        writeLog(`ffprobe-${plan.name}.json`, probed.stdout);
        try {
          const parsed = JSON.parse(probed.stdout);
          const audio = parsed.streams?.find((s) => s.codec_type === 'audio') ?? parsed.streams?.[0] ?? {};
          probe.media.container = parsed.format?.format_name ?? null;
          probe.media.codec = audio.codec_name ?? null;
          probe.media.sampleRateHz = audio.sample_rate ? Number(audio.sample_rate) : null;
          probe.media.durationSeconds = parsed.format?.duration ? Number(parsed.format.duration) : null;
          probe.media.mimeType = probe.media.container?.includes('mp4') ? 'audio/mp4'
            : probe.media.container?.includes('webm') ? 'audio/webm'
              : probe.media.container?.includes('ogg') ? 'audio/ogg'
                : `x-container/${probe.media.container ?? 'unknown'}`;
          probe.ffprobe = { streams: parsed.streams?.length ?? 0, format: parsed.format?.format_name ?? null };
        } catch {
          probe.outcome = 'ffprobe-unparseable';
        }
      } else {
        probe.outcome = 'ffprobe-failed';
        writeLog(`ffprobe-${plan.name}.err`, probed.stderr);
      }
    }
    probes.push(probe);
  }
  receipt.probes = probes;
  for (const probe of probes) {
    receipt.commands.push(...probe.commands.map((c) => ({ atUtc: isoUtcNow(), ...c, note: `probe ${probe.name}${c.note ? `: ${c.note}` : ''}` })));
  }

  // -- 10. Disposition: honest, typed, receipt-only.
  const produced = probes.some((p) => p.outcome === 'produced' && p.media);
  const startFailureVisible = probes.find((p) => p.name === 'start-failure-visible')?.outcome === 'failed-as-expected';
  if (produced && startFailureVisible) {
    receipt.disposition = 'observed';
  } else if (produced) {
    receipt.disposition = 'observed';
    receipt.observationCaveat = 'media produced but the start-failure-visible arm did not observe its typed failure — probe scope incomplete';
  } else {
    receipt.disposition = 'failed';
    receipt.failureReason = 'the pinned services ran but no probe produced durable media — this receipt is NOT audio-path evidence and qualifies nothing';
  }

  // -- 11. Teardown + finalize.
  await cleanup();
  receipt.completedAtUtc = isoUtcNow();
  return finishReceipt(runDir, receipt);
}

function sanitizeFileRef(ref) {
  // Strip any query-string credentials from a recorded object reference.
  if (typeof ref !== 'string') return null;
  const withoutQuery = ref.split('?')[0];
  return withoutQuery === '' ? null : withoutQuery;
}

async function pollEgressResult(egressRpc, roomName, egressId, apiKey, apiSecret, { timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    const listed = await twirpCall(egressRpc, 'ListEgress', { room_name: roomName }, apiKey, apiSecret);
    if (listed.ok) {
      const items = listed.result?.items ?? [];
      const item = items.find((i) => (i.egressId ?? i.egress_id) === egressId) ?? null;
      last = item;
      if (item) {
        const status = item.status ?? '';
        if (['EGRESS_COMPLETE', 'EGRESS_FAILED', 'EGRESS_ABORTED', 'EGRESS_LIMIT_REACHED'].includes(status)) {
          return { item };
        }
      }
    }
    await sleep(1500);
  }
  return { item: last };
}

function buildCleanup(receipt, owned, keepServices) {
  let finished = false;
  return async function cleanup() {
    if (finished) return;
    finished = true;
    if (keepServices) {
      receipt.cleanup = {
        completedUtc: isoUtcNow(),
        steps: [],
        note: '--keep-services: run-owned resources were left running for diagnostics; reconcile them manually by exact name (ownership recorded, not pruned blindly)',
        ownedResources: [
          ...owned.containers.map((c) => `container:${c}`),
          ...owned.processes.map((p) => `process:${p.role}:${p.pid}`),
        ],
      };
      return;
    }
    const steps = [];
    for (const container of owned.containers) {
      const stopped = await runCapture('docker', ['stop', '-t', '10', container]);
      const removed = await runCapture('docker', ['rm', '-f', container]);
      steps.push({ resource: `container:${container}`, stopped: stopped.code === 0, removed: removed.code === 0 });
    }
    for (const proc of owned.processes) {
      let stopped = false;
      try {
        process.kill(proc.pid, 'SIGTERM');
        stopped = true;
      } catch { /* already gone */ }
      steps.push({ resource: `process:${proc.role}:${proc.pid}`, stopped, removed: true });
    }
    receipt.cleanup = { completedUtc: isoUtcNow(), steps };
  };
}

// ---------------------------------------------------------------------------
// Dry-run — validates pins + bindings + schema; writes nothing, starts nothing.
// ---------------------------------------------------------------------------

function dryRun(cli) {
  const pins = loadPins();
  const lines = [
    'meet-audio-evidence dry-run',
    `  pin source:        ${DEPLOY_LIB_REL}`,
    `  egress image:      ${pins.egressImage}`,
    `  livekit version:   ${pins.livekitVersion} (release sha256 amd64 ${pins.livekitSha256Amd64.slice(0, 12)}… / arm64 ${pins.livekitSha256Arm64.slice(0, 12)}… — Linux builds)`,
    `  livekit runtime:   ${cli.livekitBinary ? `binary ${cli.livekitBinary} (sha256-verified)` : cli.livekitImage ? `image ${cli.livekitImage}` : 'install_livekit_binary (Linux hosts only; darwin ends evidence_pending)'}`,
    `  sink:              ${cli.sinkImage ? `digest-pinned image ${cli.sinkImage}` : cli.sinkEndpoint ? `${cli.sinkEndpoint} (bucket ${cli.sinkBucket ?? '?'})` : '(none configured — live run ends evidence_pending, exit 3)'}`,
    `  bus:               ${cli.busImage ?? '(none — the pinned egress runs without a pipeline bus; its actual behavior is the observation)'}`,
    `  output root:       ${cli.outputRoot ?? DEFAULT_OUTPUT_ROOT_REL}/<run-id>/receipt.json`,
    '  probes:            audio-only-default-container, audio-only-ogg-container, start-failure-visible',
    '  unimplemented:     clock alignment, gaps, duplicate/lost ack, crash recovery, revoke/end arms (declared in every receipt)',
    '  boundary:          receipt-only; NEVER promotes/pins a profile (row 32a); missing services exit non-zero evidence_pending (row 32b); never a required CI lane (row 32c)',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
  // Validate THIS run's receipt skeleton against the schema in-memory.
  const probeReceipt = baseReceipt({ runId: 'dry-run' });
  probeReceipt.disposition = 'evidence_pending';
  probeReceipt.pendingReason = 'dry-run placeholder (nothing started, nothing written)';
  probeReceipt.host = { platform: process.platform, arch: process.arch, node: process.version, docker: '(not probed)' };
  probeReceipt.pins = {
    egressImage: pins.egressImage,
    livekitVersion: pins.livekitVersion,
    livekitSha256: pins.livekitSha256Amd64,
    livekitBinaryPath: '(dry-run)',
    livekitImage: cli.livekitImage,
    egressImageResolvedDigest: `sha256:${pins.egressImage.split('@sha256:')[1]}`,
  };
  const problems = validateReceipt(probeReceipt);
  if (problems.length) {
    for (const problem of problems) process.stderr.write(`dry-run schema problem: ${problem}\n`);
    process.stderr.write('meet-audio-evidence dry-run: FAIL\n');
    return 1;
  }
  process.stdout.write('meet-audio-evidence dry-run: PASS (pins parse, bindings valid, receipt schema satisfied; nothing started, nothing written)\n');
  process.stdout.write('operator live command:\n');
  process.stdout.write('  bash scripts/run-meet-audio-evidence-harness.sh \\\n');
  process.stdout.write('    --sink-endpoint <url> --sink-bucket <b> --sink-access-key <k> --sink-secret-key <k> \\\n');
  process.stdout.write('    [--livekit-binary <p> | --livekit-image name@sha256:<digest>] [--sink-image name@sha256:<digest>] [--bus-image name@sha256:<digest>]\n');
  return 0;
}

// ---------------------------------------------------------------------------
// Entry point (import is inert; dispatch only under import.meta.main).
// ---------------------------------------------------------------------------

async function main() {
  let cli;
  try {
    cli = parseCli(process.argv.slice(2));
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`meet-audio-evidence: ${err.message}\n`);
      usage();
      return 1;
    }
    throw err;
  }
  if (cli.help) {
    usage();
    return 0;
  }
  if (cli.selfTest) return selfTest();
  if (cli.dryRun) {
    try {
      return dryRun(cli);
    } catch (err) {
      if (err instanceof MachineryError) {
        process.stderr.write(`meet-audio-evidence dry-run: ${err.message}\n`);
        return 1;
      }
      throw err;
    }
  }
  try {
    return await liveRun(cli);
  } catch (err) {
    if (err instanceof MachineryError) {
      process.stderr.write(`meet-audio-evidence: ${err.message}\n`);
      return 1;
    }
    throw err;
  }
}

if (import.meta.main) {
  main().then((code) => process.exit(code)).catch((err) => {
    process.stderr.write(`meet-audio-evidence: unhandled failure: ${err?.stack ?? err}\n`);
    process.exit(1);
  });
}
