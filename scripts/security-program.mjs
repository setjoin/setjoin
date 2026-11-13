#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  EXCLUSION_POLICY_SCHEMA,
  InventoryError,
  compileInventory,
  stringifyJsonDocument,
} from './lib/security-program-inventory.mjs';
import { canonicalJson, parseStrictJson, sha256Hex } from './lib/security-program-json.mjs';
import {
  PROJECTION_V1_SCHEMA,
  PROJECTION_V2_SCHEMA,
  assertProjectionMigrationFence,
  migrateProjection,
} from './lib/security-program-migrations.mjs';
import {
  readRuntimeResumeAuthority,
  resumeLogicalToken,
  resumeStateDecision,
  validateResumeAction,
} from './lib/security-program-resume.mjs';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..');
const VERIFY_DIR = path.join(REPO_ROOT, 'docs', 'verification');
const DECISION_FILE = path.join(VERIFY_DIR, 'security-coverage-inventory-decision.json');
const OUTPUTS = Object.freeze({
  epoch: path.join(VERIFY_DIR, 'security-coverage-epoch.json'),
  sections: path.join(VERIFY_DIR, 'security-coverage-sections.json'),
  shards: path.join(VERIFY_DIR, 'security-coverage-shards.json'),
});

const FROZEN_REVISION = '727f40ad1274d950926369913a464bcc8f2e0236';
const HISTORICAL_CANDIDATE_COUNT = 6163;
const EXPECTED = Object.freeze({ treePathCount: 6199, authorizedCount: 5824, excludedCount: 375, sectionCount: 30 });
const POLICY = Object.freeze({
  schema: EXCLUSION_POLICY_SCHEMA,
  policyVersion: 'whole-codebase-first-party/v1',
  classes: Object.freeze([
    Object.freeze({
      id: 'agent-worktrees',
      reason: 'Transient nested agent worktrees are not frozen first-party source',
      expectedCount: 1,
      selectors: Object.freeze([{ kind: 'prefix', value: '.claire/worktrees/' }]),
    }),
    Object.freeze({
      id: 'vendored-reference-docs',
      reason: 'Vendored upstream reference bodies do not own Setjoin runtime behavior',
      expectedCount: 287,
      selectors: Object.freeze([{ kind: 'prefix', value: 'clients/harmonyos/refs/openharmony-docs/' }]),
    }),
    Object.freeze({
      id: 'vendored-security-reference',
      reason: 'Vendored upstream security reference bodies do not own Setjoin runtime behavior',
      expectedCount: 66,
      selectors: Object.freeze([{ kind: 'prefix', value: 'clients/rust/refs/ios-security-framework/' }]),
    }),
    Object.freeze({
      id: 'vendored-biometric-reference',
      reason: 'Vendored upstream biometric reference bodies do not own Setjoin runtime behavior',
      expectedCount: 21,
      selectors: Object.freeze([{ kind: 'prefix', value: 'clients/rust/refs/tauri-plugin-biometric/' }]),
    }),
  ]),
});

// Canonical program exits: 0 terminal/read success, 1 invalid evidence,
// 2 usage, 3 intentional HOLD, 4 blocked prerequisite.
const EXIT = Object.freeze({ OK: 0, INVALID: 1, USAGE: 2, HOLD: 3, BLOCKED: 4 });
const CONTROL_SCHEMA = 'setjoin.security-program.control/v1';
const DIAGNOSTIC_SCHEMA = 'setjoin.security-program.diagnostic/v1';
const BENCHMARK_SCHEMA = 'setjoin.security-program.benchmark/v1';
const BENCHMARK_TARGETS = Object.freeze({ doctorStatusP95Ms: 120_000, fullJourneyP95Ms: 300_000 });
const DIAGNOSTIC_DOCS = 'docs/guides/security-remediation/troubleshooting.md';
let outputMode = 'auto';
const ERROR_CATALOG = Object.freeze({
  E_SECURITY_PROGRAM_ORPHANED_START: ['A durable start has no confirmed scan identity', 'A process stopped between start persistence and scan-ID receipt', 'Reconcile the start before any retry'],
  E_SECURITY_PROGRAM_COMPLETION_UNKNOWN: ['A known scan has no verified terminal result', 'Completion could not be proven from retained evidence', 'Reconcile completion for the existing attempt'],
  E_SECURITY_PROGRAM_LIVE_LEASE: ['Another owner holds the global scan lease', 'The retained lease is live or its owner cannot be proven dead', 'Attach to the owner or wait; do not start another scan'],
  E_SECURITY_PROGRAM_LEASE_EXPIRED: ['The retained scan lease expired', 'Its prior owner can no longer renew it safely', 'Reconcile the attempt before any lease adoption'],
  E_SECURITY_PROGRAM_SOURCE_CHANGED: ['The source no longer matches the bound fingerprint', 'Repository identity changed after authority was issued', 'Return HOLD and create a new reviewed epoch'],
  E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED: ['An evidence schema is unsupported', 'The reader cannot safely interpret the retained version', 'Run coverage migrate --check'],
  E_SECURITY_PROGRAM_BUNDLE_UNAVAILABLE: ['A retained bundle cannot be verified', 'The logical bundle reference is missing or unreadable', 'Restore the retained bundle without changing its receipt'],
  E_SECURITY_PROGRAM_BUNDLE_INSIDE_WORKTREE: ['The evidence bundle is inside a worktree', 'The configured location violates the isolation boundary', 'Move evidence through the approved migration workflow'],
  E_SECURITY_PROGRAM_BENCHMARK_TARGET_MISSED: ['The resume journey exceeded its canonical timing ceiling', 'At least one measured p95 reached the fixed 120s or 300s target', 'Retain the red measurement and diagnose the control-plane regression'],
  E_SECURITY_PROGRAM_EVIDENCE_INVALID: ['Retained evidence failed validation', 'A hash, binding, state transition, or envelope is inconsistent', 'Quarantine the affected artifact and reconcile from retained authority'],
  E_SECURITY_PROGRAM_APPROVAL_REQUIRED: ['The requested operation lacks explicit approval', 'No matching immutable approval is bound to the attempt', 'Obtain a reviewed approval before retrying'],
  E_SECURITY_PROGRAM_DX_INCOMPLETE: ['The operator control plane is incomplete', 'The remaining T7-DX runtime gates are still open', 'Complete the named gates before C0.5'],
  E_SECURITY_PROGRAM_SCAN_UNAVAILABLE: ['Scan launch is unavailable', 'The no-launch implementation gate remains active', 'Complete all admission prerequisites'],
  E_SECURITY_PROGRAM_NOT_PUBLISHED: ['Canonical C0 evidence is unavailable', 'Published records are missing or differ from fresh compilation', 'Run inventory compile --check, then the separately authorized publication step'],
  E_SECURITY_PROGRAM_PATH_TOKEN_UNKNOWN: ['The path token is unknown', 'It does not resolve uniquely in the frozen inventory', 'Copy a current token from coverage list --paths'],
  E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN: ['The attempt is unavailable for this action', 'The requested ID is not the current verified attempt in the required state', 'Run coverage resume and use its exact next argv'],
  E_SECURITY_PROGRAM_OUTPUT_PRIVACY: ['A rendered value violates the public output boundary', 'An absolute private path or protected payload marker reached the renderer', 'Remove the sensitive field and expose only a logical reference'],
  E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE: ['Projection migration is fenced', 'An unfinished attempt still owns the current evidence generation', 'Resolve or reconcile that attempt before migrating'],
  E_SECURITY_PROGRAM_C0_COUNT_MISMATCH: ['Frozen inventory counts differ from authority', 'The current tree does not match the approved C0 decision', 'Reconcile the inventory decision before continuing'],
  E_SECURITY_PROGRAM_C0_OWNERSHIP_MISMATCH: ['Section ownership is not an exact partition', 'S01-S30 or shard totals do not equal the authorized inventory', 'Repair the deterministic ownership projection before continuing'],
  E_SECURITY_PROGRAM_INTERNAL: ['The control plane failed closed', 'An unexpected internal error prevented a trustworthy result', 'Run the offline doctor and inspect the stable diagnostic code'],
  E_SECURITY_PROGRAM_PUBLICATION_BUSY: ['Canonical publication is already locked', 'Another publisher or retained crash lock owns the operation', 'Reconcile the publication lock before retrying'],
  E_SECURITY_PROGRAM_PLATFORM_UNSUPPORTED: ['This host has no supported read path', 'The OS and architecture are outside the named operator environments', 'Use macOS arm64 or Ubuntu x86_64 for this control-plane command'],
  E_SECURITY_PROGRAM_PREREQUISITE_BLOCKED: ['The selected resume branch has an unmet prerequisite', 'Persisted authority is readable but not eligible to advance', 'Run the exact read-only next command and resolve the reported prerequisite'],
  E_SECURITY_PROGRAM_USAGE: ['The command grammar is invalid', 'Arguments do not match a supported command', 'Run --help'],
});

class ControlError extends Error {
  constructor(code, message, exitCode, detail = undefined) {
    super(message);
    this.name = 'ControlError';
    this.code = code;
    this.exitCode = exitCode;
    this.detail = detail;
  }
}

function pipeScalar(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    return value.replace(/[\\\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, (character) => {
      if (character === '\\') return '\\\\';
      if (character === '\t') return '\\t';
      if (character === '\n') return '\\n';
      if (character === '\r') return '\\r';
      const code = character.codePointAt(0);
      return `\\u${code.toString(16).padStart(4, '0')}`;
    });
  }
  return String(value);
}

function flattened(value, prefix = '') {
  if (value === null || typeof value !== 'object') return [[prefix, pipeScalar(value)]];
  if (Array.isArray(value)) {
    if (value.length === 0) return [[prefix, '[]']];
    return value.flatMap((item, index) => flattened(item, `${prefix}[${index}]`));
  }
  const entries = Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  if (entries.length === 0) return [[prefix, '{}']];
  return entries.flatMap(([key, item]) => flattened(item, prefix ? `${prefix}.${key}` : key));
}

function assertPublicOutput(value, key = '') {
  if (typeof value === 'string') {
    const posixAbsolute = /(?:^|[^A-Za-z0-9._/\\-])\/(?!\/)/;
    const windowsDriveAbsolute = /(?:^|[^A-Za-z0-9._-])[A-Za-z]:[\\/](?![\\/])/;
    const windowsUncAbsolute = /(?:^|[^\\])\\\\[^\\\s]+\\[^\\\s]+/;
    if (posixAbsolute.test(value) || windowsDriveAbsolute.test(value) || windowsUncAbsolute.test(value)) {
      throw new ControlError('E_SECURITY_PROGRAM_OUTPUT_PRIVACY', 'absolute private paths are forbidden in command output', EXIT.INVALID);
    }
    return;
  }
  if (value === null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) assertPublicOutput(item, key);
    return;
  }
  for (const [childKey, child] of Object.entries(value)) {
    const normalized = childKey.toLowerCase();
    if ((normalized === 'findingbody' || normalized === 'developeridentity') && child !== false && child !== null) {
      throw new ControlError('E_SECURITY_PROGRAM_OUTPUT_PRIVACY', 'protected payload fields are forbidden in command output', EXIT.INVALID);
    }
    assertPublicOutput(child, childKey);
  }
}

export function renderOutput(value, mode) {
  assertPublicOutput(value);
  if (mode === 'json') {
    return stringifyJsonDocument(value).replace(/[\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, (character) => {
      const code = character.codePointAt(0);
      return `\\u${code.toString(16).padStart(4, '0')}`;
    });
  }
  const rows = flattened(value);
  if (mode === 'pipe') return `${rows.map(([key, item]) => `${pipeScalar(key)}\t${item}`).join('\n')}\n`;
  if (mode !== 'human') throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'unknown output mode', EXIT.USAGE);
  const heading = `${pipeScalar(value.command ?? 'security program')}: ${pipeScalar(value.status ?? 'UNKNOWN')}`;
  const body = rows
    .filter(([key]) => !['command', 'status', 'conclusion'].includes(key))
    .map(([key, item]) => `${pipeScalar(key)}: ${item}`);
  if (value.conclusion) body.push(pipeScalar(value.conclusion));
  return `${[heading, ...body].join('\n')}\n`;
}

export function classifyReadPlatform(platform = process.platform, architecture = process.arch, configuredHostClass = process.env.SETJOIN_SECURITY_HOST_CLASS) {
  const expectedHostClass = platform === 'darwin' && architecture === 'arm64' ? 'mac-ci-m5'
    : platform === 'linux' && architecture === 'x64' ? 'ubuntu-ci-m920x' : null;
  return Object.freeze({
    platform,
    architecture,
    hostClass: configuredHostClass === expectedHostClass ? configuredHostClass : 'local-unclassified',
    supportedReadPath: expectedHostClass !== null,
  });
}

export function assertSupportedReadPlatform(host) {
  if (!host?.supportedReadPath) {
    throw new ControlError('E_SECURITY_PROGRAM_PLATFORM_UNSUPPORTED', 'unsupported operator read platform', EXIT.BLOCKED, {
      command: 'doctor', status: 'BLOCKED', domainState: 'PLATFORM_BLOCKED',
      effect: 'No control-plane or scanner transition was performed',
      artifactRef: 'control:platform-read-path',
      rerun: { argv: ['bash', 'scripts/verify-security-program.sh', '--doctor', '--offline'] },
    });
  }
  return host;
}

function output(value, stream = process.stdout) {
  const resolved = outputMode === 'auto' ? (process.stdout.isTTY ? 'human' : 'pipe') : outputMode;
  stream.write(renderOutput(value, resolved));
}

function parseOutputMode(argv) {
  const jsonFlags = argv.filter((argument) => argument === '--json').length;
  if (jsonFlags > 1) throw new ControlError('E_SECURITY_PROGRAM_USAGE', '--json may be specified once', EXIT.USAGE);
  return { argv: argv.filter((argument) => argument !== '--json'), mode: jsonFlags === 1 ? 'json' : 'auto' };
}

function pathToken(repositoryPath) {
  return `pt_v1_${crypto.createHash('sha256').update('setjoin.security-program.path-token/v1\0').update(repositoryPath).digest('hex')}`;
}

function safeError(error) {
  if (error instanceof ControlError) return error;
  if (error instanceof InventoryError) {
    return new ControlError(error.code, 'C0 inventory evidence is invalid', EXIT.INVALID);
  }
  if (typeof error?.code === 'string' && error.code.startsWith('E_SECURITY_PROGRAM_')) {
    const exitCode = error.code === 'E_SECURITY_PROGRAM_USAGE' ? EXIT.USAGE
      : ['E_SECURITY_PROGRAM_APPROVAL_REQUIRED', 'E_SECURITY_PROGRAM_PUBLICATION_BUSY',
        'E_SECURITY_PROGRAM_PLATFORM_UNSUPPORTED', 'E_SECURITY_PROGRAM_PREREQUISITE_BLOCKED'].includes(error.code) ? EXIT.BLOCKED
        : ['E_SECURITY_PROGRAM_ORPHANED_START', 'E_SECURITY_PROGRAM_COMPLETION_UNKNOWN',
          'E_SECURITY_PROGRAM_LIVE_LEASE', 'E_SECURITY_PROGRAM_SOURCE_CHANGED',
          'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', 'E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE'].includes(error.code)
          ? EXIT.HOLD : EXIT.INVALID;
    return new ControlError(error.code, error.message || 'security-program evidence is invalid', exitCode, error.details);
  }
  return new ControlError('E_SECURITY_PROGRAM_INTERNAL', 'security-program control failed closed', EXIT.INVALID);
}

function diagnostic(error) {
  const [problem, cause, safeAction] = ERROR_CATALOG[error.code] ?? [
    'The security-program command failed closed',
    'Validated control-plane evidence was unavailable or inconsistent',
    'Inspect the stable code and rerun a read-only doctor',
  ];
  const detail = error.detail && typeof error.detail === 'object' ? error.detail : {};
  const reruns = {
    E_SECURITY_PROGRAM_USAGE: ['bash', 'scripts/verify-security-program.sh', '--help'],
    E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED: ['bash', 'scripts/verify-security-program.sh', 'coverage', 'migrate', '--check'],
    E_SECURITY_PROGRAM_PATH_TOKEN_UNKNOWN: ['bash', 'scripts/verify-security-program.sh', 'coverage', 'list', '--paths'],
    E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN: ['bash', 'scripts/verify-security-program.sh', 'coverage', 'resume'],
    E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE: ['bash', 'scripts/verify-security-program.sh', 'coverage', 'resume'],
  };
  const helpCommands = error.code === 'E_SECURITY_PROGRAM_USAGE' ? helpDocument().commands : undefined;
  return {
    schema: DIAGNOSTIC_SCHEMA,
    command: detail.command ?? 'diagnostic',
    status: detail.status ?? (error.exitCode === EXIT.HOLD ? 'HOLD' : 'FAIL'),
    code: error.code,
    problem,
    cause,
    actual: { state: 'withheld', reason: error.message },
    effect: detail.effect ?? 'The requested transition was not performed',
    safeAction: detail.safeAction ?? safeAction,
    artifactRef: detail.artifactRef ?? `control:${error.code}`,
    rerun: { argv: detail.rerun?.argv ?? reruns[error.code] ?? ['bash', 'scripts/verify-security-program.sh', '--doctor', '--offline'] },
    helpCommands,
    docs: DIAGNOSTIC_DOCS,
    domainState: detail.domainState ?? 'HOLD',
    exitFamily: detail.exitFamily ?? (error.exitCode === EXIT.HOLD ? 'HOLD'
      : error.exitCode === EXIT.BLOCKED ? 'BLOCKED' : 'FAIL'),
    action: detail.action,
    stateBranch: detail.stateBranch,
    targetVerdict: detail.targetVerdict,
    whySafe: detail.whySafe,
    next: detail.next,
    scanLaunch: 'HOLD',
    scannerStarts: 0,
    networkStarts: 0,
  };
}

export function diagnosticCatalogCodes() {
  return Object.freeze(Object.keys(ERROR_CATALOG).sort());
}

export function diagnosticExample(code) {
  if (!Object.hasOwn(ERROR_CATALOG, code)) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'unknown diagnostic example code', EXIT.USAGE);
  }
  return Object.freeze(diagnostic(new ControlError(code, 'planted diagnostic fixture', EXIT.INVALID, {
    command: 'diagnostic self-test', domainState: 'PLANTED_FAILURE',
  })));
}

function readStrictJson(filename) {
  try {
    return parseStrictJson(fs.readFileSync(filename, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published', EXIT.BLOCKED);
    }
    throw error;
  }
}

function compileCanonical() {
  const decision = readStrictJson(DECISION_FILE);
  const compiled = compileInventory({
    repoRoot: REPO_ROOT,
    revision: FROZEN_REVISION,
    exclusionPolicy: POLICY,
    historicalCandidateCount: HISTORICAL_CANDIDATE_COUNT,
    inventoryDecision: decision,
  });
  const observed = {
    treePathCount: compiled.epoch.treePathCount,
    authorizedCount: compiled.epoch.authorizedCount,
    excludedCount: compiled.epoch.excludedCount,
    sectionCount: compiled.sections.sections.length,
  };
  for (const [field, expected] of Object.entries(EXPECTED)) {
    if (observed[field] !== expected) {
      throw new ControlError('E_SECURITY_PROGRAM_C0_COUNT_MISMATCH', 'frozen C0 counts do not match the approved decision', EXIT.INVALID, { field });
    }
  }
  const sectionIds = compiled.sections.sections.map((section) => section.id);
  const expectedIds = Array.from({ length: 30 }, (_, index) => `S${String(index + 1).padStart(2, '0')}`);
  if (JSON.stringify(sectionIds) !== JSON.stringify(expectedIds)
      || compiled.sections.sections.reduce((sum, section) => sum + section.pathCount, 0) !== EXPECTED.authorizedCount
      || compiled.shards.shards.reduce((sum, shard) => sum + shard.pathCount, 0) !== EXPECTED.authorizedCount) {
    throw new ControlError('E_SECURITY_PROGRAM_C0_OWNERSHIP_MISMATCH', 'S01-S30 are not the exact authorized inventory union', EXIT.INVALID);
  }
  return compiled;
}

function documents(compiled) {
  return {
    epoch: stringifyJsonDocument(compiled.epoch),
    sections: stringifyJsonDocument(compiled.sections),
    shards: stringifyJsonDocument(compiled.shards),
  };
}

function publicationMatches(serialized) {
  return Object.entries(OUTPUTS).every(([name, filename]) => {
    try { return fs.readFileSync(filename, 'utf8') === serialized[name]; }
    catch (error) { if (error?.code === 'ENOENT') return false; throw error; }
  });
}

function atomicReplace(filename, contents) {
  const temporary = path.join(path.dirname(filename), `.${path.basename(filename)}.${process.pid}.tmp`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o644);
    fs.writeFileSync(descriptor, contents, 'utf8');
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, filename);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
}

function publish(serialized) {
  fs.mkdirSync(VERIFY_DIR, { recursive: true });
  const lock = path.join(VERIFY_DIR, '.security-coverage-publication.lock');
  try {
    fs.mkdirSync(lock);
  } catch (error) {
    if (error?.code === 'EEXIST') {
      throw new ControlError('E_SECURITY_PROGRAM_PUBLICATION_BUSY', 'another C0 publication is in progress', EXIT.BLOCKED);
    }
    throw error;
  }
  try {
    // Epoch is the commit marker. Readers accept the publication only when all
    // three files exactly match a fresh compilation, so interruption fails HOLD.
    atomicReplace(OUTPUTS.sections, serialized.sections);
    atomicReplace(OUTPUTS.shards, serialized.shards);
    atomicReplace(OUTPUTS.epoch, serialized.epoch);
    const directory = fs.openSync(VERIFY_DIR, 'r');
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  } finally {
    fs.rmdirSync(lock);
  }
}

function summary(compiled, publicationState, operation) {
  return {
    schema: CONTROL_SCHEMA,
    command: operation,
    status: 'PASS',
    phase: 'C0',
    revision: compiled.epoch.revision,
    treePathCount: compiled.epoch.treePathCount,
    historicalCandidateCount: compiled.epoch.historicalCandidateCount,
    authorizedCount: compiled.epoch.authorizedCount,
    excludedCount: compiled.epoch.excludedCount,
    exclusionClassCount: compiled.epoch.exclusionPolicy.classes.length,
    exclusionCounts: Object.fromEntries(compiled.epoch.exclusionPolicy.classes.map((item) => [item.id, item.expectedCount])),
    inventorySha256: compiled.epoch.inventorySha256,
    exclusionPolicySha256: compiled.epoch.exclusionPolicySha256,
    inventoryDecision: 'MATCHED',
    ownerSectionCount: compiled.sections.sections.length,
    shardCount: compiled.shards.shards.length,
    publication: publicationState,
    scannerStarts: 0,
    networkStarts: 0,
    scanLaunch: 'HOLD',
  };
}

function inventoryCompile(mode) {
  if (!['--check', '--execute'].includes(mode)) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'inventory compile requires exactly --check or --execute', EXIT.USAGE);
  }
  const compiled = compileCanonical();
  const serialized = documents(compiled);
  if (mode === '--execute' && !publicationMatches(serialized)) publish(serialized);
  output(summary(compiled, publicationMatches(serialized) ? 'MATCHED' : 'NOT_PUBLISHED', `inventory compile ${mode}`));
}

function helpDocument() {
  return {
    schema: CONTROL_SCHEMA,
    command: 'help',
    status: 'PASS',
    commands: [
      'inventory compile --check', 'inventory compile --execute', '--doctor [--json] [--offline]',
      'coverage list [--section S01] [--paths]', 'coverage status',
      'coverage show --section S01', 'coverage show --path-token TOKEN',
      'coverage resume', 'coverage attach --attempt ID',
      'coverage reconcile-start --attempt ID', 'coverage reconcile-completion --attempt ID',
      'coverage start --shard ID --approval ID --dry-run',
      'coverage lease adopt --attempt ID --acknowledge-stale-owner',
      'coverage rollback --generation ID --execute',
      'coverage evidence', 'coverage migrate --check [--to v2]',
      'coverage benchmark --journey resume --samples 5 --warmup 2',
      'coverage explain [C0|HOLD|error-code]',
    ],
    unavailable: ['scan launch', 'coverage start --execute', 'lease adoption', 'rollback execution', 'external capability probe'],
    exitCodes: { 0: 'verified or terminal', 1: 'invalid or missing evidence', 2: 'usage error', 3: 'HOLD', 4: 'blocked prerequisite' },
  };
}

function help() {
  output(helpDocument());
}

function doctor() {
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const host = assertSupportedReadPlatform(classifyReadPlatform());
  output({
    schema: CONTROL_SCHEMA,
    command: 'doctor',
    status: 'PASS',
    conclusion: 'CONTROL PLANE USABLE',
    c0: 'PASS',
    scannerAvailable: false,
    networkRequired: false,
    capabilities: [
      { id: 'source-and-inventory', state: 'PASS' },
      { id: 'canonical-publication', state: 'PASS' },
      { id: 'read-only-cli', state: 'PASS' },
      { id: 'platform-read-path', state: host.supportedReadPath ? 'PASS' : 'BLOCKED', ...host },
      { id: 't7-route-review', state: 'PASS' },
      { id: 't7-dx', state: 'HOLD', code: 'E_SECURITY_PROGRAM_DX_INCOMPLETE' },
      { id: 'scan-launch', state: 'HOLD', code: 'E_SECURITY_PROGRAM_SCAN_UNAVAILABLE' },
    ],
    scanLaunch: 'HOLD',
    scannerStarts: 0,
    networkStarts: 0,
  });
}

function list({ sectionId, includePaths = false } = {}) {
  assertSupportedReadPlatform(classifyReadPlatform());
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  if (sectionId !== undefined && !/^S(?:0[1-9]|[12][0-9]|30)$/.test(sectionId)) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'coverage list --section requires S01 through S30', EXIT.USAGE);
  }
  const selectedSections = sectionId
    ? compiled.sections.sections.filter((section) => section.id === sectionId)
    : compiled.sections.sections;
  const selectedSectionIds = new Set(selectedSections.map((section) => section.id));
  const shards = compiled.shards.shards
    .filter((shard) => selectedSectionIds.has(shard.ownerSectionId))
    .map((shard) => ({
      id: shard.id,
      ownerSectionId: shard.ownerSectionId,
      pathCount: shard.pathCount,
      pathListSha256: shard.pathListSha256,
      ...(includePaths ? { paths: shard.paths.map((entry) => ({ path: entry.path, pathToken: pathToken(entry.path) })) } : {}),
    }));
  output({
    schema: CONTROL_SCHEMA,
    command: 'list',
    status: 'PASS',
    phases: [
      { id: 'C0', name: 'canonical inventory', state: 'AVAILABLE' },
      { id: 'C0.5', name: 'pilot', state: 'HOLD' },
      { id: 'C1', name: 'standard coverage', state: 'HOLD' },
      { id: 'D1', name: 'targeted deep review', state: 'HOLD' },
      { id: 'C2', name: 'reconciliation', state: 'HOLD' },
      { id: 'C3', name: 'completion', state: 'HOLD' },
    ],
    sections: selectedSections.map((section) => ({ id: section.id, pathCount: section.pathCount })),
    shards,
    scannerStarts: 0,
    networkStarts: 0,
    scanLaunch: 'HOLD',
  });
}

function status() {
  assertSupportedReadPlatform(classifyReadPlatform());
  const compiled = compileCanonical();
  const matches = publicationMatches(documents(compiled));
  output({
    ...summary(compiled, matches ? 'MATCHED' : 'NOT_PUBLISHED', 'status'),
    status: matches ? 'PASS' : 'HOLD',
    scanLaunch: 'HOLD',
    phases: {
      C0: { claimed: matches, verified: matches, state: matches ? 'PASS' : 'HOLD' },
      'C0.5': { claimed: false, verified: false, state: 'HOLD' },
      C1: { claimed: false, verified: false, state: 'HOLD' },
      D1: { claimed: false, verified: false, state: 'HOLD' },
      C2: { claimed: false, verified: false, state: 'HOLD' },
      C3: { claimed: false, verified: false, state: 'HOLD' },
    },
  });
}

function show(name) {
  assertSupportedReadPlatform(classifyReadPlatform());
  if (!Object.hasOwn(OUTPUTS, name)) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'show requires epoch, sections, or shards', EXIT.USAGE);
  }
  const compiled = compileCanonical();
  const serialized = documents(compiled);
  if (!publicationMatches(serialized)) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const record = readStrictJson(OUTPUTS[name]);
  const common = { schema: CONTROL_SCHEMA, command: `show ${name}`, status: 'PASS', revision: record.revision, inventorySha256: record.inventorySha256 };
  if (name === 'epoch') output({ ...common, treePathCount: record.treePathCount, authorizedCount: record.authorizedCount, excludedCount: record.excludedCount });
  else if (name === 'sections') output({ ...common, sectionCount: record.sections.length, pathCount: record.sections.reduce((sum, item) => sum + item.pathCount, 0) });
  else output({ ...common, generationId: record.generationId, shardCount: record.shards.length, pathCount: record.shards.reduce((sum, item) => sum + item.pathCount, 0) });
}

function showSection(sectionId) {
  assertSupportedReadPlatform(classifyReadPlatform());
  if (!/^S(?:0[1-9]|[12][0-9]|30)$/.test(sectionId ?? '')) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'coverage show --section requires S01 through S30', EXIT.USAGE);
  }
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const section = compiled.sections.sections.find((item) => item.id === sectionId);
  const shard = compiled.shards.shards.find((item) => item.ownerSectionId === sectionId);
  output({
    schema: CONTROL_SCHEMA,
    command: `coverage show --section ${sectionId}`,
    status: 'PASS',
    sectionId,
    revision: compiled.epoch.revision,
    inventorySha256: compiled.epoch.inventorySha256,
    pathCount: section.pathCount,
    shardId: shard.id,
    pathListSha256: shard.pathListSha256,
    scanLaunch: 'HOLD',
  });
}

function showPathToken(token) {
  assertSupportedReadPlatform(classifyReadPlatform());
  if (!/^pt_v1_[0-9a-f]{64}$/.test(token ?? '')) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'coverage show --path-token requires a v1 opaque token', EXIT.USAGE);
  }
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const matches = [];
  for (const shard of compiled.shards.shards) {
    for (const entry of shard.paths) {
      if (pathToken(entry.path) === token) matches.push({ repositoryPath: entry.path, shard });
    }
  }
  if (matches.length !== 1) {
    throw new ControlError('E_SECURITY_PROGRAM_PATH_TOKEN_UNKNOWN', 'path token does not identify exactly one frozen path', EXIT.INVALID);
  }
  const [{ repositoryPath, shard }] = matches;
  output({
    schema: CONTROL_SCHEMA,
    command: 'coverage show --path-token',
    status: 'PASS',
    path: repositoryPath,
    pathToken: token,
    sectionId: shard.ownerSectionId,
    shardId: shard.id,
    revision: compiled.epoch.revision,
    inventorySha256: compiled.epoch.inventorySha256,
    scanLaunch: 'HOLD',
    scannerStarts: 0,
    networkStarts: 0,
  });
}

function resume() {
  assertSupportedReadPlatform(classifyReadPlatform());
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const authority = readRuntimeResumeAuthority({
    repoRoot: REPO_ROOT,
    expected: {
      revision: compiled.epoch.revision,
      inventorySha256: compiled.epoch.inventorySha256,
      shardGenerationId: compiled.shards.generationId,
    },
  });
  const decision = resumeStateDecision(authority);
  if (decision.exitFamily === 'OK') {
    return output({
      schema: CONTROL_SCHEMA,
      command: 'coverage resume',
      status: 'PASS',
      ...decision,
      scannerStarts: 0,
      networkStarts: 0,
      scanLaunch: 'HOLD',
    });
  }
  const branchError = {
    ORPHANED_START: ['E_SECURITY_PROGRAM_ORPHANED_START', 'the persisted scanner start has no confirmed scan identity', EXIT.HOLD],
    COMPLETION_UNKNOWN: ['E_SECURITY_PROGRAM_COMPLETION_UNKNOWN', 'the persisted scan has no verified terminal result', EXIT.HOLD],
    BLOCKED: ['E_SECURITY_PROGRAM_PREREQUISITE_BLOCKED', 'the persisted attempt has an unmet prerequisite', EXIT.BLOCKED],
    FRESH: ['E_SECURITY_PROGRAM_DX_INCOMPLETE', 'T7-DX acceptance must close before C0.5 can be admitted', EXIT.HOLD],
  }[decision.stateBranch] ?? ['E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'resume state cannot advance safely', EXIT.INVALID];
  throw new ControlError(
    branchError[0],
    branchError[1],
    branchError[2],
    {
      domainState: decision.stateBranch,
      command: 'coverage resume',
      status: decision.exitFamily === 'BLOCKED' ? 'BLOCKED' : 'HOLD',
      effect: 'No shard is eligible and no scanner may start',
      artifactRef: decision.attemptId ? `attempt:${decision.attemptId}` : 'plan:whole-codebase-security-coverage#T7-DX',
      whySafe: decision.whySafe,
      action: decision.action,
      stateBranch: decision.stateBranch,
      targetVerdict: decision.targetVerdict,
      exitFamily: decision.exitFamily,
      next: decision.next,
    },
  );
}

function explain(subject = 'C0') {
  const explanations = {
    C0: 'C0 freezes and validates the Git inventory, exclusions, S01-S30 ownership, and shards without launching a scanner.',
    HOLD: 'HOLD means later scan operations are intentionally unavailable until their separately reviewed implementation slices land.',
    E_SECURITY_PROGRAM_SCAN_UNAVAILABLE: 'Scan launch is intentionally absent from this no-launch control slice.',
    E_SECURITY_PROGRAM_NOT_PUBLISHED: 'Run inventory compile --execute after inventory compile --check passes.',
  };
  if (Object.hasOwn(ERROR_CATALOG, subject)) {
    const [problem, cause, safeAction] = ERROR_CATALOG[subject];
    return output({
      schema: CONTROL_SCHEMA,
      command: `explain ${subject}`,
      status: 'PASS',
      subject,
      diagnostic: { code: subject, problem, cause, effect: 'The unsafe transition is blocked', safeAction, docs: DIAGNOSTIC_DOCS },
      scannerStarts: 0,
      networkStarts: 0,
      scanLaunch: 'HOLD',
    });
  }
  if (!Object.hasOwn(explanations, subject)) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'unknown explain subject', EXIT.USAGE);
  }
  output({ schema: CONTROL_SCHEMA, command: `explain ${subject}`, status: 'PASS', subject, explanation: explanations[subject] });
}

function migrateCheck(targetVersion = 'current') {
  assertSupportedReadPlatform(classifyReadPlatform());
  if (!['current', 'v2'].includes(targetVersion)) {
    throw new ControlError('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', 'unsupported migration target', EXIT.HOLD);
  }
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const authority = readRuntimeResumeAuthority({
    repoRoot: REPO_ROOT,
    expected: {
      revision: compiled.epoch.revision,
      inventorySha256: compiled.epoch.inventorySha256,
      shardGenerationId: compiled.shards.generationId,
    },
  });
  const decision = resumeStateDecision(authority);
  const migrationFenceState = ['fresh', 'complete'].includes(authority.state)
    ? null : decision.stateBranch === 'BLOCKED' ? 'ACTIVE' : decision.stateBranch;
  assertProjectionMigrationFence(migrationFenceState);
  const sourceProjection = targetVersion === 'v2'
    ? { schema: PROJECTION_V1_SCHEMA, claimed: true, state: decision.stateBranch }
    : { schema: PROJECTION_V2_SCHEMA, claimed: true, verified: false, state: decision.stateBranch };
  const migratedProjection = migrateProjection(sourceProjection, 'v2');
  output({
    schema: CONTROL_SCHEMA,
    command: 'coverage migrate --check',
    status: 'PASS',
    adapterInvoked: true,
    migrationRequired: sourceProjection.schema !== migratedProjection.schema,
    targetVersion,
    sourceProjectionSchema: sourceProjection.schema,
    targetProjectionSchema: migratedProjection.schema,
    sourceProjectionSha256: sha256Hex(canonicalJson(sourceProjection)),
    targetProjectionSha256: sha256Hex(canonicalJson(migratedProjection)),
    attemptFenceState: migrationFenceState ?? 'FREE',
    schemas: {
      control: CONTROL_SCHEMA,
      diagnostic: DIAGNOSTIC_SCHEMA,
      epoch: compiled.epoch.schema,
      sections: compiled.sections.schema,
      shards: compiled.shards.schema,
      supportedProjectionAdapters: ['setjoin.security-program.projection/v1->v2'],
    },
    effect: 'No evidence was rewritten',
    scanLaunch: 'HOLD',
    scannerStarts: 0,
    networkStarts: 0,
  });
}

function evidence() {
  assertSupportedReadPlatform(classifyReadPlatform());
  const compiled = compileCanonical();
  const serialized = documents(compiled);
  if (!publicationMatches(serialized)) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  output({
    schema: CONTROL_SCHEMA,
    command: 'coverage evidence',
    status: 'PASS',
    verified: true,
    artifactRef: 'verification:security-coverage-c0',
    revision: compiled.epoch.revision,
    inventorySha256: compiled.epoch.inventorySha256,
    generationId: compiled.shards.generationId,
    sectionCount: compiled.sections.sections.length,
    shardCount: compiled.shards.shards.length,
    authorizedPathCount: compiled.epoch.authorizedCount,
    findingBodiesExposed: false,
    absolutePathsExposed: false,
    scanLaunch: 'HOLD',
    scannerStarts: 0,
    networkStarts: 0,
  });
}

function benchmarkInteger(value, flag, { minimum, maximum }) {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value ?? '')) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', `${flag} requires an integer`, EXIT.USAGE);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', `${flag} must be between ${minimum} and ${maximum}`, EXIT.USAGE);
  }
  return parsed;
}

function benchmarkSourceBinding(compiled) {
  const discovered = new Set(['scripts/verify-security-program.sh']);
  const visit = (repositoryPath) => {
    if (discovered.has(repositoryPath)) return;
    discovered.add(repositoryPath);
    const source = fs.readFileSync(path.join(REPO_ROOT, repositoryPath), 'utf8');
    const imports = source.matchAll(/(?:from\s+|import\s*)['"](\.[^'"]+)['"]/gu);
    for (const match of imports) {
      const resolved = path.resolve(REPO_ROOT, path.dirname(repositoryPath), match[1]);
      const relative = path.relative(REPO_ROOT, resolved).split(path.sep).join('/');
      if (relative.startsWith('../') || path.isAbsolute(relative)) {
        throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'benchmark dependency escapes the repository', EXIT.INVALID);
      }
      visit(relative);
    }
  };
  visit('scripts/security-program.mjs');
  const files = [...discovered].sort().map((repositoryPath) => ({
    repositoryPath,
    sha256: sha256Hex(fs.readFileSync(path.join(REPO_ROOT, repositoryPath))),
  }));
  return Object.freeze({
    revision: compiled.epoch.revision,
    inventorySha256: compiled.epoch.inventorySha256,
    shardGenerationId: compiled.shards.generationId,
    controlSourceSha256: sha256Hex(canonicalJson({ files })),
  });
}

function sealBenchmarkDocument(document) {
  return Object.freeze({ ...document, evidenceSha256: sha256Hex(canonicalJson(document)) });
}

function hasExactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort());
}

export function verifyBenchmarkDocument(value) {
  const topLevelKeys = [
    'absolutePathsExposed', 'architecture', 'command', 'developerIdentityExposed',
    'discardedWarmups', 'evidenceSha256', 'findingBodiesExposed', 'generatedAt',
    'hostClass', 'journey', 'networkStarts', 'observed', 'platform', 'results',
    'runtime', 'samples', 'scanLaunch', 'scannerStarts', 'schema', 'sourceBinding',
    'status', 'supportedReadPath', 'targets',
  ];
  if (!hasExactKeys(value, topLevelKeys) || value.schema !== BENCHMARK_SCHEMA || value.status !== 'PASS'
      || typeof value.generatedAt !== 'string' || !Number.isFinite(Date.parse(value.generatedAt))
      || value.runtime?.engine !== 'node' || !Number.isSafeInteger(value.runtime?.major)
      || !hasExactKeys(value.runtime, ['engine', 'major'])
      || value.samples !== 5 || value.discardedWarmups !== 2
      || typeof value.evidenceSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.evidenceSha256)) {
    throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'retained benchmark envelope is invalid', EXIT.INVALID);
  }
  const { evidenceSha256, ...document } = value;
  if (sha256Hex(canonicalJson(document)) !== evidenceSha256) {
    throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'retained benchmark digest does not match', EXIT.INVALID);
  }
  const compiled = compileCanonical();
  const expectedBinding = benchmarkSourceBinding(compiled);
  if (!hasExactKeys(value.sourceBinding, ['revision', 'inventorySha256', 'shardGenerationId', 'controlSourceSha256'])
      || canonicalJson(value.sourceBinding) !== canonicalJson(expectedBinding)) {
    throw new ControlError('E_SECURITY_PROGRAM_SOURCE_CHANGED', 'retained benchmark is not bound to current control sources', EXIT.INVALID);
  }
  const states = ['fresh', 'active', 'detached', 'orphaned', 'completion-unknown', 'blocked', 'eligible', 'complete'];
  const command = (...args) => ({ argv: ['bash', 'scripts/verify-security-program.sh', ...args] });
  const expectedRows = [
    ['HOLD', 'FRESH', 'WAIT_FOR_DX', 'SAFE_HOLD', null, 3, null],
    ['OK', 'ACTIVE', 'REJOIN_EXISTING', 'SAFE_ATTACH', command('coverage', 'attach', '--attempt', 'attempt-fixture'), 0, 0],
    ['OK', 'DETACHED', 'REJOIN_EXISTING', 'SAFE_ATTACH', command('coverage', 'attach', '--attempt', 'attempt-fixture'), 0, 0],
    ['HOLD', 'ORPHANED_START', 'RECONCILE_START', 'SAFE_RECONCILE', command('coverage', 'reconcile-start', '--attempt', 'attempt-fixture'), 3, 3],
    ['HOLD', 'COMPLETION_UNKNOWN', 'RECONCILE_COMPLETION', 'SAFE_RECONCILE', command('coverage', 'reconcile-completion', '--attempt', 'attempt-fixture'), 3, 3],
    ['BLOCKED', 'BLOCKED', 'RESOLVE_PREREQUISITE', 'SAFE_BLOCKED', command('--doctor', '--offline'), 4, 0],
    ['OK', 'ELIGIBLE', 'START_DRY_RUN', 'SAFE_DRY_RUN', command('coverage', 'start', '--shard', 'S01/P01', '--approval', 'approval-fixture', '--dry-run'), 0, 0],
    ['OK', 'COMPLETE', 'ALL_COVERAGE_RECONCILED', 'SAFE_TERMINAL', null, 0, null],
  ];
  if (!Array.isArray(value.results) || canonicalJson(value.results.map((row) => row.state)) !== canonicalJson(states)
      || value.results.some((row) => row.actionValidated !== true || row.scannerStarts !== 0 || row.networkStarts !== 0)
      || value.scannerStarts !== 0 || value.networkStarts !== 0 || value.absolutePathsExposed
      || value.developerIdentityExposed || value.findingBodiesExposed
      || !hasExactKeys(value.targets, ['doctorStatusP95Ms', 'fullJourneyP95Ms'])
      || canonicalJson(value.targets) !== canonicalJson(BENCHMARK_TARGETS)
      || !hasExactKeys(value.observed, ['doctorStatusP95Ms', 'fullJourneyP95Ms'])
      || value.observed.doctorStatusP95Ms !== Math.max(...value.results.map((row) => row.doctorStatusP95Ms))
      || value.observed.fullJourneyP95Ms !== Math.max(...value.results.map((row) => row.fullJourneyP95Ms))
      || value.observed.doctorStatusP95Ms >= value.targets.doctorStatusP95Ms
      || value.observed.fullJourneyP95Ms >= value.targets.fullJourneyP95Ms) {
    throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'retained benchmark claims are invalid', EXIT.INVALID);
  }
  for (let index = 0; index < value.results.length; index += 1) {
    const row = value.results[index];
    const actualTuple = [row.exitFamily, row.stateBranch, row.action, row.targetVerdict,
      row.next ?? null, row.resumeExitCode, row.nextActionExitCode];
    if (canonicalJson(actualTuple) !== canonicalJson(expectedRows[index])
        || typeof row.whySafe !== 'string' || row.whySafe.length === 0
        || row.samples !== 5 || row.fullJourneyP95Ms <= row.doctorStatusP95Ms
        || row.validationMode !== 'persisted-state-subprocess') {
      throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'retained benchmark resume action is invalid', EXIT.INVALID);
    }
  }
  assertPublicOutput(value);
  return Object.freeze(value);
}

function percentile95(values) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)];
}

export function assertBenchmarkTargets(observed) {
  if (!observed || observed.doctorStatusP95Ms >= BENCHMARK_TARGETS.doctorStatusP95Ms
      || observed.fullJourneyP95Ms >= BENCHMARK_TARGETS.fullJourneyP95Ms) {
    throw new ControlError('E_SECURITY_PROGRAM_BENCHMARK_TARGET_MISSED', 'canonical resume timing target was missed', EXIT.INVALID, {
      command: 'coverage benchmark --journey resume', status: 'FAIL', domainState: 'BENCHMARK_RED',
      artifactRef: 'verification:security-coverage-dx-benchmark',
      safeAction: 'Retain the red evidence and diagnose the control-plane regression',
    });
  }
  return observed;
}

function benchmarkAttemptEvents(state, compiled) {
  const shard = compiled.shards.shards[0];
  const base = {
    schema: 'setjoin.security-program.attempt-event/v3', eventId: 'benchmark-0',
    attemptId: 'attempt-fixture', sequence: 0, state: 'RESERVED',
    recordedAt: '2026-09-04T00:00:00.000Z', epochRevision: compiled.epoch.revision,
    sourceFingerprint: `v2:${compiled.epoch.revision}:${'d'.repeat(64)}`,
    inventorySha256: compiled.epoch.inventorySha256, shardGenerationId: compiled.shards.generationId,
    sectionId: shard.ownerSectionId, shardId: shard.id, shardPathCount: shard.pathCount,
    shardPathListSha256: shard.pathListSha256, targetArtifactSha256: 'a'.repeat(64),
    targetPathCount: shard.pathCount, targetPathListSha256: shard.pathListSha256,
    mode: 'Deep', targetForm: 'real-directory', targetKind: 'git_revision',
    controlGenerationHash: 'b'.repeat(64), leaseOwner: 'benchmark', coordinatorVersion: 'v1',
    adapterVersion: 'security-target-adapter/v1', scannerSchemaVersion: 'scanner-v1',
    fingerprintVersion: 'v2', controlSchemaSetVersion: 'v1',
  };
  const events = [base];
  const append = (nextState, { scanId, reasonCode } = {}) => {
    const prior = events.at(-1);
    const next = {
      ...prior, eventId: `benchmark-${events.length}`, sequence: events.length, state: nextState,
      recordedAt: `2026-09-04T00:00:${String(events.length).padStart(2, '0')}.000Z`,
    };
    if (scanId !== undefined) next.scanId = scanId;
    if (reasonCode === undefined) delete next.reasonCode; else next.reasonCode = reasonCode;
    events.push(next);
  };
  if (state === 'blocked') return events;
  append('START_REQUESTED');
  if (state === 'orphaned') {
    append('ORPHANED_START', { reasonCode: 'ORPHANED_START' });
    append('HOLD', { reasonCode: 'ORPHANED_START' });
    return events;
  }
  append('RUNNING', { scanId: 'scan-fixture' });
  if (state === 'active') return events;
  if (state === 'detached') { append('DETACHED'); return events; }
  append('COMPLETION_REQUESTED');
  if (state === 'completion-unknown') {
    append('COMPLETION_UNKNOWN', { reasonCode: 'COMPLETION_UNKNOWN' });
    return events;
  }
  for (const nextState of ['SEALED', 'SOURCE_VERIFIED', 'PUBLICATION_PENDING', 'PUBLISHED', 'ADMITTED']) append(nextState);
  return events;
}

function executeBenchmarkResumeJourney(state, compiled) {
  const stateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-benchmark-'));
  fs.chmodSync(stateDirectory, 0o700);
  try {
    if (!['fresh', 'eligible'].includes(state)) {
      fs.writeFileSync(path.join(stateDirectory, 'attempt-journal.json'), canonicalJson({
        schema: 'setjoin.security-program.attempt-journal/v3',
        events: benchmarkAttemptEvents(state, compiled),
      }), { mode: 0o600 });
    } else if (state === 'eligible') {
      fs.writeFileSync(path.join(stateDirectory, 'eligibility.json'), canonicalJson({
        schema: 'setjoin.security-program.eligibility/v1', revision: compiled.epoch.revision,
        inventorySha256: compiled.epoch.inventorySha256, shardGenerationId: compiled.shards.generationId,
        shardId: 'S01/P01', approvalId: 'approval-fixture',
      }), { mode: 0o600 });
    }
    const invoke = (argv, expectedExit) => {
      const result = spawnSync(argv[0], [...argv.slice(1), '--json'], {
        cwd: REPO_ROOT, encoding: 'utf8', timeout: 30_000,
        env: { ...process.env, SETJOIN_SECURITY_PROGRAM_STATE_DIR: stateDirectory },
      });
      const serialized = expectedExit === 0 ? result.stdout : result.stderr;
      let record;
      try { record = parseStrictJson(serialized); }
      catch { throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'benchmark subprocess did not return structured evidence', EXIT.INVALID); }
      if (result.error || result.signal || result.status !== expectedExit
          || record.scannerStarts !== 0 || record.networkStarts !== 0
          || (expectedExit === 0 && record.status !== 'PASS')
          || (expectedExit !== 0 && !['HOLD', 'BLOCKED', 'FAIL'].includes(record.status))) {
        throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `benchmark ${state} subprocess did not match persisted authority`, EXIT.INVALID);
      }
      return record;
    };
    const started = process.hrtime.bigint();
    invoke(['bash', 'scripts/verify-security-program.sh', '--doctor', '--offline'], 0);
    invoke(['bash', 'scripts/verify-security-program.sh', 'coverage', 'status'], 0);
    const doctorStatusFinished = process.hrtime.bigint();
    const resumeExit = ({ fresh: 3, orphaned: 3, 'completion-unknown': 3, blocked: 4 })[state] ?? 0;
    const resumeRecord = invoke(
      ['bash', 'scripts/verify-security-program.sh', 'coverage', 'resume'], resumeExit,
    );
    const decision = Object.fromEntries([
      'exitFamily', 'stateBranch', 'action', 'targetVerdict', 'whySafe', 'next', 'attemptId', 'scanId', 'shardId',
    ].filter((key) => Object.hasOwn(resumeRecord, key)).map((key) => [key, resumeRecord[key]]));
    const expectedBranches = {
      fresh: 'FRESH', active: 'ACTIVE', detached: 'DETACHED', orphaned: 'ORPHANED_START',
      'completion-unknown': 'COMPLETION_UNKNOWN', blocked: 'BLOCKED', eligible: 'ELIGIBLE', complete: 'COMPLETE',
    };
    if (decision.stateBranch !== expectedBranches[state]) {
      throw new ControlError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'benchmark resume selected the wrong persisted state', EXIT.INVALID);
    }
    let nextActionExit = null;
    if (decision.next?.argv) {
      nextActionExit = ['orphaned', 'completion-unknown'].includes(state) ? 3 : 0;
      invoke(decision.next.argv, nextActionExit);
    }
    const journeyFinished = process.hrtime.bigint();
    return Object.freeze({
      decision,
      actionValidation: {
        actionValidated: true, validationMode: 'persisted-state-subprocess',
        scannerStarts: 0, networkStarts: 0,
        resumeExitCode: resumeExit,
        nextActionExitCode: nextActionExit,
      },
      doctorStatusMs: Number(doctorStatusFinished - started) / 1_000_000,
      fullJourneyMs: Number(journeyFinished - started) / 1_000_000,
    });
  } finally {
    fs.rmSync(stateDirectory, { recursive: true, force: true });
  }
}

function measureResumeJourney(state) {
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const measured = executeBenchmarkResumeJourney(state, compiled);
  renderOutput({
    schema: CONTROL_SCHEMA,
    command: 'coverage resume',
    status: measured.decision.exitFamily === 'OK' ? 'PASS' : measured.decision.exitFamily,
    ...measured.decision,
    ...measured.actionValidation,
    scannerStarts: 0,
    networkStarts: 0,
  }, 'json');
  return measured;
}

function runtimeResumeDecision() {
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const authority = readRuntimeResumeAuthority({
    repoRoot: REPO_ROOT,
    expected: {
      revision: compiled.epoch.revision,
      inventorySha256: compiled.epoch.inventorySha256,
      shardGenerationId: compiled.shards.generationId,
    },
  });
  return resumeStateDecision(authority);
}

function runResumeAction(action, selector) {
  assertSupportedReadPlatform(classifyReadPlatform());
  const decision = runtimeResumeDecision();
  validateResumeAction(decision, { action, ...selector });
  if (action === 'reconcile-start' || action === 'reconcile-completion') {
    const code = action === 'reconcile-start'
      ? 'E_SECURITY_PROGRAM_ORPHANED_START' : 'E_SECURITY_PROGRAM_COMPLETION_UNKNOWN';
    throw new ControlError(code, 'external reconciliation is required before state may advance', EXIT.HOLD, {
      command: `coverage ${action}`,
      status: 'HOLD',
      action: decision.action,
      stateBranch: decision.stateBranch,
      targetVerdict: decision.targetVerdict,
      next: null,
      effect: 'No scanner started and no retained state changed',
      safeAction: 'Reconcile the existing scanner identity through the separately authorized adapter',
      artifactRef: `attempt:${decision.attemptId}`,
    });
  }
  output({
    schema: CONTROL_SCHEMA,
    command: action === 'start-dry-run' ? 'coverage start --dry-run' : `coverage ${action}`,
    status: 'PASS',
    ...decision,
    actionValidated: true,
    effect: 'No scanner started and no retained state changed',
    next: null,
    scanLaunch: 'HOLD',
    scannerStarts: 0,
    networkStarts: 0,
  });
}

function benchmark({ journey, samples, warmup }) {
  assertSupportedReadPlatform(classifyReadPlatform());
  if (journey !== 'resume') {
    throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'coverage benchmark supports only --journey resume', EXIT.USAGE);
  }
  const compiled = compileCanonical();
  if (!publicationMatches(documents(compiled))) {
    throw new ControlError('E_SECURITY_PROGRAM_NOT_PUBLISHED', 'canonical C0 records are not published or do not match', EXIT.BLOCKED);
  }
  const states = ['fresh', 'active', 'detached', 'orphaned', 'completion-unknown', 'blocked', 'eligible', 'complete'];
  const results = states.map((state) => {
    for (let index = 0; index < warmup; index += 1) measureResumeJourney(state);
    const doctorStatusDurationsMs = [];
    const fullJourneyDurationsMs = [];
    let measured;
    for (let index = 0; index < samples; index += 1) {
      measured = measureResumeJourney(state);
      doctorStatusDurationsMs.push(measured.doctorStatusMs);
      fullJourneyDurationsMs.push(measured.fullJourneyMs);
    }
    return {
      state,
      ...measured.decision,
      ...measured.actionValidation,
      measurementClass: warmup > 0 ? 'warm-after-discarded-warmups' : 'cold',
      samples,
      doctorStatusP95Ms: Number(percentile95(doctorStatusDurationsMs).toFixed(3)),
      fullJourneyP95Ms: Number(percentile95(fullJourneyDurationsMs).toFixed(3)),
      scannerStarts: 0,
      networkStarts: 0,
    };
  });
  const doctorStatusP95Ms = Math.max(...results.map((result) => result.doctorStatusP95Ms));
  const fullJourneyP95Ms = Math.max(...results.map((result) => result.fullJourneyP95Ms));
  assertBenchmarkTargets({ doctorStatusP95Ms, fullJourneyP95Ms });
  const host = classifyReadPlatform();
  output(sealBenchmarkDocument({
    schema: BENCHMARK_SCHEMA,
    command: 'coverage benchmark --journey resume',
    status: 'PASS',
    journey,
    hostClass: host.hostClass,
    platform: host.platform,
    architecture: host.architecture,
    generatedAt: new Date().toISOString(),
    runtime: { engine: 'node', major: Number(process.versions.node.split('.')[0]) },
    sourceBinding: benchmarkSourceBinding(compiled),
    supportedReadPath: host.supportedReadPath,
    samples,
    discardedWarmups: warmup,
    targets: { ...BENCHMARK_TARGETS },
    observed: { doctorStatusP95Ms, fullJourneyP95Ms },
    results,
    developerIdentityExposed: false,
    absolutePathsExposed: false,
    findingBodiesExposed: false,
    scanLaunch: 'HOLD',
    scannerStarts: 0,
    networkStarts: 0,
  }));
}

export function run(argv) {
  const [command, ...rest] = argv;
  if (command === undefined || command === 'help' || command === '--help' || command === '-h') {
    if (rest.length !== 0) throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'help accepts no command arguments', EXIT.USAGE);
    return help();
  }
  if (['scan', 'start', 'resume'].includes(command)) {
    throw new ControlError('E_SECURITY_PROGRAM_SCAN_UNAVAILABLE', 'scan execution remains unavailable in this no-launch slice', EXIT.HOLD);
  }
  if ((command === 'doctor' || command === '--doctor') && rest.includes('--probe-scanner')) {
    throw new ControlError('E_SECURITY_PROGRAM_SCAN_UNAVAILABLE', 'scanner probing remains unavailable in this no-launch slice', EXIT.HOLD);
  }
  if (command === 'inventory' && rest[0] === 'compile' && rest.length === 2) return inventoryCompile(rest[1]);
  if ((command === 'doctor' || command === '--doctor') && rest.every((item) => item === '--offline')) return doctor();
  if (command === 'list' && rest.length === 0) return list();
  if (command === 'status' && rest.length === 0) return status();
  if (command === 'show' && rest.length === 1) return show(rest[0]);
  if (command === 'explain' && rest.length <= 1) return explain(rest[0]);
  if (command === 'coverage') {
    const [subcommand, ...args] = rest;
    if (subcommand === 'list') {
      let sectionId;
      let includePaths = false;
      for (let index = 0; index < args.length; index += 1) {
        if (args[index] === '--paths' && !includePaths) includePaths = true;
        else if (args[index] === '--section' && sectionId === undefined && args[index + 1] !== undefined) sectionId = args[++index];
        else throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'invalid coverage list arguments', EXIT.USAGE);
      }
      return list({ sectionId, includePaths });
    }
    if (subcommand === 'status' && args.length === 0) return status();
    if (subcommand === 'attach' && args.length === 2 && args[0] === '--attempt') {
      return runResumeAction('attach', { attemptId: args[1] });
    }
    if (subcommand === 'reconcile-start' && args.length === 2 && args[0] === '--attempt') {
      return runResumeAction('reconcile-start', { attemptId: args[1] });
    }
    if (subcommand === 'reconcile-completion' && args.length === 2 && args[0] === '--attempt') {
      return runResumeAction('reconcile-completion', { attemptId: args[1] });
    }
    if (subcommand === 'start' && args.length === 5 && args[0] === '--shard'
        && args[2] === '--approval' && args[4] === '--dry-run') {
      return runResumeAction('start-dry-run', { shardId: args[1], approvalId: args[3] });
    }
    if (subcommand === 'lease' && args.length === 4 && args[0] === 'adopt'
        && args[1] === '--attempt' && args[3] === '--acknowledge-stale-owner') {
      resumeLogicalToken(args[2], 'attempt ID');
      throw new ControlError('E_SECURITY_PROGRAM_SCAN_UNAVAILABLE', 'lease adoption remains unavailable before C0.5 approval', EXIT.HOLD, {
        command: 'coverage lease adopt', status: 'HOLD', artifactRef: `attempt:${args[2]}`,
        rerun: { argv: ['bash', 'scripts/verify-security-program.sh', 'coverage', 'resume'] },
      });
    }
    if (subcommand === 'rollback' && args.length === 3 && args[0] === '--generation' && args[2] === '--execute') {
      resumeLogicalToken(args[1], 'generation ID');
      throw new ControlError('E_SECURITY_PROGRAM_APPROVAL_REQUIRED', 'rollback execution requires a separate destructive approval', EXIT.BLOCKED, {
        command: 'coverage rollback', artifactRef: `generation:${args[1]}`,
        rerun: { argv: ['bash', 'scripts/verify-security-program.sh', 'coverage', 'status'] },
      });
    }
    if (subcommand === 'show' && args.length === 2 && args[0] === '--section') return showSection(args[1]);
    if (subcommand === 'show' && args.length === 2 && args[0] === '--path-token') return showPathToken(args[1]);
    if (subcommand === 'show' && args.length === 1) return show(args[0]);
    if (subcommand === 'explain' && args.length <= 1) return explain(args[0]);
    if (subcommand === 'migrate') {
      let check = false;
      let targetVersion = 'current';
      let execute = false;
      for (let index = 0; index < args.length; index += 1) {
        if (args[index] === '--check' && !check) check = true;
        else if (args[index] === '--to' && targetVersion === 'current' && args[index + 1] !== undefined) targetVersion = args[++index];
        else if (args[index] === '--execute' && !execute) execute = true;
        else throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'invalid coverage migrate arguments', EXIT.USAGE);
      }
      if (execute) {
        throw new ControlError('E_SECURITY_PROGRAM_APPROVAL_REQUIRED', 'migration execution requires a bound approval and free global lease', EXIT.BLOCKED);
      }
      if (!check) throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'coverage migrate requires --check or an approved --execute', EXIT.USAGE);
      return migrateCheck(targetVersion);
    }
    if (subcommand === 'evidence' && args.length === 0) return evidence();
    if (subcommand === 'benchmark') {
      let journey;
      let samples;
      let warmup;
      for (let index = 0; index < args.length; index += 1) {
        if (args[index] === '--journey' && journey === undefined && args[index + 1] !== undefined) journey = args[++index];
        else if (args[index] === '--samples' && samples === undefined && args[index + 1] !== undefined) samples = benchmarkInteger(args[++index], '--samples', { minimum: 1, maximum: 50 });
        else if (args[index] === '--warmup' && warmup === undefined && args[index + 1] !== undefined) warmup = benchmarkInteger(args[++index], '--warmup', { minimum: 0, maximum: 10 });
        else throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'invalid coverage benchmark arguments', EXIT.USAGE);
      }
      if (journey === undefined || samples === undefined || warmup === undefined) {
        throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'coverage benchmark requires --journey, --samples, and --warmup', EXIT.USAGE);
      }
      return benchmark({ journey, samples, warmup });
    }
    if (subcommand === 'resume' && args.length === 0) return resume();
    if (subcommand === 'start') {
      throw new ControlError('E_SECURITY_PROGRAM_SCAN_UNAVAILABLE', 'coverage execution remains unavailable in this no-launch slice', EXIT.HOLD);
    }
  }
  throw new ControlError('E_SECURITY_PROGRAM_USAGE', 'unknown command or arguments; run help', EXIT.USAGE);
}

export function main(argv = process.argv.slice(2)) {
  try {
    const parsed = parseOutputMode(argv);
    outputMode = parsed.mode;
    run(parsed.argv);
    return EXIT.OK;
  } catch (error) {
    const safe = safeError(error);
    output(diagnostic(safe), process.stderr);
    return safe.exitCode;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
