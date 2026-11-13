import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {
  SecurityProgramError,
  assertClosedSchema,
  canonicalJson,
  parseStrictJson,
  sha256Hex,
} from './security-program-json.mjs';
import { INVENTORY_SCHEMA, SHARDS_SCHEMA, hashInventory } from './security-program-inventory.mjs';
import {
  PINNED_STANDARD_ROUTE_CONTRACT_SHA256,
  EXPORT_CAPACITY_SCHEMA,
  STANDARD_TARGET_ROUTES,
  TARGET_ADAPTER_VERSION,
  verifyPreparedTarget,
} from './security-program-targets.mjs';
import { parseFingerprint } from './source-fingerprint.mjs';

export const ATTEMPT_EVENT_SCHEMA = 'setjoin.security-program.attempt-event/v3';
export const ATTEMPT_JOURNAL_SCHEMA = 'setjoin.security-program.attempt-journal/v3';
export const LEASE_SCHEMA = 'setjoin.security-program.lease/v1';

export const ATTEMPT_TRANSITIONS = Object.freeze({
  RESERVED: new Set(['START_REQUESTED']),
  START_REQUESTED: new Set(['RUNNING', 'ORPHANED_START']),
  ORPHANED_START: new Set(['HOLD']),
  RUNNING: new Set(['DETACHED', 'CANCELED', 'TERMINAL_FAILED', 'COMPLETION_REQUESTED']),
  DETACHED: new Set(['RUNNING', 'CANCELED', 'TERMINAL_FAILED']),
  COMPLETION_REQUESTED: new Set(['COMPLETION_UNKNOWN', 'SEALED', 'CANCELED', 'TERMINAL_FAILED']),
  COMPLETION_UNKNOWN: new Set(['SEALED', 'CANCELED', 'TERMINAL_FAILED']),
  SEALED: new Set(['SOURCE_VERIFIED']),
  SOURCE_VERIFIED: new Set(['PUBLICATION_PENDING']),
  PUBLICATION_PENDING: new Set(['PUBLISHED']),
  PUBLISHED: new Set(['ADMITTED']),
  HOLD: new Set(),
  CANCELED: new Set(),
  TERMINAL_FAILED: new Set(),
  ADMITTED: new Set(),
});

export const ACTIVE_ATTEMPT_STATES = new Set([
  'RESERVED', 'START_REQUESTED', 'RUNNING', 'DETACHED', 'COMPLETION_REQUESTED',
  'COMPLETION_UNKNOWN', 'SEALED', 'SOURCE_VERIFIED', 'PUBLICATION_PENDING', 'PUBLISHED',
]);

const ATTEMPT_REQUIRED = [
  'eventId', 'attemptId', 'sequence', 'state', 'recordedAt',
  'epochRevision', 'sourceFingerprint', 'inventorySha256', 'shardGenerationId', 'sectionId', 'shardId',
  'shardPathCount', 'shardPathListSha256',
  'targetArtifactSha256', 'targetPathCount', 'targetPathListSha256',
  'mode', 'targetForm', 'targetKind', 'controlGenerationHash', 'leaseOwner', 'coordinatorVersion',
  'adapterVersion', 'scannerSchemaVersion', 'fingerprintVersion', 'controlSchemaSetVersion',
];
const ROUTE_AUTHORITY_FIELDS = [
  'standardRoute', 'routeContractSha256', 'pluginVersion',
  'directorySnapshotDigest', 'exportTreeSha256', 'stableSnapshotSha256',
  'productionEligible', 'budgetId', 'budgetSha256', 'exportCapacity',
];
const ATTEMPT_OPTIONAL = ['scanId', 'supersedesAttemptId', 'reasonCode', ...ROUTE_AUTHORITY_FIELDS];
const LEASE_REQUIRED = ['owner', 'hostId', 'processId', 'attemptId', 'tokenHash', 'acquiredAt', 'expiresAt'];
const LEASE_OPTIONAL = ['scanId'];
const LOGICAL_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const authorityValidatedReservations = new WeakSet();

function error(code, message, details) {
  throw new SecurityProgramError(code, message, details);
}

function oneLine(value, name) {
  if (typeof value !== 'string' || value.length === 0 || /[\0\r\n]/.test(value)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a non-empty single-line string`);
  }
  return value;
}

function logicalToken(value, name) {
  oneLine(value, name);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a privacy-safe logical token`);
  }
  return value;
}

function sha256(value, name) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a lowercase SHA-256`);
  }
  return value;
}

function objectId(value, name) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a full lowercase Git object ID`);
  }
  return value;
}

function pathCount(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a positive safe integer`);
  }
  return value;
}

function shardId(value, name) {
  if (typeof value !== 'string' || !/^S(?:0[1-9]|[12][0-9]|30)\/P(?:0[1-9]|[1-9][0-9]*)$/.test(value)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must identify an S01-S30 shard`);
  }
  return value;
}

function namespacedVersion(value, name) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*\/v[1-9][0-9]*$/.test(value)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a namespaced /vN identifier`);
  }
  return value;
}

function privacySafeText(value, name) {
  oneLine(value, name);
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || value.includes('\\') || value.split('/').includes('..')) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must not contain a filesystem location`);
  }
  return value;
}

function isoTime(value, name) {
  oneLine(value, name);
  if (!Number.isFinite(Date.parse(value))) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be an ISO timestamp`);
  return value;
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function readLeaseRecord(lockDirectory) {
  const leasePath = path.join(lockDirectory, 'lease.json');
  const stat = fs.lstatSync(leasePath);
  if (!stat.isFile() || stat.isSymbolicLink()) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'global lease record is not a regular file');
  return validateLease(parseStrictJson(fs.readFileSync(leasePath, 'utf8')));
}

function authenticatedLease(stateDirectory, { attemptId, token, now }) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'lease update time is invalid');
  const lockDirectory = path.join(stateDirectory, 'global-lease.lock');
  const lockStat = fs.lstatSync(lockDirectory);
  if (!lockStat.isDirectory() || lockStat.isSymbolicLink()) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'global lease lock is not a real directory');
  const lease = readLeaseRecord(lockDirectory);
  if (lease.attemptId !== attemptId || lease.tokenHash !== sha256Hex(token)) {
    error('E_SECURITY_PROGRAM_LIVE_LEASE', 'lease update identity does not match');
  }
  if (Date.parse(lease.expiresAt) <= now.getTime()) {
    error('E_SECURITY_PROGRAM_LEASE_EXPIRED', 'expired lease requires reconciliation and cannot be revived');
  }
  return { lease, lockDirectory };
}

function withLeaseUpdateLock(stateDirectory, action) {
  const lockDirectory = path.join(stateDirectory, 'global-lease.lock');
  const updateLock = path.join(lockDirectory, 'update.lock');
  try { fs.mkdirSync(updateLock, { mode: 0o700 }); }
  catch (errorValue) {
    if (errorValue.code === 'EEXIST') error('E_SECURITY_PROGRAM_LIVE_LEASE', 'another authenticated lease update is active');
    throw errorValue;
  }
  fsyncDirectory(lockDirectory);
  try { return action(); }
  finally {
    try {
      fs.rmdirSync(updateLock);
      fsyncDirectory(lockDirectory);
    } catch { /* retained update lock makes subsequent mutation fail closed */ }
  }
}

function atomicReplaceLease(lockDirectory, lease, faultInjector) {
  validateLease(lease);
  const leasePath = path.join(lockDirectory, 'lease.json');
  const temporary = path.join(lockDirectory, `.lease.json.tmp-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
  const inject = (point) => { if (faultInjector) faultInjector(point, { attemptId: lease.attemptId, scanId: lease.scanId ?? null }); };
  inject('before-lease-temp-create');
  const descriptor = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try {
    fs.writeFileSync(descriptor, canonicalJson(lease), 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  inject('after-lease-temp-fsync');
  inject('before-lease-rename');
  fs.renameSync(temporary, leasePath);
  inject('after-lease-rename');
  fsyncDirectory(lockDirectory);
  inject('after-lease-directory-fsync');
}

function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (fs.lstatSync(directory).isSymbolicLink()) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'lease directory must not be a symlink');
  fs.chmodSync(directory, 0o700);
}

function ensureDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o755 });
  if (fs.lstatSync(directory).isSymbolicLink()) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'journal directory must not be a symlink');
}

function validatePersistedExportCapacity(value) {
  assertClosedSchema(value, {
    schema: EXPORT_CAPACITY_SCHEMA,
    required: [
      'maxEntries', 'maxBytes', 'minimumFreeBytes', 'maxBuildElapsedMs',
      'maxBuildPeakRssBytes', 'maxSnapshotElapsedMs', 'maxSnapshotPeakRssBytes',
    ],
    name: 'attempt export capacity',
  });
  for (const field of [
    'maxEntries', 'maxBytes', 'maxBuildElapsedMs', 'maxBuildPeakRssBytes',
    'maxSnapshotElapsedMs', 'maxSnapshotPeakRssBytes',
  ]) {
    if (!Number.isSafeInteger(value[field]) || value[field] < 1) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `attempt ${field} must be a positive safe integer`);
    }
  }
  if (!Number.isSafeInteger(value.minimumFreeBytes) || value.minimumFreeBytes < 0) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt minimumFreeBytes must be a non-negative safe integer');
  }
  return value;
}

function deriveTargetRouteAuthority(target, verifiedTarget) {
  if (target === null || typeof target !== 'object' || Array.isArray(target)
      || target.adapterVersion !== TARGET_ADAPTER_VERSION) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'verified target has an unsupported adapter version');
  }
  if (target.mode === 'deep') {
    if (['standardRoute', 'attemptId', 'budgetId', 'exportCapacity']
      .some((field) => Object.hasOwn(verifiedTarget, field))) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Deep target must not carry Standard route authority');
    }
    return Object.freeze({
      mode: 'Deep',
      adapterVersion: target.adapterVersion,
      targetForm: 'real-directory',
      targetKind: 'git_revision',
    });
  }
  if (target.mode !== 'standard') {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'verified target mode is unsupported');
  }
  const common = {
    mode: 'Standard',
    adapterVersion: target.adapterVersion,
    standardRoute: verifiedTarget.standardRoute,
    routeContractSha256: verifiedTarget.routeContractSha256,
    pluginVersion: verifiedTarget.pluginVersion,
  };
  if (verifiedTarget.standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS) {
    if (verifiedTarget.routeContractSha256
          !== PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS]
        || verifiedTarget.pluginVersion !== '0.1.24' || verifiedTarget.productionEligible !== true
        || Object.hasOwn(verifiedTarget, 'directorySnapshotDigest')
        || Object.hasOwn(verifiedTarget, 'exportTreeSha256')
        || Object.hasOwn(verifiedTarget, 'stableSnapshotSha256')
        || Object.hasOwn(verifiedTarget, 'attemptId')
        || Object.hasOwn(verifiedTarget, 'budgetId')) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'verified SDK exact-path route authority is malformed');
    }
    return Object.freeze({ ...common, targetForm: 'exact-paths-file', targetKind: 'git_revision' });
  }
  if (verifiedTarget.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT) {
    if (verifiedTarget.routeContractSha256
          !== PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT]
        || verifiedTarget.pluginVersion !== '0.1.24'
        || typeof verifiedTarget.directorySnapshotDigest !== 'string'
        || !/^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/.test(verifiedTarget.directorySnapshotDigest)
        || typeof verifiedTarget.exportTreeSha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(verifiedTarget.exportTreeSha256)
        || typeof verifiedTarget.stableSnapshotSha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(verifiedTarget.stableSnapshotSha256)
        || verifiedTarget.productionEligible !== true
        || typeof verifiedTarget.attemptId !== 'string' || !LOGICAL_TOKEN.test(verifiedTarget.attemptId)
        || typeof verifiedTarget.sourceFingerprint !== 'string'
        || typeof verifiedTarget.controlGenerationHash !== 'string'
        || !/^[0-9a-f]{64}$/.test(verifiedTarget.controlGenerationHash)
        || typeof verifiedTarget.budgetId !== 'string' || !LOGICAL_TOKEN.test(verifiedTarget.budgetId)
        || typeof verifiedTarget.budgetSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(verifiedTarget.budgetSha256)) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'verified Desktop export route authority is malformed');
    }
    validatePersistedExportCapacity(verifiedTarget.exportCapacity);
    return Object.freeze({
      ...common,
      targetForm: 'attested-directory-export',
      targetKind: 'directory_snapshot',
      attemptId: verifiedTarget.attemptId,
      sourceFingerprint: verifiedTarget.sourceFingerprint,
      controlGenerationHash: verifiedTarget.controlGenerationHash,
      budgetId: verifiedTarget.budgetId,
      budgetSha256: verifiedTarget.budgetSha256,
      exportCapacity: Object.freeze({ ...verifiedTarget.exportCapacity }),
      directorySnapshotDigest: verifiedTarget.directorySnapshotDigest,
      exportTreeSha256: verifiedTarget.exportTreeSha256,
      stableSnapshotSha256: verifiedTarget.stableSnapshotSha256,
      productionEligible: verifiedTarget.productionEligible,
    });
  }
  error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'verified Standard target route is unsupported');
}

function validateAttemptRouteShape(event) {
  if (event.adapterVersion !== TARGET_ADAPTER_VERSION) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt target adapter version is unsupported');
  }
  if (event.mode === 'Deep') {
    if (event.targetForm !== 'real-directory' || event.targetKind !== 'git_revision'
        || ROUTE_AUTHORITY_FIELDS.some((field) => Object.hasOwn(event, field))) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Deep attempt target route shape is invalid');
    }
    return;
  }
  if (event.mode !== 'Standard' || typeof event.standardRoute !== 'string'
      || event.routeContractSha256
        !== PINNED_STANDARD_ROUTE_CONTRACT_SHA256[event.standardRoute]
      || event.pluginVersion !== '0.1.24') {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Standard attempt route authority is invalid');
  }
  if (event.standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS) {
    if (event.targetForm !== 'exact-paths-file' || event.targetKind !== 'git_revision'
        || ['directorySnapshotDigest', 'exportTreeSha256', 'stableSnapshotSha256',
          'productionEligible', 'budgetId', 'budgetSha256', 'exportCapacity']
          .some((field) => Object.hasOwn(event, field))) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'SDK exact-path attempt route shape is invalid');
    }
    return;
  }
  if (event.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT) {
    if (event.targetForm !== 'attested-directory-export' || event.targetKind !== 'directory_snapshot'
        || typeof event.directorySnapshotDigest !== 'string'
        || !/^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/.test(event.directorySnapshotDigest)
        || typeof event.exportTreeSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(event.exportTreeSha256)
        || typeof event.stableSnapshotSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(event.stableSnapshotSha256)
        || event.productionEligible !== true
        || typeof event.budgetId !== 'string' || !LOGICAL_TOKEN.test(event.budgetId)
        || typeof event.budgetSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(event.budgetSha256)) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Desktop export attempt route shape is invalid');
    }
    validatePersistedExportCapacity(event.exportCapacity);
    return;
  }
  error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Standard attempt route is unsupported');
}

export function validateAttemptEvent(event) {
  assertClosedSchema(event, {
    schema: ATTEMPT_EVENT_SCHEMA,
    required: ATTEMPT_REQUIRED,
    optional: ATTEMPT_OPTIONAL,
    name: 'attempt event',
  });
  for (const key of ['eventId', 'attemptId', 'state', 'sectionId', 'mode', 'targetForm', 'targetKind', 'leaseOwner']) {
    logicalToken(event[key], key);
  }
  for (const key of ['coordinatorVersion', 'adapterVersion', 'scannerSchemaVersion', 'fingerprintVersion', 'controlSchemaSetVersion']) privacySafeText(event[key], key);
  if (!Number.isSafeInteger(event.sequence) || event.sequence < 0) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt sequence must be a non-negative safe integer');
  }
  if (!Object.hasOwn(ATTEMPT_TRANSITIONS, event.state)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `unknown attempt state ${event.state}`);
  }
  isoTime(event.recordedAt, 'recordedAt');
  if (!/^S(?:0[1-9]|[12][0-9]|30)$/.test(event.sectionId)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt sectionId must be S01 through S30');
  }
  objectId(event.epochRevision, 'epochRevision');
  let parsedFingerprint;
  try { parsedFingerprint = parseFingerprint(event.sourceFingerprint); }
  catch { error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'sourceFingerprint must use the authoritative v2 shape'); }
  if (parsedFingerprint.commit !== event.epochRevision) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'sourceFingerprint does not bind epochRevision');
  }
  sha256(event.inventorySha256, 'inventorySha256');
  namespacedVersion(event.shardGenerationId, 'shardGenerationId');
  shardId(event.shardId, 'shardId');
  if (!event.shardId.startsWith(`${event.sectionId}/`)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt shardId must belong to sectionId');
  }
  pathCount(event.shardPathCount, 'shardPathCount');
  sha256(event.shardPathListSha256, 'shardPathListSha256');
  sha256(event.targetArtifactSha256, 'targetArtifactSha256');
  pathCount(event.targetPathCount, 'targetPathCount');
  sha256(event.targetPathListSha256, 'targetPathListSha256');
  sha256(event.controlGenerationHash, 'controlGenerationHash');
  if (!['Standard', 'Deep'].includes(event.mode)) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt mode must be Standard or Deep');
  validateAttemptRouteShape(event);
  if (event.scanId !== undefined) logicalToken(event.scanId, 'scanId');
  if (event.supersedesAttemptId !== undefined) logicalToken(event.supersedesAttemptId, 'supersedesAttemptId');
  if (event.reasonCode !== undefined) logicalToken(event.reasonCode, 'reasonCode');
  if (['RUNNING', 'DETACHED', 'COMPLETION_REQUESTED', 'COMPLETION_UNKNOWN', 'SEALED', 'SOURCE_VERIFIED', 'PUBLICATION_PENDING', 'PUBLISHED', 'ADMITTED'].includes(event.state) && !event.scanId) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${event.state} requires a persisted scanId`);
  }
  if (['RESERVED', 'START_REQUESTED'].includes(event.state) && event.scanId !== undefined) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${event.state} must not claim a scanId`);
  }
  if (event.state === 'ORPHANED_START' && event.scanId !== undefined) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'ORPHANED_START must not claim a scanId');
  }
  return event;
}

function validateEpochAuthority(epoch) {
  assertClosedSchema(epoch, {
    schema: INVENTORY_SCHEMA,
    required: [
      'recordRole', 'revision', 'sourceCommittedAt', 'historicalCandidateCount', 'treePathCount',
      'authorizedCount', 'excludedCount', 'inventorySha256', 'exclusionPolicy',
      'exclusionPolicySha256', 'authorizedPaths', 'excludedPaths',
    ],
    optional: ['inventoryDecision'],
    name: 'attempt epoch authority',
  });
  if (epoch.recordRole !== 'authority') error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt epoch must be authority');
  objectId(epoch.revision, 'attempt epoch revision');
  sha256(epoch.inventorySha256, 'attempt epoch inventorySha256');
  if (!Array.isArray(epoch.authorizedPaths) || epoch.authorizedPaths.length === 0
      || epoch.authorizedCount !== epoch.authorizedPaths.length) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt epoch authorized paths are malformed');
  }
  const entries = epoch.authorizedPaths.map((entry) => ({
    ...entry,
    pathBytes: Buffer.from(entry.path, 'utf8'),
    objectType: entry.mode === '160000' ? 'commit' : 'blob',
  }));
  if (hashInventory(entries) !== epoch.inventorySha256) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt epoch inventory hash does not match its exact tuples');
  }
  return epoch;
}

function validateShardAuthority(shards, epoch) {
  assertClosedSchema(shards, {
    schema: SHARDS_SCHEMA,
    required: ['recordRole', 'revision', 'inventorySha256', 'generationId', 'shards'],
    name: 'attempt shard authority',
  });
  if (shards.recordRole !== 'authority' || shards.revision !== epoch.revision
      || shards.inventorySha256 !== epoch.inventorySha256 || !Array.isArray(shards.shards)
      || shards.shards.length === 0) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt shard generation does not bind the epoch authority');
  }
  namespacedVersion(shards.generationId, 'attempt shard generationId');
  return shards;
}

export function validateAttemptAuthority(event, { epoch, shards, target } = {}) {
  validateAttemptEvent(event);
  validateEpochAuthority(epoch);
  validateShardAuthority(shards, epoch);
  const shard = shards?.shards?.find((item) => item.id === event.shardId);
  if (!shard || shard.ownerSectionId !== event.sectionId) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt does not name an authoritative shard');
  }
  if (shard === null || typeof shard !== 'object' || Array.isArray(shard)
      || canonicalJson(Object.keys(shard).sort()) !== canonicalJson(
        ['id', 'ownerSectionId', 'pathCount', 'pathListSha256', 'paths'].sort(),
      )
      || !Array.isArray(shard.paths) || shard.paths.length === 0 || shard.pathCount !== shard.paths.length) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt authoritative shard is malformed');
  }
  const shardEntries = shard.paths.map((entry) => ({
    ...entry,
    pathBytes: Buffer.from(entry.path, 'utf8'),
    objectType: entry.mode === '160000' ? 'commit' : 'blob',
  }));
  if (hashInventory(shardEntries) !== shard.pathListSha256) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt shard path hash does not match its exact tuples');
  }
  const epochByPath = new Map(epoch.authorizedPaths.map((entry) => [entry.path, entry]));
  for (const entry of shard.paths) {
    if (canonicalJson(epochByPath.get(entry.path)) !== canonicalJson(entry)) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt shard contains a tuple outside the epoch authority');
    }
  }
  const verifiedTarget = verifyPreparedTarget(target);
  const routeAuthority = deriveTargetRouteAuthority(target, verifiedTarget);
  for (const field of ['mode', 'adapterVersion', 'targetForm', 'targetKind', ...ROUTE_AUTHORITY_FIELDS]) {
    const eventHas = Object.hasOwn(event, field);
    const authorityHas = Object.hasOwn(routeAuthority, field);
    if (eventHas !== authorityHas || (eventHas && (field === 'exportCapacity'
      ? canonicalJson(event[field]) !== canonicalJson(routeAuthority[field])
      : event[field] !== routeAuthority[field]))) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt target route authority does not match its opaque verified target');
    }
  }
  if (routeAuthority.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
      && ['attemptId', 'sourceFingerprint', 'controlGenerationHash']
        .some((field) => event[field] !== routeAuthority[field])) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Desktop attempt identity does not match its opaque verified target');
  }
  if (event.epochRevision !== epoch.revision || event.inventorySha256 !== epoch.inventorySha256
      || event.shardGenerationId !== shards.generationId
      || event.shardPathCount !== shard.pathCount
      || event.shardPathListSha256 !== shard.pathListSha256
      || event.targetArtifactSha256 !== verifiedTarget.artifactSha256
      || event.targetPathCount !== verifiedTarget.pathCount
      || event.targetPathListSha256 !== verifiedTarget.pathListSha256
      || verifiedTarget.pathCount !== shard.pathCount
      || verifiedTarget.pathListSha256 !== shard.pathListSha256
      || target.revision !== epoch.revision || target.shardId !== shard.id
      || target.pathCount !== shard.pathCount || target.pathListSha256 !== shard.pathListSha256
      || target.mode !== event.mode.toLowerCase()) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt target does not bind the authoritative epoch, shard generation, and exact path artifact');
  }
  return event;
}

export function buildReservedAttemptEvent(fields, authority) {
  if (fields === null || typeof fields !== 'object' || Array.isArray(fields)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt reservation fields must be an object');
  }
  const { epoch, shards, target } = authority ?? {};
  const verifiedTarget = verifyPreparedTarget(target);
  const routeAuthority = deriveTargetRouteAuthority(target, verifiedTarget);
  for (const field of ['mode', 'adapterVersion', 'targetForm', 'targetKind', ...ROUTE_AUTHORITY_FIELDS]) {
    if (Object.hasOwn(fields, field)) {
      if (!Object.hasOwn(routeAuthority, field)) {
        error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt reservation contains a caller-forged target route claim');
      }
      const matches = field === 'exportCapacity'
        ? canonicalJson(fields[field]) === canonicalJson(routeAuthority[field])
        : fields[field] === routeAuthority[field];
      if (!matches) {
        error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt reservation contains a caller-forged target route claim');
      }
    }
  }
  if (routeAuthority.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
      && ['attemptId', 'sourceFingerprint', 'controlGenerationHash']
        .some((field) => fields[field] !== routeAuthority[field])) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Desktop reservation attempt identity does not match its verified target');
  }
  const requestedShardId = fields.shardId;
  const shard = shards?.shards?.find((item) => item.id === requestedShardId);
  if (!shard) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt reservation does not name an authoritative shard');
  const event = {
    ...fields,
    schema: ATTEMPT_EVENT_SCHEMA,
    sequence: 0,
    state: 'RESERVED',
    epochRevision: epoch?.revision,
    inventorySha256: epoch?.inventorySha256,
    shardGenerationId: shards?.generationId,
    sectionId: shard.ownerSectionId,
    shardPathCount: shard.pathCount,
    shardPathListSha256: shard.pathListSha256,
    targetArtifactSha256: verifiedTarget.artifactSha256,
    targetPathCount: verifiedTarget.pathCount,
    targetPathListSha256: verifiedTarget.pathListSha256,
    ...routeAuthority,
  };
  for (const field of ROUTE_AUTHORITY_FIELDS) {
    if (!Object.hasOwn(routeAuthority, field)) delete event[field];
  }
  validateAttemptAuthority(event, authority);
  authorityValidatedReservations.add(event);
  return event;
}

function assertLegalTransition(previous, next) {
  if (next.attemptId !== previous.attemptId) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt identity changed during transition');
  if (next.sequence !== previous.sequence + 1) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt sequence is not contiguous');
  if (!ATTEMPT_TRANSITIONS[previous.state].has(next.state)) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `illegal attempt transition ${previous.state}->${next.state}`);
  }
  for (const key of [
    'epochRevision', 'sourceFingerprint', 'inventorySha256', 'shardGenerationId', 'sectionId', 'shardId',
    'shardPathCount', 'shardPathListSha256', 'targetArtifactSha256', 'targetPathCount',
    'targetPathListSha256', 'mode', 'targetForm', 'targetKind', ...ROUTE_AUTHORITY_FIELDS,
    'controlGenerationHash', 'leaseOwner',
    'coordinatorVersion', 'adapterVersion', 'scannerSchemaVersion', 'fingerprintVersion',
    'controlSchemaSetVersion', 'supersedesAttemptId',
  ]) {
    const nextHas = Object.hasOwn(next, key);
    const previousHas = Object.hasOwn(previous, key);
    const changed = nextHas !== previousHas || (nextHas && (key === 'exportCapacity'
      ? canonicalJson(next[key]) !== canonicalJson(previous[key])
      : next[key] !== previous[key]));
    if (changed) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${key} changed during attempt transition`);
  }
  if (previous.scanId && next.scanId !== previous.scanId) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'persisted scanId changed');
}

export function loadAttemptJournal(journalPath) {
  if (!fs.existsSync(journalPath)) return [];
  const text = fs.readFileSync(journalPath, 'utf8');
  if (text === '') return [];
  const journal = parseStrictJson(text);
  assertClosedSchema(journal, {
    schema: ATTEMPT_JOURNAL_SCHEMA,
    required: ['events'],
    name: 'attempt journal',
  });
  if (!Array.isArray(journal.events)) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt journal events must be an array');
  const events = journal.events.map((event) => validateAttemptEvent(event));
  const eventIds = new Set();
  const latest = new Map();
  for (const event of events) {
    if (eventIds.has(event.eventId)) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `duplicate attempt event ${event.eventId}`);
    eventIds.add(event.eventId);
    const previous = latest.get(event.attemptId);
    if (!previous) {
      if (event.sequence !== 0 || event.state !== 'RESERVED') error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt must begin at RESERVED sequence 0');
      if (event.supersedesAttemptId !== undefined) {
        if (event.supersedesAttemptId === event.attemptId) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt cannot supersede itself');
        const predecessor = latest.get(event.supersedesAttemptId);
        if (!predecessor) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'superseded attempt does not exist earlier in the journal');
        if (!['CANCELED', 'TERMINAL_FAILED'].includes(predecessor.state)) {
          error('E_SECURITY_PROGRAM_ORPHANED_START', 'held or uncertain attempts require explicit external reconciliation before replacement');
        }
      }
    } else {
      assertLegalTransition(previous, event);
    }
    latest.set(event.attemptId, event);
  }
  const active = [...latest.values()].filter((event) => ACTIVE_ATTEMPT_STATES.has(event.state));
  if (active.length > 1) error('E_SECURITY_PROGRAM_LIVE_LEASE', 'attempt journal contains more than one active attempt');
  return events;
}

export function latestAttemptEvents(events) {
  const latest = new Map();
  for (const event of events) latest.set(event.attemptId, event);
  return latest;
}

function durableReplaceJournal(journalPath, events) {
  ensureDirectory(path.dirname(journalPath));
  const temporary = path.join(
    path.dirname(journalPath),
    `.${path.basename(journalPath)}.tmp-${process.pid}-${crypto.randomBytes(8).toString('hex')}`,
  );
  const descriptor = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try {
    fs.writeFileSync(descriptor, canonicalJson({ schema: ATTEMPT_JOURNAL_SCHEMA, events }), 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, journalPath);
  fsyncDirectory(path.dirname(journalPath));
}

function withJournalLock(journalPath, action) {
  ensureDirectory(path.dirname(journalPath));
  const lockDirectory = `${journalPath}.lock`;
  try { fs.mkdirSync(lockDirectory, { mode: 0o700 }); }
  catch (errorValue) {
    if (errorValue.code === 'EEXIST') error('E_SECURITY_PROGRAM_LIVE_LEASE', 'attempt journal writer is already active');
    throw errorValue;
  }
  fsyncDirectory(path.dirname(journalPath));
  try { return action(); }
  finally {
    try {
      fs.rmdirSync(lockDirectory);
      fsyncDirectory(path.dirname(journalPath));
    } catch { /* retained lock makes any later writer fail closed */ }
  }
}

function appendAttemptEventInternal(journalPath, event, desktopStartAuthority) {
  validateAttemptEvent(event);
  return withJournalLock(journalPath, () => {
    const events = loadAttemptJournal(journalPath);
    const latest = latestAttemptEvents(events);
    if (events.some((item) => item.eventId === event.eventId)) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `duplicate attempt event ${event.eventId}`);
    }
    const previous = latest.get(event.attemptId);
    if (!previous) {
      if (event.sequence !== 0 || event.state !== 'RESERVED') error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'new attempt must begin at RESERVED sequence 0');
      if (!authorityValidatedReservations.has(event)) {
        error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'new attempt requires an in-process authority-verified reservation');
      }
      const held = [...latest.values()].find((item) => item.state === 'HOLD');
      if (held) error('E_SECURITY_PROGRAM_ORPHANED_START', 'an orphaned start remains permanently HOLD pending explicit external reconciliation');
      const active = [...latest.values()].find((item) => ACTIVE_ATTEMPT_STATES.has(item.state));
      if (active) error('E_SECURITY_PROGRAM_LIVE_LEASE', `attempt ${active.attemptId} is already active`, { attemptId: active.attemptId });
      if (event.supersedesAttemptId !== undefined) {
        if (event.supersedesAttemptId === event.attemptId) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt cannot supersede itself');
        const predecessor = latest.get(event.supersedesAttemptId);
        if (!predecessor) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'superseded attempt does not exist');
        if (!['CANCELED', 'TERMINAL_FAILED'].includes(predecessor.state)) {
          error('E_SECURITY_PROGRAM_ORPHANED_START', 'held or uncertain attempts require explicit external reconciliation before replacement');
        }
      }
    } else {
      assertLegalTransition(previous, event);
    }
    const desktopSourceVerifiedStart = event.state === 'START_REQUESTED'
      && event.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT;
    if (desktopSourceVerifiedStart) {
      if (desktopStartAuthority === undefined) {
        error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'Desktop start requires an atomic live source-verified append');
      }
      validateAttemptAuthority(previous, desktopStartAuthority);
    }
    durableReplaceJournal(journalPath, [...events, event]);
    if (desktopSourceVerifiedStart) {
      // A second snapshot closes the append window. If it fails, START_REQUESTED
      // remains durable but this operation throws before any scanner call; normal
      // orphan reconciliation then moves the attempt to permanent HOLD.
      validateAttemptAuthority(event, desktopStartAuthority);
    }
    return event;
  });
}

export function appendAttemptEvent(journalPath, event) {
  return appendAttemptEventInternal(journalPath, event, undefined);
}

function buildNextAttemptEvent(previous, state, {
  eventId,
  recordedAt = new Date().toISOString(),
  scanId = previous.scanId,
  reasonCode,
} = {}) {
  const event = {
    ...previous,
    eventId: oneLine(eventId, 'eventId'),
    sequence: previous.sequence + 1,
    state,
    recordedAt,
  };
  if (scanId === undefined) delete event.scanId;
  else event.scanId = scanId;
  if (reasonCode === undefined) delete event.reasonCode;
  else event.reasonCode = reasonCode;
  return validateAttemptEvent(event);
}

export function nextAttemptEvent(previous, state, fields = {}) {
  return buildNextAttemptEvent(previous, state, fields);
}

export function appendSourceVerifiedStartEvent(journalPath, previous, fields, authority) {
  if (previous?.state !== 'RESERVED') {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'source-verified start requires a RESERVED attempt');
  }
  const event = buildNextAttemptEvent(previous, 'START_REQUESTED', fields);
  return appendAttemptEventInternal(journalPath, event, authority);
}

export function validateLease(lease) {
  assertClosedSchema(lease, {
    schema: LEASE_SCHEMA,
    required: LEASE_REQUIRED,
    optional: LEASE_OPTIONAL,
    name: 'global lease',
  });
  for (const key of ['owner', 'hostId', 'attemptId', 'tokenHash']) logicalToken(lease[key], key);
  if (!Number.isSafeInteger(lease.processId) || lease.processId <= 0) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'lease processId is invalid');
  isoTime(lease.acquiredAt, 'acquiredAt');
  isoTime(lease.expiresAt, 'expiresAt');
  if (lease.scanId !== undefined) oneLine(lease.scanId, 'scanId');
  return lease;
}

function leaseSignal(lease, live) {
  const publicLease = { attemptId: lease.attemptId, scanId: lease.scanId ?? null, expiresAt: lease.expiresAt };
  if (live) error('E_SECURITY_PROGRAM_LIVE_LEASE', 'the security-program scan lease is live', publicLease);
  if (lease.scanId) {
    return { acquired: false, action: 'REJOIN_EXISTING', state: 'DETACHED', ...publicLease };
  }
  return { acquired: false, action: 'RECONCILE_ORPHANED_START', state: 'ORPHANED_START', disposition: 'HOLD', ...publicLease };
}

export function inspectGlobalLease(stateDirectory, {
  now = new Date(),
  currentHostId = os.hostname(),
  isProcessAlive = (processId) => {
    try { process.kill(processId, 0); return true; }
    catch (errorValue) { return errorValue?.code === 'EPERM'; }
  },
} = {}) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'lease inspection time is invalid');
  const lockDirectory = path.join(stateDirectory, 'global-lease.lock');
  if (!fs.existsSync(lockDirectory)) return { status: 'FREE' };
  const lockStat = fs.lstatSync(lockDirectory);
  if (!lockStat.isDirectory() || lockStat.isSymbolicLink()) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'global lease lock is not a real directory');
  }
  if (!fs.existsSync(path.join(lockDirectory, 'lease.json'))) {
    return { status: 'HOLD', action: 'RECONCILE_ORPHANED_START', state: 'ORPHANED_START', disposition: 'HOLD', attemptId: null, scanId: null };
  }
  const lease = readLeaseRecord(lockDirectory);
  const unexpired = Date.parse(lease.expiresAt) > now.getTime();
  const localProcessAlive = lease.hostId === currentHostId && isProcessAlive(lease.processId);
  return unexpired || localProcessAlive
    ? { status: 'LIVE', attemptId: lease.attemptId, scanId: lease.scanId ?? null, expiresAt: lease.expiresAt }
    : { status: 'STALE', ...leaseSignal(lease, false) };
}

export function acquireGlobalLease(stateDirectory, {
  owner,
  hostId = os.hostname(),
  processId = process.pid,
  attemptId,
  scanId,
  now = new Date(),
  ttlMs = 60_000,
  token = cryptoRandomToken(),
  isProcessAlive,
} = {}) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime()) || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'lease time or duration is invalid');
  }
  ensurePrivateDirectory(stateDirectory);
  const lockDirectory = path.join(stateDirectory, 'global-lease.lock');
  try {
    fs.mkdirSync(lockDirectory, { mode: 0o700 });
  } catch (errorValue) {
    if (errorValue.code !== 'EEXIST') throw errorValue;
    const inspection = inspectGlobalLease(stateDirectory, { now, currentHostId: hostId, isProcessAlive });
    if (inspection.status === 'LIVE') error('E_SECURITY_PROGRAM_LIVE_LEASE', 'the security-program scan lease is live', inspection);
    return inspection;
  }

  const acquiredAt = now.toISOString();
  const lease = validateLease({
    schema: LEASE_SCHEMA,
    owner: oneLine(owner, 'owner'),
    hostId: oneLine(hostId, 'hostId'),
    processId,
    attemptId: oneLine(attemptId, 'attemptId'),
    tokenHash: sha256Hex(token),
    acquiredAt,
    expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    ...(scanId === undefined ? {} : { scanId }),
  });
  try {
    const leasePath = path.join(lockDirectory, 'lease.json');
    const descriptor = fs.openSync(leasePath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
    try { fs.writeFileSync(descriptor, canonicalJson(lease)); fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
    fsyncDirectory(lockDirectory);
    fsyncDirectory(stateDirectory);
  } catch (errorValue) {
    try { fs.rmSync(lockDirectory, { recursive: true }); } catch { /* retain original error */ }
    throw errorValue;
  }
  const handle = {
    acquired: true,
    action: 'LEASE_ACQUIRED',
    attemptId,
    expiresAt: lease.expiresAt,
  };
  Object.defineProperty(handle, 'token', { value: token, enumerable: false });
  return handle;
}

export function attachLeaseScanId(stateDirectory, {
  attemptId,
  token,
  scanId,
  now = new Date(),
  faultInjector,
} = {}) {
  logicalToken(scanId, 'scanId');
  return withLeaseUpdateLock(stateDirectory, () => {
    const { lease, lockDirectory } = authenticatedLease(stateDirectory, { attemptId, token, now });
    if (lease.scanId !== undefined) {
      if (lease.scanId !== scanId) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'persisted lease scanId cannot be replaced');
      return { updated: false, action: 'SCAN_ID_ALREADY_ATTACHED', attemptId, scanId, expiresAt: lease.expiresAt };
    }
    const updated = validateLease({ ...lease, scanId });
    atomicReplaceLease(lockDirectory, updated, faultInjector);
    return { updated: true, action: 'SCAN_ID_ATTACHED', attemptId, scanId, expiresAt: updated.expiresAt };
  });
}

export function renewGlobalLease(stateDirectory, {
  attemptId,
  token,
  now = new Date(),
  ttlMs = 60_000,
  faultInjector,
} = {}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'lease renewal duration is invalid');
  return withLeaseUpdateLock(stateDirectory, () => {
    const { lease, lockDirectory } = authenticatedLease(stateDirectory, { attemptId, token, now });
    const expiresAt = new Date(now.getTime() + ttlMs);
    if (expiresAt.getTime() <= Date.parse(lease.expiresAt)) {
      error('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'lease renewal must extend the existing expiry');
    }
    const updated = validateLease({ ...lease, expiresAt: expiresAt.toISOString() });
    atomicReplaceLease(lockDirectory, updated, faultInjector);
    return {
      updated: true,
      action: 'LEASE_RENEWED',
      attemptId,
      scanId: updated.scanId ?? null,
      expiresAt: updated.expiresAt,
    };
  });
}

function cryptoRandomToken() {
  return crypto.randomBytes(32).toString('hex');
}

export function releaseGlobalLease(stateDirectory, { attemptId, token } = {}) {
  const lockDirectory = path.join(stateDirectory, 'global-lease.lock');
  const leasePath = path.join(lockDirectory, 'lease.json');
  const lease = readLeaseRecord(lockDirectory);
  if (lease.attemptId !== attemptId || lease.tokenHash !== sha256Hex(token)) {
    error('E_SECURITY_PROGRAM_LIVE_LEASE', 'lease release identity does not match');
  }
  fs.unlinkSync(leasePath);
  fsyncDirectory(lockDirectory);
  fs.rmdirSync(lockDirectory);
  fsyncDirectory(stateDirectory);
}
