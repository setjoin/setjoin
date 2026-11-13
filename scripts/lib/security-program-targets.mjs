import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  SecurityProgramError,
  assertClosedSchema,
  assertRepositoryRelativePath,
  canonicalJson,
  parseStrictJson,
  sha256Hex,
} from './security-program-json.mjs';
import { SHARDS_SCHEMA, hashInventory, parseGitTreeZ } from './security-program-inventory.mjs';
import { parseFingerprint } from './source-fingerprint.mjs';

export const TARGET_ADAPTER_VERSION = 'security-target-adapter/v1';
export const STANDARD_TARGET_ROUTES = Object.freeze({
  SDK_EXACT_PATHS: 'sdk-exact-paths',
  DESKTOP_ATTESTED_EXPORT: 'desktop-attested-export',
});
export const DESKTOP_EXPORT_ATTESTATION_SCHEMA = 'setjoin.security-program.desktop-export-attestation/v1';
export const DESKTOP_EXPORT_PREPARATION_SCHEMA = 'setjoin.security-program.desktop-export-preparation/v1';
export const DESKTOP_ATTEMPT_BINDING_SCHEMA = 'setjoin.security-program.desktop-attempt-binding/v1';
export const EXPORT_CAPACITY_SCHEMA = 'setjoin.security-program.export-capacity/v1';
export const MACOS_READ_ONLY_BACKEND = 'macos-readonly-disk-image/v1';

// Re-adjudicated pin (ER2 discipline: re-adjudicate, then re-pin — never a silent literal bump).
// Adjudicated: 2026-09-20. Authority: owner-authorized re-adjudication of the codex-security
// plugin pin 0.1.22 -> 0.1.24 (named prerequisite from nightly-15; receipts follow
// docs/verification/deep-security-remediation-inherited-receipts.json conventions; full
// adjudication table and verification outputs: docs/verification/2026-09-20-codex-security-repin.md).
// What changed: the environment now carries only
// ~/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.24 (the 0.1.22 tree is pruned
// from every cache root), so the per-file 0.1.22 -> 0.1.24 diff is unrecoverable; adjudication
// was therefore structural on 0.1.24's content: manifest name still 'codex-security' (version
// 0.1.24); route-contract trees complete and populated (74 files: .codex-plugin 1, mcp 4,
// references 12, schemas 13, scripts 40, skills/security-scan 4); helper generate_rank_input.py
// present; scan-manifest/coverage/findings schemas and desktop-scan references present; no
// symlinks or special entries; every route file a single-link regular file. ACCEPTED as the new
// pin. Old (0.1.22) contract hashes, superseded by this re-adjudication:
//   sdk-exact-paths:         0dbc3fda61c5ac8fd77487d840deb1231bff628b032a2c8595fe31e01f3e1543
//   desktop-attested-export: eeb2692420161d78c175110045a08a6aca1b605caf02046bdd61bdcc11098a80
const PINNED_PLUGIN_VERSION = '0.1.24';
const PLUGIN_SNAPSHOT_DIGEST = /^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/;
export const PINNED_STANDARD_ROUTE_CONTRACT_SHA256 = Object.freeze({
  [STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS]: '54047eaceaf652a12e369bd1b8fc240a340e6bb9558508cf2d670e81f2badb1a',
  [STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT]: '89e304875c4d7bc1bd4038c819eeef8a5509e8ee7533e60ec6a899619895b438',
});

const GIT_OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SAFE_SHARD_ID = /^S(?:0[1-9]|[12][0-9]|30)\/P[0-9]{2,}$/;
const LOGICAL_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIRECTORY_MODE = 0o700;
const SEALED_DIRECTORY_MODE = 0o500;
const SEALED_FILE_MODE = 0o400;
const SEALED_EXECUTABLE_MODE = 0o500;
const preparedTargetAuthorities = new WeakMap();
const issuedProductionBackends = new WeakSet();
const PREPARATION_PHASES = Object.freeze([
  'CONSTRUCTION_REQUESTED', 'EXPORT_SEALED', 'READONLY_SEAL_REQUESTED',
  'READONLY_TARGET_READY', 'ATTESTATION_PUBLISHED',
]);

function fail(code, message, details) {
  throw new SecurityProgramError(code, message, details);
}

function buffer(value, label) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  fail('E_SECURITY_TARGET_RUNNER_INVALID', `${label} must be a string or Buffer`);
}

function outputText(value, label) {
  const bytes = buffer(value, label);
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) {
    fail('E_SECURITY_TARGET_RUNNER_INVALID', `${label} is not strict UTF-8`);
  }
  return text;
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function realDirectory(directory, label) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) {
    fail('E_SECURITY_TARGET_PATH_INVALID', `${label} must be an absolute path`);
  }
  const resolved = path.resolve(directory);
  let metadata;
  let real;
  try {
    metadata = fs.lstatSync(resolved);
    real = fs.realpathSync.native(resolved);
  } catch {
    fail('E_SECURITY_TARGET_PATH_INVALID', `${label} must exist`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('E_SECURITY_TARGET_PATH_INVALID', `${label} must be a real, non-symlink directory`);
  }
  return real;
}

function assertNoSymlinkComponents(root, relativePath, { directory = false } = {}) {
  if (relativePath !== '.') assertRepositoryRelativePath(relativePath, 'target path');
  const pieces = relativePath === '.' ? [] : relativePath.split('/');
  let current = root;
  for (const piece of pieces) {
    current = path.join(current, piece);
    let metadata;
    try { metadata = fs.lstatSync(current); }
    catch { fail('E_SECURITY_TARGET_PATH_INVALID', 'target path is missing from the materialization'); }
    if (metadata.isSymbolicLink()) {
      fail('E_SECURITY_TARGET_SYMLINK', 'target path contains a symbolic link');
    }
  }
  const resolved = path.resolve(root, ...pieces);
  if (!isWithin(root, resolved)) fail('E_SECURITY_TARGET_PATH_ESCAPE', 'target path escapes the materialization');
  let finalMetadata;
  try { finalMetadata = fs.lstatSync(resolved); }
  catch { fail('E_SECURITY_TARGET_PATH_INVALID', 'target path is missing from the materialization'); }
  if (directory ? !finalMetadata.isDirectory() : !finalMetadata.isFile()) {
    fail('E_SECURITY_TARGET_PATH_INVALID', `target path must be a real ${directory ? 'directory' : 'file'}`);
  }
  return { absolutePath: resolved, metadata: finalMetadata };
}

async function gitCall(gitRunner, repoRoot, args, label) {
  if (typeof gitRunner !== 'function') {
    fail('E_SECURITY_TARGET_RUNNER_REQUIRED', 'an explicit Git runner is required');
  }
  let result;
  try { result = await gitRunner({ repoRoot, args: [...args] }); }
  catch (error) {
    fail('E_SECURITY_TARGET_GIT_FAILED', `${label} failed`, { cause: error?.code ?? error?.name ?? 'ERROR' });
  }
  if (result === null || typeof result !== 'object' || Array.isArray(result)
      || !Number.isInteger(result.status) || !Object.hasOwn(result, 'stdout')) {
    fail('E_SECURITY_TARGET_RUNNER_INVALID', `${label} returned an invalid result`);
  }
  return { status: result.status, stdout: buffer(result.stdout, `${label} stdout`) };
}

function gitCallSync(gitRunner, repoRoot, args, label) {
  if (typeof gitRunner !== 'function') {
    fail('E_SECURITY_TARGET_RUNNER_REQUIRED', 'Deep target verification requires a replayable synchronous Git runner');
  }
  let result;
  try { result = gitRunner({ repoRoot, args: [...args] }); }
  catch (error) {
    fail('E_SECURITY_TARGET_GIT_FAILED', `${label} failed`, { cause: error?.code ?? error?.name ?? 'ERROR' });
  }
  if (result !== null && typeof result === 'object' && typeof result.then === 'function') {
    fail('E_SECURITY_TARGET_RUNNER_REQUIRED', 'Deep target Git runner must be synchronously replayable');
  }
  if (result === null || typeof result !== 'object' || Array.isArray(result)
      || !Number.isInteger(result.status) || !Object.hasOwn(result, 'stdout')) {
    fail('E_SECURITY_TARGET_RUNNER_INVALID', `${label} returned an invalid result`);
  }
  return { status: result.status, stdout: buffer(result.stdout, `${label} stdout`) };
}

function publicTuple(entry) {
  return { path: entry.path, objectId: entry.objectId, mode: entry.mode, kind: entry.kind };
}

function tupleMap(entries, label) {
  const result = new Map();
  for (const entry of entries) {
    assertRepositoryRelativePath(entry.path, `${label} path`);
    if (result.has(entry.path)) fail('E_SECURITY_TARGET_TUPLE_MISMATCH', `${label} contains a duplicate path`);
    result.set(entry.path, publicTuple(entry));
  }
  return result;
}

function assertExactTuples(expectedEntries, actualEntries, label) {
  const expected = [...tupleMap(expectedEntries, `${label} expected`).values()]
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const actual = [...tupleMap(actualEntries, `${label} actual`).values()]
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail('E_SECURITY_TARGET_TUPLE_MISMATCH', `${label} does not exactly match the bound path/object/mode/kind tuples`, {
      expectedCount: expected.length,
      actualCount: actual.length,
    });
  }
}

function statIdentity(metadata) {
  return [metadata.dev, metadata.ino, metadata.size, metadata.mtimeMs, metadata.mode].join(':');
}

function bigintStatIdentity(metadata) {
  return [metadata.dev, metadata.ino, metadata.size, metadata.mtimeNs, metadata.ctimeNs, metadata.mode, metadata.nlink].join(':');
}

function readStableRegularFile(filename, label, { privateFile = false, maximumBytes = 64 * 1024 * 1024 } = {}) {
  let pathBefore;
  try { pathBefore = fs.lstatSync(filename, { bigint: true }); }
  catch (error) { fail('E_SECURITY_TARGET_STATE_INVALID', `${label} is missing`, { cause: error?.code ?? 'ERROR' }); }
  if (!pathBefore.isFile() || pathBefore.isSymbolicLink() || pathBefore.nlink !== 1n) {
    fail('E_SECURITY_TARGET_LINK_UNSAFE', `${label} must be a single-link regular file`);
  }
  if (pathBefore.size > BigInt(maximumBytes)) fail('E_SECURITY_TARGET_STATE_INVALID', `${label} exceeds its size limit`);
  if (privateFile && ((Number(pathBefore.mode) & 0o777) !== PRIVATE_FILE_MODE
      || (typeof process.getuid === 'function' && pathBefore.uid !== BigInt(process.getuid())))) {
    fail('E_SECURITY_TARGET_STATE_MODE', `${label} must be caller-owned mode 0600`);
  }
  let descriptor;
  try { descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0)); }
  catch (error) { fail('E_SECURITY_TARGET_STATE_INVALID', `${label} could not be opened safely`, { cause: error?.code ?? 'ERROR' }); }
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (bigintStatIdentity(opened) !== bigintStatIdentity(pathBefore)) fail('E_SECURITY_TARGET_RACE', `${label} changed while opening`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(filename, { bigint: true });
    if (bigintStatIdentity(after) !== bigintStatIdentity(opened)
        || bigintStatIdentity(pathAfter) !== bigintStatIdentity(after)) {
      fail('E_SECURITY_TARGET_RACE', `${label} changed while reading`);
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function stableFileSha256(filename, label) {
  return sha256Hex(readStableRegularFile(filename, label));
}

function validateExportCapacity(value) {
  assertClosedSchema(value, {
    schema: EXPORT_CAPACITY_SCHEMA,
    required: [
      'maxEntries', 'maxBytes', 'minimumFreeBytes', 'maxBuildElapsedMs',
      'maxBuildPeakRssBytes', 'maxSnapshotElapsedMs', 'maxSnapshotPeakRssBytes',
    ],
    name: 'Desktop export capacity',
  });
  for (const field of [
    'maxEntries', 'maxBytes', 'maxBuildElapsedMs', 'maxBuildPeakRssBytes',
    'maxSnapshotElapsedMs', 'maxSnapshotPeakRssBytes',
  ]) {
    if (!Number.isSafeInteger(value[field]) || value[field] < 1) {
      fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', `${field} must be a positive safe integer`);
    }
  }
  if (!Number.isSafeInteger(value.minimumFreeBytes) || value.minimumFreeBytes < 0) {
    fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', 'minimumFreeBytes must be a non-negative safe integer');
  }
  return Object.freeze({
    schema: EXPORT_CAPACITY_SCHEMA,
    maxEntries: value.maxEntries,
    maxBytes: value.maxBytes,
    minimumFreeBytes: value.minimumFreeBytes,
    maxBuildElapsedMs: value.maxBuildElapsedMs,
    maxBuildPeakRssBytes: value.maxBuildPeakRssBytes,
    maxSnapshotElapsedMs: value.maxSnapshotElapsedMs,
    maxSnapshotPeakRssBytes: value.maxSnapshotPeakRssBytes,
  });
}

function validateAttemptBinding(value, revision) {
  assertClosedSchema(value, {
    schema: DESKTOP_ATTEMPT_BINDING_SCHEMA,
    required: [
      'attemptId', 'sourceFingerprint', 'controlGenerationHash', 'budgetId',
      'budgetSha256', 'exportCapacity',
    ],
    name: 'Desktop export attempt binding',
  });
  for (const field of ['attemptId', 'budgetId']) {
    if (typeof value[field] !== 'string' || !LOGICAL_TOKEN.test(value[field])) {
      fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', `${field} must be a privacy-safe logical token`);
    }
  }
  for (const field of ['controlGenerationHash', 'budgetSha256']) {
    if (typeof value[field] !== 'string' || !/^[0-9a-f]{64}$/.test(value[field])) {
      fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', `${field} must be a lowercase SHA-256`);
    }
  }
  let fingerprint;
  try { fingerprint = parseFingerprint(value.sourceFingerprint); }
  catch { fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', 'sourceFingerprint is malformed'); }
  if (fingerprint.commit !== revision) {
    fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', 'sourceFingerprint does not bind the export revision');
  }
  return Object.freeze({
    schema: DESKTOP_ATTEMPT_BINDING_SCHEMA,
    attemptId: value.attemptId,
    sourceFingerprint: value.sourceFingerprint,
    controlGenerationHash: value.controlGenerationHash,
    budgetId: value.budgetId,
    budgetSha256: value.budgetSha256,
    exportCapacity: validateExportCapacity(value.exportCapacity),
  });
}

async function verifyBoundSourceFingerprint(sourceFingerprintVerifier, repoRoot, attemptBinding) {
  if (typeof sourceFingerprintVerifier !== 'function') {
    fail('E_SECURITY_TARGET_FINGERPRINT_REQUIRED', 'an explicit source fingerprint verifier is required');
  }
  let result;
  try {
    result = await sourceFingerprintVerifier({ repoRoot });
  } catch (error) {
    fail('E_SECURITY_TARGET_FINGERPRINT_MISMATCH', 'source fingerprint verification failed', {
      cause: error?.code ?? error?.name ?? 'ERROR',
    });
  }
  const actual = typeof result === 'string' ? result : result?.sourceFingerprint;
  let parsed;
  try { parsed = parseFingerprint(actual); }
  catch { fail('E_SECURITY_TARGET_FINGERPRINT_MISMATCH', 'source fingerprint verifier returned an invalid value'); }
  if (parsed.value !== attemptBinding.sourceFingerprint) {
    fail('E_SECURITY_TARGET_FINGERPRINT_MISMATCH', 'source fingerprint no longer matches the durable attempt binding');
  }
}

function verifyBoundSourceFingerprintSync(sourceFingerprintRevalidator, repoRoot, attemptBinding) {
  if (typeof sourceFingerprintRevalidator !== 'function') {
    fail('E_SECURITY_TARGET_FINGERPRINT_REQUIRED', 'a synchronous live source fingerprint revalidator is required');
  }
  let result;
  try {
    result = sourceFingerprintRevalidator({ repoRoot });
  } catch (error) {
    fail('E_SECURITY_TARGET_FINGERPRINT_MISMATCH', 'live source fingerprint revalidation failed', {
      cause: error?.code ?? error?.name ?? 'ERROR',
    });
  }
  if (result !== null && typeof result === 'object' && typeof result.then === 'function') {
    fail('E_SECURITY_TARGET_FINGERPRINT_REQUIRED', 'live source fingerprint revalidator must be synchronous');
  }
  const actual = typeof result === 'string' ? result : result?.sourceFingerprint;
  let parsed;
  try { parsed = parseFingerprint(actual); }
  catch { fail('E_SECURITY_TARGET_FINGERPRINT_MISMATCH', 'live source fingerprint revalidator returned an invalid value'); }
  if (parsed.value !== attemptBinding.sourceFingerprint) {
    fail('E_SECURITY_TARGET_FINGERPRINT_MISMATCH', 'live source fingerprint no longer matches the durable attempt binding');
  }
}

function holdCapacity(code, message, details) {
  fail(code, message, { disposition: 'HOLD', ...details });
}

function projectionCount(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', `${label} must be a non-negative safe integer`);
  }
  return value;
}

function projectionBigInt(value, label) {
  try {
    const parsed = typeof value === 'bigint' ? value
      : (typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value) ? BigInt(value) : null);
    if (parsed === null || parsed < 0n) throw new Error('invalid');
    return parsed;
  } catch {
    fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', `${label} must be a non-negative integer byte count`);
  }
}

export function projectExportCapacity({ fileCount, directoryCount, exportBytes, volumes }, capacityInput) {
  const capacity = validateExportCapacity(capacityInput);
  projectionCount(fileCount, 'projection fileCount');
  projectionCount(directoryCount, 'projection directoryCount');
  projectionCount(exportBytes, 'projection exportBytes');
  if (!Array.isArray(volumes) || volumes.length === 0) {
    fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', 'projection volumes must be non-empty');
  }
  const expectedEntryCount = fileCount + directoryCount;
  if (!Number.isSafeInteger(expectedEntryCount)) {
    fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', 'projection entry count exceeds safe integer precision');
  }
  const projectedVolumes = volumes.map((volume, index) => {
    if (volume === null || typeof volume !== 'object' || Array.isArray(volume)
        || canonicalJson(Object.keys(volume).sort()) !== canonicalJson(['availableBytes', 'copies', 'volumeId'].sort())
        || typeof volume.volumeId !== 'string' || !LOGICAL_TOKEN.test(volume.volumeId)) {
      fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', `projection volume ${index} is malformed`);
    }
    projectionCount(volume.copies, `projection volume ${index} copies`);
    if (volume.copies < 1) fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', 'projection volume copies must be positive');
    const availableBytes = projectionBigInt(volume.availableBytes, `projection volume ${index} availableBytes`);
    const requiredBytes = BigInt(capacity.minimumFreeBytes)
      + (BigInt(exportBytes) * BigInt(volume.copies));
    return Object.freeze({
      volumeId: volume.volumeId,
      copies: volume.copies,
      availableBytes: String(availableBytes),
      requiredBytes: String(requiredBytes),
      spaceLimitPass: availableBytes >= requiredBytes,
    });
  });
  return Object.freeze({
    fileCount,
    directoryCount,
    exportBytes,
    expectedEntryCount,
    entryLimitPass: expectedEntryCount <= capacity.maxEntries,
    byteLimitPass: exportBytes <= capacity.maxBytes,
    volumes: Object.freeze(projectedVolumes),
    capacity: Object.freeze(capacity),
  });
}

function exportStorageVolumes(storageRoots) {
  const volumes = new Map();
  for (const root of storageRoots) {
    const deviceId = String(fs.statSync(root, { bigint: true }).dev);
    const prior = volumes.get(deviceId) ?? { copies: 0, root };
    prior.copies += 1;
    volumes.set(deviceId, prior);
  }
  const projectedVolumes = [];
  for (const [volumeId, volume] of volumes) {
    const filesystem = fs.statfsSync(volume.root, { bigint: true });
    projectedVolumes.push({
      volumeId,
      copies: volume.copies,
      availableBytes: filesystem.bavail * filesystem.bsize,
    });
  }
  return projectedVolumes;
}

function preflightExportCapacity(storageRoots, materialization, entries, capacity) {
  const directories = new Set();
  for (const entry of entries) {
    const pieces = entry.path.split('/');
    for (let index = 1; index < pieces.length; index += 1) directories.add(pieces.slice(0, index).join('/'));
  }
  let expectedBytes = 0;
  for (const entry of entries) {
    const metadata = fs.lstatSync(path.join(materialization.repoRoot, ...entry.path.split('/')));
    expectedBytes += metadata.size;
    if (!Number.isSafeInteger(expectedBytes)) holdCapacity(
      'E_SECURITY_TARGET_HOLD_CAPACITY_BYTES', 'export byte projection exceeds safe integer precision',
    );
  }
  const projectedVolumes = exportStorageVolumes(storageRoots);
  const projection = projectExportCapacity({
    fileCount: entries.length,
    directoryCount: directories.size,
    exportBytes: expectedBytes,
    volumes: projectedVolumes,
  }, capacity);
  if (!projection.entryLimitPass) {
    holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_ENTRIES', 'export entry capacity would be exceeded', {
      limit: capacity.maxEntries, actual: projection.expectedEntryCount,
    });
  }
  if (!projection.byteLimitPass) {
    holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_BYTES', 'export byte capacity would be exceeded', {
      limit: capacity.maxBytes, actual: projection.exportBytes,
    });
  }
  for (const volume of projection.volumes) {
    if (!volume.spaceLimitPass) {
      holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_SPACE', 'export free-space reserve is insufficient', {
        requiredBytes: volume.requiredBytes, availableBytes: volume.availableBytes, copies: volume.copies,
      });
    }
  }
  return expectedBytes;
}

function enforceMeasuredCapacity(capacity, metrics) {
  const retainedEntries = metrics.exportFileCount + metrics.exportDirectoryCount;
  if (retainedEntries > capacity.maxEntries) {
    holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_ENTRIES', 'retained export entry count exceeds capacity', {
      limit: capacity.maxEntries, actual: retainedEntries,
    });
  }
  if (metrics.exportBytes > capacity.maxBytes) {
    holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_BYTES', 'retained export byte count exceeds capacity', {
      limit: capacity.maxBytes, actual: metrics.exportBytes,
    });
  }
  for (const [field, limitField, code] of [
    ['buildElapsedMs', 'maxBuildElapsedMs', 'E_SECURITY_TARGET_HOLD_BUILD_ELAPSED'],
    ['buildPeakRssBytes', 'maxBuildPeakRssBytes', 'E_SECURITY_TARGET_HOLD_BUILD_RSS'],
    ['snapshotElapsedMs', 'maxSnapshotElapsedMs', 'E_SECURITY_TARGET_HOLD_SNAPSHOT_ELAPSED'],
    ['snapshotPeakRssBytes', 'maxSnapshotPeakRssBytes', 'E_SECURITY_TARGET_HOLD_SNAPSHOT_RSS'],
  ]) {
    if (metrics[field] > capacity[limitField]) {
      holdCapacity(code, `${field} exceeded its immutable export capacity`, {
        limit: capacity[limitField], actual: metrics[field],
      });
    }
  }
}

export function enforceMeasuredExportCapacity(capacityInput, metrics) {
  const capacity = validateExportCapacity(capacityInput);
  if (metrics === null || typeof metrics !== 'object' || Array.isArray(metrics)) {
    fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', 'measured export metrics must be an object');
  }
  for (const field of [
    'exportFileCount', 'exportDirectoryCount', 'exportBytes', 'buildElapsedMs',
    'buildPeakRssBytes', 'snapshotElapsedMs', 'snapshotPeakRssBytes',
  ]) {
    if (!Number.isFinite(metrics[field]) || metrics[field] < 0) {
      fail('E_SECURITY_TARGET_ATTEMPT_BINDING_INVALID', `measured export ${field} is invalid`);
    }
  }
  enforceMeasuredCapacity(capacity, metrics);
  return Object.freeze({ disposition: 'PASS' });
}

function validatePrivateDirectory(directory, label, forbiddenRoots = []) {
  const real = realDirectory(directory, label);
  const metadata = fs.statSync(real);
  if ((metadata.mode & 0o777) !== PRIVATE_DIRECTORY_MODE
      || (typeof process.getuid === 'function' && metadata.uid !== process.getuid())) {
    fail('E_SECURITY_TARGET_STATE_MODE', `${label} must be caller-owned mode 0700`);
  }
  for (const forbidden of forbiddenRoots) {
    if (isWithin(forbidden, real) || isWithin(real, forbidden)) {
      fail('E_SECURITY_TARGET_STATE_LOCATION', `${label} must be external and disjoint`);
    }
  }
  return real;
}

function collectRouteFiles(pluginRoot) {
  const selected = new Set(['.codex-plugin/plugin.json']);
  const collect = (relativeDirectory, accept) => {
    const absoluteDirectory = path.join(pluginRoot, ...relativeDirectory.split('/'));
    const visit = (absolute, relative) => {
      for (const name of fs.readdirSync(absolute).sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))) {
        if (name === '__pycache__') continue;
        const child = path.join(absolute, name);
        const childRelative = `${relative}/${name}`;
        const metadata = fs.lstatSync(child);
        if (metadata.isSymbolicLink()) fail('E_SECURITY_TARGET_PLUGIN_INVALID', 'route-contract tree contains a symbolic link');
        if (metadata.isDirectory()) visit(child, childRelative);
        else if (!metadata.isFile()) fail('E_SECURITY_TARGET_PLUGIN_INVALID', 'route-contract tree contains a special entry');
        else if (accept(childRelative)) selected.add(childRelative);
      }
    };
    visit(absoluteDirectory, relativeDirectory);
  };
  collect('scripts', (relativePath) => relativePath.endsWith('.py') && !relativePath.endsWith('.pyc'));
  collect('mcp', () => true);
  collect('schemas', (relativePath) => relativePath.endsWith('.json'));
  collect('references', () => true);
  collect('skills/security-scan', () => true);
  return [...selected].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

function readPinnedPluginContract(pluginRoot, standardRoute) {
  if (!Object.values(STANDARD_TARGET_ROUTES).includes(standardRoute)) {
    fail('E_SECURITY_TARGET_ROUTE_INVALID', 'Standard target route is unsupported');
  }
  const root = realDirectory(pluginRoot, 'pinned Codex Security plugin root');
  let manifest;
  try { manifest = parseStrictJson(readStableRegularFile(path.join(root, '.codex-plugin/plugin.json'), 'plugin manifest').toString('utf8')); }
  catch (error) {
    if (error instanceof SecurityProgramError) throw error;
    fail('E_SECURITY_TARGET_PLUGIN_INVALID', 'pinned plugin manifest is invalid');
  }
  if (manifest?.name !== 'codex-security' || manifest?.version !== PINNED_PLUGIN_VERSION) {
    fail('E_SECURITY_TARGET_PLUGIN_DRIFT', `Codex Security plugin must be exactly ${PINNED_PLUGIN_VERSION}`);
  }
  const files = collectRouteFiles(root).map((relativePath) => {
    assertRepositoryRelativePath(relativePath, 'route-contract file');
    const filename = path.join(root, ...relativePath.split('/'));
    if (!isWithin(root, filename)) fail('E_SECURITY_TARGET_PATH_ESCAPE', 'route-contract file escaped plugin root');
    const bytes = readStableRegularFile(filename, `route-contract ${relativePath}`);
    return { path: relativePath, size: bytes.length, sha256: sha256Hex(bytes) };
  });
  const contract = {
    schema: 'setjoin.security-program.standard-route-contract/v1',
    standardRoute,
    plugin: { name: 'codex-security', version: PINNED_PLUGIN_VERSION },
    targetKind: standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS ? 'git_revision' : 'directory_snapshot',
    scopeTransport: standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS
      ? 'CODEX_SECURITY_TARGET_PATHS_FILE' : 'sealed-read-only-export',
    files,
  };
  const routeContractSha256 = sha256Hex(canonicalJson(contract));
  if (routeContractSha256 !== PINNED_STANDARD_ROUTE_CONTRACT_SHA256[standardRoute]) {
    fail('E_SECURITY_TARGET_ROUTE_DRIFT', 'pinned Codex Security route contract changed', {
      expected: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[standardRoute], actual: routeContractSha256,
    });
  }
  return Object.freeze({
    pluginRoot: root,
    pluginVersion: PINNED_PLUGIN_VERSION,
    routeContractSha256,
  });
}

export function verifyStandardRouteContract({ pluginRoot, standardRoute }) {
  return readPinnedPluginContract(pluginRoot, standardRoute);
}

async function hashMaterializedBlob(filename, expected) {
  if (!['file', 'executable'].includes(expected.kind) || !['100644', '100755'].includes(expected.mode)) {
    fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'exact scanner targets must be regular files or executables', {
      pathSha256: sha256Hex(expected.path), kind: expected.kind,
    });
  }
  const { metadata: before } = assertNoSymlinkComponents(path.dirname(filename), path.basename(filename));
  const executable = (before.mode & 0o111) !== 0;
  if ((expected.mode === '100755') !== executable) {
    fail('E_SECURITY_TARGET_MODE_MISMATCH', 'materialized executable mode does not match the bound Git tuple', {
      pathSha256: sha256Hex(expected.path),
    });
  }
  const algorithm = expected.objectId.length === 40 ? 'sha1' : 'sha256';
  const hash = crypto.createHash(algorithm);
  hash.update(Buffer.from(`blob ${before.size}\0`, 'utf8'));
  const handle = await fs.promises.open(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || statIdentity(opened) !== statIdentity(before)) {
      fail('E_SECURITY_TARGET_RACE', 'target changed while it was opened');
    }
    for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk);
    const after = await handle.stat();
    if (statIdentity(after) !== statIdentity(opened)) fail('E_SECURITY_TARGET_RACE', 'target changed while it was hashed');
  } finally {
    await handle.close();
  }
  const afterPath = fs.lstatSync(filename);
  if (statIdentity(afterPath) !== statIdentity(before) || afterPath.isSymbolicLink()) {
    fail('E_SECURITY_TARGET_RACE', 'target path changed while it was hashed');
  }
  if (hash.digest('hex') !== expected.objectId) {
    fail('E_SECURITY_TARGET_CONTENT_MISMATCH', 'materialized file content does not match the bound Git object', {
      pathSha256: sha256Hex(expected.path),
    });
  }
}

function hashMaterializedBlobSync(filename, expected) {
  if (!['file', 'executable'].includes(expected.kind) || !['100644', '100755'].includes(expected.mode)) {
    fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'exact scanner targets must be regular files or executables', {
      pathSha256: sha256Hex(expected.path), kind: expected.kind,
    });
  }
  const { metadata: before } = assertNoSymlinkComponents(path.dirname(filename), path.basename(filename));
  const executable = (before.mode & 0o111) !== 0;
  if ((expected.mode === '100755') !== executable) {
    fail('E_SECURITY_TARGET_MODE_MISMATCH', 'materialized executable mode does not match the bound Git tuple', {
      pathSha256: sha256Hex(expected.path),
    });
  }
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || statIdentity(opened) !== statIdentity(before)) {
      fail('E_SECURITY_TARGET_RACE', 'target changed while it was opened');
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const afterPath = fs.lstatSync(filename);
    if (statIdentity(after) !== statIdentity(opened)
        || statIdentity(afterPath) !== statIdentity(opened) || afterPath.isSymbolicLink()) {
      fail('E_SECURITY_TARGET_RACE', 'target changed while it was hashed');
    }
    const algorithm = expected.objectId.length === 40 ? 'sha1' : 'sha256';
    const digest = crypto.createHash(algorithm)
      .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8')).update(bytes).digest('hex');
    if (digest !== expected.objectId) {
      fail('E_SECURITY_TARGET_CONTENT_MISMATCH', 'materialized file content does not match the bound Git object', {
        pathSha256: sha256Hex(expected.path),
      });
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function selectShard(shardGeneration, shardId) {
  assertClosedSchema(shardGeneration, {
    schema: SHARDS_SCHEMA,
    required: ['recordRole', 'revision', 'inventorySha256', 'generationId', 'shards'],
    name: 'target shard generation',
  });
  if (shardGeneration.recordRole !== 'authority' || !GIT_OBJECT_ID.test(shardGeneration.revision)
      || !/^[0-9a-f]{64}$/.test(shardGeneration.inventorySha256)
      || !/^[A-Za-z0-9][A-Za-z0-9._-]*\/v[1-9][0-9]*$/.test(shardGeneration.generationId)
      || !Array.isArray(shardGeneration.shards) || shardGeneration.shards.length === 0) {
    fail('E_SECURITY_TARGET_SHARD_INVALID', 'shard generation authority is malformed');
  }
  const seen = new Set();
  const generationPaths = new Set();
  const generationEntries = [];
  for (const candidate of shardGeneration.shards) {
    if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)
        || canonicalJson(Object.keys(candidate).sort()) !== canonicalJson(
          ['id', 'ownerSectionId', 'pathCount', 'pathListSha256', 'paths'].sort(),
        )
        || !SAFE_SHARD_ID.test(candidate.id) || candidate.id.split('/')[0] !== candidate.ownerSectionId
        || seen.has(candidate.id) || !Array.isArray(candidate.paths) || candidate.paths.length === 0
        || candidate.pathCount !== candidate.paths.length) {
      fail('E_SECURITY_TARGET_SHARD_INVALID', 'shard generation contains a malformed or duplicate shard');
    }
    seen.add(candidate.id);
    const entries = candidate.paths.map((entry) => ({
      ...entry,
      pathBytes: Buffer.from(entry.path, 'utf8'),
      objectType: entry.mode === '160000' ? 'commit' : 'blob',
    }));
    for (const entry of entries) {
      if (generationPaths.has(entry.path)) fail('E_SECURITY_TARGET_SHARD_INVALID', 'shard generation contains a duplicate owned path');
      generationPaths.add(entry.path);
      generationEntries.push(entry);
    }
    if (candidate.pathListSha256 !== hashInventory(entries)) {
      fail('E_SECURITY_TARGET_SHARD_INVALID', 'shard path hash does not match its exact path tuples');
    }
  }
  if (hashInventory(generationEntries) !== shardGeneration.inventorySha256) {
    fail('E_SECURITY_TARGET_SHARD_INVALID', 'shard generation does not exactly project its inventory hash');
  }
  if (typeof shardId !== 'string' || !SAFE_SHARD_ID.test(shardId)) {
    fail('E_SECURITY_TARGET_SHARD_INVALID', 'shardId is invalid');
  }
  const shard = shardGeneration.shards.find((candidate) => candidate.id === shardId);
  if (!shard) fail('E_SECURITY_TARGET_SHARD_INVALID', 'shardId is not present in the bound generation');
  return shard;
}

export async function validateGitMaterialization({ repoRoot, revision, entries, gitRunner }) {
  const root = realDirectory(repoRoot, 'materialization root');
  if (typeof revision !== 'string' || !GIT_OBJECT_ID.test(revision)) {
    fail('E_SECURITY_TARGET_REVISION_INVALID', 'revision must be a full lowercase Git object ID');
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    fail('E_SECURITY_TARGET_EMPTY', 'target entries must be a non-empty array');
  }

  const inside = await gitCall(gitRunner, root, ['rev-parse', '--is-inside-work-tree'], 'Git worktree check');
  if (inside.status !== 0 || outputText(inside.stdout, 'Git worktree check stdout').trim() !== 'true') {
    fail('E_SECURITY_TARGET_NOT_WORKTREE', 'materialization is not a Git worktree');
  }
  const top = await gitCall(gitRunner, root, ['rev-parse', '--show-toplevel'], 'Git top-level check');
  if (top.status !== 0 || path.resolve(outputText(top.stdout, 'Git top-level stdout').trim()) !== root) {
    fail('E_SECURITY_TARGET_REPOSITORY_MISMATCH', 'materialization root is not its Git top level');
  }
  const head = await gitCall(gitRunner, root, ['rev-parse', '--verify', 'HEAD^{commit}'], 'Git HEAD check');
  if (head.status !== 0 || outputText(head.stdout, 'Git HEAD stdout').trim() !== revision) {
    fail('E_SECURITY_TARGET_REVISION_MISMATCH', 'materialization HEAD does not equal the bound source revision');
  }
  const symbolic = await gitCall(gitRunner, root, ['symbolic-ref', '-q', 'HEAD'], 'Git detached-HEAD check');
  if (symbolic.status !== 1 || symbolic.stdout.length !== 0) {
    fail('E_SECURITY_TARGET_MUTABLE_HEAD', 'materialization must use a detached HEAD');
  }
  const status = await gitCall(gitRunner, root, [
    'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching', '--ignore-submodules=none',
  ], 'Git cleanliness check');
  if (status.status !== 0 || status.stdout.length !== 0) {
    fail('E_SECURITY_TARGET_DIRTY', 'materialization contains changed, untracked, ignored, or dirty-submodule state');
  }
  const tree = await gitCall(gitRunner, root, ['ls-tree', '-r', '-z', '--full-tree', revision], 'Git tree check');
  if (tree.status !== 0) fail('E_SECURITY_TARGET_GIT_FAILED', 'Git tree check failed');
  let treeEntries;
  try { treeEntries = parseGitTreeZ(tree.stdout); }
  catch (error) {
    fail('E_SECURITY_TARGET_TREE_INVALID', 'Git tree output is invalid', { causeCode: error?.code ?? 'UNKNOWN' });
  }
  const byPath = tupleMap(treeEntries, 'Git tree');
  const selectedTreeEntries = [];
  for (const entry of entries) {
    const actual = byPath.get(entry.path);
    if (!actual) fail('E_SECURITY_TARGET_TUPLE_MISMATCH', 'bound target is absent from the source tree');
    assertExactTuples([entry], [actual], 'target tuple');
    if (!['file', 'executable'].includes(entry.kind) || !['100644', '100755'].includes(entry.mode)) {
      fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'exact scanner targets must be regular files or executables', {
        pathSha256: sha256Hex(entry.path), kind: entry.kind,
      });
    }
    const { absolutePath } = assertNoSymlinkComponents(root, entry.path);
    await hashMaterializedBlob(absolutePath, entry);
    selectedTreeEntries.push(actual);
  }
  return { repoRoot: root, revision, treeEntries, selectedTreeEntries };
}

function validateGitMaterializationSync({ repoRoot, revision, entries, gitRunner }) {
  const root = realDirectory(repoRoot, 'materialization root');
  if (typeof revision !== 'string' || !GIT_OBJECT_ID.test(revision)) {
    fail('E_SECURITY_TARGET_REVISION_INVALID', 'revision must be a full lowercase Git object ID');
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    fail('E_SECURITY_TARGET_EMPTY', 'target entries must be a non-empty array');
  }
  const inside = gitCallSync(gitRunner, root, ['rev-parse', '--is-inside-work-tree'], 'Git worktree check');
  if (inside.status !== 0 || outputText(inside.stdout, 'Git worktree check stdout').trim() !== 'true') {
    fail('E_SECURITY_TARGET_NOT_WORKTREE', 'materialization is not a Git worktree');
  }
  const top = gitCallSync(gitRunner, root, ['rev-parse', '--show-toplevel'], 'Git top-level check');
  if (top.status !== 0 || path.resolve(outputText(top.stdout, 'Git top-level stdout').trim()) !== root) {
    fail('E_SECURITY_TARGET_REPOSITORY_MISMATCH', 'materialization root is not its Git top level');
  }
  const head = gitCallSync(gitRunner, root, ['rev-parse', '--verify', 'HEAD^{commit}'], 'Git HEAD check');
  if (head.status !== 0 || outputText(head.stdout, 'Git HEAD stdout').trim() !== revision) {
    fail('E_SECURITY_TARGET_REVISION_MISMATCH', 'materialization HEAD does not equal the bound source revision');
  }
  const symbolic = gitCallSync(gitRunner, root, ['symbolic-ref', '-q', 'HEAD'], 'Git detached-HEAD check');
  if (symbolic.status !== 1 || symbolic.stdout.length !== 0) {
    fail('E_SECURITY_TARGET_MUTABLE_HEAD', 'materialization must use a detached HEAD');
  }
  const status = gitCallSync(gitRunner, root, [
    'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching', '--ignore-submodules=none',
  ], 'Git cleanliness check');
  if (status.status !== 0 || status.stdout.length !== 0) {
    fail('E_SECURITY_TARGET_DIRTY', 'materialization contains changed, untracked, ignored, or dirty-submodule state');
  }
  const tree = gitCallSync(gitRunner, root, ['ls-tree', '-r', '-z', '--full-tree', revision], 'Git tree check');
  if (tree.status !== 0) fail('E_SECURITY_TARGET_GIT_FAILED', 'Git tree check failed');
  let treeEntries;
  try { treeEntries = parseGitTreeZ(tree.stdout); }
  catch (error) {
    fail('E_SECURITY_TARGET_TREE_INVALID', 'Git tree output is invalid', { causeCode: error?.code ?? 'UNKNOWN' });
  }
  const byPath = tupleMap(treeEntries, 'Git tree');
  const selectedTreeEntries = [];
  for (const entry of entries) {
    const actual = byPath.get(entry.path);
    if (!actual) fail('E_SECURITY_TARGET_TUPLE_MISMATCH', 'bound target is absent from the source tree');
    assertExactTuples([entry], [actual], 'target tuple');
    const { absolutePath } = assertNoSymlinkComponents(root, entry.path);
    hashMaterializedBlobSync(absolutePath, entry);
    selectedTreeEntries.push(actual);
  }
  return { repoRoot: root, revision, treeEntries, selectedTreeEntries };
}

function createPrivateFile(filename, contents) {
  let descriptor;
  try {
    descriptor = fs.openSync(filename,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE);
    fs.fchmodSync(descriptor, PRIVATE_FILE_MODE);
    if (contents.length > 0) fs.writeFileSync(descriptor, contents);
    fs.fsyncSync(descriptor);
  } catch (error) {
    fail('E_SECURITY_TARGET_STATE_WRITE', 'could not create private target state', { cause: error?.code ?? 'ERROR' });
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  validatePrivateFile(filename, contents);
}

function replacePrivateFile(filename, contents) {
  const temporary = `${filename}.tmp-${process.pid}-${crypto.randomBytes(8).toString('hex')}`;
  createPrivateFile(temporary, contents);
  try {
    fs.renameSync(temporary, filename);
    fsyncDirectory(path.dirname(filename));
  } catch (error) {
    try { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); } catch {}
    fail('E_SECURITY_TARGET_STATE_WRITE', 'could not replace private target state', {
      cause: error?.code ?? 'ERROR',
    });
  }
  validatePrivateFile(filename, contents);
}

function validatePrivateFile(filename, expectedContents) {
  const actual = readStableRegularFile(filename, 'target state file', { privateFile: true });
  const expected = expectedContents === undefined ? undefined : buffer(expectedContents, 'expected target state');
  if (expected !== undefined && !actual.equals(expected)) {
    fail('E_SECURITY_TARGET_STATE_CONTENT', 'private target state changed after creation');
  }
  return fs.lstatSync(filename);
}

function validateStateDirectory(stateDir, repoRoot) {
  const state = realDirectory(stateDir, 'target state directory');
  const metadata = fs.statSync(state);
  if ((metadata.mode & 0o777) !== 0o700
      || (typeof process.getuid === 'function' && metadata.uid !== process.getuid())) {
    fail('E_SECURITY_TARGET_STATE_MODE', 'target state directory must be caller-owned mode 0700');
  }
  if (isWithin(repoRoot, state) || isWithin(state, repoRoot)) {
    fail('E_SECURITY_TARGET_STATE_LOCATION', 'target state directory must be external to the materialization');
  }
  return state;
}

function strictUtf8Name(rawName) {
  const value = rawName.toString('utf8');
  if (!Buffer.from(value, 'utf8').equals(rawName)) {
    fail('E_SECURITY_TARGET_PATH_INVALID', 'export contains a non-UTF-8 path');
  }
  return value;
}

function expectedExportLayout(entries) {
  const files = new Map();
  const directories = new Set();
  let fileCount = 0;
  let executableCount = 0;
  for (const entry of entries) {
    assertRepositoryRelativePath(entry.path, 'export tuple path');
    if (entry.kind === 'file' && entry.mode === '100644') fileCount += 1;
    else if (entry.kind === 'executable' && entry.mode === '100755') executableCount += 1;
    else {
      fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'Desktop exact export rejects symlinks, submodules, and special Git entries', {
        pathSha256: sha256Hex(entry.path), kind: entry.kind, mode: entry.mode,
        disposition: 'HOLD_UNSUPPORTED_ENTRY',
      });
    }
    files.set(entry.path, publicTuple(entry));
    const pieces = entry.path.split('/');
    for (let index = 1; index < pieces.length; index += 1) directories.add(pieces.slice(0, index).join('/'));
  }
  return {
    files,
    directories,
    disposition: Object.freeze({
      regularFileCount: fileCount,
      executableFileCount: executableCount,
      rejectedEntryCount: 0,
      unsupportedDisposition: 'none',
    }),
  };
}

function updateExportFrame(hash, value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  const length = Buffer.allocUnsafe(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(length);
  hash.update(bytes);
}

function enforceExportProjection(projection) {
  if (!projection.entryLimitPass) {
    holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_ENTRIES', 'export entry capacity would be exceeded', {
      limit: projection.capacity.maxEntries, actual: projection.expectedEntryCount,
    });
  }
  if (!projection.byteLimitPass) {
    holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_BYTES', 'export byte capacity would be exceeded', {
      limit: projection.capacity.maxBytes, actual: projection.exportBytes,
    });
  }
  for (const volume of projection.volumes) {
    if (!volume.spaceLimitPass) {
      holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_SPACE', 'export free-space reserve is insufficient', {
        requiredBytes: volume.requiredBytes, availableBytes: volume.availableBytes, copies: volume.copies,
      });
    }
  }
}

export function runDesktopExportStreamingPass({ entryChunks, phase, backend, capacity, volumes }) {
  if (!['build', 'snapshot'].includes(phase) || backend === null || typeof backend !== 'object'
      || typeof backend.rootIdentity !== 'function' || typeof backend.directory !== 'function'
      || typeof backend.file !== 'function' || entryChunks === null
      || typeof entryChunks?.[Symbol.iterator] !== 'function') {
    fail('E_SECURITY_TARGET_EXPORT_INVALID', 'Desktop export streaming pass configuration is invalid');
  }
  const validatedCapacity = validateExportCapacity(capacity);
  const started = process.hrtime.bigint();
  const startedRssBytes = process.memoryUsage().rss;
  let peakRssBytes = startedRssBytes;
  const exportHash = crypto.createHash('sha256');
  const identityHash = crypto.createHash('sha256');
  updateExportFrame(exportHash, 'setjoin-exact-export-tree/v2');
  updateExportFrame(identityHash, 'setjoin-exact-export-identities/v2');
  const rootIdentity = backend.rootIdentity();
  if (typeof rootIdentity !== 'string' || rootIdentity.length === 0) {
    fail('E_SECURITY_TARGET_EXPORT_INVALID', 'Desktop export streaming backend root identity is invalid');
  }
  updateExportFrame(identityHash, rootIdentity);
  let previousPathBytes;
  let priorDirectoryParts = [];
  let fileCount = 0;
  let directoryCount = 0;
  let byteCount = 0;
  let regularFileCount = 0;
  let executableFileCount = 0;

  function accountEntry() {
    if (fileCount + directoryCount > validatedCapacity.maxEntries) {
      holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_ENTRIES', 'export entry capacity would be exceeded', {
        limit: validatedCapacity.maxEntries, actual: fileCount + directoryCount,
      });
    }
  }

  function addDirectory(relativePath) {
    const result = backend.directory({ relativePath, expectedMode: SEALED_DIRECTORY_MODE, phase });
    if (result === null || typeof result !== 'object' || Array.isArray(result)
        || typeof result.identity !== 'string' || result.identity.length === 0) {
      fail('E_SECURITY_TARGET_EXPORT_INVALID', 'Desktop export directory adapter returned invalid authority');
    }
    const digestEntry = { path: relativePath, kind: 'directory', mode: '0500' };
    updateExportFrame(exportHash, canonicalJson(digestEntry));
    updateExportFrame(identityHash, canonicalJson({ path: relativePath, identity: result.identity }));
    directoryCount += 1;
    accountEntry();
  }

  for (const chunk of entryChunks) {
    if (!Array.isArray(chunk) || chunk.length === 0) {
      fail('E_SECURITY_TARGET_EXPORT_INVALID', 'Desktop export streaming chunks must be non-empty arrays');
    }
    for (const entry of chunk) {
      assertRepositoryRelativePath(entry?.path, 'export tuple path');
      if (!GIT_OBJECT_ID.test(entry?.objectId ?? '')) {
        fail('E_SECURITY_TARGET_TUPLE_MISMATCH', 'Desktop export tuple object ID is invalid');
      }
      let expectedFilesystemMode;
      if (entry.kind === 'file' && entry.mode === '100644') {
        regularFileCount += 1;
        expectedFilesystemMode = SEALED_FILE_MODE;
      } else if (entry.kind === 'executable' && entry.mode === '100755') {
        executableFileCount += 1;
        expectedFilesystemMode = SEALED_EXECUTABLE_MODE;
      } else {
        fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'Desktop exact export rejects symlinks, submodules, and special Git entries', {
          pathSha256: sha256Hex(entry.path), kind: entry.kind, mode: entry.mode,
          disposition: 'HOLD_UNSUPPORTED_ENTRY',
        });
      }
      const pathBytes = Buffer.from(entry.path, 'utf8');
      if (previousPathBytes !== undefined) {
        const order = Buffer.compare(previousPathBytes, pathBytes);
        if (order === 0) fail('E_SECURITY_TARGET_EXPORT_SET_MISMATCH', 'Desktop export stream contains a duplicate path');
        if (order > 0) fail('E_SECURITY_TARGET_EXPORT_SET_MISMATCH', 'Desktop export stream is not globally raw-byte sorted');
        const previousPath = previousPathBytes.toString('utf8');
        if (entry.path.startsWith(`${previousPath}/`)) {
          fail('E_SECURITY_TARGET_EXPORT_SET_MISMATCH', 'Desktop export file path conflicts with a descendant');
        }
      }
      previousPathBytes = Buffer.from(pathBytes);
      const directoryParts = entry.path.split('/').slice(0, -1);
      let common = 0;
      while (common < priorDirectoryParts.length && common < directoryParts.length
          && priorDirectoryParts[common] === directoryParts[common]) common += 1;
      for (let index = common; index < directoryParts.length; index += 1) {
        addDirectory(directoryParts.slice(0, index + 1).join('/'));
      }
      priorDirectoryParts = directoryParts;

      let declaredSize;
      let objectHash;
      const contentHash = crypto.createHash('sha256');
      let observedBytes = 0;
      let began = false;
      const result = backend.file({
        entry,
        expectedFilesystemMode,
        phase,
        begin(size) {
          if (began || !Number.isSafeInteger(size) || size < 0) {
            fail('E_SECURITY_TARGET_EXPORT_INVALID', 'Desktop export file adapter declared an invalid size');
          }
          began = true;
          declaredSize = size;
          objectHash = crypto.createHash(entry.objectId.length === 40 ? 'sha1' : 'sha256');
          objectHash.update(Buffer.from(`blob ${size}\0`, 'utf8'));
        },
        write(bytes) {
          if (!began || !Buffer.isBuffer(bytes) || bytes.length === 0) {
            fail('E_SECURITY_TARGET_EXPORT_INVALID', 'Desktop export file adapter emitted invalid bytes');
          }
          observedBytes += bytes.length;
          if (!Number.isSafeInteger(observedBytes) || observedBytes > declaredSize) {
            fail('E_SECURITY_TARGET_RACE', 'Desktop export file size changed while streaming');
          }
          objectHash.update(bytes);
          contentHash.update(bytes);
        },
      });
      if (!began || observedBytes !== declaredSize || result === null || typeof result !== 'object'
          || Array.isArray(result) || result.filesystemMode !== expectedFilesystemMode
          || typeof result.identity !== 'string' || result.identity.length === 0) {
        fail('E_SECURITY_TARGET_EXPORT_INVALID', 'Desktop export file adapter returned invalid authority');
      }
      if (objectHash.digest('hex') !== entry.objectId) {
        fail('E_SECURITY_TARGET_CONTENT_MISMATCH', 'Desktop export file does not match its Git object');
      }
      byteCount += observedBytes;
      if (!Number.isSafeInteger(byteCount)) {
        holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_BYTES', 'export byte projection exceeds safe integer precision');
      }
      if (byteCount > validatedCapacity.maxBytes) {
        holdCapacity('E_SECURITY_TARGET_HOLD_CAPACITY_BYTES', 'export byte capacity would be exceeded', {
          limit: validatedCapacity.maxBytes, actual: byteCount,
        });
      }
      const digestEntry = {
        path: entry.path,
        kind: entry.kind,
        gitMode: entry.mode,
        filesystemMode: expectedFilesystemMode.toString(8).padStart(4, '0'),
        objectId: entry.objectId,
        size: observedBytes,
        sha256: contentHash.digest('hex'),
      };
      updateExportFrame(exportHash, canonicalJson(digestEntry));
      updateExportFrame(identityHash, canonicalJson({ path: entry.path, identity: result.identity }));
      fileCount += 1;
      accountEntry();
    }
    peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
  }
  if (fileCount === 0) fail('E_SECURITY_TARGET_EMPTY', 'Desktop export stream is empty');
  const exportTreeSha256 = exportHash.digest('hex');
  updateExportFrame(identityHash, exportTreeSha256);
  const stableSnapshotSha256 = identityHash.digest('hex');
  const projection = projectExportCapacity({ fileCount, directoryCount, exportBytes: byteCount, volumes }, validatedCapacity);
  enforceExportProjection(projection);
  peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
  return Object.freeze({
    phase,
    exportTreeSha256,
    stableSnapshotSha256,
    byteCount,
    fileCount,
    directoryCount,
    elapsedMs: Number(process.hrtime.bigint() - started) / 1_000_000,
    startedRssBytes,
    peakRssBytes,
    deltaRssBytes: Math.max(0, peakRssBytes - startedRssBytes),
    entryDisposition: Object.freeze({
      regularFileCount,
      executableFileCount,
      rejectedEntryCount: 0,
      unsupportedDisposition: 'none',
    }),
    projection,
  });
}

function createFreshDirectory(parent, name) {
  assertRepositoryRelativePath(name, 'export directory name');
  const destination = path.join(parent, name);
  if (!isWithin(parent, destination)) fail('E_SECURITY_TARGET_PATH_ESCAPE', 'export directory escaped its parent');
  try { fs.mkdirSync(destination, { mode: PRIVATE_DIRECTORY_MODE }); }
  catch (error) { fail('E_SECURITY_TARGET_EXPORT_EXISTS', 'export destination must be fresh', { cause: error?.code ?? 'ERROR' }); }
  const metadata = fs.lstatSync(destination);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== PRIVATE_DIRECTORY_MODE) {
    fail('E_SECURITY_TARGET_EXPORT_INVALID', 'fresh export directory is not a private real directory');
  }
  return destination;
}

function ensureExportParent(root, relativeDirectory, createdDirectories) {
  if (relativeDirectory === '.') return root;
  let current = root;
  for (const piece of relativeDirectory.split('/')) {
    current = path.join(current, piece);
    if (!isWithin(root, current)) fail('E_SECURITY_TARGET_PATH_ESCAPE', 'export parent escaped target root');
    if (!fs.existsSync(current)) {
      try { fs.mkdirSync(current, { mode: PRIVATE_DIRECTORY_MODE }); }
      catch (error) { fail('E_SECURITY_TARGET_EXPORT_WRITE', 'could not create export directory', { cause: error?.code ?? 'ERROR' }); }
      createdDirectories.add(current);
    }
    const metadata = fs.lstatSync(current);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== PRIVATE_DIRECTORY_MODE) {
      fail('E_SECURITY_TARGET_LINK_UNSAFE', 'export parent is not a private real directory');
    }
  }
  return current;
}

function copyExactExportFile(sourceRoot, exportRoot, entry, createdDirectories, stream) {
  const source = assertNoSymlinkComponents(sourceRoot, entry.path).absolutePath;
  const destination = path.join(exportRoot, ...entry.path.split('/'));
  if (!isWithin(exportRoot, destination)) fail('E_SECURITY_TARGET_PATH_ESCAPE', 'export file escaped target root');
  ensureExportParent(exportRoot, path.posix.dirname(entry.path), createdDirectories);
  const sourceBefore = fs.lstatSync(source, { bigint: true });
  if (!sourceBefore.isFile() || sourceBefore.isSymbolicLink()) fail('E_SECURITY_TARGET_LINK_UNSAFE', 'source blob is not a regular file');
  let sourceDescriptor;
  let destinationDescriptor;
  try {
    sourceDescriptor = fs.openSync(source, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(sourceDescriptor, { bigint: true });
    if (bigintStatIdentity(opened) !== bigintStatIdentity(sourceBefore)) fail('E_SECURITY_TARGET_RACE', 'source blob changed while opening');
    const sourceSize = Number(sourceBefore.size);
    if (!Number.isSafeInteger(sourceSize)) fail('E_SECURITY_TARGET_EXPORT_INVALID', 'source blob size exceeds safe integer precision');
    stream.begin(sourceSize);
    destinationDescriptor = fs.openSync(destination,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), PRIVATE_FILE_MODE);
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const length = fs.readSync(sourceDescriptor, chunk, 0, chunk.length, null);
      if (length === 0) break;
      const bytes = chunk.subarray(0, length);
      stream.write(bytes);
      fs.writeSync(destinationDescriptor, bytes);
    }
    const sourceAfter = fs.fstatSync(sourceDescriptor, { bigint: true });
    const sourcePathAfter = fs.lstatSync(source, { bigint: true });
    if (bigintStatIdentity(opened) !== bigintStatIdentity(sourceAfter)
        || bigintStatIdentity(sourceAfter) !== bigintStatIdentity(sourcePathAfter)) {
      fail('E_SECURITY_TARGET_RACE', 'source blob changed while exporting');
    }
    fs.fsyncSync(destinationDescriptor);
    fs.fchmodSync(destinationDescriptor, entry.mode === '100755' ? SEALED_EXECUTABLE_MODE : SEALED_FILE_MODE);
    fs.fsyncSync(destinationDescriptor);
  } catch (error) {
    if (error instanceof SecurityProgramError) throw error;
    fail('E_SECURITY_TARGET_EXPORT_WRITE', 'could not export Git blob', { cause: error?.code ?? 'ERROR' });
  } finally {
    if (sourceDescriptor !== undefined) fs.closeSync(sourceDescriptor);
    if (destinationDescriptor !== undefined) fs.closeSync(destinationDescriptor);
  }
  const destinationMetadata = fs.lstatSync(destination, { bigint: true });
  return {
    filesystemMode: Number(destinationMetadata.mode) & 0o777,
    identity: bigintStatIdentity(destinationMetadata),
  };
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
    fs.fsyncSync(descriptor);
  } catch (error) {
    fail('E_SECURITY_TARGET_EXPORT_WRITE', 'could not durably sync export directory', { cause: error?.code ?? 'ERROR' });
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function sealExportDirectories(exportRoot, createdDirectories) {
  const deepestFirst = [...createdDirectories].sort((left, right) => right.split(path.sep).length - left.split(path.sep).length);
  for (const directory of deepestFirst) {
    fsyncDirectory(directory);
    fs.chmodSync(directory, SEALED_DIRECTORY_MODE);
    fsyncDirectory(directory);
  }
  fsyncDirectory(exportRoot);
  fs.chmodSync(exportRoot, SEALED_DIRECTORY_MODE);
  fsyncDirectory(exportRoot);
}

function walkExport(root) {
  const results = [];
  function visit(absoluteDirectory, relativeDirectory) {
    const rawNames = fs.readdirSync(absoluteDirectory, { encoding: 'buffer' }).sort(Buffer.compare);
    for (const rawName of rawNames) {
      const name = strictUtf8Name(rawName);
      if (name === '.' || name === '..' || name.includes('/')) fail('E_SECURITY_TARGET_PATH_INVALID', 'export contains an invalid path component');
      const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      assertRepositoryRelativePath(relativePath, 'export snapshot path');
      const absolutePath = path.join(absoluteDirectory, name);
      if (!isWithin(root, absolutePath)) fail('E_SECURITY_TARGET_PATH_ESCAPE', 'export snapshot escaped target root');
      const metadata = fs.lstatSync(absolutePath, { bigint: true });
      if (metadata.isSymbolicLink()) fail('E_SECURITY_TARGET_LINK_UNSAFE', 'export contains a symbolic link');
      if (metadata.isDirectory()) {
        results.push({ relativePath, absolutePath, metadata, kind: 'directory' });
        visit(absolutePath, relativePath);
      } else if (metadata.isFile()) {
        if (metadata.nlink !== 1n) fail('E_SECURITY_TARGET_LINK_UNSAFE', 'export contains a hard-linked file');
        results.push({ relativePath, absolutePath, metadata, kind: 'file' });
      } else {
        fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'export contains a special filesystem entry');
      }
    }
  }
  visit(root, '');
  return results;
}

function snapshotExactExport(targetRoot, expectedEntries, capacity, volumes) {
  const rootBefore = fs.lstatSync(targetRoot, { bigint: true });
  if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink()) fail('E_SECURITY_TARGET_EXPORT_INVALID', 'mounted export root is not a real directory');
  const layout = expectedExportLayout(expectedEntries);
  const walked = walkExport(targetRoot)
    .sort((left, right) => Buffer.compare(Buffer.from(left.relativePath), Buffer.from(right.relativePath)));
  const actualDirectories = walked.filter((item) => item.kind === 'directory').map((item) => item.relativePath);
  const expectedDirectories = [...layout.directories].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  if (canonicalJson(actualDirectories) !== canonicalJson(expectedDirectories)) {
    fail('E_SECURITY_TARGET_EXPORT_SET_MISMATCH', 'export directory set does not exactly match the shard');
  }
  const actualFiles = walked.filter((item) => item.kind === 'file');
  const expectedPaths = [...layout.files.keys()].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  if (canonicalJson(actualFiles.map((item) => item.relativePath)) !== canonicalJson(expectedPaths)) {
    fail('E_SECURITY_TARGET_EXPORT_SET_MISMATCH', 'export file set does not exactly match the shard');
  }
  const byPath = new Map(walked.map((item) => [item.relativePath, item]));
  const sortedEntries = [...expectedEntries]
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const result = runDesktopExportStreamingPass({
    entryChunks: [sortedEntries],
    phase: 'snapshot',
    capacity,
    volumes,
    backend: {
      rootIdentity: () => bigintStatIdentity(rootBefore),
      directory({ relativePath, expectedMode }) {
        const item = byPath.get(relativePath);
        if (!item || item.kind !== 'directory' || (Number(item.metadata.mode) & 0o777) !== expectedMode) {
          fail('E_SECURITY_TARGET_MODE_MISMATCH', 'export directory mode is not sealed read-only');
        }
        return { identity: bigintStatIdentity(item.metadata) };
      },
      file({ entry, expectedFilesystemMode, begin, write }) {
        const item = byPath.get(entry.path);
        if (!item || item.kind !== 'file' || (Number(item.metadata.mode) & 0o777) !== expectedFilesystemMode) {
          fail('E_SECURITY_TARGET_MODE_MISMATCH', 'export file mode does not match its sealed Git disposition');
        }
        const descriptor = fs.openSync(item.absolutePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
        try {
          const opened = fs.fstatSync(descriptor, { bigint: true });
          if (bigintStatIdentity(opened) !== bigintStatIdentity(item.metadata)) {
            fail('E_SECURITY_TARGET_RACE', 'export file changed while opening');
          }
          const size = Number(opened.size);
          if (!Number.isSafeInteger(size)) fail('E_SECURITY_TARGET_EXPORT_INVALID', 'export file size exceeds safe integer precision');
          begin(size);
          const chunk = Buffer.allocUnsafe(1024 * 1024);
          for (;;) {
            const length = fs.readSync(descriptor, chunk, 0, chunk.length, null);
            if (length === 0) break;
            write(chunk.subarray(0, length));
          }
          const after = fs.fstatSync(descriptor, { bigint: true });
          const afterPath = fs.lstatSync(item.absolutePath, { bigint: true });
          if (bigintStatIdentity(opened) !== bigintStatIdentity(after)
              || bigintStatIdentity(after) !== bigintStatIdentity(afterPath)) {
            fail('E_SECURITY_TARGET_RACE', 'export file changed while snapshotting');
          }
          return { filesystemMode: Number(after.mode) & 0o777, identity: bigintStatIdentity(after) };
        } finally {
          fs.closeSync(descriptor);
        }
      },
    },
  });
  const rootAfter = fs.lstatSync(targetRoot, { bigint: true });
  if (bigintStatIdentity(rootBefore) !== bigintStatIdentity(rootAfter)) fail('E_SECURITY_TARGET_RACE', 'export root changed during snapshot');
  return result;
}

function assertStableExportPair(left, right) {
  if (left.exportTreeSha256 !== right.exportTreeSha256
      || left.stableSnapshotSha256 !== right.stableSnapshotSha256
      || left.byteCount !== right.byteCount || left.fileCount !== right.fileCount
      || left.directoryCount !== right.directoryCount) {
    fail('E_SECURITY_TARGET_RACE', 'two consecutive export snapshots do not match');
  }
}

function backendCall(runner, command, args, label, input) {
  if (typeof runner !== 'function') fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', `${label} requires an explicit backend runner`);
  let result;
  try { result = runner({ command, args: [...args], input }); }
  catch (error) { fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', `${label} failed`, { cause: error?.code ?? error?.name ?? 'ERROR' }); }
  if (result === null || typeof result !== 'object' || Array.isArray(result)
      || !Number.isInteger(result.status) || !Object.hasOwn(result, 'stdout')) {
    fail('E_SECURITY_TARGET_RUNNER_INVALID', `${label} returned an invalid result`);
  }
  if (result.status !== 0) fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', `${label} did not succeed`, { status: result.status });
  return buffer(result.stdout, `${label} stdout`);
}

function fileSha256Streamed(filename, label) {
  const beforePath = fs.lstatSync(filename, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink() || beforePath.nlink !== 1n) {
    fail('E_SECURITY_TARGET_LINK_UNSAFE', `${label} must be a single-link regular file`);
  }
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (bigintStatIdentity(opened) !== bigintStatIdentity(beforePath)) fail('E_SECURITY_TARGET_RACE', `${label} changed while opening`);
    const hash = crypto.createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const length = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      if (length === 0) break;
      hash.update(chunk.subarray(0, length));
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(filename, { bigint: true });
    if (bigintStatIdentity(opened) !== bigintStatIdentity(after)
        || bigintStatIdentity(after) !== bigintStatIdentity(afterPath)) fail('E_SECURITY_TARGET_RACE', `${label} changed while hashing`);
    return hash.digest('hex');
  } finally { fs.closeSync(descriptor); }
}

function mountIdentityFromInspection(backendId, targetPath, inspection, imagePath) {
  if (inspection === null || typeof inspection !== 'object' || Array.isArray(inspection)
      || inspection.readOnly !== true || typeof inspection.targetPath !== 'string'
      || typeof inspection.realPath !== 'string' || typeof inspection.deviceId !== 'string'
      || typeof inspection.rootInode !== 'string' || typeof inspection.deviceIdentifier !== 'string'
      || typeof inspection.volumeUuid !== 'string') {
    fail('E_SECURITY_TARGET_MOUNT_INVALID', 'read-only backend returned an invalid mount inspection');
  }
  const expectedTarget = path.resolve(targetPath);
  if (path.resolve(inspection.targetPath) !== expectedTarget || fs.realpathSync.native(expectedTarget) !== inspection.realPath) {
    fail('E_SECURITY_TARGET_MOUNT_INVALID', 'read-only backend inspected a different target');
  }
  const rootMetadata = fs.lstatSync(expectedTarget);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()
      || (rootMetadata.mode & 0o777) !== SEALED_DIRECTORY_MODE) {
    fail('E_SECURITY_TARGET_MODE_MISMATCH', 'read-only export root mode must remain 0500');
  }
  return Object.freeze({
    backendId,
    readOnly: true,
    targetPath: expectedTarget,
    realPath: inspection.realPath,
    deviceId: inspection.deviceId,
    rootInode: inspection.rootInode,
    deviceIdentifier: inspection.deviceIdentifier,
    volumeUuid: inspection.volumeUuid,
    imagePath,
    imageSha256: fileSha256Streamed(imagePath, 'read-only export image'),
  });
}

export function createMacOsReadOnlyDiskImageBackend({ runner, platform = process.platform } = {}) {
  const supported = platform === 'darwin' && process.platform === 'darwin';
  const backend = Object.freeze({
    backendId: MACOS_READ_ONLY_BACKEND,
    productionEligible: supported,
    unsupportedDisposition: supported ? 'none' : 'HOLD_UNSUPPORTED_READONLY_BACKEND',
    inspect({ targetPath, imagePath }) {
      if (!supported) fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', 'macOS read-only disk-image backend is unavailable on this host');
      const plist = backendCall(runner, '/usr/sbin/diskutil', ['info', '-plist', targetPath], 'disk-image mount inspection');
      const jsonBytes = backendCall(runner, '/usr/bin/plutil', ['-convert', 'json', '-o', '-', '-'], 'disk-image plist decoding', plist);
      let info;
      try { info = parseStrictJson(jsonBytes.toString('utf8')); }
      catch { fail('E_SECURITY_TARGET_MOUNT_INVALID', 'disk-image mount metadata is invalid'); }
      const metadata = fs.lstatSync(targetPath, { bigint: true });
      if (!metadata.isDirectory() || metadata.isSymbolicLink() || info.Writable !== false
          || path.resolve(info.MountPoint ?? '') !== path.resolve(targetPath)
          || typeof info.DeviceIdentifier !== 'string' || info.DeviceIdentifier.length === 0) {
        fail('E_SECURITY_TARGET_MOUNT_WRITABLE', 'disk-image target is not a verified read-only mount');
      }
      if (typeof imagePath !== 'string' || !path.isAbsolute(imagePath)) fail('E_SECURITY_TARGET_MOUNT_INVALID', 'disk-image path is invalid');
      return Object.freeze({
        readOnly: true,
        targetPath: path.resolve(targetPath),
        realPath: fs.realpathSync.native(targetPath),
        deviceId: String(metadata.dev),
        rootInode: String(metadata.ino),
        deviceIdentifier: info.DeviceIdentifier,
        volumeUuid: typeof info.VolumeUUID === 'string' ? info.VolumeUUID : '',
      });
    },
    seal({ sourceDirectory, mountParent, stateDirectory, stem }) {
      if (!supported) fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', 'macOS read-only disk-image backend is unavailable on this host');
      const imagePath = path.join(stateDirectory, `desktop-export-${stem}.dmg`);
      const mountPath = path.join(mountParent, `desktop-export-${stem}-mount`);
      for (const candidate of [imagePath, mountPath]) {
        if (fs.existsSync(candidate)) fail('E_SECURITY_TARGET_EXPORT_EXISTS', 'disk-image output must be fresh');
      }
      fs.mkdirSync(mountPath, { mode: PRIVATE_DIRECTORY_MODE });
      let attached = false;
      try {
        backendCall(runner, '/usr/bin/hdiutil', [
          'create', '-quiet', '-format', 'UDRO', '-srcfolder', sourceDirectory,
          '-volname', `setjoin-${stem}`, imagePath,
        ], 'read-only disk-image creation');
        const imageMetadata = fs.lstatSync(imagePath);
        if (!imageMetadata.isFile() || imageMetadata.isSymbolicLink() || imageMetadata.nlink !== 1) {
          fail('E_SECURITY_TARGET_LINK_UNSAFE', 'disk-image artifact is not a single-link regular file');
        }
        fs.chmodSync(imagePath, PRIVATE_FILE_MODE);
        backendCall(runner, '/usr/bin/hdiutil', [
          'attach', '-quiet', '-readonly', '-nobrowse', '-mountpoint', mountPath, imagePath,
        ], 'read-only disk-image attach');
        attached = true;
        const inspection = backend.inspect({ targetPath: mountPath, imagePath });
        return Object.freeze({ targetPath: mountPath, imagePath, inspection });
      } catch (error) {
        if (attached) {
          try { backendCall(runner, '/usr/bin/hdiutil', ['detach', '-quiet', mountPath], 'failed disk-image cleanup'); }
          catch (cleanupError) {
            fail('E_SECURITY_TARGET_READONLY_CLEANUP', 'failed disk-image mount could not be detached', {
              cause: cleanupError?.code ?? cleanupError?.name ?? 'ERROR',
            });
          }
        }
        try {
          if (fs.existsSync(mountPath)) fs.rmdirSync(mountPath);
          if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
        } catch (cleanupError) {
          fail('E_SECURITY_TARGET_READONLY_CLEANUP', 'failed disk-image artifacts could not be removed', {
            cause: cleanupError?.code ?? cleanupError?.name ?? 'ERROR',
          });
        }
        throw error;
      }
    },
    detach({ targetPath }) {
      if (!supported) fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', 'macOS read-only disk-image backend is unavailable on this host');
      backendCall(runner, '/usr/bin/hdiutil', ['detach', '-quiet', targetPath], 'read-only disk-image detach');
    },
    recoverCrashArtifacts({ targetPath, imagePath }) {
      if (!supported) fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', 'macOS read-only disk-image backend is unavailable on this host');
      if (!fs.existsSync(targetPath)) return Object.freeze({ detached: false, disposition: 'target-absent' });
      const target = fs.lstatSync(targetPath);
      const parent = fs.lstatSync(path.dirname(targetPath));
      if (!target.isDirectory() || target.isSymbolicLink()) {
        fail('E_SECURITY_TARGET_PREPARATION_INVALID', 'crash-survivor mount path is not a real directory');
      }
      if (target.dev === parent.dev) {
        return Object.freeze({ detached: false, disposition: 'not-mounted' });
      }
      backend.inspect({ targetPath, imagePath });
      backendCall(runner, '/usr/bin/hdiutil', ['detach', '-quiet', targetPath], 'crash-survivor disk-image detach');
      const after = fs.lstatSync(targetPath);
      const afterParent = fs.lstatSync(path.dirname(targetPath));
      if (!after.isDirectory() || after.isSymbolicLink() || after.dev !== afterParent.dev) {
        fail('E_SECURITY_TARGET_READONLY_CLEANUP', 'crash-survivor disk image remained mounted after detach');
      }
      return Object.freeze({ detached: true, disposition: 'verified-detach' });
    },
  });
  if (supported) issuedProductionBackends.add(backend);
  return backend;
}

function pluginDirectoryDigest(pluginDigestRunner, pluginRoot, targetPath) {
  if (typeof pluginDigestRunner !== 'function') {
    fail('E_SECURITY_TARGET_PLUGIN_DIGEST_REQUIRED', 'pinned plugin directory digest runner is required');
  }
  let result;
  try { result = pluginDigestRunner({ pluginRoot, targetPath }); }
  catch (error) { fail('E_SECURITY_TARGET_PLUGIN_DIGEST_FAILED', 'pinned plugin directory digest failed', { cause: error?.code ?? error?.name ?? 'ERROR' }); }
  const digest = typeof result === 'string' ? result : result?.digest;
  if (!PLUGIN_SNAPSHOT_DIGEST.test(digest ?? '')) {
    fail('E_SECURITY_TARGET_PLUGIN_DIGEST_FAILED', 'pinned plugin directory digest result is invalid');
  }
  return digest;
}

function validateReadOnlyBackend(backend, { allowTestBackend = false } = {}) {
  if (backend === null || typeof backend !== 'object' || Array.isArray(backend)
      || typeof backend.backendId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*\/v[1-9][0-9]*$/.test(backend.backendId)
      || typeof backend.productionEligible !== 'boolean' || typeof backend.seal !== 'function'
      || typeof backend.inspect !== 'function') {
    fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', 'read-only export backend is invalid');
  }
  if (!backend.productionEligible && !allowTestBackend) {
    fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', 'host has no production-eligible scanner-unwritable backend', {
      disposition: backend.unsupportedDisposition ?? 'HOLD_UNSUPPORTED_READONLY_BACKEND',
    });
  }
  if (backend.productionEligible
      && (backend.backendId !== MACOS_READ_ONLY_BACKEND || !issuedProductionBackends.has(backend))) {
    fail('E_SECURITY_TARGET_READONLY_UNAVAILABLE', 'production read-only backend was not issued by this adapter');
  }
  return backend;
}

function closedExportAttestation(attestation) {
  assertClosedSchema(attestation, {
    schema: DESKTOP_EXPORT_ATTESTATION_SCHEMA,
    required: [
      'recordRole', 'adapterVersion', 'standardRoute', 'pluginVersion', 'routeContractSha256',
      'revision', 'inventorySha256', 'shardGenerationId', 'shardId', 'pathCount',
      'pathListSha256', 'exportTreeSha256', 'stableSnapshotSha256', 'directorySnapshotDigest',
      'attemptBinding', 'entryDisposition',
      'mount', 'metrics', 'authorityBindingSha256',
    ],
    name: 'Desktop export attestation',
  });
  if (attestation.recordRole !== 'authority' || attestation.adapterVersion !== TARGET_ADAPTER_VERSION
      || attestation.standardRoute !== STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
      || attestation.pluginVersion !== PINNED_PLUGIN_VERSION
      || !GIT_OBJECT_ID.test(attestation.revision) || !/^[0-9a-f]{64}$/.test(attestation.inventorySha256)
      || !/^[A-Za-z0-9][A-Za-z0-9._-]*\/v[1-9][0-9]*$/.test(attestation.shardGenerationId)
      || !SAFE_SHARD_ID.test(attestation.shardId) || !Number.isSafeInteger(attestation.pathCount)
      || attestation.pathCount <= 0 || !/^[0-9a-f]{64}$/.test(attestation.pathListSha256)
      || !/^[0-9a-f]{64}$/.test(attestation.exportTreeSha256)
      || !/^[0-9a-f]{64}$/.test(attestation.stableSnapshotSha256)
      || !PLUGIN_SNAPSHOT_DIGEST.test(attestation.directorySnapshotDigest)
      || !/^[0-9a-f]{64}$/.test(attestation.routeContractSha256)
      || !/^[0-9a-f]{64}$/.test(attestation.authorityBindingSha256)) {
    fail('E_SECURITY_TARGET_ATTESTATION_INVALID', 'Desktop export attestation identity is malformed');
  }
  const validatedBinding = validateAttemptBinding(attestation.attemptBinding, attestation.revision);
  if (canonicalJson(validatedBinding) !== canonicalJson(attestation.attemptBinding)) {
    fail('E_SECURITY_TARGET_ATTESTATION_INVALID', 'Desktop export attempt binding is not canonical');
  }
  const dispositionKeys = ['executableFileCount', 'regularFileCount', 'rejectedEntryCount', 'unsupportedDisposition'];
  if (attestation.entryDisposition === null || typeof attestation.entryDisposition !== 'object'
      || Array.isArray(attestation.entryDisposition)
      || canonicalJson(Object.keys(attestation.entryDisposition).sort()) !== canonicalJson(dispositionKeys.sort())
      || !Number.isSafeInteger(attestation.entryDisposition.regularFileCount)
      || !Number.isSafeInteger(attestation.entryDisposition.executableFileCount)
      || attestation.entryDisposition.rejectedEntryCount !== 0
      || attestation.entryDisposition.unsupportedDisposition !== 'none'
      || attestation.entryDisposition.regularFileCount + attestation.entryDisposition.executableFileCount !== attestation.pathCount) {
    fail('E_SECURITY_TARGET_ATTESTATION_INVALID', 'Desktop export entry disposition is malformed');
  }
  const mountKeys = [
    'backendId', 'deviceId', 'deviceIdentifier', 'imagePath', 'imageSha256', 'productionEligible',
    'readOnly', 'realPath', 'rootInode', 'targetPath', 'volumeUuid',
  ];
  if (attestation.mount === null || typeof attestation.mount !== 'object' || Array.isArray(attestation.mount)
      || canonicalJson(Object.keys(attestation.mount).sort()) !== canonicalJson(mountKeys.sort())
      || typeof attestation.mount.backendId !== 'string' || attestation.mount.readOnly !== true
      || typeof attestation.mount.productionEligible !== 'boolean'
      || !path.isAbsolute(attestation.mount.targetPath) || !path.isAbsolute(attestation.mount.realPath)
      || !path.isAbsolute(attestation.mount.imagePath) || !/^[0-9a-f]{64}$/.test(attestation.mount.imageSha256)
      || !['deviceId', 'deviceIdentifier', 'rootInode', 'volumeUuid'].every((field) => typeof attestation.mount[field] === 'string')) {
    fail('E_SECURITY_TARGET_ATTESTATION_INVALID', 'Desktop export mount identity is malformed');
  }
  const metricKeys = [
    'buildElapsedMs', 'buildPeakRssBytes', 'exportBytes', 'exportDirectoryCount',
    'exportFileCount', 'snapshotElapsedMs', 'snapshotPeakRssBytes',
  ];
  if (attestation.metrics === null || typeof attestation.metrics !== 'object' || Array.isArray(attestation.metrics)
      || canonicalJson(Object.keys(attestation.metrics).sort()) !== canonicalJson(metricKeys.sort())
      || metricKeys.some((field) => !Number.isSafeInteger(attestation.metrics[field]) || attestation.metrics[field] < 0)
      || attestation.metrics.exportFileCount !== attestation.pathCount) {
    fail('E_SECURITY_TARGET_ATTESTATION_INVALID', 'Desktop export metrics are malformed');
  }
  enforceMeasuredCapacity(validatedBinding.exportCapacity, attestation.metrics);
  const { authorityBindingSha256, ...binding } = attestation;
  if (sha256Hex(canonicalJson(binding)) !== authorityBindingSha256) {
    fail('E_SECURITY_TARGET_ATTESTATION_TAMPERED', 'Desktop export attestation binding hash does not match');
  }
  return attestation;
}

function readExportAttestation(attestationFile) {
  if (typeof attestationFile !== 'string' || !path.isAbsolute(attestationFile)) {
    fail('E_SECURITY_TARGET_ATTESTATION_INVALID', 'Desktop export attestation path must be absolute');
  }
  let attestation;
  const bytes = readStableRegularFile(attestationFile, 'Desktop export attestation', { privateFile: true });
  try { attestation = parseStrictJson(bytes.toString('utf8')); }
  catch (error) {
    if (error instanceof SecurityProgramError) throw error;
    fail('E_SECURITY_TARGET_ATTESTATION_INVALID', 'Desktop export attestation JSON is invalid');
  }
  return { attestation: closedExportAttestation(attestation), bytes };
}

function exportAuthorityProjection(attestation, artifactSha256) {
  return Object.freeze({
    artifactSha256,
    pathCount: attestation.pathCount,
    pathListSha256: attestation.pathListSha256,
    standardRoute: attestation.standardRoute,
    routeContractSha256: attestation.routeContractSha256,
    pluginVersion: attestation.pluginVersion,
    exportTreeSha256: attestation.exportTreeSha256,
    stableSnapshotSha256: attestation.stableSnapshotSha256,
    directorySnapshotDigest: attestation.directorySnapshotDigest,
    productionEligible: attestation.mount.productionEligible,
    attemptId: attestation.attemptBinding.attemptId,
    sourceFingerprint: attestation.attemptBinding.sourceFingerprint,
    controlGenerationHash: attestation.attemptBinding.controlGenerationHash,
    budgetId: attestation.attemptBinding.budgetId,
    budgetSha256: attestation.attemptBinding.budgetSha256,
    exportCapacity: Object.freeze({ ...attestation.attemptBinding.exportCapacity }),
  });
}

function verifyDesktopExportAuthority(internal) {
  verifyBoundSourceFingerprintSync(
    internal.sourceFingerprintRevalidator, internal.sourceRepository, internal.attemptBinding,
  );
  const { attestation, bytes } = readExportAttestation(internal.attestationFile);
  const shard = selectShard(internal.shardGeneration, internal.shardId);
  const route = readPinnedPluginContract(internal.pluginRoot, STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT);
  if (attestation.revision !== internal.shardGeneration.revision
      || attestation.inventorySha256 !== internal.shardGeneration.inventorySha256
      || attestation.shardGenerationId !== internal.shardGeneration.generationId
      || attestation.shardId !== internal.shardId || attestation.pathCount !== shard.pathCount
      || attestation.pathListSha256 !== shard.pathListSha256
      || attestation.routeContractSha256 !== route.routeContractSha256
      || canonicalJson(attestation.attemptBinding) !== canonicalJson(internal.attemptBinding)
      || attestation.mount.backendId !== internal.backend.backendId
      || attestation.mount.productionEligible !== internal.backend.productionEligible) {
    fail('E_SECURITY_TARGET_ATTESTATION_TAMPERED', 'Desktop export attestation contradicts live route authority');
  }
  const inspection = internal.backend.inspect({
    targetPath: attestation.mount.targetPath,
    imagePath: attestation.mount.imagePath,
  });
  const liveMount = mountIdentityFromInspection(
    internal.backend.backendId, attestation.mount.targetPath, inspection, attestation.mount.imagePath,
  );
  for (const field of [
    'backendId', 'readOnly', 'targetPath', 'realPath', 'deviceId', 'rootInode',
    'deviceIdentifier', 'volumeUuid', 'imagePath', 'imageSha256',
  ]) {
    if (liveMount[field] !== attestation.mount[field]) fail('E_SECURITY_TARGET_MOUNT_CHANGED', 'read-only export mount or device identity changed');
  }
  const snapshotVolumes = exportStorageVolumes([
    attestation.mount.targetPath, path.dirname(attestation.mount.imagePath),
  ]);
  const first = snapshotExactExport(
    attestation.mount.targetPath, shard.paths, attestation.attemptBinding.exportCapacity, snapshotVolumes,
  );
  const second = snapshotExactExport(
    attestation.mount.targetPath, shard.paths, attestation.attemptBinding.exportCapacity, snapshotVolumes,
  );
  assertStableExportPair(first, second);
  enforceMeasuredCapacity(attestation.attemptBinding.exportCapacity, {
    ...attestation.metrics,
    snapshotElapsedMs: Math.ceil(first.elapsedMs + second.elapsedMs),
    snapshotPeakRssBytes: Math.max(first.peakRssBytes, second.peakRssBytes),
  });
  if (first.stableSnapshotSha256 !== attestation.stableSnapshotSha256
      || second.stableSnapshotSha256 !== attestation.stableSnapshotSha256) {
    fail('E_SECURITY_TARGET_EXPORT_CHANGED', 'Desktop export stable filesystem identity changed');
  }
  if (first.exportTreeSha256 !== attestation.exportTreeSha256) {
    fail('E_SECURITY_TARGET_EXPORT_CHANGED', 'Desktop export tree digest changed');
  }
  const pluginDigest = pluginDirectoryDigest(internal.pluginDigestRunner, internal.pluginRoot, attestation.mount.targetPath);
  if (pluginDigest !== attestation.directorySnapshotDigest) {
    fail('E_SECURITY_TARGET_PLUGIN_DIGEST_MISMATCH', 'Desktop export no longer matches the pinned plugin directory digest');
  }
  return exportAuthorityProjection(attestation, sha256Hex(bytes));
}

function parseScopeRows(text) {
  if (typeof text !== 'string' || text.length === 0 || !text.endsWith('\n')) {
    fail('E_SECURITY_TARGET_SCOPE_OUTPUT', 'scope helper output must be non-empty newline-terminated JSONL');
  }
  const rows = text.slice(0, -1).split('\n').map((line, index) => {
    if (line.length === 0) fail('E_SECURITY_TARGET_SCOPE_OUTPUT', 'scope helper output contains a blank row');
    let row;
    try { row = parseStrictJson(line); }
    catch (error) {
      fail('E_SECURITY_TARGET_SCOPE_OUTPUT', 'scope helper output contains invalid JSON', {
        line: index + 1, causeCode: error?.code ?? 'UNKNOWN',
      });
    }
    if (row === null || typeof row !== 'object' || Array.isArray(row)
        || Object.keys(row).length !== 1 || typeof row.path !== 'string') {
      fail('E_SECURITY_TARGET_SCOPE_OUTPUT', 'scope helper row must contain only a string path');
    }
    assertRepositoryRelativePath(row.path, `scope helper row ${index + 1} path`);
    return row.path;
  });
  if (new Set(rows).size !== rows.length) fail('E_SECURITY_TARGET_SCOPE_OUTPUT', 'scope helper returned duplicate paths');
  return rows;
}

function closedPreparationRecord(record) {
  assertClosedSchema(record, {
    schema: DESKTOP_EXPORT_PREPARATION_SCHEMA,
    required: [
      'recordRole', 'adapterVersion', 'standardRoute', 'stem', 'phase',
      'ownerHostname', 'ownerProcessId', 'stateDir', 'exportParentDir',
      'stagingPath', 'imagePath', 'mountPath', 'attemptBindingSha256',
      'recordSha256',
    ],
    name: 'Desktop export preparation record',
  });
  if (record.recordRole !== 'crash-recovery-authority'
      || record.adapterVersion !== TARGET_ADAPTER_VERSION
      || record.standardRoute !== STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
      || !/^[0-9a-f]{24}$/.test(record.stem)
      || !PREPARATION_PHASES.includes(record.phase)
      || typeof record.ownerHostname !== 'string' || record.ownerHostname.length === 0
      || !Number.isSafeInteger(record.ownerProcessId) || record.ownerProcessId <= 0
      || ![record.stateDir, record.exportParentDir, record.stagingPath,
        record.imagePath, record.mountPath].every((value) => typeof value === 'string' && path.isAbsolute(value))
      || !/^[0-9a-f]{64}$/.test(record.attemptBindingSha256)
      || !/^[0-9a-f]{64}$/.test(record.recordSha256)) {
    fail('E_SECURITY_TARGET_PREPARATION_INVALID', 'Desktop export preparation record is malformed');
  }
  const { recordSha256, ...binding } = record;
  if (sha256Hex(canonicalJson(binding)) !== recordSha256) {
    fail('E_SECURITY_TARGET_PREPARATION_INVALID', 'Desktop export preparation record digest does not match');
  }
  return record;
}

function preparationRecord(identity, phase) {
  const binding = {
    schema: DESKTOP_EXPORT_PREPARATION_SCHEMA,
    recordRole: 'crash-recovery-authority',
    adapterVersion: TARGET_ADAPTER_VERSION,
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    stem: identity.stem,
    phase,
    ownerHostname: os.hostname(),
    ownerProcessId: process.pid,
    stateDir: identity.state,
    exportParentDir: identity.exportParent,
    stagingPath: identity.staging,
    imagePath: identity.imagePath,
    mountPath: identity.mountPath,
    attemptBindingSha256: identity.attemptBindingSha256,
  };
  return Object.freeze({ ...binding, recordSha256: sha256Hex(canonicalJson(binding)) });
}

function writePreparationRecord(filename, identity, phase, { create = false } = {}) {
  const record = preparationRecord(identity, phase);
  closedPreparationRecord(record);
  const bytes = `${canonicalJson(record)}\n`;
  if (create) {
    createPrivateFile(filename, bytes);
    fsyncDirectory(path.dirname(filename));
  }
  else replacePrivateFile(filename, bytes);
  return record;
}

function readPreparationRecord(filename) {
  let record;
  try {
    record = parseStrictJson(readStableRegularFile(
      filename, 'Desktop export preparation record', { privateFile: true },
    ).toString('utf8'));
  } catch (error) {
    if (error instanceof SecurityProgramError) throw error;
    fail('E_SECURITY_TARGET_PREPARATION_INVALID', 'Desktop export preparation record is invalid JSON');
  }
  return closedPreparationRecord(record);
}

function processDefinitelyDead(record) {
  if (record.ownerHostname !== os.hostname()) {
    fail('E_SECURITY_TARGET_PREPARATION_HOLD', 'pre-attestation owner is on another host');
  }
  try {
    process.kill(record.ownerProcessId, 0);
    fail('E_SECURITY_TARGET_PREPARATION_HOLD', 'pre-attestation owner process is still live');
  } catch (error) {
    if (error instanceof SecurityProgramError) throw error;
    if (error?.code !== 'ESRCH') {
      fail('E_SECURITY_TARGET_PREPARATION_HOLD', 'pre-attestation owner liveness is ambiguous', {
        cause: error?.code ?? 'ERROR',
      });
    }
  }
}

function assertPreparationIdentity(record, identity) {
  const expected = preparationRecord({ ...identity }, record.phase);
  for (const field of [
    'schema', 'recordRole', 'adapterVersion', 'standardRoute', 'stem', 'stateDir',
    'exportParentDir', 'stagingPath', 'imagePath', 'mountPath', 'attemptBindingSha256',
  ]) {
    if (record[field] !== expected[field]) {
      fail('E_SECURITY_TARGET_PREPARATION_INVALID', 'pre-attestation survivor has the wrong identity');
    }
  }
}

function quarantinePreparationArtifact(candidate, parent, stem, label, suffix) {
  if (!fs.existsSync(candidate)) return null;
  const metadata = fs.lstatSync(candidate);
  if (metadata.isSymbolicLink()
      || (!metadata.isDirectory() && !(metadata.isFile() && metadata.nlink === 1))) {
    fail('E_SECURITY_TARGET_PREPARATION_INVALID', `${label} crash survivor has an unsafe type`);
  }
  if (!isWithin(parent, path.resolve(candidate))) {
    fail('E_SECURITY_TARGET_PREPARATION_INVALID', `${label} crash survivor escaped its authority directory`);
  }
  const destination = path.join(parent, `.quarantine-desktop-export-${stem}-${suffix}`);
  if (fs.existsSync(destination)) {
    fail('E_SECURITY_TARGET_PREPARATION_HOLD', `${label} quarantine destination already exists`);
  }
  fs.renameSync(candidate, destination);
  fsyncDirectory(parent);
  return destination;
}

function recoverPreparationSurvivor({ preparationFile, identity, backend }) {
  const record = readPreparationRecord(preparationFile);
  assertPreparationIdentity(record, identity);
  processDefinitelyDead(record);
  if (['READONLY_SEAL_REQUESTED', 'READONLY_TARGET_READY'].includes(record.phase)) {
    if (typeof backend.recoverCrashArtifacts !== 'function') {
      fail('E_SECURITY_TARGET_PREPARATION_HOLD', 'read-only backend cannot classify pre-attestation crash artifacts');
    }
    backend.recoverCrashArtifacts({ targetPath: record.mountPath, imagePath: record.imagePath });
  }
  const quarantineKey = sha256Hex(canonicalJson(record)).slice(0, 16);
  quarantinePreparationArtifact(record.stagingPath, identity.exportParent, identity.stem,
    'export construction', `${quarantineKey}-build`);
  quarantinePreparationArtifact(record.mountPath, identity.exportParent, identity.stem,
    'read-only mount', `${quarantineKey}-mount`);
  quarantinePreparationArtifact(record.imagePath, identity.state, identity.stem,
    'read-only image', `${quarantineKey}-image`);
  const quarantinedRecord = path.join(identity.state,
    `.quarantine-desktop-export-${identity.stem}-${quarantineKey}-preparation.json`);
  if (fs.existsSync(quarantinedRecord)) {
    fail('E_SECURITY_TARGET_PREPARATION_HOLD', 'preparation-record quarantine destination already exists');
  }
  fs.renameSync(preparationFile, quarantinedRecord);
  fsyncDirectory(identity.state);
  return Object.freeze({ record, quarantinedRecord });
}

function targetFault(faultInjector, checkpoint, context) {
  if (faultInjector === undefined) return;
  if (typeof faultInjector !== 'function') {
    fail('E_SECURITY_TARGET_FAULT_INJECTOR_INVALID', 'target fault injector must be a function');
  }
  faultInjector(checkpoint, Object.freeze({ ...context }));
}

export async function prepareDesktopAttestedExportTarget({
  repoRoot,
  shardGeneration,
  shardId,
  stateDir,
  exportParentDir,
  pluginRoot,
  gitRunner,
  pluginDigestRunner,
  readOnlyBackend,
  attemptBinding,
  sourceFingerprintVerifier,
  sourceFingerprintRevalidator,
  allowTestBackend = false,
  faultInjector,
}) {
  const shard = selectShard(shardGeneration, shardId);
  const bindingAuthority = validateAttemptBinding(attemptBinding, shardGeneration.revision);
  const liveFingerprintRevalidator = sourceFingerprintRevalidator ?? sourceFingerprintVerifier;
  const materialization = await validateGitMaterialization({
    repoRoot, revision: shardGeneration.revision, entries: shard.paths, gitRunner,
  });
  await verifyBoundSourceFingerprint(sourceFingerprintVerifier, materialization.repoRoot, bindingAuthority);
  const layout = expectedExportLayout(shard.paths);
  const state = validatePrivateDirectory(stateDir, 'Desktop export authority directory', [materialization.repoRoot]);
  const exportParent = validatePrivateDirectory(
    exportParentDir, 'Desktop export parent directory', [materialization.repoRoot, state],
  );
  const route = readPinnedPluginContract(pluginRoot, STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT);
  const backend = validateReadOnlyBackend(readOnlyBackend, { allowTestBackend });
  const storageVolumes = exportStorageVolumes([exportParent, state]);
  const expectedExportBytes = preflightExportCapacity(
    [exportParent, state], materialization, shard.paths, bindingAuthority.exportCapacity,
  );
  if (process.memoryUsage().rss > bindingAuthority.exportCapacity.maxBuildPeakRssBytes) {
    holdCapacity('E_SECURITY_TARGET_HOLD_BUILD_RSS', 'build RSS already exceeds immutable export capacity', {
      limit: bindingAuthority.exportCapacity.maxBuildPeakRssBytes, actual: process.memoryUsage().rss,
    });
  }
  const stem = sha256Hex(canonicalJson({
    adapterVersion: TARGET_ADAPTER_VERSION,
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    revision: shardGeneration.revision,
    inventorySha256: shardGeneration.inventorySha256,
    shardGenerationId: shardGeneration.generationId,
    shardId,
    pathListSha256: shard.pathListSha256,
    routeContractSha256: route.routeContractSha256,
    attemptBinding: bindingAuthority,
  })).slice(0, 24);
  const staging = path.join(exportParent, `desktop-export-${stem}-build`);
  const imagePathAuthority = path.join(state, `desktop-export-${stem}.dmg`);
  const mountPathAuthority = path.join(exportParent, `desktop-export-${stem}-mount`);
  const attestationFile = path.join(state, `desktop-export-attestation-${stem}.json`);
  const preparationFile = path.join(state, `desktop-export-preparation-${stem}.json`);
  const preparationIdentity = Object.freeze({
    stem,
    state,
    exportParent,
    staging,
    imagePath: imagePathAuthority,
    mountPath: mountPathAuthority,
    attemptBindingSha256: sha256Hex(canonicalJson(bindingAuthority)),
  });
  if (fs.existsSync(attestationFile)) {
    if (fs.existsSync(preparationFile)) {
      const retainedPreparation = readPreparationRecord(preparationFile);
      assertPreparationIdentity(retainedPreparation, preparationIdentity);
      if (!['READONLY_TARGET_READY', 'ATTESTATION_PUBLISHED'].includes(retainedPreparation.phase)) {
        fail('E_SECURITY_TARGET_PREPARATION_INVALID', 'published attestation has an impossible preparation phase');
      }
    }
    return rehydrateDesktopAttestedExportTarget({
      repoRoot: materialization.repoRoot,
      attestationFile,
      shardGeneration,
      shardId,
      pluginRoot: route.pluginRoot,
      pluginDigestRunner,
      readOnlyBackend: backend,
      attemptBinding: bindingAuthority,
      gitRunner,
      sourceFingerprintVerifier,
      sourceFingerprintRevalidator: liveFingerprintRevalidator,
      allowTestBackend,
    });
  }
  if (fs.existsSync(preparationFile)) {
    recoverPreparationSurvivor({ preparationFile, identity: preparationIdentity, backend });
  }
  writePreparationRecord(preparationFile, preparationIdentity, 'CONSTRUCTION_REQUESTED', { create: true });
  targetFault(faultInjector, 'construction-requested', { stem, preparationFile });
  const buildStarted = process.hrtime.bigint();
  let buildPeakRssBytes = process.memoryUsage().rss;
  createFreshDirectory(exportParent, `desktop-export-${stem}-build`);
  const createdDirectories = new Set();
  const sortedEntries = [...shard.paths]
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const built = runDesktopExportStreamingPass({
    entryChunks: [sortedEntries],
    phase: 'build',
    capacity: bindingAuthority.exportCapacity,
    volumes: storageVolumes,
    backend: {
      rootIdentity: () => bigintStatIdentity(fs.lstatSync(staging, { bigint: true })),
      directory({ relativePath }) {
        const directory = ensureExportParent(staging, relativePath, createdDirectories);
        return { identity: bigintStatIdentity(fs.lstatSync(directory, { bigint: true })) };
      },
      file({ entry, begin, write }) {
        return copyExactExportFile(
          materialization.repoRoot, staging, entry, createdDirectories, { begin, write },
        );
      },
    },
  });
  const exportBytes = built.byteCount;
  if (canonicalJson(built.entryDisposition) !== canonicalJson(layout.disposition)) {
    fail('E_SECURITY_TARGET_EXPORT_SET_MISMATCH', 'streamed export disposition does not match its shard');
  }
  buildPeakRssBytes = Math.max(buildPeakRssBytes, built.peakRssBytes);
  sealExportDirectories(staging, createdDirectories);
  writePreparationRecord(preparationFile, preparationIdentity, 'EXPORT_SEALED');
  targetFault(faultInjector, 'export-sealed', { stem, preparationFile, staging });
  writePreparationRecord(preparationFile, preparationIdentity, 'READONLY_SEAL_REQUESTED');
  targetFault(faultInjector, 'readonly-seal-requested', {
    stem, preparationFile, staging, imagePath: imagePathAuthority, mountPath: mountPathAuthority,
  });
  const sealed = backend.seal({
    sourceDirectory: staging,
    mountParent: exportParent,
    stateDirectory: state,
    stem,
  });
  if (sealed === null || typeof sealed !== 'object' || Array.isArray(sealed)
      || typeof sealed.targetPath !== 'string' || typeof sealed.imagePath !== 'string') {
    fail('E_SECURITY_TARGET_MOUNT_INVALID', 'read-only backend returned an invalid sealed target');
  }
  if (backend.productionEligible && (path.resolve(sealed.targetPath) !== mountPathAuthority
      || path.resolve(sealed.imagePath) !== imagePathAuthority)) {
    fail('E_SECURITY_TARGET_MOUNT_INVALID', 'read-only backend returned an unexpected target identity');
  }
  writePreparationRecord(preparationFile, preparationIdentity, 'READONLY_TARGET_READY');
  targetFault(faultInjector, 'readonly-target-ready', {
    stem, preparationFile, targetPath: sealed.targetPath, imagePath: sealed.imagePath,
  });
  const targetPath = realDirectory(sealed.targetPath, 'read-only export target');
  const imagePath = path.resolve(sealed.imagePath);
  if (!isWithin(exportParent, targetPath) || !isWithin(state, imagePath)
      || isWithin(materialization.repoRoot, targetPath) || isWithin(targetPath, materialization.repoRoot)) {
    fail('E_SECURITY_TARGET_STATE_LOCATION', 'read-only export target or image is outside its authority boundary');
  }
  const inspection = sealed.inspection ?? backend.inspect({ targetPath, imagePath });
  const mount = Object.freeze({
    ...mountIdentityFromInspection(backend.backendId, targetPath, inspection, imagePath),
    productionEligible: backend.productionEligible,
  });
  const buildElapsedMs = Number((process.hrtime.bigint() - buildStarted) / 1_000_000n);
  buildPeakRssBytes = Math.max(buildPeakRssBytes, process.memoryUsage().rss);
  const first = snapshotExactExport(targetPath, shard.paths, bindingAuthority.exportCapacity, storageVolumes);
  const second = snapshotExactExport(targetPath, shard.paths, bindingAuthority.exportCapacity, storageVolumes);
  assertStableExportPair(first, second);
  if (first.exportTreeSha256 !== built.exportTreeSha256) {
    fail('E_SECURITY_TARGET_EXPORT_CHANGED', 'sealed export tree differs from the streamed build');
  }
  const metrics = Object.freeze({
    buildElapsedMs,
    buildPeakRssBytes,
    exportBytes,
    exportDirectoryCount: first.directoryCount,
    exportFileCount: first.fileCount,
    snapshotElapsedMs: Math.ceil(first.elapsedMs + second.elapsedMs),
    snapshotPeakRssBytes: Math.max(first.peakRssBytes, second.peakRssBytes),
  });
  if (exportBytes !== expectedExportBytes) fail('E_SECURITY_TARGET_RACE', 'export byte count changed after capacity preflight');
  try { enforceMeasuredCapacity(bindingAuthority.exportCapacity, metrics); }
  catch (capacityError) {
    if (typeof backend.detach === 'function') {
      try { backend.detach({ targetPath }); }
      catch (cleanupError) {
        fail('E_SECURITY_TARGET_READONLY_CLEANUP', 'capacity-HOLD export mount could not be detached', {
          cause: cleanupError?.code ?? cleanupError?.name ?? 'ERROR',
        });
      }
    }
    throw capacityError;
  }
  const directorySnapshotDigest = pluginDirectoryDigest(pluginDigestRunner, route.pluginRoot, targetPath);
  const binding = {
    schema: DESKTOP_EXPORT_ATTESTATION_SCHEMA,
    recordRole: 'authority',
    adapterVersion: TARGET_ADAPTER_VERSION,
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    pluginVersion: route.pluginVersion,
    routeContractSha256: route.routeContractSha256,
    revision: shardGeneration.revision,
    inventorySha256: shardGeneration.inventorySha256,
    shardGenerationId: shardGeneration.generationId,
    shardId,
    pathCount: shard.pathCount,
    pathListSha256: shard.pathListSha256,
    exportTreeSha256: first.exportTreeSha256,
    stableSnapshotSha256: first.stableSnapshotSha256,
    directorySnapshotDigest,
    attemptBinding: bindingAuthority,
    entryDisposition: layout.disposition,
    mount,
    metrics,
  };
  const attestation = Object.freeze({
    ...binding,
    authorityBindingSha256: sha256Hex(canonicalJson(binding)),
  });
  closedExportAttestation(attestation);
  const attestationBytes = `${canonicalJson(attestation)}\n`;
  createPrivateFile(attestationFile, attestationBytes);
  fsyncDirectory(state);
  writePreparationRecord(preparationFile, preparationIdentity, 'ATTESTATION_PUBLISHED');
  targetFault(faultInjector, 'attestation-published', { stem, preparationFile, attestationFile });
  const prepared = Object.freeze({
    adapterVersion: TARGET_ADAPTER_VERSION,
    mode: 'standard',
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    routeContractSha256: route.routeContractSha256,
    pluginVersion: route.pluginVersion,
    revision: materialization.revision,
    inventorySha256: shardGeneration.inventorySha256,
    shardGenerationId: shardGeneration.generationId,
    shardId,
    pathCount: shard.pathCount,
    pathListSha256: shard.pathListSha256,
    targetPath,
    scope: '.',
    targetKind: 'directory_snapshot',
    directorySnapshotDigest,
    exportTreeSha256: first.exportTreeSha256,
    stableSnapshotSha256: first.stableSnapshotSha256,
    attestationFile,
    entryDisposition: layout.disposition,
    productionEligible: backend.productionEligible,
    attemptId: bindingAuthority.attemptId,
    sourceFingerprint: bindingAuthority.sourceFingerprint,
    controlGenerationHash: bindingAuthority.controlGenerationHash,
    budgetId: bindingAuthority.budgetId,
    budgetSha256: bindingAuthority.budgetSha256,
    exportCapacity: bindingAuthority.exportCapacity,
  });
  const internal = {
    type: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    attestationFile,
    shardGeneration,
    shardId,
    pluginRoot: route.pluginRoot,
    pluginDigestRunner,
    backend,
    attemptBinding: bindingAuthority,
    sourceRepository: materialization.repoRoot,
    sourceFingerprintRevalidator: liveFingerprintRevalidator,
  };
  preparedTargetAuthorities.set(prepared, internal);
  verifyDesktopExportAuthority(internal);
  return prepared;
}

export async function rehydrateDesktopAttestedExportTarget({
  repoRoot,
  attestationFile,
  shardGeneration,
  shardId,
  pluginRoot,
  pluginDigestRunner,
  readOnlyBackend,
  attemptBinding,
  gitRunner,
  sourceFingerprintVerifier,
  sourceFingerprintRevalidator,
  allowTestBackend = false,
}) {
  const shard = selectShard(shardGeneration, shardId);
  const bindingAuthority = validateAttemptBinding(attemptBinding, shardGeneration.revision);
  const liveFingerprintRevalidator = sourceFingerprintRevalidator ?? sourceFingerprintVerifier;
  const materialization = await validateGitMaterialization({
    repoRoot, revision: shardGeneration.revision, entries: shard.paths, gitRunner,
  });
  const repository = materialization.repoRoot;
  await verifyBoundSourceFingerprint(sourceFingerprintVerifier, repository, bindingAuthority);
  const backend = validateReadOnlyBackend(readOnlyBackend, { allowTestBackend });
  const { attestation } = readExportAttestation(attestationFile);
  const state = validatePrivateDirectory(path.dirname(attestationFile), 'Desktop export authority directory', [repository]);
  if (!isWithin(state, path.resolve(attestationFile))
      || isWithin(repository, attestation.mount.targetPath) || isWithin(attestation.mount.targetPath, repository)
      || isWithin(state, attestation.mount.targetPath) || isWithin(attestation.mount.targetPath, state)) {
    fail('E_SECURITY_TARGET_STATE_LOCATION', 'rehydrated attestation, target, and worktree are not disjoint');
  }
  const internal = {
    type: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    attestationFile: path.resolve(attestationFile),
    shardGeneration,
    shardId,
    pluginRoot,
    pluginDigestRunner,
    backend,
    attemptBinding: bindingAuthority,
    sourceRepository: repository,
    sourceFingerprintRevalidator: liveFingerprintRevalidator,
  };
  const authority = verifyDesktopExportAuthority(internal);
  const prepared = Object.freeze({
    adapterVersion: TARGET_ADAPTER_VERSION,
    mode: 'standard',
    standardRoute: attestation.standardRoute,
    routeContractSha256: attestation.routeContractSha256,
    pluginVersion: attestation.pluginVersion,
    revision: attestation.revision,
    inventorySha256: attestation.inventorySha256,
    shardGenerationId: attestation.shardGenerationId,
    shardId: attestation.shardId,
    pathCount: attestation.pathCount,
    pathListSha256: attestation.pathListSha256,
    targetPath: attestation.mount.targetPath,
    scope: '.',
    targetKind: 'directory_snapshot',
    directorySnapshotDigest: attestation.directorySnapshotDigest,
    exportTreeSha256: attestation.exportTreeSha256,
    stableSnapshotSha256: attestation.stableSnapshotSha256,
    attestationFile: path.resolve(attestationFile),
    entryDisposition: Object.freeze({ ...attestation.entryDisposition }),
    productionEligible: attestation.mount.productionEligible,
    attemptId: bindingAuthority.attemptId,
    sourceFingerprint: bindingAuthority.sourceFingerprint,
    controlGenerationHash: bindingAuthority.controlGenerationHash,
    budgetId: bindingAuthority.budgetId,
    budgetSha256: bindingAuthority.budgetSha256,
    exportCapacity: bindingAuthority.exportCapacity,
  });
  preparedTargetAuthorities.set(prepared, internal);
  if (authority.artifactSha256 !== sha256Hex(readStableRegularFile(attestationFile, 'Desktop export attestation', { privateFile: true }))) {
    fail('E_SECURITY_TARGET_ATTESTATION_TAMPERED', 'rehydrated attestation changed before capability issue');
  }
  return prepared;
}

function verifySdkTargetAuthority(internal) {
  const route = readPinnedPluginContract(internal.pluginRoot, STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS);
  if (route.routeContractSha256 !== internal.routeContractSha256) {
    fail('E_SECURITY_TARGET_ROUTE_DRIFT', 'SDK exact-path route contract changed');
  }
  validatePrivateFile(internal.targetPathsFile, internal.scopesContents);
  validatePrivateFile(internal.scopeInputFile, internal.scopeRowsText);
  const returnedPaths = parseScopeRows(internal.scopeRowsText);
  if (canonicalJson(returnedPaths) !== canonicalJson(internal.expectedPaths)) {
    fail('E_SECURITY_TARGET_SCOPE_MISMATCH', 'SDK exact-path authority no longer matches its shard');
  }
  return Object.freeze({
    artifactSha256: internal.artifactSha256,
    pathCount: internal.expectedPaths.length,
    pathListSha256: internal.pathListSha256,
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    routeContractSha256: internal.routeContractSha256,
    pluginVersion: PINNED_PLUGIN_VERSION,
    productionEligible: true,
  });
}

export async function prepareStandardTarget({
  repoRoot, shardGeneration, shardId, stateDir, helperScriptPath, gitRunner, scopeRunner,
}) {
  const shard = selectShard(shardGeneration, shardId);
  const materialization = await validateGitMaterialization({
    repoRoot, revision: shardGeneration.revision, entries: shard.paths, gitRunner,
  });
  const state = validateStateDirectory(stateDir, materialization.repoRoot);
  if (typeof helperScriptPath !== 'string' || !path.isAbsolute(helperScriptPath)
      || path.basename(helperScriptPath) !== 'generate_rank_input.py') {
    fail('E_SECURITY_TARGET_HELPER_INVALID', 'generate_rank_input.py must be supplied as an absolute path');
  }
  const helperInput = path.resolve(helperScriptPath);
  let helperMetadata;
  try { helperMetadata = fs.lstatSync(helperInput); }
  catch { fail('E_SECURITY_TARGET_HELPER_INVALID', 'generate_rank_input.py is missing'); }
  if (!helperMetadata.isFile() || helperMetadata.isSymbolicLink()) {
    fail('E_SECURITY_TARGET_HELPER_INVALID', 'generate_rank_input.py must be a real regular file');
  }
  const helper = fs.realpathSync.native(helperInput);
  const pluginRoot = path.dirname(path.dirname(helper));
  const route = readPinnedPluginContract(pluginRoot, STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS);
  if (typeof scopeRunner !== 'function') {
    fail('E_SECURITY_TARGET_RUNNER_REQUIRED', 'an explicit scope helper runner is required');
  }

  const stem = sha256Hex(canonicalJson({
    adapterVersion: TARGET_ADAPTER_VERSION,
    revision: shardGeneration.revision,
    generationId: shardGeneration.generationId,
    shardId,
    pathListSha256: shard.pathListSha256,
  })).slice(0, 24);
  const scopesFile = path.join(state, `standard-scopes-${stem}.json`);
  const scopeOutputFile = path.join(state, `standard-scope-input-${stem}.jsonl`);
  if (!isWithin(state, scopesFile) || !isWithin(state, scopeOutputFile)) {
    fail('E_SECURITY_TARGET_PATH_ESCAPE', 'derived target state path escapes the state directory');
  }
  const expectedPaths = shard.paths.map((entry) => entry.path);
  const scopesContents = `${JSON.stringify(expectedPaths)}\n`;
  const targetArtifactSha256 = sha256Hex(scopesContents);
  createPrivateFile(scopesFile, scopesContents);
  createPrivateFile(scopeOutputFile, '');

  let runnerResult;
  try {
    runnerResult = await scopeRunner({
      command: 'python3',
      args: [
        helper, 'make-repo-scope-input', '--repo', materialization.repoRoot,
        '--scopes-file', scopesFile, '--out', scopeOutputFile,
      ],
      cwd: materialization.repoRoot,
    });
  } catch (error) {
    fail('E_SECURITY_TARGET_SCOPE_HELPER_FAILED', 'scope helper failed', { cause: error?.code ?? error?.name ?? 'ERROR' });
  }
  if (runnerResult === null || typeof runnerResult !== 'object' || runnerResult.status !== 0) {
    fail('E_SECURITY_TARGET_SCOPE_HELPER_FAILED', 'scope helper did not exit successfully');
  }
  validatePrivateFile(scopesFile, scopesContents);
  validatePrivateFile(scopeOutputFile);
  let scopeRowsText;
  try { scopeRowsText = fs.readFileSync(scopeOutputFile, 'utf8'); }
  catch (error) {
    fail('E_SECURITY_TARGET_STATE_INVALID', 'scope helper output is unreadable', { cause: error?.code ?? 'ERROR' });
  }
  const returnedPaths = parseScopeRows(scopeRowsText);
  if (canonicalJson(returnedPaths) !== canonicalJson(expectedPaths)) {
    fail('E_SECURITY_TARGET_SCOPE_MISMATCH', 'scope helper paths do not exactly equal the authorized shard paths', {
      expectedCount: expectedPaths.length, actualCount: returnedPaths.length,
    });
  }
  const artifactSha256 = sha256Hex(canonicalJson({
    adapterVersion: TARGET_ADAPTER_VERSION,
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    pluginVersion: route.pluginVersion,
    routeContractSha256: route.routeContractSha256,
    revision: materialization.revision,
    inventorySha256: shardGeneration.inventorySha256,
    shardGenerationId: shardGeneration.generationId,
    shardId,
    pathCount: expectedPaths.length,
    pathListSha256: shard.pathListSha256,
    targetPathsFileSha256: targetArtifactSha256,
  }));
  const prepared = {
    adapterVersion: TARGET_ADAPTER_VERSION,
    mode: 'standard',
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    routeContractSha256: route.routeContractSha256,
    pluginVersion: route.pluginVersion,
    revision: materialization.revision,
    inventorySha256: shardGeneration.inventorySha256,
    shardGenerationId: shardGeneration.generationId,
    shardId,
    pathCount: expectedPaths.length,
    pathListSha256: shard.pathListSha256,
    targetPath: materialization.repoRoot,
    scope: '.',
    targetPathsFile: scopesFile,
    scopeInputFile: scopeOutputFile,
  };
  const frozen = Object.freeze(prepared);
  preparedTargetAuthorities.set(frozen, {
    type: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    pluginRoot: route.pluginRoot,
    routeContractSha256: route.routeContractSha256,
    targetPathsFile: scopesFile,
    scopeInputFile: scopeOutputFile,
    scopesContents,
    scopeRowsText,
    expectedPaths: Object.freeze([...expectedPaths]),
    pathListSha256: shard.pathListSha256,
    artifactSha256,
  });
  return frozen;
}

function pathInScope(pathname, scope) {
  return scope === '.' || pathname.startsWith(`${scope}/`);
}

function directoryIdentity(directory, label) {
  const metadata = fs.lstatSync(directory, { bigint: true });
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('E_SECURITY_TARGET_PATH_INVALID', `${label} must remain a real directory`);
  }
  return `${metadata.dev}:${metadata.ino}`;
}

function verifyDeepTargetAuthority(internal) {
  const root = realDirectory(internal.repoRoot, 'Deep materialization root');
  if (root !== internal.repoRoot
      || directoryIdentity(root, 'Deep materialization root') !== internal.rootIdentity) {
    fail('E_SECURITY_TARGET_REPOSITORY_MISMATCH', 'Deep materialization root identity changed after preparation');
  }
  const materialization = validateGitMaterializationSync({
    repoRoot: root,
    revision: internal.revision,
    entries: internal.entries,
    gitRunner: internal.gitRunner,
  });
  const { absolutePath } = assertNoSymlinkComponents(root, internal.directoryScope, { directory: true });
  if (absolutePath !== internal.targetPath
      || directoryIdentity(absolutePath, 'Deep target directory') !== internal.targetIdentity) {
    fail('E_SECURITY_TARGET_REPOSITORY_MISMATCH', 'Deep target directory identity changed after preparation');
  }
  const treeWithinScope = materialization.treeEntries
    .filter((entry) => pathInScope(entry.path, internal.directoryScope));
  if (treeWithinScope.some((entry) => !['file', 'executable'].includes(entry.kind))) {
    fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'Deep directory scope contains a symlink or submodule');
  }
  try { assertExactTuples(internal.entries, treeWithinScope, 'Deep directory scope'); }
  catch (error) {
    if (error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_TUPLE_MISMATCH') {
      fail('E_SECURITY_TARGET_NONCONTIGUOUS', 'Deep directory no longer exactly represents the authorized shard tuples', error.details);
    }
    throw error;
  }
  return internal.projection;
}

export async function prepareDeepTarget({
  repoRoot,
  shardGeneration,
  shardId,
  scope,
  gitRunner,
  verificationGitRunner = gitRunner,
}) {
  const shard = selectShard(shardGeneration, shardId);
  if (scope !== '.') assertRepositoryRelativePath(scope, 'Deep directory scope');
  const materialization = await validateGitMaterialization({
    repoRoot, revision: shardGeneration.revision, entries: shard.paths, gitRunner,
  });
  const { absolutePath } = assertNoSymlinkComponents(materialization.repoRoot, scope, { directory: true });
  const treeWithinScope = materialization.treeEntries.filter((entry) => pathInScope(entry.path, scope));
  if (treeWithinScope.some((entry) => !['file', 'executable'].includes(entry.kind))) {
    fail('E_SECURITY_TARGET_KIND_UNSUPPORTED', 'Deep directory scope contains a symlink or submodule');
  }
  if (shard.paths.some((entry) => !pathInScope(entry.path, scope))) {
    fail('E_SECURITY_TARGET_NONCONTIGUOUS', 'Deep shard paths are not all inside the requested real directory');
  }
  try { assertExactTuples(shard.paths, treeWithinScope, 'Deep directory scope'); }
  catch (error) {
    if (error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_TUPLE_MISMATCH') {
      fail('E_SECURITY_TARGET_NONCONTIGUOUS', 'Deep directory does not exactly represent the authorized shard tuples', error.details);
    }
    throw error;
  }
  const prepared = {
    adapterVersion: TARGET_ADAPTER_VERSION,
    mode: 'deep',
    revision: materialization.revision,
    shardId,
    pathCount: shard.pathCount,
    pathListSha256: shard.pathListSha256,
    targetPath: absolutePath,
    scope: '.',
  };
  const internal = Object.freeze({
    type: 'deep-real-directory',
    repoRoot: materialization.repoRoot,
    rootIdentity: directoryIdentity(materialization.repoRoot, 'Deep materialization root'),
    targetPath: absolutePath,
    targetIdentity: directoryIdentity(absolutePath, 'Deep target directory'),
    directoryScope: scope,
    revision: materialization.revision,
    entries: Object.freeze(shard.paths.map((entry) => Object.freeze(publicTuple(entry)))),
    gitRunner: verificationGitRunner,
    projection: Object.freeze({
      artifactSha256: sha256Hex(canonicalJson({
      adapterVersion: TARGET_ADAPTER_VERSION,
      revision: materialization.revision,
      shardId,
      pathListSha256: shard.pathListSha256,
      directoryScope: scope,
      })),
      pathCount: shard.pathCount,
      pathListSha256: shard.pathListSha256,
    }),
  });
  verifyDeepTargetAuthority(internal);
  const frozen = Object.freeze(prepared);
  preparedTargetAuthorities.set(frozen, internal);
  return frozen;
}

export function verifyPreparedTarget(prepared) {
  const internal = preparedTargetAuthorities.get(prepared);
  if (internal === undefined) {
    fail('E_SECURITY_TARGET_UNVERIFIED', 'target was not prepared and verified by this adapter instance');
  }
  if (internal.type === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS) return verifySdkTargetAuthority(internal);
  if (internal.type === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT) return verifyDesktopExportAuthority(internal);
  if (internal.type === 'deep-real-directory') return verifyDeepTargetAuthority(internal);
  fail('E_SECURITY_TARGET_UNVERIFIED', 'target authority type is invalid');
}
