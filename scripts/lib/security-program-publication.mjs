import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {
  SecurityProgramError,
  assertClosedSchema,
  assertRepositoryRelativePath,
  canonicalJson,
  logicalArtifactRef,
  parseStrictJson,
  sha256Hex,
} from './security-program-json.mjs';

export const BUNDLE_RECEIPT_SCHEMA = 'setjoin.security-program.bundle-receipt/v1';
export const GENERATION_RECEIPT_SCHEMA = 'setjoin.security-program.generation-receipt/v1';
export const LATEST_POINTER_SCHEMA = 'setjoin.security-program.latest-pointer/v1';
export const VERIFIED_GENERATION_SCHEMA = 'setjoin.security-program.verified-generation/v1';

const PUBLICATION_LOCK_OWNER_SCHEMA = 'setjoin.security-program.publication-lock-owner/v1';
const PUBLICATION_LOCK_OWNER_FILE = 'owner.json';
const PUBLICATION_SURVIVOR_SCHEMA = 'setjoin.security-program.publication-survivor/v1';
const PUBLICATION_SURVIVOR_FILE = 'publication-survivor.json';
const PUBLICATION_QUARANTINE_SCHEMA = 'setjoin.security-program.publication-quarantine/v1';
const PROCESS_INSTANCE_NONCE = crypto.randomBytes(32).toString('hex');
const PROCESS_STARTED_AT = new Date().toISOString();

function fail(code, message, details) {
  throw new SecurityProgramError(code, message, details);
}

function safeId(value, name) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} is invalid`);
  }
  return value;
}

function validTime(value, name) {
  const match = typeof value === 'string'
    ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3}|\d{6})Z$/.exec(value)
    : null;
  if (match === null) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a canonical UTC timestamp`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1]
      || hour > 23 || minute > 59 || second > 59 || !Number.isFinite(Date.parse(value))) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a canonical UTC timestamp`);
  }
  return value;
}

function exactMode(stat) {
  return Number(stat.mode & 0o777n);
}

function assertRealDirectory(directory, name, expectedMode = undefined) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a real directory`);
  if (expectedMode !== undefined && (stat.mode & 0o777) !== expectedMode) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must have sealed mode ${expectedMode.toString(8)}`);
  }
}

function assertRegularFile(filename, name, expectedMode = undefined) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink()) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a regular file`);
  if (expectedMode !== undefined && (stat.mode & 0o777) !== expectedMode) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must have sealed mode ${expectedMode.toString(8)}`);
  }
}

function readCanonicalJsonFile(filename, name) {
  const text = fs.readFileSync(filename, 'utf8');
  const value = parseStrictJson(text);
  if (text !== canonicalJson(value)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} is not canonical JSON`);
  }
  return value;
}

function readStableCanonicalJsonFile(filename, name, expectedMode) {
  const beforePath = fs.lstatSync(filename, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink() || exactMode(beforePath) !== expectedMode) {
    fail('E_SECURITY_PROGRAM_LIVE_LEASE', `${name} is not a canonical lock owner file`);
  }
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFileSnapshot(beforePath, before)) {
      fail('E_SECURITY_PROGRAM_LIVE_LEASE', `${name} changed before inspection`);
    }
    const text = fs.readFileSync(descriptor, 'utf8');
    const after = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(filename, { bigint: true });
    if (!sameFileSnapshot(before, after) || !sameFileSnapshot(after, afterPath)) {
      fail('E_SECURITY_PROGRAM_LIVE_LEASE', `${name} changed during inspection`);
    }
    const value = parseStrictJson(text);
    if (text !== canonicalJson(value)) {
      fail('E_SECURITY_PROGRAM_LIVE_LEASE', `${name} is not canonical JSON`);
    }
    return { value, stat: after };
  } finally {
    fs.closeSync(descriptor);
  }
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function ensureDirectory(directory, mode = 0o755, enforceMode = false) {
  fs.mkdirSync(directory, { recursive: true, mode });
  if (fs.lstatSync(directory).isSymbolicLink()) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication directory must not be a symlink');
  if (enforceMode) fs.chmodSync(directory, mode);
}

function fsyncDirectoryTree(root) {
  const directories = [];
  function collect(directory) {
    directories.push(directory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && !entry.isSymbolicLink()) collect(path.join(directory, entry.name));
    }
  }
  collect(root);
  for (const directory of directories.reverse()) fsyncDirectory(directory);
}

function inject(faultInjector, point, context = {}) {
  if (faultInjector) faultInjector(point, context);
}

function writeExclusiveDurable(filename, bytes, mode = 0o600, directoryMode = 0o755) {
  ensureDirectory(path.dirname(filename), directoryMode);
  const descriptor = fs.openSync(filename, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, mode);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(filename));
}

function walkRegularFiles(root, { expectedDirectoryMode, expectedFileMode } = {}) {
  const output = [];
  function walk(directory, prefix) {
    if (expectedDirectoryMode !== undefined) assertRealDirectory(directory, 'published directory', expectedDirectoryMode);
    const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)));
    for (const entry of entries) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      assertRepositoryRelativePath(relative, 'published file path');
      const filename = path.join(directory, entry.name);
      const stat = fs.lstatSync(filename);
      if (stat.isSymbolicLink()) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `published input contains symlink ${relative}`);
      if (stat.isDirectory()) walk(filename, relative);
      else if (stat.isFile()) {
        if (expectedFileMode !== undefined && (stat.mode & 0o777) !== expectedFileMode) {
          fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `published file ${relative} is not sealed read-only`);
        }
        output.push({ relative, filename, mode: 0o600 });
      }
      else fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `published input contains unsupported entry ${relative}`);
    }
  }
  walk(root, '');
  return output;
}

function sealReadOnlyTree(root) {
  const files = [];
  const directories = [];
  function collect(directory) {
    const metadata = fs.lstatSync(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication seal encountered a non-directory root');
    }
    directories.push(directory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      const stat = fs.lstatSync(filename);
      if (stat.isSymbolicLink()) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication seal encountered a symlink');
      if (stat.isDirectory()) collect(filename);
      else if (stat.isFile()) files.push(filename);
      else fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication seal encountered an unsupported entry');
    }
  }
  collect(root);
  for (const filename of files) {
    const beforePath = fs.lstatSync(filename, { bigint: true });
    const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const before = fs.fstatSync(descriptor, { bigint: true });
      if (!before.isFile() || beforePath.dev !== before.dev || beforePath.ino !== before.ino) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'published file changed before sealing');
      }
      fs.fchmodSync(descriptor, 0o400);
      const stat = fs.fstatSync(descriptor, { bigint: true });
      if (!stat.isFile() || exactMode(stat) !== 0o400) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'published file did not seal read-only');
      }
      fs.fsyncSync(descriptor);
      const afterPath = fs.lstatSync(filename, { bigint: true });
      if (!afterPath.isFile() || afterPath.isSymbolicLink()
          || stat.dev !== afterPath.dev || stat.ino !== afterPath.ino || exactMode(afterPath) !== 0o400) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'published file changed while sealing');
      }
    } finally {
      fs.closeSync(descriptor);
    }
  }
  for (const directory of directories.reverse()) {
    const beforePath = fs.lstatSync(directory, { bigint: true });
    const descriptor = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const before = fs.fstatSync(descriptor, { bigint: true });
      if (!before.isDirectory() || beforePath.dev !== before.dev || beforePath.ino !== before.ino) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'published directory changed before sealing');
      }
      fs.fchmodSync(descriptor, 0o500);
      fs.fsyncSync(descriptor);
      const stat = fs.fstatSync(descriptor, { bigint: true });
      const afterPath = fs.lstatSync(directory, { bigint: true });
      if (!stat.isDirectory() || !afterPath.isDirectory() || afterPath.isSymbolicLink()
          || stat.dev !== afterPath.dev || stat.ino !== afterPath.ino
          || exactMode(stat) !== 0o500 || exactMode(afterPath) !== 0o500) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'published directory changed while sealing');
      }
    } finally {
      fs.closeSync(descriptor);
    }
  }
}

function sealReadOnlyFile(filename, name) {
  const beforePath = fs.lstatSync(filename, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink()) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} must be a regular file`);
  }
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.dev !== beforePath.dev || before.ino !== beforePath.ino) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} changed before sealing`);
    }
    fs.fchmodSync(descriptor, 0o400);
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || exactMode(stat) !== 0o400) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} did not seal read-only`);
    }
    fs.fsyncSync(descriptor);
    const afterPath = fs.lstatSync(filename, { bigint: true });
    if (!afterPath.isFile() || afterPath.isSymbolicLink()
        || stat.dev !== afterPath.dev || stat.ino !== afterPath.ino || exactMode(afterPath) !== 0o400) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} changed while sealing`);
    }
  } finally {
    fs.closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(filename));
}

function copyFileHashed(source, destination, mode, faultInjector, relative) {
  ensureDirectory(path.dirname(destination), 0o700);
  const sourcePathBefore = fs.lstatSync(source, { bigint: true });
  if (!sourcePathBefore.isFile() || sourcePathBefore.isSymbolicLink()) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `bundle source is not a regular file: ${relative}`);
  }
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const input = fs.openSync(source, fs.constants.O_RDONLY | noFollow);
  const sourceBefore = fs.fstatSync(input, { bigint: true });
  if (!sameFileSnapshot(sourcePathBefore, sourceBefore)) {
    fs.closeSync(input);
    fail('E_SECURITY_PROGRAM_SOURCE_CHANGED', `bundle source changed before copying ${relative}`);
  }
  let output;
  // Use a streaming read/write loop and update the digest from exactly the bytes
  // accepted by the destination descriptor.
  const digest = createSha256();
  let size = 0;
  try {
    output = fs.openSync(destination, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, mode);
    const buffer = Buffer.allocUnsafe(64 * 1024);
    while (true) {
      const read = fs.readSync(input, buffer, 0, buffer.length, null);
      if (read === 0) break;
      let offset = 0;
      while (offset < read) offset += fs.writeSync(output, buffer, offset, read - offset);
      digest.update(buffer.subarray(0, read));
      size += read;
      inject(faultInjector, 'after-copy-chunk', { artifactRef: `bundle-file:${relative}`, size });
    }
    fs.fsyncSync(output);
    const sourceAfter = fs.fstatSync(input, { bigint: true });
    const sourcePathAfter = fs.lstatSync(source, { bigint: true });
    if (!sourcePathAfter.isFile() || sourcePathAfter.isSymbolicLink()
        || !sameFileSnapshot(sourceBefore, sourceAfter)
        || !sameFileSnapshot(sourceAfter, sourcePathAfter)) {
      fail('E_SECURITY_PROGRAM_SOURCE_CHANGED', `bundle source changed while copying ${relative}`);
    }
  } finally {
    fs.closeSync(input);
    if (output !== undefined) fs.closeSync(output);
  }
  inject(faultInjector, 'after-copy-file-fsync', { artifactRef: `bundle-file:${relative}`, size });
  fsyncDirectory(path.dirname(destination));
  return { path: relative, sha256: digest.digest('hex'), size };
}

function createSha256() { return crypto.createHash('sha256'); }

function sameFileSnapshot(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.size === after.size
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs;
}

function sameObjectIdentity(before, after) {
  return before.dev === after.dev && before.ino === after.ino;
}

function hashRegularFileStable(filename, logicalPath) {
  const beforePath = fs.lstatSync(filename, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink()) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `evidence file is not regular: ${logicalPath}`);
  }
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | noFollow);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFileSnapshot(beforePath, before)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `evidence file changed before verification: ${logicalPath}`);
    const digest = createSha256();
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let size = 0;
    while (true) {
      const read = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (read === 0) break;
      digest.update(buffer.subarray(0, read));
      size += read;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(filename, { bigint: true });
    if (!sameFileSnapshot(before, after) || !sameFileSnapshot(after, afterPath)) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `evidence file changed during verification: ${logicalPath}`);
    }
    return { sha256: digest.digest('hex'), size };
  } finally {
    fs.closeSync(descriptor);
  }
}

function digestEntries(entries) {
  return sha256Hex(canonicalJson(entries));
}

function publicationSurvivorMarker(kind, publicationId, receipt, lockOwner) {
  return {
    schema: PUBLICATION_SURVIVOR_SCHEMA,
    kind,
    publicationId,
    receiptSha256: sha256Hex(canonicalJson(receipt)),
    lockOwnerSha256: sha256Hex(canonicalJson(lockOwner)),
  };
}

function validatePublicationSurvivorMarker(marker, { kind, publicationId, receipt, lockOwner }) {
  assertClosedSchema(marker, {
    schema: PUBLICATION_SURVIVOR_SCHEMA,
    required: ['kind', 'publicationId', 'receiptSha256', 'lockOwnerSha256'],
    name: 'publication survivor marker',
  });
  if (marker.kind !== kind || marker.publicationId !== publicationId
      || marker.receiptSha256 !== sha256Hex(canonicalJson(receipt))
      || !/^[0-9a-f]{64}$/.test(marker.lockOwnerSha256)
      || (lockOwner !== undefined
        && marker.lockOwnerSha256 !== sha256Hex(canonicalJson(lockOwner)))) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication survivor marker is invalid');
  }
  return marker;
}

function snapshotProtocolSurvivor(root, { directoryModes, fileModes }) {
  const entries = [];
  function walk(directory, relative) {
    const metadata = fs.lstatSync(directory, { bigint: true });
    if (!metadata.isDirectory() || metadata.isSymbolicLink()
        || !directoryModes.includes(exactMode(metadata))) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication survivor directory is not protocol-attributable');
    }
    entries.push({
      path: relative, kind: 'directory', mode: exactMode(metadata),
      device: String(metadata.dev), inode: String(metadata.ino),
      size: String(metadata.size), mtimeNs: String(metadata.mtimeNs), ctimeNs: String(metadata.ctimeNs),
    });
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => Buffer.from(left.name).compare(Buffer.from(right.name)))) {
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
      assertRepositoryRelativePath(childRelative, 'publication survivor path');
      const filename = path.join(directory, entry.name);
      const stat = fs.lstatSync(filename, { bigint: true });
      if (stat.isSymbolicLink()) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication survivor contains a symlink');
      if (stat.isDirectory()) walk(filename, childRelative);
      else if (stat.isFile() && fileModes.includes(exactMode(stat))) {
        if (stat.nlink !== 1n) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication survivor contains a hard link');
        const digest = hashRegularFileStable(filename, childRelative);
        entries.push({
          path: childRelative, kind: 'file', mode: exactMode(stat),
          device: String(stat.dev), inode: String(stat.ino),
          size: digest.size, sha256: digest.sha256,
          mtimeNs: String(stat.mtimeNs), ctimeNs: String(stat.ctimeNs),
        });
      } else fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'publication survivor contains a non-protocol entry');
    }
  }
  walk(root, '');
  return entries;
}

function writeQuarantineReceipt(parent, quarantineBase, fields) {
  const receiptPath = path.join(parent, `${quarantineBase}.recovery.json`);
  const receipt = {
    schema: PUBLICATION_QUARANTINE_SCHEMA,
    reason: 'crash-after-canonical-rename-before-seal',
    quarantinedAt: new Date().toISOString(),
    ...fields,
  };
  writeExclusiveDurable(receiptPath, canonicalJson(receipt), 0o600);
  sealReadOnlyFile(receiptPath, 'publication quarantine receipt');
  return receiptPath;
}

function bundlePublicationResult(receipt) {
  return {
    artifactRef: logicalArtifactRef('attempt', receipt.attemptId),
    bundleHash: receipt.bundleHash,
    fileCount: receipt.files.length,
  };
}

function snapshotBundleSource(sourceDirectory) {
  const before = fs.lstatSync(sourceDirectory, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle source must be a real directory');
  }
  const files = walkRegularFiles(sourceDirectory).map((input) => ({
    schema: 'setjoin.security-program.file-hash/v1',
    path: input.relative,
    ...hashRegularFileStable(input.filename, input.relative),
  }));
  const after = fs.lstatSync(sourceDirectory, { bigint: true });
  if (!after.isDirectory() || after.isSymbolicLink() || !sameFileSnapshot(before, after)) {
    fail('E_SECURITY_PROGRAM_SOURCE_CHANGED', 'bundle source changed while verifying replay');
  }
  return files;
}

function digestGeneration({ generationId, predecessorGenerationId, predecessorGenerationHash, createdAt, files }) {
  return sha256Hex(canonicalJson({
    schema: 'setjoin.security-program.generation-content/v1',
    generationId,
    predecessorGenerationId,
    predecessorGenerationHash,
    createdAt,
    files,
  }));
}

function validatePredecessor(record, name) {
  const root = record.predecessorGenerationId === null && record.predecessorGenerationHash === null;
  if (root) return;
  if (record.predecessorGenerationId === null || record.predecessorGenerationHash === null) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} predecessor identity is incomplete`);
  }
  safeId(record.predecessorGenerationId, `${name} predecessorGenerationId`);
  if (!/^[0-9a-f]{64}$/.test(record.predecessorGenerationHash)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `${name} predecessorGenerationHash is invalid`);
  }
}

function lockHold(message) {
  fail('E_SECURITY_PROGRAM_LIVE_LEASE', message, { disposition: 'HOLD' });
}

function publicationLockOwner(lockName) {
  return {
    schema: PUBLICATION_LOCK_OWNER_SCHEMA,
    lockName,
    hostId: os.hostname(),
    processId: process.pid,
    processInstanceNonce: PROCESS_INSTANCE_NONCE,
    processStartedAt: PROCESS_STARTED_AT,
    acquiredAt: new Date().toISOString(),
  };
}

function validatePublicationLockOwner(owner, lockName) {
  assertClosedSchema(owner, {
    schema: PUBLICATION_LOCK_OWNER_SCHEMA,
    required: ['lockName', 'hostId', 'processId', 'processInstanceNonce', 'processStartedAt', 'acquiredAt'],
    name: 'publication lock owner',
  });
  if (owner.lockName !== lockName || typeof owner.hostId !== 'string'
      || owner.hostId.length === 0 || owner.hostId.length > 255
      || !Number.isSafeInteger(owner.processId) || owner.processId <= 0
      || !/^[0-9a-f]{64}$/.test(owner.processInstanceNonce)) {
    lockHold('publication lock owner metadata is invalid');
  }
  validTime(owner.processStartedAt, 'publication lock processStartedAt');
  validTime(owner.acquiredAt, 'publication lock acquiredAt');
  return owner;
}

function inspectLocalProcess(processId) {
  try {
    process.kill(processId, 0);
    return 'alive';
  } catch (error) {
    if (error?.code === 'ESRCH') return 'dead';
    return 'ambiguous';
  }
}

function inspectPublicationLock(lockDirectory, lockName) {
  const directory = fs.lstatSync(lockDirectory, { bigint: true });
  if (!directory.isDirectory() || directory.isSymbolicLink() || exactMode(directory) !== 0o700) {
    lockHold('publication lock directory is malformed or unsealed');
  }
  const ownerPath = path.join(lockDirectory, PUBLICATION_LOCK_OWNER_FILE);
  const ownerFile = readStableCanonicalJsonFile(ownerPath, 'publication lock owner', 0o600);
  const owner = validatePublicationLockOwner(ownerFile.value, lockName);
  const after = fs.lstatSync(lockDirectory, { bigint: true });
  if (!sameFileSnapshot(directory, after)) lockHold('publication lock directory changed during inspection');
  return { directory, owner, ownerPath, ownerFile: ownerFile.stat };
}

function assertDeadLocalLock(owner) {
  if (owner.hostId !== os.hostname()) lockHold('publication lock belongs to another or unknown host');
  if (inspectLocalProcess(owner.processId) !== 'dead') {
    lockHold('publication lock owner is live or process liveness is ambiguous');
  }
}

function recoverDefinitelyStaleLock(parent, lockDirectory, lockName, faultInjector) {
  try {
    const inspected = inspectPublicationLock(lockDirectory, lockName);
    assertDeadLocalLock(inspected.owner);
    inject(faultInjector, 'after-publication-lock-inspected', { lockName });
    const confirmed = inspectPublicationLock(lockDirectory, lockName);
    if (!sameFileSnapshot(inspected.directory, confirmed.directory)
        || !sameFileSnapshot(inspected.ownerFile, confirmed.ownerFile)
        || canonicalJson(inspected.owner) !== canonicalJson(confirmed.owner)) {
      lockHold('publication lock changed before stale recovery');
    }
    assertDeadLocalLock(confirmed.owner);
    inject(faultInjector, 'before-publication-lock-quarantine', { lockName });
    const finalCheck = inspectPublicationLock(lockDirectory, lockName);
    if (!sameFileSnapshot(confirmed.directory, finalCheck.directory)
        || !sameFileSnapshot(confirmed.ownerFile, finalCheck.ownerFile)
        || canonicalJson(confirmed.owner) !== canonicalJson(finalCheck.owner)) {
      lockHold('publication lock changed before quarantine');
    }
    assertDeadLocalLock(finalCheck.owner);
    const quarantineId = sha256Hex(canonicalJson({
      schema: 'setjoin.security-program.stale-lock-address/v1',
      owner: finalCheck.owner,
      recoveryNonce: crypto.randomBytes(32).toString('hex'),
    }));
    const quarantinePath = path.join(parent, `.quarantine-stale-lock-${quarantineId}`);
    if (fs.existsSync(quarantinePath)) lockHold('stale publication lock quarantine address already exists');
    try {
      fs.renameSync(lockDirectory, quarantinePath);
    } catch {
      lockHold('publication lock raced during stale recovery');
    }
    fsyncDirectory(parent);
    const quarantined = fs.lstatSync(quarantinePath, { bigint: true });
    if (!sameObjectIdentity(finalCheck.directory, quarantined)) {
      lockHold('quarantined publication lock identity changed');
    }
    const quarantinedOwnerFile = readStableCanonicalJsonFile(
      path.join(quarantinePath, PUBLICATION_LOCK_OWNER_FILE),
      'quarantined publication lock owner',
      0o600,
    );
    const quarantinedOwner = validatePublicationLockOwner(quarantinedOwnerFile.value, lockName);
    if (!sameFileSnapshot(finalCheck.ownerFile, quarantinedOwnerFile.stat)) {
      lockHold('quarantined publication lock owner identity changed');
    }
    if (canonicalJson(quarantinedOwner) !== canonicalJson(finalCheck.owner)) {
      lockHold('quarantined publication lock owner changed');
    }
    return { owner: quarantinedOwner, quarantinePath };
  } catch (error) {
    if (error instanceof SecurityProgramError && error.code === 'E_SECURITY_PROGRAM_LIVE_LEASE') throw error;
    lockHold('publication lock cannot be safely classified for recovery');
  }
}

function createPublicationLock(parent, lockDirectory, lockName) {
  const owner = publicationLockOwner(lockName);
  fs.mkdirSync(lockDirectory, { mode: 0o700 });
  const createdDirectory = fs.lstatSync(lockDirectory, { bigint: true });
  if (!createdDirectory.isDirectory() || createdDirectory.isSymbolicLink() || exactMode(createdDirectory) !== 0o700) {
    lockHold('new publication lock directory is invalid');
  }
  writeExclusiveDurable(
    path.join(lockDirectory, PUBLICATION_LOCK_OWNER_FILE),
    canonicalJson(owner),
    0o600,
    0o700,
  );
  fsyncDirectory(lockDirectory);
  fsyncDirectory(parent);
  const confirmed = inspectPublicationLock(lockDirectory, lockName);
  if (!sameObjectIdentity(createdDirectory, confirmed.directory)
      || canonicalJson(owner) !== canonicalJson(confirmed.owner)) {
    lockHold('new publication lock changed during acquisition');
  }
  return { parent, lockDirectory, lockName, directory: confirmed.directory, owner };
}

function acquirePublicationLock(parent, lockName, faultInjector) {
  ensureDirectory(parent);
  const lockDirectory = path.join(parent, lockName);
  try {
    return { ...createPublicationLock(parent, lockDirectory, lockName), recoveredOwner: null };
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const recovered = recoverDefinitelyStaleLock(parent, lockDirectory, lockName, faultInjector);
  try {
    return {
      ...createPublicationLock(parent, lockDirectory, lockName),
      recoveredOwner: recovered.owner,
      recoveredLockQuarantine: recovered.quarantinePath,
    };
  } catch (error) {
    if (error?.code === 'EEXIST') lockHold('publication lock was concurrently reacquired');
    throw error;
  }
}

function releasePublicationLock(lock) {
  try {
    const confirmed = inspectPublicationLock(lock.lockDirectory, lock.lockName);
    if (!sameFileSnapshot(lock.directory, confirmed.directory)
        || canonicalJson(lock.owner) !== canonicalJson(confirmed.owner)) return;
    fs.unlinkSync(confirmed.ownerPath);
    fsyncDirectory(lock.lockDirectory);
    const emptyDirectory = fs.lstatSync(lock.lockDirectory, { bigint: true });
    if (!emptyDirectory.isDirectory() || emptyDirectory.isSymbolicLink()
        || !sameObjectIdentity(emptyDirectory, lock.directory)
        || fs.readdirSync(lock.lockDirectory).length !== 0) return;
    fs.rmdirSync(lock.lockDirectory);
    fsyncDirectory(lock.parent);
  } catch { /* Retain anything that cannot be proven to be the lock we acquired. */ }
}

function withExclusiveLock(parent, lockName, faultInjector, action) {
  const lock = acquirePublicationLock(parent, lockName, faultInjector);
  try { return action(lock); }
  finally { releasePublicationLock(lock); }
}

export function validateBundleReceipt(receipt) {
  assertClosedSchema(receipt, {
    schema: BUNDLE_RECEIPT_SCHEMA,
    required: ['attemptId', 'createdAt', 'files', 'bundleHash'],
    name: 'bundle receipt',
  });
  safeId(receipt.attemptId, 'attemptId');
  validTime(receipt.createdAt, 'bundle createdAt');
  if (!Array.isArray(receipt.files)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle receipt files must be an array');
  for (const entry of receipt.files) {
    assertClosedSchema(entry, {
      schema: 'setjoin.security-program.file-hash/v1',
      required: ['path', 'sha256', 'size'],
      name: 'file hash',
    });
    assertRepositoryRelativePath(entry.path);
    if (!/^[0-9a-f]{64}$/.test(entry.sha256) || !Number.isSafeInteger(entry.size) || entry.size < 0) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle receipt contains invalid file hash');
    }
  }
  if (receipt.bundleHash !== digestEntries(receipt.files)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle receipt hash is invalid');
  return receipt;
}

export function publishImmutableBundle({
  sourceDirectory,
  attemptsDirectory,
  attemptId,
  now = new Date(),
  faultInjector,
}) {
  safeId(attemptId, 'attemptId');
  const sourceStat = fs.lstatSync(sourceDirectory);
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle source must be a real directory');
  ensureDirectory(attemptsDirectory, 0o700, true);
  return withExclusiveLock(attemptsDirectory, `.publish-lock-${attemptId}`, faultInjector, (publicationLock) => {
    const temporary = path.join(attemptsDirectory, `.tmp-${attemptId}`);
    const final = path.join(attemptsDirectory, attemptId);
    if (fs.existsSync(final)) {
      if (fs.existsSync(temporary)) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'immutable attempt bundle has a conflicting partial survivor');
      }
      try {
        const receipt = verifyImmutableBundle({ attemptsDirectory, attemptId });
        const sourceFiles = snapshotBundleSource(sourceDirectory);
        if (canonicalJson(sourceFiles) !== canonicalJson(receipt.files)) {
          fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'immutable attempt bundle conflicts with replay source');
        }
        return bundlePublicationResult(receipt);
      } catch (error) {
        recoverBundleCrashSurvivor({
          final, attemptsDirectory, attemptId, sourceDirectory, publicationLock, faultInjector,
        });
      }
    }
    try {
      fs.mkdirSync(temporary, { mode: 0o700 });
      fsyncDirectory(attemptsDirectory);
      inject(faultInjector, 'after-bundle-temp-created', { artifactRef: logicalArtifactRef('attempt', attemptId) });
      const canonicalDirectory = path.join(temporary, 'canonical');
      fs.mkdirSync(canonicalDirectory, { mode: 0o700 });
      const files = [];
      for (const input of walkRegularFiles(sourceDirectory)) {
        files.push({
          schema: 'setjoin.security-program.file-hash/v1',
          ...copyFileHashed(input.filename, path.join(canonicalDirectory, ...input.relative.split('/')), input.mode, faultInjector, input.relative),
        });
      }
      fsyncDirectoryTree(canonicalDirectory);
      inject(faultInjector, 'after-bundle-canonical-fsync', { fileCount: files.length });
      const receipt = validateBundleReceipt({
        schema: BUNDLE_RECEIPT_SCHEMA,
        attemptId,
        createdAt: now.toISOString(),
        files,
        bundleHash: digestEntries(files),
      });
      writeExclusiveDurable(path.join(temporary, 'bundle-receipt.json'), canonicalJson(receipt), 0o600, 0o700);
      writeExclusiveDurable(
        path.join(temporary, PUBLICATION_SURVIVOR_FILE),
        canonicalJson(publicationSurvivorMarker('bundle', attemptId, receipt, publicationLock.owner)),
        0o600,
        0o700,
      );
      inject(faultInjector, 'after-bundle-receipt-fsync', { bundleHash: receipt.bundleHash });
      fsyncDirectoryTree(temporary);
      inject(faultInjector, 'after-bundle-temp-fsync', { bundleHash: receipt.bundleHash });
      fs.renameSync(temporary, final);
      inject(faultInjector, 'after-bundle-rename', { bundleHash: receipt.bundleHash });
      sealReadOnlyTree(final);
      inject(faultInjector, 'after-bundle-sealed', { bundleHash: receipt.bundleHash });
      fsyncDirectory(attemptsDirectory);
      inject(faultInjector, 'after-bundle-parent-fsync', { bundleHash: receipt.bundleHash });
      const verified = verifyImmutableBundle({ attemptsDirectory, attemptId });
      return bundlePublicationResult(verified);
    } catch (error) {
      if (fs.existsSync(temporary) && !fs.existsSync(final)) {
        const quarantine = path.join(attemptsDirectory, `.quarantine-${attemptId}`);
        if (!fs.existsSync(quarantine)) {
          try { fs.renameSync(temporary, quarantine); fsyncDirectory(attemptsDirectory); }
          catch { /* retaining the exclusive temp also fails closed */ }
        }
      }
      throw error;
    }
  });
}

export function verifyImmutableBundle({ attemptsDirectory, attemptId }) {
  safeId(attemptId, 'attemptId');
  return verifyBundleDirectory(path.join(attemptsDirectory, attemptId), attemptId);
}

function verifyBundleDirectory(final, attemptId) {
  assertRealDirectory(final, 'immutable bundle', 0o500);
  const receiptPath = path.join(final, 'bundle-receipt.json');
  assertRegularFile(receiptPath, 'bundle receipt', 0o400);
  const receipt = validateBundleReceipt(readCanonicalJsonFile(receiptPath, 'bundle receipt'));
  if (receipt.attemptId !== attemptId) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle attempt identity mismatch');
  const markerPath = path.join(final, PUBLICATION_SURVIVOR_FILE);
  assertRegularFile(markerPath, 'bundle publication survivor marker', 0o400);
  validatePublicationSurvivorMarker(
    readCanonicalJsonFile(markerPath, 'bundle publication survivor marker'),
    { kind: 'bundle', publicationId: attemptId, receipt },
  );
  const actualPaths = walkRegularFiles(path.join(final, 'canonical'), {
    expectedDirectoryMode: 0o500, expectedFileMode: 0o400,
  }).map((entry) => entry.relative)
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  const receiptPaths = receipt.files.map((entry) => entry.path)
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  if (canonicalJson(actualPaths) !== canonicalJson(receiptPaths)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle file set does not match receipt');
  for (const entry of receipt.files) {
    const filename = path.join(final, 'canonical', ...entry.path.split('/'));
    const actual = hashRegularFileStable(filename, entry.path);
    if (actual.size !== entry.size || actual.sha256 !== entry.sha256) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `bundle file verification failed for ${entry.path}`);
    }
  }
  return receipt;
}

function inspectBundleCrashSurvivor({ final, attemptId, sourceDirectory, recoveredOwner }) {
  if (recoveredOwner === null || recoveredOwner === undefined) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed bundle evidence has no attributable dead publication owner');
  }
  const snapshot = snapshotProtocolSurvivor(final, {
    directoryModes: [0o500, 0o700], fileModes: [0o400, 0o600],
  });
  const receipt = validateBundleReceipt(readCanonicalJsonFile(
    path.join(final, 'bundle-receipt.json'), 'unsealed bundle receipt',
  ));
  if (receipt.attemptId !== attemptId) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed bundle identity mismatch');
  validatePublicationSurvivorMarker(
    readCanonicalJsonFile(path.join(final, PUBLICATION_SURVIVOR_FILE), 'unsealed bundle survivor marker'),
    { kind: 'bundle', publicationId: attemptId, receipt, lockOwner: recoveredOwner },
  );
  const sourceFiles = snapshotBundleSource(sourceDirectory);
  if (canonicalJson(sourceFiles) !== canonicalJson(receipt.files)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed bundle conflicts with replay source');
  }
  const fileEntries = new Map(snapshot.filter((entry) => entry.kind === 'file').map((entry) => [entry.path, entry]));
  const expectedFiles = new Set(['bundle-receipt.json', PUBLICATION_SURVIVOR_FILE]);
  for (const entry of receipt.files) {
    const relative = `canonical/${entry.path}`;
    expectedFiles.add(relative);
    const actual = fileEntries.get(relative);
    if (actual === undefined || actual.size !== entry.size || actual.sha256 !== entry.sha256) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed bundle content does not match its receipt');
    }
  }
  if (canonicalJson([...fileEntries.keys()].sort()) !== canonicalJson([...expectedFiles].sort())) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed bundle contains an unexpected file');
  }
  const expectedDirectories = new Set(['', 'canonical']);
  for (const filename of expectedFiles) {
    let directory = path.posix.dirname(filename);
    while (directory !== '.') {
      expectedDirectories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  const actualDirectories = snapshot.filter((entry) => entry.kind === 'directory').map((entry) => entry.path).sort();
  if (canonicalJson(actualDirectories) !== canonicalJson([...expectedDirectories].sort())) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed bundle contains an unexpected directory');
  }
  return { snapshot, receipt };
}

function recoverBundleCrashSurvivor({
  final, attemptsDirectory, attemptId, sourceDirectory, publicationLock, faultInjector,
}) {
  let before;
  try {
    before = inspectBundleCrashSurvivor({
      final, attemptId, sourceDirectory, recoveredOwner: publicationLock.recoveredOwner,
    });
  } catch {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'canonical bundle evidence is not attributable crash residue');
  }
  inject(faultInjector, 'before-bundle-survivor-quarantine', { artifactRef: logicalArtifactRef('attempt', attemptId) });
  let confirmed;
  try {
    confirmed = inspectBundleCrashSurvivor({
      final, attemptId, sourceDirectory, recoveredOwner: publicationLock.recoveredOwner,
    });
  } catch {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'canonical bundle changed before crash recovery');
  }
  if (canonicalJson(before.snapshot) !== canonicalJson(confirmed.snapshot)
      || canonicalJson(before.receipt) !== canonicalJson(confirmed.receipt)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed bundle changed before quarantine');
  }
  const quarantineId = sha256Hex(canonicalJson({
    schema: 'setjoin.security-program.crash-survivor-address/v1',
    kind: 'bundle', publicationId: attemptId,
    receiptSha256: sha256Hex(canonicalJson(confirmed.receipt)),
    nonce: crypto.randomBytes(32).toString('hex'),
  }));
  const quarantineBase = `.quarantine-crash-bundle-${quarantineId}`;
  const quarantinePath = path.join(attemptsDirectory, quarantineBase);
  if (fs.existsSync(quarantinePath)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle quarantine address exists');
  try { fs.renameSync(final, quarantinePath); }
  catch { fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle survivor raced during quarantine'); }
  fsyncDirectory(attemptsDirectory);
  const quarantinedRoot = fs.lstatSync(quarantinePath, { bigint: true });
  const originalRoot = before.snapshot.find((entry) => entry.path === '');
  if (String(quarantinedRoot.dev) !== originalRoot.device || String(quarantinedRoot.ino) !== originalRoot.inode) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'bundle quarantine identity changed');
  }
  sealReadOnlyTree(quarantinePath);
  verifyBundleDirectory(quarantinePath, attemptId);
  writeQuarantineReceipt(attemptsDirectory, quarantineBase, {
    kind: 'bundle', publicationId: attemptId,
    receiptSha256: sha256Hex(canonicalJson(confirmed.receipt)),
  });
  fsyncDirectory(attemptsDirectory);
}

function normalizeGenerationFiles(files) {
  if (files === null || typeof files !== 'object' || Array.isArray(files)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation files must be an object');
  return Object.entries(files).sort(([left], [right]) => Buffer.from(left).compare(Buffer.from(right))).map(([relative, value]) => {
    assertRepositoryRelativePath(relative, 'generation file');
    const bytes = Buffer.from(Buffer.isBuffer(value) ? value : (typeof value === 'string' ? value : canonicalJson(value)));
    return { relative, bytes };
  });
}

function generationFileHashes(entries) {
  return entries.map((entry) => ({
    schema: 'setjoin.security-program.file-hash/v1',
    path: entry.relative,
    sha256: sha256Hex(entry.bytes),
    size: entry.bytes.length,
  }));
}

function normalizeExpectedPrevious(expectedPrevious) {
  if (expectedPrevious === undefined) return undefined;
  if (expectedPrevious === null) {
    return { generationId: null, generationHash: null };
  }
  if (expectedPrevious === null || typeof expectedPrevious !== 'object' || Array.isArray(expectedPrevious)
      || canonicalJson(Object.keys(expectedPrevious).sort()) !== canonicalJson(['generationHash', 'generationId'])) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'expectedPrevious must be null or an exact generation identity');
  }
  safeId(expectedPrevious.generationId, 'expectedPrevious generationId');
  if (typeof expectedPrevious.generationHash !== 'string' || !/^[0-9a-f]{64}$/.test(expectedPrevious.generationHash)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'expectedPrevious generationHash is invalid');
  }
  return {
    generationId: expectedPrevious.generationId,
    generationHash: expectedPrevious.generationHash,
  };
}

function receiptPrevious(receipt) {
  return {
    generationId: receipt.predecessorGenerationId,
    generationHash: receipt.predecessorGenerationHash,
  };
}

function currentIdentity(current) {
  return current === null
    ? { generationId: null, generationHash: null }
    : { generationId: current.generationId, generationHash: current.generationHash };
}

function assertPreviousMatches(expected, actual, message) {
  if (expected.generationId !== actual.generationId || expected.generationHash !== actual.generationHash) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', message);
  }
}

function readCurrentGeneration({ generationsDirectory, pointerPath, pendingGenerationId }) {
  if (fs.existsSync(pointerPath)) return readVerifiedLatest({ generationsDirectory, pointerPath });
  const committed = fs.readdirSync(generationsDirectory).filter((name) => !name.startsWith('.'));
  if (committed.some((name) => name !== pendingGenerationId)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation history exists without an authoritative pointer');
  }
  return null;
}

function pointerForReceipt(receipt) {
  return {
    schema: LATEST_POINTER_SCHEMA,
    generationId: receipt.generationId,
    generationHash: receipt.generationHash,
    predecessorGenerationId: receipt.predecessorGenerationId,
    predecessorGenerationHash: receipt.predecessorGenerationHash,
    createdAt: receipt.createdAt,
  };
}

function verifyPreparedPointer(pointerTemporary, receipt) {
  assertRegularFile(pointerTemporary, 'prepared pointer', 0o400);
  const prepared = validatePointer(readCanonicalJsonFile(pointerTemporary, 'prepared pointer'));
  if (canonicalJson(prepared) !== canonicalJson(pointerForReceipt(receipt))) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'prepared pointer does not exactly match its generation receipt');
  }
  return prepared;
}

function snapshotPreparedPointer(pointerTemporary, receipt) {
  const before = fs.lstatSync(pointerTemporary, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || exactMode(before) !== 0o400 || before.nlink !== 1n) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'prepared pointer is not attributable protocol evidence');
  }
  verifyPreparedPointer(pointerTemporary, receipt);
  const digest = hashRegularFileStable(pointerTemporary, 'prepared pointer');
  const after = fs.lstatSync(pointerTemporary, { bigint: true });
  if (!sameFileSnapshot(before, after)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'prepared pointer changed during inspection');
  return {
    device: String(after.dev), inode: String(after.ino), mode: exactMode(after),
    size: digest.size, sha256: digest.sha256,
    mtimeNs: String(after.mtimeNs), ctimeNs: String(after.ctimeNs),
  };
}

function currentPointerIdentityForRecovery({ generationsDirectory, pointerPath }) {
  if (!fs.existsSync(pointerPath)) return { generationId: null, generationHash: null };
  assertRegularFile(pointerPath, 'latest pointer', 0o400);
  const pointer = validatePointer(readCanonicalJsonFile(pointerPath, 'latest pointer'));
  const receipt = verifyGenerationDirectory(path.join(generationsDirectory, pointer.generationId));
  if (canonicalJson(pointerForReceipt(receipt)) !== canonicalJson(pointer)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'latest pointer does not match its generation during recovery');
  }
  return { generationId: pointer.generationId, generationHash: pointer.generationHash };
}

function inspectGenerationCrashSurvivor({
  final, generationsDirectory, pointerPath, pointerTemporary, generationId,
  requestedPrevious, requestedHashes, recoveredOwner,
}) {
  if (recoveredOwner === null || recoveredOwner === undefined) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed generation evidence has no attributable dead publication owner');
  }
  const snapshot = snapshotProtocolSurvivor(final, {
    directoryModes: [0o500, 0o755], fileModes: [0o400, 0o644],
  });
  const receipt = validateGenerationReceipt(readCanonicalJsonFile(
    path.join(final, 'generation-receipt.json'), 'unsealed generation receipt',
  ));
  if (receipt.generationId !== generationId
      || canonicalJson(receipt.files) !== canonicalJson(requestedHashes)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed generation conflicts with replay input');
  }
  validatePublicationSurvivorMarker(
    readCanonicalJsonFile(path.join(final, PUBLICATION_SURVIVOR_FILE), 'unsealed generation survivor marker'),
    { kind: 'generation', publicationId: generationId, receipt, lockOwner: recoveredOwner },
  );
  const receiptExpected = receiptPrevious(receipt);
  if (requestedPrevious !== undefined) {
    assertPreviousMatches(requestedPrevious, receiptExpected,
      'unsealed generation expectedPrevious contradicts its receipt');
  }
  assertPreviousMatches(receiptExpected,
    currentPointerIdentityForRecovery({ generationsDirectory, pointerPath }),
    'unsealed generation predecessor pointer changed');
  const pointerSnapshot = snapshotPreparedPointer(pointerTemporary, receipt);
  const fileEntries = new Map(snapshot.filter((entry) => entry.kind === 'file').map((entry) => [entry.path, entry]));
  const expectedFiles = new Set(['generation-receipt.json', PUBLICATION_SURVIVOR_FILE]);
  for (const entry of receipt.files) {
    expectedFiles.add(entry.path);
    const actual = fileEntries.get(entry.path);
    if (actual === undefined || actual.size !== entry.size || actual.sha256 !== entry.sha256) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed generation content does not match its receipt');
    }
  }
  if (canonicalJson([...fileEntries.keys()].sort()) !== canonicalJson([...expectedFiles].sort())) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed generation contains an unexpected file');
  }
  const expectedDirectories = new Set(['']);
  for (const filename of expectedFiles) {
    let directory = path.posix.dirname(filename);
    while (directory !== '.') {
      expectedDirectories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  const actualDirectories = snapshot.filter((entry) => entry.kind === 'directory').map((entry) => entry.path).sort();
  if (canonicalJson(actualDirectories) !== canonicalJson([...expectedDirectories].sort())) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed generation contains an unexpected directory');
  }
  return { snapshot, pointerSnapshot, receipt };
}

function recoverGenerationCrashSurvivor({
  final, generationsDirectory, pointerPath, pointerTemporary, generationId,
  requestedPrevious, requestedHashes, publicationLock, faultInjector,
}) {
  const inspection = {
    final, generationsDirectory, pointerPath, pointerTemporary, generationId,
    requestedPrevious, requestedHashes, recoveredOwner: publicationLock.recoveredOwner,
  };
  let before;
  try { before = inspectGenerationCrashSurvivor(inspection); }
  catch { fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'canonical generation evidence is not attributable crash residue'); }
  inject(faultInjector, 'before-generation-survivor-quarantine', {
    artifactRef: logicalArtifactRef('generation', generationId),
  });
  let confirmed;
  try { confirmed = inspectGenerationCrashSurvivor(inspection); }
  catch { fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'canonical generation changed before crash recovery'); }
  if (canonicalJson(before) !== canonicalJson(confirmed)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'unsealed generation changed before quarantine');
  }
  const quarantineId = sha256Hex(canonicalJson({
    schema: 'setjoin.security-program.crash-survivor-address/v1',
    kind: 'generation', publicationId: generationId,
    receiptSha256: sha256Hex(canonicalJson(confirmed.receipt)),
    nonce: crypto.randomBytes(32).toString('hex'),
  }));
  const quarantineBase = `.quarantine-crash-generation-${quarantineId}`;
  const quarantinePath = path.join(generationsDirectory, quarantineBase);
  const pointerQuarantinePath = path.join(
    path.dirname(pointerPath), `.quarantine-crash-pointer-${quarantineId}`,
  );
  if (fs.existsSync(quarantinePath) || fs.existsSync(pointerQuarantinePath)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation quarantine address exists');
  }
  try { fs.renameSync(final, quarantinePath); }
  catch { fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation survivor raced during quarantine'); }
  fsyncDirectory(generationsDirectory);
  const quarantinedRoot = fs.lstatSync(quarantinePath, { bigint: true });
  const originalRoot = confirmed.snapshot.find((entry) => entry.path === '');
  if (String(quarantinedRoot.dev) !== originalRoot.device || String(quarantinedRoot.ino) !== originalRoot.inode) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation quarantine identity changed');
  }
  try { fs.renameSync(pointerTemporary, pointerQuarantinePath); }
  catch { fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'prepared pointer raced during quarantine'); }
  fsyncDirectory(path.dirname(pointerPath));
  const quarantinedPointer = fs.lstatSync(pointerQuarantinePath, { bigint: true });
  if (String(quarantinedPointer.dev) !== confirmed.pointerSnapshot.device
      || String(quarantinedPointer.ino) !== confirmed.pointerSnapshot.inode) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'prepared pointer quarantine identity changed');
  }
  sealReadOnlyTree(quarantinePath);
  verifyGenerationDirectory(quarantinePath, confirmed.receipt);
  writeQuarantineReceipt(generationsDirectory, quarantineBase, {
    kind: 'generation', publicationId: generationId,
    receiptSha256: sha256Hex(canonicalJson(confirmed.receipt)),
    preparedPointerSha256: confirmed.pointerSnapshot.sha256,
  });
  fsyncDirectory(generationsDirectory);
}

export function validateGenerationReceipt(receipt) {
  assertClosedSchema(receipt, {
    schema: GENERATION_RECEIPT_SCHEMA,
    required: ['generationId', 'predecessorGenerationId', 'predecessorGenerationHash', 'createdAt', 'files', 'generationHash'],
    name: 'generation receipt',
  });
  safeId(receipt.generationId, 'generationId');
  validatePredecessor(receipt, 'generation');
  validTime(receipt.createdAt, 'generation createdAt');
  if (!Array.isArray(receipt.files)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation receipt files must be an array');
  for (const entry of receipt.files) {
    assertClosedSchema(entry, {
      schema: 'setjoin.security-program.file-hash/v1',
      required: ['path', 'sha256', 'size'],
      name: 'file hash',
    });
    assertRepositoryRelativePath(entry.path);
    if (!/^[0-9a-f]{64}$/.test(entry.sha256) || !Number.isSafeInteger(entry.size) || entry.size < 0) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation receipt contains invalid file hash');
    }
  }
  if (receipt.generationHash !== digestGeneration(receipt)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation receipt hash is invalid');
  return receipt;
}

export function publishVerifiedGeneration({
  generationsDirectory,
  pointerPath,
  generationId,
  files,
  expectedPrevious,
  now = new Date(),
  faultInjector,
}) {
  safeId(generationId, 'generationId');
  const requestedPrevious = normalizeExpectedPrevious(expectedPrevious);
  const normalizedFiles = normalizeGenerationFiles(files);
  const requestedHashes = generationFileHashes(normalizedFiles);
  ensureDirectory(generationsDirectory);
  ensureDirectory(path.dirname(pointerPath));
  return withExclusiveLock(generationsDirectory, '.publication.lock', faultInjector, (publicationLock) => {
    const temporary = path.join(generationsDirectory, `.tmp-${generationId}`);
    const final = path.join(generationsDirectory, generationId);
    const pointerTemporary = `${pointerPath}.tmp-${generationId}`;
    if (fs.existsSync(final)) {
      if (fs.existsSync(temporary)) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'immutable generation has a conflicting partial survivor');
      }
      let receipt;
      try {
        receipt = verifyGenerationDirectory(final);
        if (receipt.generationId !== generationId
            || canonicalJson(receipt.files) !== canonicalJson(requestedHashes)) {
          fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'immutable generation conflicts with replay input');
        }
      } catch (error) {
        recoverGenerationCrashSurvivor({
          final, generationsDirectory, pointerPath, pointerTemporary, generationId,
          requestedPrevious, requestedHashes, publicationLock, faultInjector,
        });
        receipt = undefined;
      }
      if (receipt === undefined) {
        // The attributable crash residue is retained under quarantine; continue
        // below and create a fresh canonical publication.
      } else {
      const receiptExpected = receiptPrevious(receipt);
      const effectiveExpected = requestedPrevious ?? receiptExpected;
      assertPreviousMatches(effectiveExpected, receiptExpected,
        'generation replay expectedPrevious contradicts the immutable receipt');
      const current = readCurrentGeneration({ generationsDirectory, pointerPath, pendingGenerationId: generationId });
      if (current?.generationId === generationId) {
        if (current.generationHash !== receipt.generationHash) {
          fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'current pointer conflicts with replay generation');
        }
        return current;
      }
      assertPreviousMatches(effectiveExpected, currentIdentity(current),
        'generation replay pointer no longer matches expectedPrevious');
      const pendingPrefix = `${path.basename(pointerPath)}.tmp-`;
      const pendingNames = fs.readdirSync(path.dirname(pointerPath))
        .filter((name) => name.startsWith(pendingPrefix));
      if (pendingNames.length !== 1 || pendingNames[0] !== path.basename(pointerTemporary)) {
        fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation replay requires exactly one matching prepared pointer');
      }
      verifyPreparedPointer(pointerTemporary, receipt);
      verifyGenerationDirectory(final, receipt);
      const currentBeforeRename = readCurrentGeneration({
        generationsDirectory, pointerPath, pendingGenerationId: generationId,
      });
      if (currentBeforeRename?.generationId === generationId) {
        if (currentBeforeRename.generationHash !== receipt.generationHash) {
          fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'current pointer conflicts with replay generation');
        }
        return currentBeforeRename;
      }
      assertPreviousMatches(effectiveExpected, currentIdentity(currentBeforeRename),
        'generation replay pointer changed before completion');
      inject(faultInjector, 'before-pointer-rename', { artifactRef: 'projection:latest' });
      fs.renameSync(pointerTemporary, pointerPath);
      inject(faultInjector, 'after-pointer-rename', { artifactRef: 'projection:latest' });
      sealReadOnlyFile(pointerPath, 'latest pointer');
      inject(faultInjector, 'after-pointer-sealed', { artifactRef: 'projection:latest' });
      fsyncDirectory(path.dirname(pointerPath));
      inject(faultInjector, 'after-pointer-directory-fsync', { artifactRef: 'projection:latest' });
      return readVerifiedLatest({ generationsDirectory, pointerPath });
      }
    }
    const predecessor = readCurrentGeneration({ generationsDirectory, pointerPath });
    const livePrevious = currentIdentity(predecessor);
    if (requestedPrevious !== undefined) {
      assertPreviousMatches(requestedPrevious, livePrevious,
        'generation publication pointer does not match expectedPrevious');
    }
    const predecessorGenerationId = livePrevious.generationId;
    const predecessorGenerationHash = livePrevious.generationHash;
    fs.mkdirSync(temporary, { mode: 0o755 });
    fsyncDirectory(generationsDirectory);
    inject(faultInjector, 'after-generation-temp-created', { artifactRef: logicalArtifactRef('generation', generationId) });
    const hashes = [];
    for (const entry of normalizedFiles) {
      const destination = path.join(temporary, ...entry.relative.split('/'));
      writeExclusiveDurable(destination, entry.bytes, 0o644, 0o755);
      hashes.push({ schema: 'setjoin.security-program.file-hash/v1', path: entry.relative, sha256: sha256Hex(entry.bytes), size: entry.bytes.length });
      inject(faultInjector, 'after-generation-file-fsync', { artifactRef: `generation-file:${entry.relative}` });
    }
    const createdAt = now.toISOString();
    const receipt = validateGenerationReceipt({
      schema: GENERATION_RECEIPT_SCHEMA,
      generationId,
      predecessorGenerationId,
      predecessorGenerationHash,
      createdAt,
      files: hashes,
      generationHash: digestGeneration({ generationId, predecessorGenerationId, predecessorGenerationHash, createdAt, files: hashes }),
    });
    writeExclusiveDurable(path.join(temporary, 'generation-receipt.json'), canonicalJson(receipt), 0o644, 0o755);
    writeExclusiveDurable(
      path.join(temporary, PUBLICATION_SURVIVOR_FILE),
      canonicalJson(publicationSurvivorMarker('generation', generationId, receipt, publicationLock.owner)),
      0o644,
      0o755,
    );
    inject(faultInjector, 'after-generation-receipt-fsync', { generationHash: receipt.generationHash });
    fsyncDirectoryTree(temporary);
    inject(faultInjector, 'after-generation-temp-fsync', { generationHash: receipt.generationHash });
    const pointer = pointerForReceipt(receipt);
    inject(faultInjector, 'before-pointer-temp-create', { artifactRef: 'projection:latest' });
    writeExclusiveDurable(pointerTemporary, canonicalJson(pointer), 0o644, 0o755);
    sealReadOnlyFile(pointerTemporary, 'prepared pointer');
    inject(faultInjector, 'after-pointer-temp-fsync', { artifactRef: 'projection:latest' });
    fs.renameSync(temporary, final);
    inject(faultInjector, 'after-generation-rename', { generationHash: receipt.generationHash });
    sealReadOnlyTree(final);
    inject(faultInjector, 'after-generation-sealed', { generationHash: receipt.generationHash });
    fsyncDirectory(generationsDirectory);
    inject(faultInjector, 'after-generation-parent-fsync', { generationHash: receipt.generationHash });
    verifyGenerationDirectory(final, receipt);
    inject(faultInjector, 'after-generation-verified', { generationHash: receipt.generationHash });
    // Re-verify immediately before the authority pointer changes.
    verifyGenerationDirectory(final, receipt);
    const predecessorBeforeRename = readCurrentGeneration({
      generationsDirectory, pointerPath, pendingGenerationId: generationId,
    });
    assertPreviousMatches(livePrevious, currentIdentity(predecessorBeforeRename),
      'generation publication pointer changed before completion');
    inject(faultInjector, 'before-pointer-rename', { artifactRef: 'projection:latest' });
    fs.renameSync(pointerTemporary, pointerPath);
    inject(faultInjector, 'after-pointer-rename', { artifactRef: 'projection:latest' });
    sealReadOnlyFile(pointerPath, 'latest pointer');
    inject(faultInjector, 'after-pointer-sealed', { artifactRef: 'projection:latest' });
    fsyncDirectory(path.dirname(pointerPath));
    inject(faultInjector, 'after-pointer-directory-fsync', { artifactRef: 'projection:latest' });
    return readVerifiedLatest({ generationsDirectory, pointerPath });
  });
}

function validatePointer(pointer) {
  assertClosedSchema(pointer, {
    schema: LATEST_POINTER_SCHEMA,
    required: ['generationId', 'generationHash', 'predecessorGenerationId', 'predecessorGenerationHash', 'createdAt'],
    name: 'latest pointer',
  });
  safeId(pointer.generationId, 'generationId');
  validatePredecessor(pointer, 'pointer');
  validTime(pointer.createdAt, 'pointer createdAt');
  if (!/^[0-9a-f]{64}$/.test(pointer.generationHash)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'pointer generation hash is invalid');
  return pointer;
}

function verifyGenerationDirectory(directory, expectedReceipt = undefined) {
  assertRealDirectory(directory, 'generation', 0o500);
  const receiptPath = path.join(directory, 'generation-receipt.json');
  assertRegularFile(receiptPath, 'generation receipt', 0o400);
  const receipt = validateGenerationReceipt(readCanonicalJsonFile(receiptPath, 'generation receipt'));
  if (expectedReceipt && canonicalJson(receipt) !== canonicalJson(expectedReceipt)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation receipt changed');
  const markerPath = path.join(directory, PUBLICATION_SURVIVOR_FILE);
  assertRegularFile(markerPath, 'generation publication survivor marker', 0o400);
  validatePublicationSurvivorMarker(
    readCanonicalJsonFile(markerPath, 'generation publication survivor marker'),
    { kind: 'generation', publicationId: receipt.generationId, receipt },
  );
  const actualPaths = walkRegularFiles(directory, {
    expectedDirectoryMode: 0o500, expectedFileMode: 0o400,
  })
    .map((entry) => entry.relative)
    .filter((relative) => !['generation-receipt.json', PUBLICATION_SURVIVOR_FILE].includes(relative))
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  const receiptPaths = receipt.files.map((entry) => entry.path)
    .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  if (canonicalJson(actualPaths) !== canonicalJson(receiptPaths)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation file set does not match receipt');
  for (const entry of receipt.files) {
    const filename = path.join(directory, ...entry.path.split('/'));
    const actual = hashRegularFileStable(filename, entry.path);
    if (actual.size !== entry.size || actual.sha256 !== entry.sha256) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', `generation file verification failed for ${entry.path}`);
    }
  }
  return receipt;
}

export function readVerifiedLatest({ generationsDirectory, pointerPath }) {
  assertRegularFile(pointerPath, 'latest pointer', 0o400);
  const pointer = validatePointer(readCanonicalJsonFile(pointerPath, 'latest pointer'));
  const pendingPrefix = `${path.basename(pointerPath)}.tmp-`;
  const pending = new Set();
  for (const name of fs.readdirSync(path.dirname(pointerPath)).filter((entry) => entry.startsWith(pendingPrefix))) {
    const pendingPath = path.join(path.dirname(pointerPath), name);
    assertRegularFile(pendingPath, 'prepared pointer', 0o400);
    const prepared = validatePointer(readCanonicalJsonFile(pendingPath, 'prepared pointer'));
    if (name !== `${pendingPrefix}${prepared.generationId}`) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'prepared pointer filename does not match its generation');
    if (prepared.generationId === pointer.generationId) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'current pointer still has a prepared marker');
    const finalDirectory = path.join(generationsDirectory, prepared.generationId);
    const temporaryDirectory = path.join(generationsDirectory, `.tmp-${prepared.generationId}`);
    const preparedDirectory = fs.existsSync(finalDirectory) ? finalDirectory : temporaryDirectory;
    const preparedReceipt = verifyGenerationDirectory(preparedDirectory);
    if (preparedReceipt.generationHash !== prepared.generationHash
      || preparedReceipt.predecessorGenerationId !== prepared.predecessorGenerationId
      || preparedReceipt.predecessorGenerationHash !== prepared.predecessorGenerationHash
      || preparedReceipt.createdAt !== prepared.createdAt) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'prepared pointer does not match its generation');
    }
    pending.add(prepared.generationId);
  }

  const receipts = new Map();
  for (const name of fs.readdirSync(generationsDirectory).filter((entry) => !entry.startsWith('.'))) {
    safeId(name, 'generation directory');
    if (!pending.has(name)) receipts.set(name, verifyGenerationDirectory(path.join(generationsDirectory, name)));
  }
  if (receipts.size === 0) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'no committed generation exists');
  const roots = [...receipts.values()].filter((receipt) => receipt.predecessorGenerationId === null);
  if (roots.length !== 1) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation lineage must have exactly one root');
  const childByParent = new Map();
  for (const receipt of receipts.values()) {
    if (receipt.predecessorGenerationId === null) continue;
    const predecessor = receipts.get(receipt.predecessorGenerationId);
    if (!predecessor || predecessor.generationHash !== receipt.predecessorGenerationHash) {
      fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation predecessor is missing or has the wrong hash');
    }
    if (childByParent.has(predecessor.generationId)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation lineage branches');
    childByParent.set(predecessor.generationId, receipt.generationId);
  }
  let tip = roots[0];
  const visited = new Set([tip.generationId]);
  while (childByParent.has(tip.generationId)) {
    const childId = childByParent.get(tip.generationId);
    if (visited.has(childId)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation lineage contains a cycle');
    visited.add(childId);
    tip = receipts.get(childId);
  }
  if (visited.size !== receipts.size) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'generation lineage is disconnected');
  if (tip.generationHash !== pointer.generationHash
    || tip.generationId !== pointer.generationId
    || tip.predecessorGenerationId !== pointer.predecessorGenerationId
    || tip.predecessorGenerationHash !== pointer.predecessorGenerationHash
    || tip.createdAt !== pointer.createdAt) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'latest pointer is not the monotonic generation tip');
  }
  return {
    schema: VERIFIED_GENERATION_SCHEMA,
    generationId: pointer.generationId,
    generationHash: pointer.generationHash,
    predecessorGenerationId: pointer.predecessorGenerationId,
    predecessorGenerationHash: pointer.predecessorGenerationHash,
    artifactRef: logicalArtifactRef('generation', pointer.generationId),
  };
}
