#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  closeSync, createReadStream, existsSync, lstatSync, mkdtempSync, openSync,
  readFileSync, readlinkSync, readSync, realpathSync, rmSync, statSync,
} from 'node:fs';
import { lstat, mkdtemp, readFile, readlink, realpath, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve, sep } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const VERSION = 'v2';
const shaPattern = '[0-9a-f]{40}|[0-9a-f]{64}';
const fingerprintPattern = new RegExp(`^${VERSION}:(${shaPattern}):([0-9a-f]{64})$`);

export class SourceFingerprintError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SourceFingerprintError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new SourceFingerprintError(code, message);
}

function frameHeader(hash, label, byteLength) {
  if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
    fail('E_SOURCE_FINGERPRINT_LENGTH', `invalid frame length for ${label}`);
  }
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(byteLength));
  hash.update(Buffer.from(label, 'utf8'));
  hash.update(Buffer.from([0]));
  hash.update(length);
}

function frameBuffer(hash, label, bytes) {
  frameHeader(hash, label, bytes.length);
  hash.update(bytes);
}

async function frameFile(hash, label, filename, expectedSize = undefined) {
  const fileStat = await stat(filename);
  const size = expectedSize ?? fileStat.size;
  frameHeader(hash, label, size);
  let seen = 0;
  for await (const chunk of createReadStream(filename)) {
    seen += chunk.length;
    hash.update(chunk);
  }
  if (seen !== size) {
    fail('E_SOURCE_FINGERPRINT_CHANGED', `${label} changed while it was fingerprinted`);
  }
}

async function runGitToFile(root, args, outputFile) {
  const outputFd = openSync(outputFile, 'w', 0o600);
  let stderr = Buffer.alloc(0);
  try {
    const exitCode = await new Promise((accept, reject) => {
      const child = spawn('git', ['-C', root, ...args], {
        stdio: ['ignore', outputFd, 'pipe'],
      });
      child.once('error', reject);
      child.stderr.on('data', (chunk) => {
        if (stderr.length < 64 * 1024) stderr = Buffer.concat([stderr, chunk]).subarray(0, 64 * 1024);
      });
      child.once('close', accept);
    });
    if (exitCode !== 0) {
      const detail = stderr.toString('utf8').trim() || `git exited ${exitCode}`;
      fail('E_SOURCE_FINGERPRINT_GIT', detail);
    }
  } finally {
    closeSync(outputFd);
  }
}

async function readSmallGitOutput(root, args, scratch, name) {
  const output = join(scratch, name);
  await runGitToFile(root, args, output);
  const info = await stat(output);
  if (info.size > 4096) fail('E_SOURCE_FINGERPRINT_GIT', `${args[0]} returned an oversized value`);
  return readFile(output);
}

function stripSingleLineEnding(bytes) {
  if (bytes.length > 0 && bytes.at(-1) === 0x0a) bytes = bytes.subarray(0, bytes.length - 1);
  if (bytes.length > 0 && bytes.at(-1) === 0x0d) bytes = bytes.subarray(0, bytes.length - 1);
  return bytes;
}

function validateRelativeGitPath(relative) {
  if (relative.length === 0 || relative[0] === 0x2f || relative.includes(0)) {
    fail('E_SOURCE_FINGERPRINT_PATH', `invalid Git path: ${relative.toString('hex')}`);
  }
  for (const part of relative.toString('binary').split('/')) {
    if (part === '' || part === '.' || part === '..') {
      fail('E_SOURCE_FINGERPRINT_PATH', `unsafe Git path: ${relative.toString('hex')}`);
    }
  }
}

async function* nulRecords(filename) {
  let pending = Buffer.alloc(0);
  for await (const chunk of createReadStream(filename)) {
    let cursor = 0;
    for (;;) {
      const end = chunk.indexOf(0, cursor);
      if (end === -1) {
        pending = Buffer.concat([pending, chunk.subarray(cursor)]);
        break;
      }
      const record = pending.length === 0
        ? chunk.subarray(cursor, end)
        : Buffer.concat([pending, chunk.subarray(cursor, end)]);
      pending = Buffer.alloc(0);
      yield record;
      cursor = end + 1;
    }
  }
  if (pending.length !== 0) fail('E_SOURCE_FINGERPRINT_GIT', 'Git path list is not NUL terminated');
}

export function parseFingerprint(value) {
  if (typeof value !== 'string') fail('E_SOURCE_FINGERPRINT_VERSION', 'fingerprint must be a string');
  const match = fingerprintPattern.exec(value);
  if (!match) {
    const version = value.includes(':') ? value.slice(0, value.indexOf(':')) : 'unversioned';
    fail('E_SOURCE_FINGERPRINT_VERSION', `unsupported or malformed source fingerprint version: ${version}`);
  }
  return Object.freeze({
    version: VERSION,
    commit: match[1],
    digest: match[2],
    value,
  });
}

async function computeSourceFingerprintSnapshot(root) {
  const scratch = await mkdtemp(join(tmpdir(), 'setjoin-source-fingerprint-'));
  try {
    const topLevelBytes = stripSingleLineEnding(await readSmallGitOutput(root, ['rev-parse', '--show-toplevel'], scratch, 'top-level'));
    const topLevel = await realpath(resolve(topLevelBytes.toString('utf8')));
    if (topLevel !== root) fail('E_SOURCE_FINGERPRINT_ROOT', `root is not the repository top level: ${root}`);

    const commit = stripSingleLineEnding(await readSmallGitOutput(root, ['rev-parse', '--verify', 'HEAD'], scratch, 'commit'));
    if (!new RegExp(`^(?:${shaPattern})$`).test(commit.toString('ascii'))) {
      fail('E_SOURCE_FINGERPRINT_GIT', 'HEAD is not a supported Git object ID');
    }

    const trackedDiff = join(scratch, 'tracked-diff');
    await runGitToFile(root, ['diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', 'HEAD', '--'], trackedDiff);
    const untrackedList = join(scratch, 'untracked-paths');
    await runGitToFile(root, ['ls-files', '--others', '--exclude-standard', '-z'], untrackedList);

    const hash = createHash('sha256');
    frameBuffer(hash, 'head', commit);
    await frameFile(hash, 'tracked-diff', trackedDiff);

    let previous = null;
    for await (const relative of nulRecords(untrackedList)) {
      validateRelativeGitPath(relative);
      if (previous !== null && Buffer.compare(previous, relative) >= 0) {
        fail('E_SOURCE_FINGERPRINT_GIT', `Git returned unordered or duplicate paths near ${relative.toString('hex')}`);
      }
      previous = Buffer.from(relative);
      const filename = Buffer.concat([Buffer.from(root), Buffer.from(sep), relative]);
      const info = await lstat(filename);
      frameBuffer(hash, 'untracked-path', relative);
      if (info.isFile()) {
        frameBuffer(hash, 'untracked-kind', Buffer.from('file'));
        await frameFile(hash, 'untracked-bytes', filename, info.size);
      } else if (info.isSymbolicLink()) {
        frameBuffer(hash, 'untracked-kind', Buffer.from('symlink'));
        frameBuffer(hash, 'untracked-bytes', await readlink(filename, { encoding: 'buffer' }));
      } else {
        fail('E_SOURCE_FINGERPRINT_PATH', `unsupported untracked path type: ${relative.toString('hex')}`);
      }
    }

    return `${VERSION}:${commit.toString('ascii')}:${hash.digest('hex')}`;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

export async function computeSourceFingerprint(rootOption, options = {}) {
  if (typeof rootOption !== 'string' || rootOption.length === 0 || !isAbsolute(rootOption)) {
    fail('E_SOURCE_FINGERPRINT_ROOT', 'root must be an absolute repository path');
  }
  if (options === null || typeof options !== 'object' || Array.isArray(options)
      || Object.keys(options).some((key) => key !== 'betweenSnapshots')
      || (options.betweenSnapshots !== undefined && typeof options.betweenSnapshots !== 'function')) {
    fail('E_SOURCE_FINGERPRINT_USAGE', 'fingerprint options are invalid');
  }
  const root = await realpath(resolve(rootOption));
  const first = await computeSourceFingerprintSnapshot(root);
  if (options.betweenSnapshots) await options.betweenSnapshots();
  const second = await computeSourceFingerprintSnapshot(root);
  if (first !== second) fail('E_SOURCE_FINGERPRINT_CHANGED', 'repository changed across fingerprint snapshots');
  return second;
}

function runGitToFileSync(root, args, outputFile, { gitBinary, env }) {
  const outputFd = openSync(outputFile, 'w', 0o600);
  try {
    const result = spawnSync(gitBinary, ['-C', root, ...args], {
      stdio: ['ignore', outputFd, 'pipe'],
      env,
      maxBuffer: 64 * 1024,
    });
    if (result.error || result.status !== 0) {
      const detail = result.error?.message
        ?? result.stderr?.toString('utf8').trim()
        ?? `git exited ${result.status}`;
      fail('E_SOURCE_FINGERPRINT_GIT', detail || `git exited ${result.status}`);
    }
  } finally {
    closeSync(outputFd);
  }
}

function readSmallGitOutputSync(root, args, scratch, name, options) {
  const output = join(scratch, name);
  runGitToFileSync(root, args, output, options);
  const info = statSync(output);
  if (info.size > 4096) fail('E_SOURCE_FINGERPRINT_GIT', `${args[0]} returned an oversized value`);
  return readFileSync(output);
}

function frameFileSync(hash, label, filename) {
  const before = statSync(filename, { bigint: true });
  const size = Number(before.size);
  if (!Number.isSafeInteger(size)) fail('E_SOURCE_FINGERPRINT_LENGTH', `${label} exceeds safe integer precision`);
  frameHeader(hash, label, size);
  const descriptor = openSync(filename, 'r');
  let seen = 0;
  try {
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const length = readSync(descriptor, chunk, 0, chunk.length, null);
      if (length === 0) break;
      seen += length;
      hash.update(chunk.subarray(0, length));
    }
  } finally {
    closeSync(descriptor);
  }
  const after = statSync(filename, { bigint: true });
  if (seen !== size || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs) {
    fail('E_SOURCE_FINGERPRINT_CHANGED', `${label} changed while it was fingerprinted`);
  }
}

function computeSourceFingerprintSnapshotSync(root, options) {
  const scratch = mkdtempSync(join(tmpdir(), 'setjoin-source-fingerprint-sync-'));
  try {
    const topLevelBytes = stripSingleLineEnding(readSmallGitOutputSync(
      root, ['rev-parse', '--show-toplevel'], scratch, 'top-level', options,
    ));
    const topLevel = realpathSync(resolve(topLevelBytes.toString('utf8')));
    if (topLevel !== root) fail('E_SOURCE_FINGERPRINT_ROOT', `root is not the repository top level: ${root}`);
    const commit = stripSingleLineEnding(readSmallGitOutputSync(
      root, ['rev-parse', '--verify', 'HEAD'], scratch, 'commit', options,
    ));
    if (!new RegExp(`^(?:${shaPattern})$`).test(commit.toString('ascii'))) {
      fail('E_SOURCE_FINGERPRINT_GIT', 'HEAD is not a supported Git object ID');
    }
    const trackedDiff = join(scratch, 'tracked-diff');
    runGitToFileSync(root, ['diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', 'HEAD', '--'], trackedDiff, options);
    const untrackedList = join(scratch, 'untracked-paths');
    runGitToFileSync(root, ['ls-files', '--others', '--exclude-standard', '-z'], untrackedList, options);
    const hash = createHash('sha256');
    frameBuffer(hash, 'head', commit);
    frameFileSync(hash, 'tracked-diff', trackedDiff);
    const records = readFileSync(untrackedList);
    if (records.length > 0 && records.at(-1) !== 0) {
      fail('E_SOURCE_FINGERPRINT_GIT', 'Git path list is not NUL terminated');
    }
    let previous = null;
    let cursor = 0;
    while (cursor < records.length) {
      const end = records.indexOf(0, cursor);
      const relative = records.subarray(cursor, end);
      validateRelativeGitPath(relative);
      if (previous !== null && Buffer.compare(previous, relative) >= 0) {
        fail('E_SOURCE_FINGERPRINT_GIT', `Git returned unordered or duplicate paths near ${relative.toString('hex')}`);
      }
      previous = Buffer.from(relative);
      const filename = Buffer.concat([Buffer.from(root), Buffer.from(sep), relative]);
      const info = lstatSync(filename);
      frameBuffer(hash, 'untracked-path', relative);
      if (info.isFile()) {
        frameBuffer(hash, 'untracked-kind', Buffer.from('file'));
        frameFileSync(hash, 'untracked-bytes', filename);
      } else if (info.isSymbolicLink()) {
        frameBuffer(hash, 'untracked-kind', Buffer.from('symlink'));
        frameBuffer(hash, 'untracked-bytes', readlinkSync(filename, { encoding: 'buffer' }));
      } else {
        fail('E_SOURCE_FINGERPRINT_PATH', `unsupported untracked path type: ${relative.toString('hex')}`);
      }
      cursor = end + 1;
    }
    return `${VERSION}:${commit.toString('ascii')}:${hash.digest('hex')}`;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

export function computeSourceFingerprintSync(rootOption, options = {}) {
  if (typeof rootOption !== 'string' || rootOption.length === 0 || !isAbsolute(rootOption)) {
    fail('E_SOURCE_FINGERPRINT_ROOT', 'root must be an absolute repository path');
  }
  if (options === null || typeof options !== 'object' || Array.isArray(options)
      || Object.keys(options).some((key) => !['betweenSnapshots', 'env', 'gitBinary'].includes(key))
      || (options.betweenSnapshots !== undefined && typeof options.betweenSnapshots !== 'function')
      || (options.gitBinary !== undefined && typeof options.gitBinary !== 'string')
      || (options.env !== undefined && (options.env === null || typeof options.env !== 'object' || Array.isArray(options.env)))) {
    fail('E_SOURCE_FINGERPRINT_USAGE', 'synchronous fingerprint options are invalid');
  }
  const root = realpathSync(resolve(rootOption));
  const execution = { gitBinary: options.gitBinary ?? 'git', env: options.env ?? process.env };
  const first = computeSourceFingerprintSnapshotSync(root, execution);
  if (options.betweenSnapshots) options.betweenSnapshots();
  const second = computeSourceFingerprintSnapshotSync(root, execution);
  if (first !== second) fail('E_SOURCE_FINGERPRINT_CHANGED', 'repository changed across fingerprint snapshots');
  return second;
}

function usage() {
  return 'Usage: node scripts/lib/source-fingerprint.mjs compute --root /absolute/repository\n'
    + '       node scripts/lib/source-fingerprint.mjs parse --value v2:<commit>:<sha256>\n';
}

async function main(argv) {
  const [command, flag, value, ...rest] = argv;
  if (rest.length !== 0) fail('E_SOURCE_FINGERPRINT_USAGE', 'unexpected arguments');
  if (command === 'compute' && flag === '--root' && value) {
    process.stdout.write(await computeSourceFingerprint(value));
    return;
  }
  if (command === 'parse' && flag === '--value' && value) {
    process.stdout.write(JSON.stringify(parseFingerprint(value)));
    return;
  }
  if ((command === '--help' || command === '-h') && flag === undefined) {
    process.stdout.write(usage());
    return;
  }
  fail('E_SOURCE_FINGERPRINT_USAGE', usage().trimEnd());
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  main(process.argv.slice(2)).catch((error) => {
    const code = error instanceof SourceFingerprintError ? error.code : 'E_SOURCE_FINGERPRINT_INTERNAL';
    process.stderr.write(`${code} ${error.message}\n`);
    process.exitCode = 1;
  });
}
