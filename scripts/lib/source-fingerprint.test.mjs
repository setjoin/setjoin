#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  SourceFingerprintError,
  computeSourceFingerprint,
  parseFingerprint,
} from './source-fingerprint.mjs';

const script = join(dirname(fileURLToPath(import.meta.url)), 'source-fingerprint.mjs');
const fixture = mkdtempSync(join(tmpdir(), 'setjoin-source-fingerprint-test-'));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: null, ...options });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed: ${(result.stderr ?? Buffer.alloc(0)).toString('utf8')}`);
  }
  return result.stdout;
}

function git(args) {
  return run('git', ['-C', fixture, ...args]);
}

function legacyFingerprint() {
  const commit = git(['rev-parse', 'HEAD']).toString('ascii').trim();
  const trackedDiff = git(['diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', 'HEAD', '--']);
  const untrackedBytes = git(['ls-files', '--others', '--exclude-standard', '-z']);
  const untracked = untrackedBytes.subarray(0, -1).toString('binary').split('\0')
    .filter(Boolean)
    .map((value) => Buffer.from(value, 'binary'))
    .sort(Buffer.compare);
  const hash = createHash('sha256');
  const frame = (label, bytes) => {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(Buffer.from(label));
    hash.update(Buffer.from([0]));
    hash.update(length);
    hash.update(bytes);
  };
  frame('head', Buffer.from(commit, 'ascii'));
  frame('tracked-diff', trackedDiff);
  for (const relative of untracked) {
    const filename = Buffer.concat([Buffer.from(fixture), Buffer.from('/'), relative]);
    const info = lstatSync(filename);
    const kind = info.isSymbolicLink() ? 'symlink' : 'file';
    const bytes = info.isSymbolicLink()
      ? readlinkSync(filename, { encoding: 'buffer' })
      : readFileSync(filename);
    frame('untracked-path', relative);
    frame('untracked-kind', Buffer.from(kind));
    frame('untracked-bytes', bytes);
  }
  return `${commit}:${hash.digest('hex')}`;
}

function expectVersionFailure(value) {
  assert.throws(
    () => parseFingerprint(value),
    (error) => error instanceof SourceFingerprintError && error.code === 'E_SOURCE_FINGERPRINT_VERSION',
  );
}

try {
  mkdirSync(join(fixture, 'tracked'), { recursive: true });
  git(['init', '-q', '-b', 'main']);
  git(['config', 'user.name', 'Source Fingerprint Fixture']);
  git(['config', 'user.email', 'source-fingerprint@example.invalid']);
  writeFileSync(join(fixture, 'tracked', 'binary.dat'), Buffer.from([0, 1, 2, 10, 255]));
  git(['add', '.']);
  git(['commit', '-qm', 'baseline']);

  writeFileSync(join(fixture, 'tracked', 'binary.dat'), Buffer.concat([
    Buffer.from([0, 1, 2, 10, 255]),
    Buffer.alloc(2 * 1024 * 1024, 0x5a),
  ]));
  writeFileSync(join(fixture, 'line\nbreak'), Buffer.from([0, 58, 10, 255]));
  writeFileSync(join(fixture, 'colon:name'), 'delimiter-safe\n');
  writeFileSync(join(fixture, 'raw-é'), Buffer.from('UTF-8 path bytes'));
  symlinkSync('tracked/binary.dat', join(fixture, 'untracked-link'));

  const fingerprint = await computeSourceFingerprint(fixture);
  assert.equal(fingerprint, `v2:${legacyFingerprint()}`, 'v2 must preserve the framed R5 digest exactly');
  const parsed = parseFingerprint(fingerprint);
  assert.equal(parsed.version, 'v2');
  assert.equal(parsed.value, fingerprint);
  assert.match(parsed.commit, /^[0-9a-f]{40}$/);
  assert.match(parsed.digest, /^[0-9a-f]{64}$/);

  const cliFingerprint = run(process.execPath, [script, 'compute', '--root', fixture]).toString('utf8');
  assert.equal(cliFingerprint, fingerprint, 'CLI and module computation must agree');
  const cliParsed = JSON.parse(run(process.execPath, [script, 'parse', '--value', fingerprint]).toString('utf8'));
  assert.deepEqual(cliParsed, parsed, 'CLI and module parsing must agree');

  const beforeMutation = fingerprint;
  writeFileSync(join(fixture, 'colon:name'), 'delimiter-safe, mutated\n');
  assert.notEqual(await computeSourceFingerprint(fixture), beforeMutation, 'untracked byte changes must alter the fingerprint');

  await assert.rejects(
    computeSourceFingerprint(fixture, {
      betweenSnapshots() {
        writeFileSync(join(fixture, 'colon:name'), 'changed between stability snapshots\n');
      },
    }),
    (error) => error instanceof SourceFingerprintError && error.code === 'E_SOURCE_FINGERPRINT_CHANGED',
    'a repository mutation between the two bounded snapshots must fail closed',
  );

  const unversioned = fingerprint.slice(3);
  for (const invalid of [
    unversioned,
    `v1:${unversioned}`,
    `v3:${unversioned}`,
    `${fingerprint}\n`,
    fingerprint.toUpperCase(),
    'v2:abc:def',
    `v2:${parsed.commit}:${'0'.repeat(63)}`,
  ]) expectVersionFailure(invalid);
  expectVersionFailure(null);

  const rejected = spawnSync(process.execPath, [script, 'parse', '--value', `v1:${unversioned}`], { encoding: 'utf8' });
  assert.equal(rejected.status, 1);
  assert.match(rejected.stderr, /^E_SOURCE_FINGERPRINT_VERSION /);
  await assert.rejects(
    computeSourceFingerprint(join(fixture, 'tracked')),
    (error) => error instanceof SourceFingerprintError && error.code === 'E_SOURCE_FINGERPRINT_ROOT',
  );

  console.log('source-fingerprint v2: PASS (two stable streamed Git snapshots, binary paths/bytes, golden equivalence, mutation, strict version rejection)');
} finally {
  rmSync(fixture, { recursive: true, force: true });
}
