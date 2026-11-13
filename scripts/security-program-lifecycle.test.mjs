#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  latestAttemptEvents,
  loadAttemptJournal,
} from './lib/security-program-attempts.mjs';
import {
  publishVerifiedGeneration,
  readVerifiedLatest,
  verifyImmutableBundle,
} from './lib/security-program-publication.mjs';
import { canonicalJson, parseStrictJson } from './lib/security-program-json.mjs';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-lifecycle-'));
const attemptsModuleUrl = new URL('./lib/security-program-attempts.mjs', import.meta.url).href;
const inventoryModuleUrl = new URL('./lib/security-program-inventory.mjs', import.meta.url).href;
const publicationModuleUrl = new URL('./lib/security-program-publication.mjs', import.meta.url).href;
const targetsModuleUrl = new URL('./lib/security-program-targets.mjs', import.meta.url).href;
const fixedTime = '2026-08-30T00:00:00.000Z';

function removeTree(target) {
  if (!fs.existsSync(target)) return;
  const metadata = fs.lstatSync(target);
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    fs.chmodSync(target, 0o700);
    for (const name of fs.readdirSync(target)) removeTree(path.join(target, name));
  } else if (!metadata.isSymbolicLink()) {
    fs.chmodSync(target, 0o600);
  }
  fs.rmSync(target, { recursive: true, force: true });
}

function runChild(source, args, { status = 0, signal = null } = {}) {
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source, ...args], {
    encoding: 'utf8',
    env: {},
  });
  assert.equal(result.status, status, result.stderr);
  assert.equal(result.signal, signal, result.stderr);
  return result;
}

function oneAttempt(journalPath, expectedState, expectedEvents, expectedScanId) {
  const events = loadAttemptJournal(journalPath);
  assert.equal(events.length, expectedEvents);
  const latest = [...latestAttemptEvents(events).values()];
  assert.equal(latest.length, 1, 'crash recovery created a second attempt');
  assert.equal(latest[0].attemptId, 'attempt-lifecycle');
  assert.equal(latest[0].state, expectedState);
  const scanIds = new Set(events.flatMap((event) => event.scanId === undefined ? [] : [event.scanId]));
  assert(scanIds.size <= 1, 'crash recovery persisted more than one scan ID');
  assert.equal(scanIds.size === 0 ? undefined : [...scanIds][0], expectedScanId);
  return latest[0];
}

const attemptChild = String.raw`
  const [attemptsUrl, inventoryUrl, targetsUrl, root, phase] = process.argv.slice(1);
  const crypto = await import('node:crypto');
  const fs = await import('node:fs');
  const path = await import('node:path');
  const attempts = await import(attemptsUrl);
  const inventory = await import(inventoryUrl);
  const targets = await import(targetsUrl);
  const journalPath = path.join(root, 'attempt-journal.json');
  const at = (offset) => new Date(Date.parse('2026-08-30T00:00:00.000Z') + offset).toISOString();

  if (phase === 'reservation') {
    const repoRoot = fs.realpathSync.native(path.join(root, 'repo'));
    const contents = fs.readFileSync(path.join(repoRoot, 'scope', 'target.txt'));
    const objectId = crypto.createHash('sha1')
      .update('blob ' + contents.length + '\0').update(contents).digest('hex');
    const entry = { path: 'scope/target.txt', objectId, mode: '100644', kind: 'file' };
    const inventorySha256 = inventory.hashInventory([{
      ...entry, pathBytes: Buffer.from(entry.path), objectType: 'blob',
    }]);
    const revision = '7'.repeat(40);
    const exclusionPolicy = {
      schema: inventory.EXCLUSION_POLICY_SCHEMA,
      policyVersion: 'fixture/empty/v1',
      classes: [],
    };
    const epoch = {
      schema: 'setjoin.security-program.epoch/v1', recordRole: 'authority', revision,
      sourceCommittedAt: '2026-08-29T00:00:00.000Z', historicalCandidateCount: 1,
      treePathCount: 1, authorizedCount: 1, excludedCount: 0, inventorySha256,
      exclusionPolicy, exclusionPolicySha256: inventory.hashJson(exclusionPolicy),
      authorizedPaths: [entry], excludedPaths: [],
    };
    const shards = {
      schema: 'setjoin.security-program.shards/v1', recordRole: 'authority', revision,
      inventorySha256, generationId: 'fixture-lifecycle/v1',
      shards: [{
        id: 'S02/P01', ownerSectionId: 'S02', pathCount: 1,
        pathListSha256: inventorySha256, paths: [entry],
      }],
    };
    const gitResponse = ({ repoRoot: requestedRoot, args }) => {
      if (requestedRoot !== repoRoot) throw new Error('unexpected repository root');
      const joined = args.join('\0');
      if (joined === ['rev-parse', '--is-inside-work-tree'].join('\0')) return { status: 0, stdout: 'true\n' };
      if (joined === ['rev-parse', '--show-toplevel'].join('\0')) return { status: 0, stdout: repoRoot + '\n' };
      if (joined === ['rev-parse', '--verify', 'HEAD^{commit}'].join('\0')) return { status: 0, stdout: revision + '\n' };
      if (args[0] === 'symbolic-ref') return { status: 1, stdout: Buffer.alloc(0) };
      if (args[0] === 'status') return { status: 0, stdout: Buffer.alloc(0) };
      if (args[0] === 'ls-tree') return { status: 0, stdout: Buffer.from('100644 blob ' + objectId + '\t' + entry.path + '\0') };
      throw new Error('unexpected Git command ' + args.join(' '));
    };
    const target = await targets.prepareDeepTarget({
      repoRoot, shardGeneration: shards, shardId: 'S02/P01', scope: 'scope',
      gitRunner: async (invocation) => gitResponse(invocation),
      verificationGitRunner: (invocation) => gitResponse(invocation),
    });
    const reserved = attempts.buildReservedAttemptEvent({
      eventId: 'lifecycle-0', attemptId: 'attempt-lifecycle', recordedAt: at(0),
      shardId: 'S02/P01', sourceFingerprint: 'v2:' + revision + ':' + 'd'.repeat(64),
      mode: 'Deep', targetForm: 'real-directory', controlGenerationHash: 'b'.repeat(64),
      leaseOwner: 'coordinator-main', coordinatorVersion: 'v1',
      adapterVersion: targets.TARGET_ADAPTER_VERSION, scannerSchemaVersion: 'scanner-v1',
      fingerprintVersion: 'v2', controlSchemaSetVersion: 'v1',
    }, { epoch, shards, target });
    attempts.appendAttemptEvent(journalPath, reserved);
    process.kill(process.pid, 'SIGKILL');
  }

  const events = attempts.loadAttemptJournal(journalPath);
  let current = [...attempts.latestAttemptEvents(events).values()][0];
  if (phase === 'start-requested') {
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'START_REQUESTED', { eventId: 'lifecycle-1', recordedAt: at(1) },
    ));
    process.kill(process.pid, 'SIGKILL');
  }
  if (phase === 'scan-id-receipt') {
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'RUNNING', { eventId: 'lifecycle-2', recordedAt: at(2), scanId: 'scan-lifecycle' },
    ));
    process.kill(process.pid, 'SIGKILL');
  }
  if (phase === 'completion') {
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'COMPLETION_REQUESTED', { eventId: 'lifecycle-3', recordedAt: at(3) },
    ));
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'SEALED', { eventId: 'lifecycle-4', recordedAt: at(4) },
    ));
    process.kill(process.pid, 'SIGKILL');
  }
  if (phase === 'publication-pending') {
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'SOURCE_VERIFIED', { eventId: 'lifecycle-5', recordedAt: at(5) },
    ));
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'PUBLICATION_PENDING', { eventId: 'lifecycle-6', recordedAt: at(6) },
    ));
    process.stdout.write(JSON.stringify(current));
    process.exit(0);
  }
  if (phase === 'published') {
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'PUBLISHED', { eventId: 'lifecycle-7', recordedAt: at(7) },
    ));
    current = attempts.appendAttemptEvent(journalPath, attempts.nextAttemptEvent(
      current, 'ADMITTED', { eventId: 'lifecycle-8', recordedAt: at(8) },
    ));
    process.stdout.write(JSON.stringify(current));
    process.exit(0);
  }
  throw new Error('unknown attempt phase');
`;

const bundleChild = String.raw`
  const [moduleUrl, root, phase] = process.argv.slice(1);
  const path = await import('node:path');
  const publication = await import(moduleUrl);
  const result = publication.publishImmutableBundle({
    sourceDirectory: path.join(root, 'bundle-source'),
    attemptsDirectory: path.join(root, 'attempts'),
    attemptId: 'attempt-lifecycle',
    now: new Date('2026-08-30T00:00:10.000Z'),
    faultInjector: phase === 'crash-copy'
      ? (point) => { if (point === 'after-copy-chunk') process.kill(process.pid, 'SIGKILL'); }
      : undefined,
  });
  process.stdout.write(JSON.stringify(result));
`;

const generationChild = String.raw`
  const [moduleUrl, root, phase, previousHash] = process.argv.slice(1);
  const path = await import('node:path');
  const publication = await import(moduleUrl);
  const result = publication.publishVerifiedGeneration({
    generationsDirectory: path.join(root, 'generations'),
    pointerPath: path.join(root, 'latest.json'),
    generationId: 'lifecycle-new',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'VERIFIED' } },
    expectedPrevious: { generationId: 'lifecycle-old', generationHash: previousHash },
    now: new Date('2026-08-30T00:00:20.000Z'),
    faultInjector: phase === 'crash-generation'
      ? (point) => { if (point === 'before-pointer-rename') process.kill(process.pid, 'SIGKILL'); }
      : undefined,
  });
  process.stdout.write(JSON.stringify(result));
`;

const pointerChild = String.raw`
  const [moduleUrl, root, phase, previousHash] = process.argv.slice(1);
  const path = await import('node:path');
  const publication = await import(moduleUrl);
  const result = publication.publishVerifiedGeneration({
    generationsDirectory: path.join(root, 'generations'),
    pointerPath: path.join(root, 'latest.json'),
    generationId: 'pointer-new',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'VERIFIED' } },
    expectedPrevious: { generationId: 'pointer-old', generationHash: previousHash },
    now: new Date('2026-08-30T00:00:30.000Z'),
    faultInjector: phase === 'crash-pointer'
      ? (point) => { if (point === 'after-pointer-directory-fsync') process.kill(process.pid, 'SIGKILL'); }
      : undefined,
  });
  process.stdout.write(JSON.stringify(result));
`;

try {
  const repoRoot = path.join(scratch, 'repo');
  fs.mkdirSync(path.join(repoRoot, 'scope'), { recursive: true });
  fs.writeFileSync(path.join(repoRoot, 'scope', 'target.txt'), 'lifecycle target\n');
  const journalPath = path.join(scratch, 'attempt-journal.json');
  const attemptArgs = [attemptsModuleUrl, inventoryModuleUrl, targetsModuleUrl, scratch];

  runChild(attemptChild, [...attemptArgs, 'reservation'], { status: null, signal: 'SIGKILL' });
  oneAttempt(journalPath, 'RESERVED', 1, undefined);
  runChild(attemptChild, [...attemptArgs, 'start-requested'], { status: null, signal: 'SIGKILL' });
  oneAttempt(journalPath, 'START_REQUESTED', 2, undefined);
  runChild(attemptChild, [...attemptArgs, 'scan-id-receipt'], { status: null, signal: 'SIGKILL' });
  oneAttempt(journalPath, 'RUNNING', 3, 'scan-lifecycle');
  runChild(attemptChild, [...attemptArgs, 'completion'], { status: null, signal: 'SIGKILL' });
  oneAttempt(journalPath, 'SEALED', 5, 'scan-lifecycle');
  runChild(attemptChild, [...attemptArgs, 'publication-pending']);
  oneAttempt(journalPath, 'PUBLICATION_PENDING', 7, 'scan-lifecycle');

  const bundleSource = path.join(scratch, 'bundle-source');
  fs.mkdirSync(bundleSource);
  fs.writeFileSync(path.join(bundleSource, 'coverage.json'), canonicalJson({
    schema: 'setjoin.security-program.coverage/v1', reviewedFiles: ['scope/target.txt'],
  }));
  fs.writeFileSync(path.join(bundleSource, 'manifest.json'), canonicalJson({
    schema: 'setjoin.security-program.manifest/v1', attemptId: 'attempt-lifecycle',
  }));
  runChild(bundleChild, [publicationModuleUrl, scratch, 'crash-copy'], {
    status: null, signal: 'SIGKILL',
  });
  const firstBundleRecovery = spawnSync(process.execPath, [
    '--input-type=module', '--eval', bundleChild, publicationModuleUrl, scratch, 'recover',
  ], { encoding: 'utf8', env: {} });
  assert.notEqual(firstBundleRecovery.status, 0,
    'partial copy recovery must quarantine before a fresh publication attempt');
  assert.equal(fs.existsSync(path.join(scratch, 'attempts', '.quarantine-attempt-lifecycle')), true);
  const bundlePublished = parseStrictJson(runChild(
    bundleChild, [publicationModuleUrl, scratch, 'recover'],
  ).stdout);
  const bundleReceiptPath = path.join(
    scratch, 'attempts', 'attempt-lifecycle', 'bundle-receipt.json',
  );
  const bundleReceiptText = fs.readFileSync(bundleReceiptPath, 'utf8');
  const bundleReplayed = parseStrictJson(runChild(
    bundleChild, [publicationModuleUrl, scratch, 'recover'],
  ).stdout);
  assert.deepEqual(bundleReplayed, bundlePublished, 'bundle replay changed its canonical receipt');
  assert.equal(fs.readFileSync(bundleReceiptPath, 'utf8'), bundleReceiptText,
    'bundle replay rewrote the canonical receipt');
  const verifiedBundle = verifyImmutableBundle({
    attemptsDirectory: path.join(scratch, 'attempts'), attemptId: 'attempt-lifecycle',
  });
  assert.equal(verifiedBundle.bundleHash, bundlePublished.bundleHash);
  assert.deepEqual(fs.readdirSync(path.join(scratch, 'attempts')).filter((name) => !name.startsWith('.')),
    ['attempt-lifecycle'], 'bundle recovery created more than one canonical attempt bundle');

  const generationRoot = path.join(scratch, 'generation-publication');
  const generationsDirectory = path.join(generationRoot, 'generations');
  const pointerPath = path.join(generationRoot, 'latest.json');
  const oldGeneration = publishVerifiedGeneration({
    generationsDirectory, pointerPath, generationId: 'lifecycle-old',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } },
    expectedPrevious: null, now: new Date(fixedTime),
  });
  const pointerBefore = fs.readFileSync(pointerPath, 'utf8');
  runChild(generationChild, [
    publicationModuleUrl, generationRoot, 'crash-generation', oldGeneration.generationHash,
  ], { status: null, signal: 'SIGKILL' });
  assert.equal(readVerifiedLatest({ generationsDirectory, pointerPath }).generationId, 'lifecycle-old');
  assert.equal(fs.readFileSync(pointerPath, 'utf8'), pointerBefore,
    'generation crash advanced the authority pointer early');
  const newReceiptBefore = fs.readFileSync(
    path.join(generationsDirectory, 'lifecycle-new', 'generation-receipt.json'), 'utf8',
  );
  const generationRecovered = parseStrictJson(runChild(generationChild, [
    publicationModuleUrl, generationRoot, 'recover', oldGeneration.generationHash,
  ]).stdout);
  const generationPointerText = fs.readFileSync(pointerPath, 'utf8');
  const generationReplayed = parseStrictJson(runChild(generationChild, [
    publicationModuleUrl, generationRoot, 'recover', oldGeneration.generationHash,
  ]).stdout);
  assert.deepEqual(generationReplayed, generationRecovered);
  assert.equal(fs.readFileSync(pointerPath, 'utf8'), generationPointerText,
    'generation replay advanced or rewrote the pointer a second time');
  assert.equal(fs.readFileSync(
    path.join(generationsDirectory, 'lifecycle-new', 'generation-receipt.json'), 'utf8',
  ), newReceiptBefore, 'generation recovery changed the canonical survivor receipt');
  assert.equal(readVerifiedLatest({ generationsDirectory, pointerPath }).generationId, 'lifecycle-new');
  assert.equal(fs.readdirSync(generationsDirectory).filter((name) => name === 'lifecycle-new').length, 1,
    'generation recovery created more than one canonical generation identity');

  const pointerRoot = path.join(scratch, 'pointer-publication');
  const pointerGenerations = path.join(pointerRoot, 'generations');
  const pointerLatest = path.join(pointerRoot, 'latest.json');
  const pointerOld = publishVerifiedGeneration({
    generationsDirectory: pointerGenerations, pointerPath: pointerLatest, generationId: 'pointer-old',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } },
    expectedPrevious: null, now: new Date(fixedTime),
  });
  const oldPointerValue = parseStrictJson(fs.readFileSync(pointerLatest, 'utf8'));
  runChild(pointerChild, [
    publicationModuleUrl, pointerRoot, 'crash-pointer', pointerOld.generationHash,
  ], { status: null, signal: 'SIGKILL' });
  const pointerAfterCrash = readVerifiedLatest({
    generationsDirectory: pointerGenerations, pointerPath: pointerLatest,
  });
  assert.equal(pointerAfterCrash.generationId, 'pointer-new');
  assert.equal(pointerAfterCrash.predecessorGenerationId, oldPointerValue.generationId);
  assert.equal(pointerAfterCrash.predecessorGenerationHash, oldPointerValue.generationHash);
  const pointerTextAfterCrash = fs.readFileSync(pointerLatest, 'utf8');
  const pointerRecovered = parseStrictJson(runChild(pointerChild, [
    publicationModuleUrl, pointerRoot, 'recover', pointerOld.generationHash,
  ]).stdout);
  assert.deepEqual(pointerRecovered, pointerAfterCrash,
    'fresh-process pointer replay did not preserve the committed advance');
  assert.equal(fs.readFileSync(pointerLatest, 'utf8'), pointerTextAfterCrash,
    'fresh-process pointer replay rewrote the committed pointer');
  assert.deepEqual(readVerifiedLatest({
    generationsDirectory: pointerGenerations, pointerPath: pointerLatest,
  }), pointerAfterCrash, 'pointer recovery advanced or rolled back a second time');
  assert.equal(fs.readdirSync(pointerGenerations).filter((name) => name === 'pointer-new').length, 1,
    'pointer replay created more than one canonical generation identity');

  runChild(attemptChild, [...attemptArgs, 'published']);
  oneAttempt(journalPath, 'ADMITTED', 9, 'scan-lifecycle');

  const scannerStarts = 0;
  const networkStarts = 0;
  assert.equal(scannerStarts, 0);
  assert.equal(networkStarts, 0);
  console.log('security-program lifecycle: PASS (7 named hard-exit boundaries, attempts=1 scanIds=1 canonicalBundles=1 canonicalGenerations=1 pointer=monotonic scanner=0 network=0)');
} finally {
  removeTree(scratch);
}
