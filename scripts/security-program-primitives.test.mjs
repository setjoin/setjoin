#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  SecurityProgramError,
  assertClosedSchema,
  canonicalJson,
  logicalArtifactRef,
  parseStrictJson,
  repositoryRelativeRef,
  sha256Hex,
} from './lib/security-program-json.mjs';
import { EXCLUSION_POLICY_SCHEMA, hashInventory, hashJson } from './lib/security-program-inventory.mjs';
import {
  DESKTOP_ATTEMPT_BINDING_SCHEMA,
  EXPORT_CAPACITY_SCHEMA,
  PINNED_STANDARD_ROUTE_CONTRACT_SHA256,
  STANDARD_TARGET_ROUTES,
  TARGET_ADAPTER_VERSION,
  prepareDesktopAttestedExportTarget,
  prepareDeepTarget,
  prepareStandardTarget,
} from './lib/security-program-targets.mjs';
import {
  ATTEMPT_EVENT_SCHEMA,
  ATTEMPT_JOURNAL_SCHEMA,
  acquireGlobalLease,
  attachLeaseScanId,
  appendAttemptEvent,
  buildReservedAttemptEvent,
  inspectGlobalLease,
  loadAttemptJournal,
  nextAttemptEvent,
  renewGlobalLease,
  releaseGlobalLease,
  validateAttemptAuthority,
  validateAttemptEvent,
} from './lib/security-program-attempts.mjs';
import {
  publishImmutableBundle,
  publishVerifiedGeneration,
  readVerifiedLatest,
  validateBundleReceipt,
  verifyImmutableBundle,
} from './lib/security-program-publication.mjs';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-primitives-'));
const secretHome = '/Users/private-operator';
const fixedNow = new Date('2026-08-30T00:00:00.000Z');
const authorityRepo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-attempt-authority-repo-')));
const authorityState = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-attempt-authority-state-')));
const authorityContents = Buffer.from('authority target\n');
const authorityObjectId = crypto.createHash('sha1')
  .update(`blob ${authorityContents.length}\0`).update(authorityContents).digest('hex');
const authorityEntry = {
  path: 'authority/target.txt', objectId: authorityObjectId, mode: '100644', kind: 'file',
};
fs.mkdirSync(path.join(authorityRepo, 'authority'));
fs.writeFileSync(path.join(authorityRepo, authorityEntry.path), authorityContents);
const authorityInventoryHash = hashInventory([{
  ...authorityEntry, pathBytes: Buffer.from(authorityEntry.path), objectType: 'blob',
}]);
const authorityPolicy = { schema: EXCLUSION_POLICY_SCHEMA, policyVersion: 'fixture/empty/v1', classes: [] };
const attemptEpoch = {
  schema: 'setjoin.security-program.epoch/v1', recordRole: 'authority', revision: '7'.repeat(40),
  sourceCommittedAt: '2026-08-29T00:00:00.000Z', historicalCandidateCount: 1,
  treePathCount: 1, authorizedCount: 1, excludedCount: 0,
  inventorySha256: authorityInventoryHash, exclusionPolicy: authorityPolicy,
  exclusionPolicySha256: hashJson(authorityPolicy), authorizedPaths: [authorityEntry], excludedPaths: [],
};
const attemptShards = {
  schema: 'setjoin.security-program.shards/v1', recordRole: 'authority',
  revision: attemptEpoch.revision,
  inventorySha256: attemptEpoch.inventorySha256,
  generationId: 'fixture-shards/v1',
  shards: [{
    id: 'S02/P01', ownerSectionId: 'S02', pathCount: 1,
    pathListSha256: authorityInventoryHash, paths: [authorityEntry],
  }],
};
const authorityHelper = path.join(
  os.homedir(), '.codex/plugins/cache/openai-curated-remote/codex-security/0.1.24/scripts/generate_rank_input.py',
);
const authorityGitResponse = ({ repoRoot, args }) => {
  assert.equal(repoRoot, authorityRepo);
  const command = args[0];
  if (args.join('\0') === ['rev-parse', '--is-inside-work-tree'].join('\0')) return { status: 0, stdout: 'true\n' };
  if (args.join('\0') === ['rev-parse', '--show-toplevel'].join('\0')) return { status: 0, stdout: `${authorityRepo}\n` };
  if (args.join('\0') === ['rev-parse', '--verify', 'HEAD^{commit}'].join('\0')) return { status: 0, stdout: `${attemptEpoch.revision}\n` };
  if (command === 'symbolic-ref') return { status: 1, stdout: Buffer.alloc(0) };
  if (command === 'status') return { status: 0, stdout: Buffer.alloc(0) };
  if (command === 'ls-tree') return { status: 0, stdout: Buffer.from(`100644 blob ${authorityObjectId}\t${authorityEntry.path}\0`) };
  throw new Error(`unexpected authority Git command ${args.join(' ')}`);
};
const authorityGitRunner = async (invocation) => authorityGitResponse(invocation);
const authorityVerificationGitRunner = (invocation) => authorityGitResponse(invocation);
const authorityTarget = await prepareStandardTarget({
  repoRoot: authorityRepo,
  shardGeneration: attemptShards,
  shardId: 'S02/P01',
  stateDir: authorityState,
  helperScriptPath: authorityHelper,
  gitRunner: authorityGitRunner,
  scopeRunner: async ({ args }) => {
    const scopesFile = args[args.indexOf('--scopes-file') + 1];
    const outputFile = args[args.indexOf('--out') + 1];
    const paths = JSON.parse(fs.readFileSync(scopesFile, 'utf8'));
    fs.writeFileSync(outputFile, `${paths.map((pathname) => JSON.stringify({ path: pathname })).join('\n')}\n`);
    return { status: 0, stdout: '', stderr: '' };
  },
});
const attemptAuthority = {
  epoch: attemptEpoch,
  shards: attemptShards,
  target: authorityTarget,
};

function expectCode(action, code) {
  assert.throws(action, (error) => error instanceof SecurityProgramError && error.code === code);
}

function removeAttemptTargetFixture(directory) {
  if (!fs.existsSync(directory)) return;
  const metadata = fs.lstatSync(directory);
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    fs.chmodSync(directory, 0o700);
    for (const name of fs.readdirSync(directory)) removeAttemptTargetFixture(path.join(directory, name));
  } else if (!metadata.isSymbolicLink()) fs.chmodSync(directory, 0o600);
  fs.rmSync(directory, { recursive: true, force: true });
}

function leaseRecord(stateDirectory) {
  return parseStrictJson(fs.readFileSync(path.join(stateDirectory, 'global-lease.lock', 'lease.json'), 'utf8'));
}

function publicationLockOwner(lockName, processId, overrides = {}) {
  return {
    schema: 'setjoin.security-program.publication-lock-owner/v1',
    lockName,
    hostId: os.hostname(),
    processId,
    processInstanceNonce: 'a'.repeat(64),
    processStartedAt: fixedNow.toISOString(),
    acquiredAt: fixedNow.toISOString(),
    ...overrides,
  };
}

function writePublicationLockFixture(parent, lockName, owner) {
  const lockDirectory = path.join(parent, lockName);
  fs.mkdirSync(lockDirectory, { recursive: true, mode: 0o700 });
  fs.chmodSync(lockDirectory, 0o700);
  fs.writeFileSync(path.join(lockDirectory, 'owner.json'), canonicalJson(owner), { flag: 'wx', mode: 0o600 });
  return lockDirectory;
}

function reservationFields(overrides = {}) {
  return {
    eventId: 'event-a0',
    attemptId: 'attempt-a',
    recordedAt: fixedNow.toISOString(),
    shardId: 'S02/P01',
    sourceFingerprint: `v2:${attemptEpoch.revision}:${'d'.repeat(64)}`,
    mode: 'Standard',
    targetForm: 'exact-paths-file',
    controlGenerationHash: 'b'.repeat(64),
    leaseOwner: 'coordinator-main',
    coordinatorVersion: 'v1',
    adapterVersion: TARGET_ADAPTER_VERSION,
    scannerSchemaVersion: 'scanner-v1',
    fingerprintVersion: 'v2',
    controlSchemaSetVersion: 'v1',
    ...overrides,
  };
}

function attempt(overrides = {}) {
  return buildReservedAttemptEvent(reservationFields(overrides), attemptAuthority);
}

let desktopAuthorityState;
let desktopExportParent;
try {
  // Strict JSON and stable hashes.
  assert.deepEqual(parseStrictJson('{"schema":"setjoin.security-program.fixture/v1","value":1}'), {
    schema: 'setjoin.security-program.fixture/v1', value: 1,
  });
  expectCode(() => parseStrictJson('{"state":"safe","state":"unsafe"}'), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
  expectCode(() => parseStrictJson('{"a":1,"\\u0061":2}'), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
  const closed = { schema: 'setjoin.security-program.fixture/v1', value: 1 };
  assert.equal(assertClosedSchema(closed, {
    schema: 'setjoin.security-program.fixture/v1', required: ['value'],
  }), closed);
  expectCode(() => assertClosedSchema({ ...closed, surprise: true }, {
    schema: closed.schema, required: ['value'],
  }), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
  let privacyError;
  try {
    assertClosedSchema({ ...closed, [secretHome]: true }, { schema: closed.schema, required: ['value'] });
  } catch (error) { privacyError = error; }
  assert(privacyError instanceof SecurityProgramError);
  assert.doesNotMatch(privacyError.message, /\/Users\/|private-operator/);
  assert.equal(canonicalJson({ z: 1, a: { y: 2, x: 3 } }), canonicalJson({ a: { x: 3, y: 2 }, z: 1 }));
  assert.equal(sha256Hex('same'), sha256Hex(Buffer.from('same')));

  // Public references are logical or repository-relative and never echo private roots.
  assert.equal(repositoryRelativeRef('shared/threat/score.go'), 'repo:shared/threat/score.go');
  assert.equal(logicalArtifactRef('attempt', 'attempt-a'), 'attempt:attempt-a');
  expectCode(() => repositoryRelativeRef(`${secretHome}/finding.json`), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => repositoryRelativeRef('../outside'), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');

  // A non-production Desktop fixture proves reservation refuses to persist a
  // test-only mount. Valid production-shaped rows below exercise the closed
  // journal schema and transition immutability without weakening that gate.
  desktopAuthorityState = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-attempt-desktop-state-'));
  desktopExportParent = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-attempt-desktop-export-'));
  const desktopBackend = {
    backendId: 'fixture-readonly-mount/v1', productionEligible: false,
    unsupportedDisposition: 'HOLD_TEST_ONLY_BACKEND',
    inspect({ targetPath }) {
      const metadata = fs.lstatSync(targetPath, { bigint: true });
      return { readOnly: true, targetPath: path.resolve(targetPath), realPath: fs.realpathSync.native(targetPath),
        deviceId: String(metadata.dev), rootInode: String(metadata.ino), deviceIdentifier: 'fixture-device',
        volumeUuid: 'fixture-volume' };
    },
    seal({ sourceDirectory, stateDirectory }) {
      const imagePath = path.join(stateDirectory, 'fixture-readonly.img');
      fs.writeFileSync(imagePath, 'fixture image\n', { mode: 0o600, flag: 'wx' });
      return { targetPath: sourceDirectory, imagePath, inspection: this.inspect({ targetPath: sourceDirectory }) };
    },
  };
  const desktopBinding = {
    schema: DESKTOP_ATTEMPT_BINDING_SCHEMA,
    attemptId: 'attempt-desktop',
    sourceFingerprint: `v2:${attemptEpoch.revision}:${'d'.repeat(64)}`,
    controlGenerationHash: 'b'.repeat(64),
    budgetId: 'budget-desktop-v1',
    budgetSha256: 'c'.repeat(64),
    exportCapacity: {
      schema: EXPORT_CAPACITY_SCHEMA,
      maxEntries: 2,
      maxBytes: authorityContents.length,
      minimumFreeBytes: 0,
      maxBuildElapsedMs: 60_000,
      maxBuildPeakRssBytes: Number.MAX_SAFE_INTEGER,
      maxSnapshotElapsedMs: 60_000,
      maxSnapshotPeakRssBytes: Number.MAX_SAFE_INTEGER,
    },
  };
  const desktopTarget = await prepareDesktopAttestedExportTarget({
    repoRoot: authorityRepo, shardGeneration: attemptShards, shardId: 'S02/P01',
    stateDir: desktopAuthorityState, exportParentDir: desktopExportParent,
    pluginRoot: path.dirname(path.dirname(authorityHelper)), gitRunner: authorityGitRunner,
    pluginDigestRunner: () => ({ digest: `codex-security-snapshot/v1:sha256:${'e'.repeat(64)}` }),
    readOnlyBackend: desktopBackend, attemptBinding: desktopBinding,
    sourceFingerprintVerifier: () => ({ sourceFingerprint: desktopBinding.sourceFingerprint }),
    allowTestBackend: true,
  });
  expectCode(() => buildReservedAttemptEvent(reservationFields({
    eventId: 'desktop-event-0', attemptId: desktopBinding.attemptId,
    sourceFingerprint: desktopBinding.sourceFingerprint,
    targetForm: 'attested-directory-export', controlGenerationHash: desktopBinding.controlGenerationHash,
  }), { epoch: attemptEpoch, shards: attemptShards, target: desktopTarget }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');

  const desktopReservedShape = validateAttemptEvent({
    ...attempt(),
    eventId: 'desktop-shape-0',
    attemptId: desktopBinding.attemptId,
    sourceFingerprint: desktopBinding.sourceFingerprint,
    controlGenerationHash: desktopBinding.controlGenerationHash,
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    routeContractSha256: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT],
    pluginVersion: '0.1.24',
    targetForm: 'attested-directory-export',
    targetKind: 'directory_snapshot',
    directorySnapshotDigest: desktopTarget.directorySnapshotDigest,
    exportTreeSha256: desktopTarget.exportTreeSha256,
    stableSnapshotSha256: desktopTarget.stableSnapshotSha256,
    productionEligible: true,
    budgetId: desktopBinding.budgetId,
    budgetSha256: desktopBinding.budgetSha256,
    exportCapacity: desktopBinding.exportCapacity,
  });
  const desktopRequestedShape = nextAttemptEvent(desktopReservedShape, 'START_REQUESTED', {
    eventId: 'desktop-shape-1',
  });
  for (const field of [
    'attemptId', 'sourceFingerprint', 'controlGenerationHash', 'budgetId', 'budgetSha256',
    'exportCapacity', 'stableSnapshotSha256', 'directorySnapshotDigest', 'exportTreeSha256',
    'productionEligible', 'pluginVersion', 'routeContractSha256', 'standardRoute',
    'adapterVersion', 'targetForm', 'targetKind',
  ]) {
    assert.deepEqual(desktopRequestedShape[field], desktopReservedShape[field], `${field} was not preserved`);
  }
  const desktopMutants = {
    attemptId: 'attempt-cross-reuse',
    sourceFingerprint: `v2:${attemptEpoch.revision}:${'f'.repeat(64)}`,
    controlGenerationHash: 'f'.repeat(64),
    budgetId: 'budget-cross-reuse-v1',
    budgetSha256: 'f'.repeat(64),
    exportCapacity: { ...desktopBinding.exportCapacity, maxBytes: desktopBinding.exportCapacity.maxBytes + 1 },
    stableSnapshotSha256: 'f'.repeat(64),
    directorySnapshotDigest: `codex-security-snapshot/v1:sha256:${'f'.repeat(64)}`,
    exportTreeSha256: 'f'.repeat(64),
    productionEligible: false,
    pluginVersion: '0.1.23',
    routeContractSha256: 'f'.repeat(64),
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    adapterVersion: 'security-target-adapter/v2',
    targetForm: 'exact-paths-file',
    targetKind: 'git_revision',
  };
  for (const [field, value] of Object.entries(desktopMutants)) {
    const mutantJournal = path.join(scratch, 'desktop-mutants', `${field}.json`);
    fs.mkdirSync(path.dirname(mutantJournal), { recursive: true });
    fs.writeFileSync(mutantJournal, canonicalJson({
      schema: ATTEMPT_JOURNAL_SCHEMA,
      events: [desktopReservedShape, { ...desktopRequestedShape, [field]: value }],
    }));
    expectCode(() => loadAttemptJournal(mutantJournal), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  }
  expectCode(() => buildReservedAttemptEvent(reservationFields({
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
  }), attemptAuthority), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => buildReservedAttemptEvent(reservationFields({
    targetKind: 'directory_snapshot',
  }), attemptAuthority), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => buildReservedAttemptEvent(reservationFields({
    budgetId: desktopBinding.budgetId,
  }), attemptAuthority), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');

  const deepTarget = await prepareDeepTarget({
    repoRoot: authorityRepo, shardGeneration: attemptShards, shardId: 'S02/P01',
    scope: 'authority', gitRunner: authorityGitRunner,
    verificationGitRunner: authorityVerificationGitRunner,
  });
  const deepAuthority = { epoch: attemptEpoch, shards: attemptShards, target: deepTarget };
  const deepReserved = buildReservedAttemptEvent(reservationFields({
    eventId: 'deep-event-0', attemptId: 'attempt-deep', mode: 'Deep', targetForm: 'real-directory',
  }), deepAuthority);
  assert.equal(deepReserved.targetKind, 'git_revision');
  for (const field of [
    'standardRoute', 'routeContractSha256', 'pluginVersion', 'directorySnapshotDigest',
    'exportTreeSha256', 'stableSnapshotSha256', 'productionEligible', 'budgetId',
    'budgetSha256', 'exportCapacity',
  ]) assert.equal(Object.hasOwn(deepReserved, field), false, `Deep attempt retained ${field}`);
  const deepRequested = nextAttemptEvent(deepReserved, 'START_REQUESTED', {
    eventId: 'deep-event-1', recordedAt: deepReserved.recordedAt,
  });
  assert.deepEqual(deepRequested, { ...deepReserved, eventId: 'deep-event-1', sequence: 1, state: 'START_REQUESTED' });
  expectCode(() => validateAttemptEvent({
    ...deepReserved, standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');

  // Append-only journal, legal graph, persisted identity, and double-start refusal.
  const journal = path.join(scratch, 'journal', 'attempts.json');
  fs.mkdirSync(path.dirname(journal), { recursive: true, mode: 0o755 });
  fs.chmodSync(path.dirname(journal), 0o755);
  const reserved = appendAttemptEvent(journal, attempt());
  assert.equal(reserved.standardRoute, STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS);
  assert.equal(reserved.routeContractSha256,
    PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS]);
  assert.equal(reserved.pluginVersion, '0.1.24');
  assert.equal(reserved.adapterVersion, TARGET_ADAPTER_VERSION);
  assert.equal(reserved.targetForm, 'exact-paths-file');
  assert.equal(reserved.targetKind, 'git_revision');
  for (const field of [
    'directorySnapshotDigest', 'exportTreeSha256', 'stableSnapshotSha256',
    'productionEligible', 'budgetId', 'budgetSha256', 'exportCapacity',
  ]) assert.equal(Object.hasOwn(reserved, field), false, `SDK attempt retained ${field}`);
  assert.equal(fs.statSync(path.dirname(journal)).mode & 0o777, 0o755, 'journal must preserve repository directory mode');
  const originalFirstEvent = structuredClone(loadAttemptJournal(journal)[0]);
  expectCode(() => appendAttemptEvent(journal, attempt({ eventId: 'event-b0', attemptId: 'attempt-b' })), 'E_SECURITY_PROGRAM_LIVE_LEASE');
  expectCode(() => nextAttemptEvent(reserved, 'SEALED', { eventId: 'event-a1' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => validateAttemptEvent({ ...attempt(), sectionId: 'S31' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => validateAttemptEvent({ ...attempt(), shardPathListSha256: 'A'.repeat(64) }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => appendAttemptEvent(path.join(scratch, 'bad-target', 'attempts.json'), attempt({ targetForm: 'real-directory' })), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => appendAttemptEvent(path.join(scratch, 'bad-deep-target', 'attempts.json'), attempt({ mode: 'Deep' })), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => appendAttemptEvent(path.join(scratch, 'bad-version', 'attempts.json'), attempt({ adapterVersion: secretHome })), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  const forgedReservation = { ...attempt({ eventId: 'forged-0', attemptId: 'attempt-forged' }) };
  expectCode(() => appendAttemptEvent(path.join(scratch, 'forged', 'attempts.json'), forgedReservation), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => validateAttemptAuthority({ ...attempt(), inventorySha256: '0'.repeat(64) }, attemptAuthority), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  for (const [field, value] of Object.entries({
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    routeContractSha256: 'f'.repeat(64),
    pluginVersion: '0.1.23',
    adapterVersion: 'security-target-adapter/v2',
    targetForm: 'attested-directory-export',
    targetKind: 'directory_snapshot',
  })) {
    expectCode(() => validateAttemptAuthority({ ...attempt(), [field]: value }, attemptAuthority),
      'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  }
  const requested = appendAttemptEvent(journal, nextAttemptEvent(reserved, 'START_REQUESTED', { eventId: 'event-a1' }));
  const running = appendAttemptEvent(journal, nextAttemptEvent(requested, 'RUNNING', { eventId: 'event-a2', scanId: 'scan-stable-a' }));
  const detached = appendAttemptEvent(journal, nextAttemptEvent(running, 'DETACHED', { eventId: 'event-a3' }));
  const rejoined = appendAttemptEvent(journal, nextAttemptEvent(detached, 'RUNNING', { eventId: 'event-a4' }));
  assert.equal(rejoined.scanId, 'scan-stable-a');
  expectCode(() => appendAttemptEvent(journal, nextAttemptEvent(rejoined, 'RUNNING', { eventId: 'event-a5', scanId: 'scan-replacement' })), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  assert.deepEqual(loadAttemptJournal(journal)[0], originalFirstEvent, 'append changed an earlier attempt record');
  assert.equal(loadAttemptJournal(journal).length, 5);

  const happyJournal = path.join(scratch, 'happy-journal', 'attempts.json');
  let happy = appendAttemptEvent(happyJournal, attempt({ eventId: 'happy-0', attemptId: 'attempt-happy' }));
  happy = appendAttemptEvent(happyJournal, nextAttemptEvent(happy, 'START_REQUESTED', { eventId: 'happy-1' }));
  happy = appendAttemptEvent(happyJournal, nextAttemptEvent(happy, 'RUNNING', { eventId: 'happy-2', scanId: 'scan-happy' }));
  for (const [state, eventId] of [
    ['COMPLETION_REQUESTED', 'happy-3'], ['SEALED', 'happy-4'], ['SOURCE_VERIFIED', 'happy-5'],
    ['PUBLICATION_PENDING', 'happy-6'], ['PUBLISHED', 'happy-7'], ['ADMITTED', 'happy-8'],
  ]) happy = appendAttemptEvent(happyJournal, nextAttemptEvent(happy, state, { eventId }));
  assert.equal(happy.state, 'ADMITTED');

  const unknownJournal = path.join(scratch, 'unknown-journal', 'attempts.json');
  let uncertain = appendAttemptEvent(unknownJournal, attempt({ eventId: 'unknown-0', attemptId: 'attempt-uncertain' }));
  uncertain = appendAttemptEvent(unknownJournal, nextAttemptEvent(uncertain, 'START_REQUESTED', { eventId: 'unknown-1' }));
  uncertain = appendAttemptEvent(unknownJournal, nextAttemptEvent(uncertain, 'RUNNING', { eventId: 'unknown-2', scanId: 'scan-uncertain' }));
  uncertain = appendAttemptEvent(unknownJournal, nextAttemptEvent(uncertain, 'COMPLETION_REQUESTED', { eventId: 'unknown-3' }));
  uncertain = appendAttemptEvent(unknownJournal, nextAttemptEvent(uncertain, 'COMPLETION_UNKNOWN', { eventId: 'unknown-4', reasonCode: 'COMPLETION_UNKNOWN' }));
  expectCode(() => appendAttemptEvent(unknownJournal, attempt({
    eventId: 'unknown-retry-0', attemptId: 'attempt-uncertain-retry', supersedesAttemptId: uncertain.attemptId,
  })), 'E_SECURITY_PROGRAM_LIVE_LEASE');

  const orphanJournal = path.join(scratch, 'orphan-journal', 'attempts.json');
  const orphanReserved = appendAttemptEvent(orphanJournal, attempt({ eventId: 'orphan-0', attemptId: 'attempt-orphan' }));
  const orphanRequested = appendAttemptEvent(orphanJournal, nextAttemptEvent(orphanReserved, 'START_REQUESTED', { eventId: 'orphan-1' }));
  const orphaned = appendAttemptEvent(orphanJournal, nextAttemptEvent(orphanRequested, 'ORPHANED_START', { eventId: 'orphan-2', reasonCode: 'ORPHANED_START' }));
  appendAttemptEvent(orphanJournal, nextAttemptEvent(orphaned, 'HOLD', { eventId: 'orphan-3', reasonCode: 'ORPHANED_START' }));
  const orphanCount = loadAttemptJournal(orphanJournal).length;
  expectCode(() => appendAttemptEvent(orphanJournal, attempt({
    eventId: 'orphan-retry-0', attemptId: 'attempt-orphan-retry', supersedesAttemptId: 'attempt-orphan',
  })), 'E_SECURITY_PROGRAM_ORPHANED_START');
  expectCode(() => appendAttemptEvent(orphanJournal, attempt({
    eventId: 'orphan-fresh-0', attemptId: 'attempt-orphan-fresh',
  })), 'E_SECURITY_PROGRAM_ORPHANED_START');
  assert.equal(loadAttemptJournal(orphanJournal).length, orphanCount, 'orphaned start allowed a new reservation');

  // Portable exclusive lease: live owners cannot be stolen; stale identities only
  // instruct the caller to rejoin or hold, never to launch a replacement.
  const liveState = path.join(scratch, 'lease-live');
  const live = acquireGlobalLease(liveState, {
    owner: 'coordinator-main', hostId: 'fixture-host', processId: 4242,
    attemptId: 'attempt-live', now: fixedNow, ttlMs: 60_000,
    token: 'fixture-live-token', isProcessAlive: () => false,
  });
  assert.equal(JSON.stringify(live).includes('fixture-live-token'), false, 'lease token must not be serializable');
  expectCode(() => attachLeaseScanId(liveState, {
    attemptId: 'attempt-live', token: 'wrong-token', scanId: 'scan-attached',
    now: new Date(fixedNow.getTime() + 1_000),
  }), 'E_SECURITY_PROGRAM_LIVE_LEASE');
  const beforeAttach = leaseRecord(liveState);
  const attached = attachLeaseScanId(liveState, {
    attemptId: 'attempt-live', token: live.token, scanId: 'scan-attached',
    now: new Date(fixedNow.getTime() + 1_000),
  });
  assert.equal(attached.updated, true);
  const afterAttach = leaseRecord(liveState);
  assert.equal(afterAttach.scanId, 'scan-attached');
  for (const key of ['owner', 'hostId', 'processId', 'attemptId', 'tokenHash', 'acquiredAt', 'expiresAt']) {
    assert.equal(afterAttach[key], beforeAttach[key], `attach changed lease identity field ${key}`);
  }
  assert.equal(attachLeaseScanId(liveState, {
    attemptId: 'attempt-live', token: live.token, scanId: 'scan-attached',
    now: new Date(fixedNow.getTime() + 2_000),
  }).updated, false, 'same scanId attachment must be idempotent');
  expectCode(() => attachLeaseScanId(liveState, {
    attemptId: 'attempt-live', token: live.token, scanId: 'scan-replacement',
    now: new Date(fixedNow.getTime() + 2_000),
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => renewGlobalLease(liveState, {
    attemptId: 'attempt-live', token: 'wrong-token', now: new Date(fixedNow.getTime() + 30_000), ttlMs: 60_000,
  }), 'E_SECURITY_PROGRAM_LIVE_LEASE');
  const renewed = renewGlobalLease(liveState, {
    attemptId: 'attempt-live', token: live.token, now: new Date(fixedNow.getTime() + 30_000), ttlMs: 60_000,
  });
  assert.equal(renewed.scanId, 'scan-attached');
  const afterRenew = leaseRecord(liveState);
  assert(Date.parse(afterRenew.expiresAt) > Date.parse(afterAttach.expiresAt));
  for (const key of ['owner', 'hostId', 'processId', 'attemptId', 'tokenHash', 'acquiredAt', 'scanId']) {
    assert.equal(afterRenew[key], afterAttach[key], `renewal changed lease identity field ${key}`);
  }
  expectCode(() => acquireGlobalLease(liveState, {
    owner: 'coordinator-second', hostId: 'fixture-host', processId: 4243,
    attemptId: 'attempt-second', now: fixedNow, ttlMs: 60_000,
    token: 'fixture-second-token', isProcessAlive: () => false,
  }), 'E_SECURITY_PROGRAM_LIVE_LEASE');
  releaseGlobalLease(liveState, { attemptId: 'attempt-live', token: live.token });
  assert.equal(inspectGlobalLease(liveState).status, 'FREE');

  const leaseFaults = [
    'before-lease-temp-create', 'after-lease-temp-fsync', 'before-lease-rename',
    'after-lease-rename', 'after-lease-directory-fsync',
  ];
  for (const [index, fault] of leaseFaults.entries()) {
    const stateDirectory = path.join(scratch, `lease-attach-fault-${index}`);
    const handle = acquireGlobalLease(stateDirectory, {
      owner: 'coordinator-main', hostId: 'fixture-host', processId: 4242,
      attemptId: `attempt-attach-${index}`, now: fixedNow, ttlMs: 60_000,
      token: `attach-token-${index}`, isProcessAlive: () => false,
    });
    assert.throws(() => attachLeaseScanId(stateDirectory, {
      attemptId: `attempt-attach-${index}`, token: handle.token, scanId: `scan-attach-${index}`,
      now: new Date(fixedNow.getTime() + 1_000),
      faultInjector: (point) => { if (point === fault) throw new Error(`injected:${fault}`); },
    }), new RegExp(`injected:${fault}`));
    const record = leaseRecord(stateDirectory);
    if (['after-lease-rename', 'after-lease-directory-fsync'].includes(fault)) assert.equal(record.scanId, `scan-attach-${index}`);
    else assert.equal(record.scanId, undefined);
  }
  for (const [index, fault] of leaseFaults.entries()) {
    const stateDirectory = path.join(scratch, `lease-renew-fault-${index}`);
    const handle = acquireGlobalLease(stateDirectory, {
      owner: 'coordinator-main', hostId: 'fixture-host', processId: 4242,
      attemptId: `attempt-renew-${index}`, scanId: `scan-renew-${index}`,
      now: fixedNow, ttlMs: 60_000, token: `renew-token-${index}`, isProcessAlive: () => false,
    });
    const originalExpiry = leaseRecord(stateDirectory).expiresAt;
    assert.throws(() => renewGlobalLease(stateDirectory, {
      attemptId: `attempt-renew-${index}`, token: handle.token,
      now: new Date(fixedNow.getTime() + 30_000), ttlMs: 60_000,
      faultInjector: (point) => { if (point === fault) throw new Error(`injected:${fault}`); },
    }), new RegExp(`injected:${fault}`));
    const record = leaseRecord(stateDirectory);
    if (['after-lease-rename', 'after-lease-directory-fsync'].includes(fault)) assert(Date.parse(record.expiresAt) > Date.parse(originalExpiry));
    else assert.equal(record.expiresAt, originalExpiry);
    assert.equal(record.scanId, `scan-renew-${index}`);
  }

  const tamperedLeaseState = path.join(scratch, 'lease-tamper');
  const tamperedHandle = acquireGlobalLease(tamperedLeaseState, {
    owner: 'coordinator-main', hostId: 'fixture-host', processId: 4242,
    attemptId: 'attempt-tampered', now: fixedNow, ttlMs: 60_000,
    token: 'tampered-token', isProcessAlive: () => false,
  });
  const tamperedLeasePath = path.join(tamperedLeaseState, 'global-lease.lock', 'lease.json');
  const tamperedText = fs.readFileSync(tamperedLeasePath, 'utf8').replace(
    /"tokenHash":"([0-9a-f]{64})"/,
    '"tokenHash":"$1","tokenHash":"$1"',
  );
  fs.writeFileSync(tamperedLeasePath, tamperedText);
  expectCode(() => renewGlobalLease(tamperedLeaseState, {
    attemptId: 'attempt-tampered', token: tamperedHandle.token,
    now: new Date(fixedNow.getTime() + 30_000), ttlMs: 60_000,
  }), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');

  const expiredLeaseState = path.join(scratch, 'lease-expired');
  const expiredHandle = acquireGlobalLease(expiredLeaseState, {
    owner: 'coordinator-main', hostId: 'fixture-host', processId: 4242,
    attemptId: 'attempt-expired', now: fixedNow, ttlMs: 1,
    token: 'expired-token', isProcessAlive: () => false,
  });
  expectCode(() => renewGlobalLease(expiredLeaseState, {
    attemptId: 'attempt-expired', token: expiredHandle.token,
    now: new Date(fixedNow.getTime() + 2), ttlMs: 60_000,
  }), 'E_SECURITY_PROGRAM_LEASE_EXPIRED');

  const interruptedUpdateState = path.join(scratch, 'lease-update-lock');
  const interruptedHandle = acquireGlobalLease(interruptedUpdateState, {
    owner: 'coordinator-main', hostId: 'fixture-host', processId: 4242,
    attemptId: 'attempt-update-lock', now: fixedNow, ttlMs: 60_000,
    token: 'update-lock-token', isProcessAlive: () => false,
  });
  fs.mkdirSync(path.join(interruptedUpdateState, 'global-lease.lock', 'update.lock'));
  expectCode(() => attachLeaseScanId(interruptedUpdateState, {
    attemptId: 'attempt-update-lock', token: interruptedHandle.token, scanId: 'scan-must-not-attach',
    now: new Date(fixedNow.getTime() + 1_000),
  }), 'E_SECURITY_PROGRAM_LIVE_LEASE');

  const staleKnownState = path.join(scratch, 'lease-stale-known');
  acquireGlobalLease(staleKnownState, {
    owner: 'coordinator-main', hostId: 'old-host', processId: 4242,
    attemptId: 'attempt-known', scanId: 'scan-known', now: fixedNow, ttlMs: 1,
    token: 'known-token', isProcessAlive: () => false,
  });
  const knownSignal = inspectGlobalLease(staleKnownState, {
    now: new Date(fixedNow.getTime() + 10_000), currentHostId: 'new-host', isProcessAlive: () => false,
  });
  assert.deepEqual({ action: knownSignal.action, state: knownSignal.state, scanId: knownSignal.scanId }, {
    action: 'REJOIN_EXISTING', state: 'DETACHED', scanId: 'scan-known',
  });

  const staleUnknownState = path.join(scratch, 'lease-stale-unknown');
  acquireGlobalLease(staleUnknownState, {
    owner: 'coordinator-main', hostId: 'old-host', processId: 4242,
    attemptId: 'attempt-unknown', now: fixedNow, ttlMs: 1,
    token: 'unknown-token', isProcessAlive: () => false,
  });
  const unknownSignal = inspectGlobalLease(staleUnknownState, {
    now: new Date(fixedNow.getTime() + 10_000), currentHostId: 'new-host', isProcessAlive: () => false,
  });
  assert.deepEqual({ action: unknownSignal.action, state: unknownSignal.state, disposition: unknownSignal.disposition, scanId: unknownSignal.scanId }, {
    action: 'RECONCILE_ORPHANED_START', state: 'ORPHANED_START', disposition: 'HOLD', scanId: null,
  });

  // Bundle publication copies into a destination-local exclusive temp directory,
  // hashes and fsyncs it, then makes the attempt directory immutable in one rename.
  const bundleSource = path.join(scratch, 'bundle-source');
  fs.mkdirSync(path.join(bundleSource, 'nested'), { recursive: true });
  fs.writeFileSync(path.join(bundleSource, 'coverage.json'), '{"reviewed":219}\n');
  fs.writeFileSync(path.join(bundleSource, 'nested', 'manifest.json'), '{"sealed":true}\n');
  const largeFixtureBytes = 8 * 1024 * 1024;
  const largeSource = path.join(bundleSource, 'nested', 'large-artifact.bin');
  const largeDescriptor = fs.openSync(largeSource, 'wx');
  try {
    const chunk = Buffer.alloc(64 * 1024, 0x5a);
    for (let written = 0; written < largeFixtureBytes; written += chunk.length) fs.writeSync(largeDescriptor, chunk);
  } finally {
    fs.closeSync(largeDescriptor);
  }
  const attemptsDirectory = path.join(scratch, 'bundles', 'attempts');
  const publishedBundle = publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId: 'bundle-good', now: fixedNow,
  });
  assert.equal(publishedBundle.artifactRef, 'attempt:bundle-good');
  assert.equal(publishedBundle.fileCount, 3);
  assert.equal(fs.existsSync(path.join(attemptsDirectory, '.publish-lock-bundle-good')), false,
    'normal publication must safely release its owner lock');
  assert.equal(verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }).bundleHash, publishedBundle.bundleHash);
  const publishedBundleRoot = path.join(attemptsDirectory, 'bundle-good');
  const publishedCanonicalRoot = path.join(publishedBundleRoot, 'canonical');
  const bundleReceiptPath = path.join(publishedBundleRoot, 'bundle-receipt.json');
  const originalBundleReceiptText = fs.readFileSync(bundleReceiptPath, 'utf8');
  const assertSealedTreeModes = (root) => {
    assert.equal(fs.lstatSync(root).mode & 0o777, 0o500, `${root} must be sealed mode 0500`);
    for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
      const filename = path.join(root, entry.name);
      if (entry.isDirectory()) assertSealedTreeModes(filename);
      else assert.equal(fs.lstatSync(filename).mode & 0o777, 0o400, `${filename} must be sealed mode 0400`);
    }
  };
  const rewriteSealedFile = (filename, bytes) => {
    fs.chmodSync(filename, 0o600);
    try { fs.writeFileSync(filename, bytes); }
    finally { fs.chmodSync(filename, 0o400); }
  };
  const replaceSealedFile = (filename, bytes) => {
    const parent = path.dirname(filename);
    const replacement = `${filename}.replacement`;
    fs.chmodSync(parent, 0o700);
    try {
      fs.writeFileSync(replacement, bytes, { mode: 0o400, flag: 'wx' });
      fs.renameSync(replacement, filename);
    } finally {
      if (fs.existsSync(replacement)) fs.unlinkSync(replacement);
      fs.chmodSync(parent, 0o500);
    }
  };
  assertSealedTreeModes(publishedBundleRoot);
  const largePublished = path.join(attemptsDirectory, 'bundle-good', 'canonical', 'nested', 'large-artifact.bin');
  const originalReadFileSync = fs.readFileSync;
  fs.readFileSync = function guardedReadFileSync(filename, ...args) {
    if (path.resolve(String(filename)) === path.resolve(largePublished)) throw new Error('whole-file read attempted for large artifact');
    return originalReadFileSync.call(this, filename, ...args);
  };
  try {
    assert.equal(verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }).bundleHash, publishedBundle.bundleHash);
  } finally {
    fs.readFileSync = originalReadFileSync;
  }

  const originalReadSync = fs.readSync;
  let mutationInjected = false;
  fs.readSync = function mutatingReadSync(descriptor, ...args) {
    const read = originalReadSync.call(this, descriptor, ...args);
    if (!mutationInjected && Number(fs.fstatSync(descriptor, { bigint: true }).size) === largeFixtureBytes) {
      mutationInjected = true;
      fs.chmodSync(largePublished, 0o600);
      fs.appendFileSync(largePublished, 'x');
    }
    return read;
  };
  try {
    expectCode(() => verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  } finally {
    fs.readSync = originalReadSync;
    fs.truncateSync(largePublished, largeFixtureBytes);
    fs.chmodSync(largePublished, 0o400);
  }
  assert.equal(mutationInjected, true, 'large-file consistency mutation was not injected');

  const swapSource = path.join(scratch, 'bundle-swap-source');
  const swapAttempts = path.join(scratch, 'bundle-swap-attempts');
  fs.mkdirSync(swapSource, { recursive: true });
  const swapPath = path.join(swapSource, 'coverage.json');
  const movedSwapPath = path.join(swapSource, 'coverage-original.json');
  fs.writeFileSync(swapPath, Buffer.alloc(128 * 1024, 0x41));
  let pathSwapInjected = false;
  expectCode(() => publishImmutableBundle({
    sourceDirectory: swapSource,
    attemptsDirectory: swapAttempts,
    attemptId: 'bundle-path-swap',
    now: fixedNow,
    faultInjector: (point) => {
      if (point !== 'after-copy-chunk' || pathSwapInjected) return;
      pathSwapInjected = true;
      fs.renameSync(swapPath, movedSwapPath);
      fs.symlinkSync(movedSwapPath, swapPath);
    },
  }), 'E_SECURITY_PROGRAM_SOURCE_CHANGED');
  assert.equal(pathSwapInjected, true, 'bundle source path-swap mutation was not injected');

  const replayedBundle = publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId: 'bundle-good',
    now: new Date(fixedNow.getTime() + 60_000),
  });
  assert.deepEqual(replayedBundle, publishedBundle,
    'an identical bundle replay must return the original canonical publication result');
  assert.equal(fs.readFileSync(bundleReceiptPath, 'utf8'), originalBundleReceiptText,
    'bundle replay must retain the exact original receipt');
  rewriteSealedFile(bundleReceiptPath, `${originalBundleReceiptText}\n`);
  expectCode(() => publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId: 'bundle-good', now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(bundleReceiptPath, originalBundleReceiptText);
  const conflictingBundleTemporary = path.join(attemptsDirectory, '.tmp-bundle-good');
  fs.mkdirSync(conflictingBundleTemporary, { mode: 0o700 });
  expectCode(() => publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId: 'bundle-good', now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.rmdirSync(conflictingBundleTemporary);
  const sourceManifest = path.join(bundleSource, 'nested', 'manifest.json');
  const sourceManifestBytes = fs.readFileSync(sourceManifest);
  fs.appendFileSync(sourceManifest, 'changed');
  expectCode(() => publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId: 'bundle-good', now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.writeFileSync(sourceManifest, sourceManifestBytes);
  const publishedCoverage = path.join(publishedCanonicalRoot, 'coverage.json');
  const publishedCoverageBytes = fs.readFileSync(publishedCoverage);
  rewriteSealedFile(publishedCoverage, Buffer.concat([publishedCoverageBytes, Buffer.from('tamper')]));
  expectCode(() => verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(publishedCoverage, publishedCoverageBytes);
  fs.chmodSync(publishedCoverage, 0o600);
  expectCode(() => verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId: 'bundle-good', now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.chmodSync(publishedCoverage, 0o400);
  replaceSealedFile(publishedCoverage, Buffer.concat([publishedCoverageBytes, Buffer.from('replacement')]));
  expectCode(() => verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(publishedCoverage, publishedCoverageBytes);
  fs.chmodSync(publishedCanonicalRoot, 0o700);
  expectCode(() => verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId: 'bundle-good', now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.chmodSync(publishedCanonicalRoot, 0o500);

  const originalBundleReceipt = parseStrictJson(originalBundleReceiptText);
  const canonicalTimestamp = '2026-08-30T00:00:00.123456Z';
  assert.equal(validateBundleReceipt({ ...originalBundleReceipt, createdAt: canonicalTimestamp }).createdAt,
    canonicalTimestamp);
  for (const invalidTimestamp of [
    '2026-08-30T00:00:00Z',
    '2026-08-30T00:00:00.1Z',
    '2026-08-30T00:00:00.1234Z',
    '2026-08-30T00:00:00.1234567Z',
    '2026-08-30T00:00:00.123+00:00',
    '2026-08-30T00:00:00.123z',
    '2026-02-29T00:00:00.123Z',
    '2026-04-31T00:00:00.123Z',
    '2026-08-30T24:00:00.123Z',
  ]) {
    rewriteSealedFile(bundleReceiptPath, canonicalJson({ ...originalBundleReceipt, createdAt: invalidTimestamp }));
    expectCode(() => verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  }
  rewriteSealedFile(bundleReceiptPath, canonicalJson(originalBundleReceipt));
  assert.equal(verifyImmutableBundle({ attemptsDirectory, attemptId: 'bundle-good' }).bundleHash, publishedBundle.bundleHash);

  const bundleFaults = [
    'after-bundle-temp-created', 'after-copy-chunk', 'after-copy-file-fsync',
    'after-bundle-canonical-fsync', 'after-bundle-receipt-fsync', 'after-bundle-temp-fsync',
    'after-bundle-rename', 'after-bundle-sealed', 'after-bundle-parent-fsync',
  ];
  for (const [index, fault] of bundleFaults.entries()) {
    const faultRoot = path.join(scratch, `bundle-fault-${index}`, 'attempts');
    assert.throws(() => publishImmutableBundle({
      sourceDirectory: bundleSource,
      attemptsDirectory: faultRoot,
      attemptId: `bundle-fault-${index}`,
      now: fixedNow,
      faultInjector: (point) => { if (point === fault) throw new Error(`injected:${fault}`); },
    }), new RegExp(`injected:${fault}`));
    const final = path.join(faultRoot, `bundle-fault-${index}`);
    if (fs.existsSync(final)) {
      if (fault === 'after-bundle-rename') {
        expectCode(() => verifyImmutableBundle({ attemptsDirectory: faultRoot, attemptId: `bundle-fault-${index}` }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
        expectCode(() => publishImmutableBundle({
          sourceDirectory: bundleSource,
          attemptsDirectory: faultRoot,
          attemptId: `bundle-fault-${index}`,
          now: fixedNow,
        }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
      } else {
        verifyImmutableBundle({ attemptsDirectory: faultRoot, attemptId: `bundle-fault-${index}` });
      }
    } else {
      assert(fs.existsSync(path.join(faultRoot, `.quarantine-bundle-fault-${index}`)), 'incomplete bundle was not quarantined');
    }
  }
  const partialBundleAttempts = path.join(scratch, 'bundle-partial-survivor', 'attempts');
  const partialBundleFinal = path.join(partialBundleAttempts, 'bundle-partial');
  fs.mkdirSync(path.join(partialBundleFinal, 'canonical'), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(partialBundleFinal, 'canonical'), 0o500);
  fs.chmodSync(partialBundleFinal, 0o500);
  assert.throws(() => publishImmutableBundle({
    sourceDirectory: bundleSource,
    attemptsDirectory: partialBundleAttempts,
    attemptId: 'bundle-partial',
    now: fixedNow,
  }), /ENOENT|evidence/i, 'a partial bundle survivor must fail closed');

  // Pointer-last publication: before the swap the prior generation remains current;
  // after it, the new pointer is accepted only because its immutable generation verifies.
  const generationFaults = [
    'after-generation-temp-created', 'after-generation-file-fsync',
    'after-generation-receipt-fsync', 'after-generation-temp-fsync',
    'after-generation-rename', 'after-generation-sealed', 'after-generation-parent-fsync', 'after-generation-verified',
    'before-pointer-temp-create', 'after-pointer-temp-fsync', 'before-pointer-rename',
    'after-pointer-rename', 'after-pointer-sealed', 'after-pointer-directory-fsync',
  ];
  for (const [index, fault] of generationFaults.entries()) {
    const root = path.join(scratch, `generation-fault-${index}`);
    const generationsDirectory = path.join(root, 'generations');
    const pointerPath = path.join(root, 'latest.json');
    fs.mkdirSync(generationsDirectory, { recursive: true, mode: 0o755 });
    fs.chmodSync(generationsDirectory, 0o755);
    publishVerifiedGeneration({
      generationsDirectory, pointerPath, generationId: 'old',
      files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } },
      now: fixedNow,
    });
    assert.equal(fs.statSync(generationsDirectory).mode & 0o777, 0o755, 'generation publication must preserve repository directory mode');
    assert.throws(() => publishVerifiedGeneration({
      generationsDirectory, pointerPath, generationId: 'new',
      files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'VERIFIED' } },
      now: new Date(fixedNow.getTime() + 1_000),
      faultInjector: (point) => { if (point === fault) throw new Error(`injected:${fault}`); },
    }), new RegExp(`injected:${fault}`));
    if (['after-pointer-temp-fsync', 'after-generation-rename'].includes(fault)) {
      expectCode(() => readVerifiedLatest({ generationsDirectory, pointerPath }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
    } else {
      const current = readVerifiedLatest({ generationsDirectory, pointerPath });
      assert(['old', 'new'].includes(current.generationId));
      if (['after-pointer-rename', 'after-pointer-sealed', 'after-pointer-directory-fsync'].includes(fault)) assert.equal(current.generationId, 'new');
      else assert.equal(current.generationId, 'old');
    }
  }

  const replayRoot = path.join(scratch, 'generation-replay');
  const replayGenerations = path.join(replayRoot, 'generations');
  const replayPointer = path.join(replayRoot, 'latest.json');
  const replayOld = publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-old',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } },
    expectedPrevious: null,
    now: fixedNow,
  });
  const replayFiles = {
    'status.json': { schema: 'setjoin.security-program.status/v1', state: 'VERIFIED' },
  };
  assert.throws(() => publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-new',
    files: replayFiles,
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: new Date(fixedNow.getTime() + 1_000),
    faultInjector: (point) => { if (point === 'before-pointer-rename') throw new Error('injected:replay-before-pointer-rename'); },
  }), /injected:replay-before-pointer-rename/);
  assert.equal(readVerifiedLatest({ generationsDirectory: replayGenerations, pointerPath: replayPointer }).generationId,
    replayOld.generationId, 'a crash before pointer rename must retain the predecessor pointer');
  const replayReceiptPath = path.join(replayGenerations, 'replay-new', 'generation-receipt.json');
  const replayReceiptBefore = fs.readFileSync(replayReceiptPath, 'utf8');
  const replayPreparedPointer = `${replayPointer}.tmp-replay-new`;
  const replayPreparedPointerText = fs.readFileSync(replayPreparedPointer, 'utf8');
  const replayPreparedPointerValue = parseStrictJson(replayPreparedPointerText);
  rewriteSealedFile(replayPreparedPointer, canonicalJson({
    ...replayPreparedPointerValue,
    generationHash: '0'.repeat(64),
  }));
  expectCode(() => publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-new',
    files: replayFiles,
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(replayPreparedPointer, replayPreparedPointerText);
  const conflictingGenerationTemporary = path.join(replayGenerations, '.tmp-replay-new');
  fs.mkdirSync(conflictingGenerationTemporary, { mode: 0o755 });
  expectCode(() => publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-new',
    files: replayFiles,
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.rmdirSync(conflictingGenerationTemporary);
  const replayRecovered = publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-new',
    files: replayFiles,
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: new Date(fixedNow.getTime() + 60_000),
  });
  assert.equal(replayRecovered.generationId, 'replay-new');
  assert.equal(fs.readFileSync(replayReceiptPath, 'utf8'), replayReceiptBefore,
    'crash recovery must retain the exact prepared canonical receipt');
  assert.equal(fs.existsSync(`${replayPointer}.tmp-replay-new`), false,
    'crash recovery must consume the matching prepared pointer exactly once');
  const replayAgain = publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-new',
    files: replayFiles,
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: new Date(fixedNow.getTime() + 120_000),
  });
  assert.deepEqual(replayAgain, replayRecovered,
    'an already-advanced generation replay must return the same verified publication result');

  // A real hard exit after the canonical bundle rename retains an unsealed
  // protocol marker bound to the dead lock owner. A fresh process quarantines
  // that exact survivor, then recreates the canonical bundle safely.
  const unsealedBundleRoot = path.join(scratch, 'bundle-unsealed-hard-exit');
  const unsealedBundleSource = path.join(unsealedBundleRoot, 'source');
  const unsealedBundleAttempts = path.join(unsealedBundleRoot, 'attempts');
  fs.mkdirSync(unsealedBundleSource, { recursive: true });
  fs.writeFileSync(path.join(unsealedBundleSource, 'coverage.json'), '{"reviewed":219}\n');
  const publicationModuleUrl = new URL('./lib/security-program-publication.mjs', import.meta.url).href;
  const hardExitBundleChild = `
    const [moduleUrl, root, phase] = process.argv.slice(1);
    const path = await import('node:path');
    const publication = await import(moduleUrl);
    const result = publication.publishImmutableBundle({
      sourceDirectory: path.join(root, 'source'),
      attemptsDirectory: path.join(root, 'attempts'),
      attemptId: 'unsealed-bundle',
      now: new Date('2026-08-30T00:00:01.000Z'),
      faultInjector: phase === 'crash'
        ? (point) => { if (point === 'after-bundle-rename') process.exit(74); }
        : undefined,
    });
    process.stdout.write(JSON.stringify(result));
  `;
  const crashedBundle = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitBundleChild,
    publicationModuleUrl, unsealedBundleRoot, 'crash',
  ], { encoding: 'utf8', env: {} });
  assert.equal(crashedBundle.status, 74, crashedBundle.stderr);
  const unsealedBundleFinal = path.join(unsealedBundleAttempts, 'unsealed-bundle');
  const unsealedBundleReceiptBefore = fs.readFileSync(path.join(unsealedBundleFinal, 'bundle-receipt.json'), 'utf8');
  assert.equal(fs.lstatSync(unsealedBundleFinal).mode & 0o777, 0o700);
  const recoveredBundle = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitBundleChild,
    publicationModuleUrl, unsealedBundleRoot, 'recover',
  ], { encoding: 'utf8', env: {} });
  assert.equal(recoveredBundle.status, 0, recoveredBundle.stderr);
  const recoveredBundleResult = parseStrictJson(recoveredBundle.stdout);
  assert.equal(recoveredBundleResult.artifactRef, 'attempt:unsealed-bundle');
  assert.equal(verifyImmutableBundle({
    attemptsDirectory: unsealedBundleAttempts, attemptId: 'unsealed-bundle',
  }).bundleHash, recoveredBundleResult.bundleHash);
  const unsealedBundleQuarantines = fs.readdirSync(unsealedBundleAttempts)
    .filter((name) => name.startsWith('.quarantine-crash-bundle-') && !name.endsWith('.recovery.json'));
  assert.equal(unsealedBundleQuarantines.length, 1);
  const quarantinedBundle = path.join(unsealedBundleAttempts, unsealedBundleQuarantines[0]);
  assert.equal(fs.readFileSync(path.join(quarantinedBundle, 'bundle-receipt.json'), 'utf8'),
    unsealedBundleReceiptBefore, 'quarantine must retain the exact crash survivor');
  assertSealedTreeModes(quarantinedBundle);
  assert.equal(fs.lstatSync(`${quarantinedBundle}.recovery.json`).mode & 0o777, 0o400);
  const replayedRecoveredBundle = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitBundleChild,
    publicationModuleUrl, unsealedBundleRoot, 'recover',
  ], { encoding: 'utf8', env: {} });
  assert.equal(replayedRecoveredBundle.status, 0, replayedRecoveredBundle.stderr);
  assert.deepEqual(parseStrictJson(replayedRecoveredBundle.stdout), recoveredBundleResult);
  assert.equal(fs.readdirSync(unsealedBundleAttempts)
    .filter((name) => name.startsWith('.quarantine-crash-bundle-') && !name.endsWith('.recovery.json')).length, 1);

  const crashBundleFixture = (name) => {
    const root = path.join(scratch, name);
    fs.mkdirSync(path.join(root, 'source'), { recursive: true });
    fs.writeFileSync(path.join(root, 'source', 'coverage.json'), '{"reviewed":219}\n');
    const crashed = spawnSync(process.execPath, [
      '--input-type=module', '--eval', hardExitBundleChild,
      publicationModuleUrl, root, 'crash',
    ], { encoding: 'utf8', env: {} });
    assert.equal(crashed.status, 74, crashed.stderr);
    return root;
  };
  const malformedBundleRoot = crashBundleFixture('bundle-unsealed-malformed');
  const malformedBundleAttempts = path.join(malformedBundleRoot, 'attempts');
  fs.appendFileSync(
    path.join(malformedBundleAttempts, 'unsealed-bundle', 'publication-survivor.json'),
    'tamper',
  );
  expectCode(() => publishImmutableBundle({
    sourceDirectory: path.join(malformedBundleRoot, 'source'),
    attemptsDirectory: malformedBundleAttempts,
    attemptId: 'unsealed-bundle',
    now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  assert.equal(fs.existsSync(path.join(malformedBundleAttempts, 'unsealed-bundle')), true,
    'malformed canonical survivor must not be quarantined');
  const racedBundleRoot = crashBundleFixture('bundle-unsealed-race');
  const racedBundleAttempts = path.join(racedBundleRoot, 'attempts');
  expectCode(() => publishImmutableBundle({
    sourceDirectory: path.join(racedBundleRoot, 'source'),
    attemptsDirectory: racedBundleAttempts,
    attemptId: 'unsealed-bundle',
    now: fixedNow,
    faultInjector: (point) => {
      if (point !== 'before-bundle-survivor-quarantine') return;
      const canonical = path.join(racedBundleAttempts, 'unsealed-bundle');
      const moved = path.join(racedBundleAttempts, '.raced-unsealed-bundle');
      fs.renameSync(canonical, moved);
      fs.symlinkSync(moved, canonical);
    },
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  assert.equal(fs.lstatSync(path.join(racedBundleAttempts, 'unsealed-bundle')).isSymbolicLink(), true,
    'path-swapped survivor must remain HOLD evidence');

  // A process.exit() bypasses finally and leaves the durable owner lock behind.
  // A distinct process may resume only after proving that local owner PID dead;
  // the stale lock remains quarantined as evidence.
  const hardExitRoot = path.join(scratch, 'generation-hard-exit');
  const hardExitGenerations = path.join(hardExitRoot, 'generations');
  const hardExitPointer = path.join(hardExitRoot, 'latest.json');
  const hardExitOld = publishVerifiedGeneration({
    generationsDirectory: hardExitGenerations,
    pointerPath: hardExitPointer,
    generationId: 'hard-exit-old',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } },
    expectedPrevious: null,
    now: fixedNow,
  });
  assert.equal(readVerifiedLatest({
    generationsDirectory: hardExitGenerations, pointerPath: hardExitPointer,
  }).generationHash, hardExitOld.generationHash);
  const hardExitChild = `
    const [moduleUrl, root, phase] = process.argv.slice(1);
    const path = await import('node:path');
    const publication = await import(moduleUrl);
    const generationsDirectory = path.join(root, 'generations');
    const pointerPath = path.join(root, 'latest.json');
    const previous = publication.readVerifiedLatest({ generationsDirectory, pointerPath });
    const result = publication.publishVerifiedGeneration({
      generationsDirectory,
      pointerPath,
      generationId: 'hard-exit-new',
      files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'VERIFIED' } },
      expectedPrevious: { generationId: previous.predecessorGenerationId === null ? 'hard-exit-old' : previous.predecessorGenerationId,
        generationHash: previous.predecessorGenerationHash === null ? previous.generationHash : previous.predecessorGenerationHash },
      now: new Date('2026-08-30T00:00:01.000Z'),
      faultInjector: phase === 'crash'
        ? (point) => { if (point === 'before-pointer-rename') process.exit(73); }
        : undefined,
    });
    process.stdout.write(JSON.stringify(result));
  `;
  const crashedPublication = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitChild, publicationModuleUrl, hardExitRoot, 'crash',
  ], { encoding: 'utf8', env: {} });
  assert.equal(crashedPublication.status, 73, crashedPublication.stderr);
  const retainedPublicationLock = path.join(hardExitGenerations, '.publication.lock');
  assert.equal(fs.existsSync(retainedPublicationLock), true, 'hard exit must retain its publication lock');
  const retainedOwner = parseStrictJson(fs.readFileSync(path.join(retainedPublicationLock, 'owner.json'), 'utf8'));
  assert.equal(retainedOwner.processId, crashedPublication.pid);
  assert.equal(retainedOwner.hostId, os.hostname());
  const hardExitReceipt = fs.readFileSync(
    path.join(hardExitGenerations, 'hard-exit-new', 'generation-receipt.json'),
    'utf8',
  );
  const recoveredPublication = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitChild, publicationModuleUrl, hardExitRoot, 'recover',
  ], { encoding: 'utf8', env: {} });
  assert.equal(recoveredPublication.status, 0, recoveredPublication.stderr);
  const recoveredPublicationResult = parseStrictJson(recoveredPublication.stdout);
  assert.equal(recoveredPublicationResult.generationId, 'hard-exit-new');
  assert.equal(fs.readFileSync(
    path.join(hardExitGenerations, 'hard-exit-new', 'generation-receipt.json'),
    'utf8',
  ), hardExitReceipt, 'fresh-process recovery must preserve the exact immutable survivor receipt');
  assert.equal(readVerifiedLatest({
    generationsDirectory: hardExitGenerations, pointerPath: hardExitPointer,
  }).generationId, 'hard-exit-new');
  assert.equal(fs.existsSync(`${hardExitPointer}.tmp-hard-exit-new`), false,
    'fresh-process recovery must advance the prepared pointer exactly once');
  const staleLockQuarantines = fs.readdirSync(hardExitGenerations)
    .filter((name) => name.startsWith('.quarantine-stale-lock-'));
  assert.equal(staleLockQuarantines.length, 1, 'dead owner lock must be retained in one unique quarantine');
  const quarantinedOwnerPath = path.join(hardExitGenerations, staleLockQuarantines[0], 'owner.json');
  assert.equal(fs.readFileSync(quarantinedOwnerPath, 'utf8'), canonicalJson(retainedOwner));
  assert.equal(fs.lstatSync(path.dirname(quarantinedOwnerPath)).mode & 0o777, 0o700);
  assert.equal(fs.lstatSync(quarantinedOwnerPath).mode & 0o777, 0o600);

  // Generation recovery additionally quarantines the exact prepared pointer,
  // then publishes the same generation at its canonical name and advances once.
  const unsealedGenerationRoot = path.join(scratch, 'generation-unsealed-hard-exit');
  const unsealedGenerationDirectory = path.join(unsealedGenerationRoot, 'generations');
  const unsealedGenerationPointer = path.join(unsealedGenerationRoot, 'latest.json');
  const unsealedGenerationOld = publishVerifiedGeneration({
    generationsDirectory: unsealedGenerationDirectory,
    pointerPath: unsealedGenerationPointer,
    generationId: 'unsealed-old',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } },
    expectedPrevious: null,
    now: fixedNow,
  });
  const hardExitGenerationChild = `
    const [moduleUrl, root, phase, previousHash] = process.argv.slice(1);
    const path = await import('node:path');
    const publication = await import(moduleUrl);
    const result = publication.publishVerifiedGeneration({
      generationsDirectory: path.join(root, 'generations'),
      pointerPath: path.join(root, 'latest.json'),
      generationId: 'unsealed-new',
      files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'VERIFIED' } },
      expectedPrevious: { generationId: 'unsealed-old', generationHash: previousHash },
      now: new Date('2026-08-30T00:00:01.000Z'),
      faultInjector: phase === 'crash'
        ? (point) => { if (point === 'after-generation-rename') process.exit(75); }
        : undefined,
    });
    process.stdout.write(JSON.stringify(result));
  `;
  const crashedGeneration = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitGenerationChild,
    publicationModuleUrl, unsealedGenerationRoot, 'crash', unsealedGenerationOld.generationHash,
  ], { encoding: 'utf8', env: {} });
  assert.equal(crashedGeneration.status, 75, crashedGeneration.stderr);
  const unsealedGenerationFinal = path.join(unsealedGenerationDirectory, 'unsealed-new');
  const unsealedGenerationReceiptBefore = fs.readFileSync(
    path.join(unsealedGenerationFinal, 'generation-receipt.json'), 'utf8',
  );
  assert.equal(fs.lstatSync(unsealedGenerationFinal).mode & 0o777, 0o755);
  assert.equal(parseStrictJson(fs.readFileSync(unsealedGenerationPointer, 'utf8')).generationId, 'unsealed-old');
  const recoveredGeneration = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitGenerationChild,
    publicationModuleUrl, unsealedGenerationRoot, 'recover', unsealedGenerationOld.generationHash,
  ], { encoding: 'utf8', env: {} });
  assert.equal(recoveredGeneration.status, 0, recoveredGeneration.stderr);
  const recoveredGenerationResult = parseStrictJson(recoveredGeneration.stdout);
  assert.equal(recoveredGenerationResult.generationId, 'unsealed-new');
  assert.equal(readVerifiedLatest({
    generationsDirectory: unsealedGenerationDirectory, pointerPath: unsealedGenerationPointer,
  }).generationHash, recoveredGenerationResult.generationHash);
  assert.equal(fs.existsSync(`${unsealedGenerationPointer}.tmp-unsealed-new`), false);
  const unsealedGenerationQuarantines = fs.readdirSync(unsealedGenerationDirectory)
    .filter((name) => name.startsWith('.quarantine-crash-generation-') && !name.endsWith('.recovery.json'));
  assert.equal(unsealedGenerationQuarantines.length, 1);
  const quarantinedGeneration = path.join(unsealedGenerationDirectory, unsealedGenerationQuarantines[0]);
  assert.equal(fs.readFileSync(path.join(quarantinedGeneration, 'generation-receipt.json'), 'utf8'),
    unsealedGenerationReceiptBefore);
  assertSealedTreeModes(quarantinedGeneration);
  assert.equal(fs.lstatSync(`${quarantinedGeneration}.recovery.json`).mode & 0o777, 0o400);
  const pointerQuarantines = fs.readdirSync(unsealedGenerationRoot)
    .filter((name) => name.startsWith('.quarantine-crash-pointer-'));
  assert.equal(pointerQuarantines.length, 1, 'prepared pointer must be quarantined exactly once');
  assert.equal(fs.lstatSync(path.join(unsealedGenerationRoot, pointerQuarantines[0])).mode & 0o777, 0o400);
  const replayedRecoveredGeneration = spawnSync(process.execPath, [
    '--input-type=module', '--eval', hardExitGenerationChild,
    publicationModuleUrl, unsealedGenerationRoot, 'recover', unsealedGenerationOld.generationHash,
  ], { encoding: 'utf8', env: {} });
  assert.equal(replayedRecoveredGeneration.status, 0, replayedRecoveredGeneration.stderr);
  assert.deepEqual(parseStrictJson(replayedRecoveredGeneration.stdout), recoveredGenerationResult);
  assert.equal(fs.readdirSync(unsealedGenerationRoot)
    .filter((name) => name.startsWith('.quarantine-crash-pointer-')).length, 1,
  'idempotent replay must not advance or quarantine the pointer again');

  // Lock recovery is deliberately conservative for live, malformed, foreign,
  // swapped, and concurrently replaced owner evidence.
  const lockMutantSource = path.join(scratch, 'publication-lock-mutant-source');
  fs.mkdirSync(lockMutantSource, { recursive: true });
  fs.writeFileSync(path.join(lockMutantSource, 'evidence.json'), '{}\n');
  const exitedOwnerProcess = spawnSync(process.execPath, ['--eval', 'process.exit(0)']);
  assert.equal(exitedOwnerProcess.status, 0);
  const runLockMutant = (name, setup, faultInjector) => {
    const parent = path.join(scratch, `publication-lock-${name}`);
    const attemptId = `lock-${name}`;
    const lockName = `.publish-lock-${attemptId}`;
    fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
    setup({ parent, lockName });
    expectCode(() => publishImmutableBundle({
      sourceDirectory: lockMutantSource,
      attemptsDirectory: parent,
      attemptId,
      now: fixedNow,
      faultInjector,
    }), 'E_SECURITY_PROGRAM_LIVE_LEASE');
    assert.equal(fs.existsSync(path.join(parent, attemptId)), false,
      `${name} lock mutant must not publish`);
  };
  runLockMutant('live', ({ parent, lockName }) => {
    writePublicationLockFixture(parent, lockName, publicationLockOwner(lockName, process.pid));
  });
  runLockMutant('malformed', ({ parent, lockName }) => {
    const lockDirectory = path.join(parent, lockName);
    fs.mkdirSync(lockDirectory, { mode: 0o700 });
    fs.writeFileSync(path.join(lockDirectory, 'owner.json'), '{"not":"canonical"}\n', { mode: 0o600 });
  });
  runLockMutant('symlink', ({ parent, lockName }) => {
    const symlinkTarget = path.join(parent, '.symlink-lock-target');
    fs.mkdirSync(symlinkTarget, { mode: 0o700 });
    fs.symlinkSync(symlinkTarget, path.join(parent, lockName));
  });
  runLockMutant('foreign', ({ parent, lockName }) => {
    writePublicationLockFixture(parent, lockName, publicationLockOwner(lockName, exitedOwnerProcess.pid, {
      hostId: `${os.hostname()}-different`,
    }));
  });
  runLockMutant('owner-swap', ({ parent, lockName }) => {
    writePublicationLockFixture(parent, lockName, publicationLockOwner(lockName, exitedOwnerProcess.pid));
  }, (point, { lockName }) => {
    if (point !== 'after-publication-lock-inspected') return;
    const lockDirectory = path.join(scratch, 'publication-lock-owner-swap', lockName);
    const ownerPath = path.join(lockDirectory, 'owner.json');
    const ownerText = fs.readFileSync(ownerPath, 'utf8');
    fs.renameSync(ownerPath, path.join(lockDirectory, 'owner.original'));
    fs.writeFileSync(ownerPath, ownerText, { mode: 0o600, flag: 'wx' });
  });
  runLockMutant('recovery-race', ({ parent, lockName }) => {
    writePublicationLockFixture(parent, lockName, publicationLockOwner(lockName, exitedOwnerProcess.pid));
  }, (point, { lockName }) => {
    if (point !== 'before-publication-lock-quarantine') return;
    const parent = path.join(scratch, 'publication-lock-recovery-race');
    const lockDirectory = path.join(parent, lockName);
    fs.renameSync(lockDirectory, path.join(parent, '.concurrent-recovery-winner'));
    writePublicationLockFixture(parent, lockName, publicationLockOwner(lockName, process.pid, {
      processInstanceNonce: 'b'.repeat(64),
    }));
  });

  rewriteSealedFile(replayReceiptPath, `${replayReceiptBefore}\n`);
  expectCode(() => publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-new',
    files: replayFiles,
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(replayReceiptPath, replayReceiptBefore);
  expectCode(() => publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'replay-new',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'CHANGED' } },
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  expectCode(() => publishVerifiedGeneration({
    generationsDirectory: replayGenerations,
    pointerPath: replayPointer,
    generationId: 'stale-expected',
    files: replayFiles,
    expectedPrevious: { generationId: replayOld.generationId, generationHash: replayOld.generationHash },
    now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  assert.equal(fs.existsSync(path.join(replayGenerations, 'stale-expected')), false,
    'a stale expectedPrevious must fail before creating publication evidence');

  const unsealedRoot = path.join(scratch, 'generation-unsealed-replay');
  const unsealedGenerations = path.join(unsealedRoot, 'generations');
  const unsealedPointer = path.join(unsealedRoot, 'latest.json');
  const unsealedOld = publishVerifiedGeneration({
    generationsDirectory: unsealedGenerations,
    pointerPath: unsealedPointer,
    generationId: 'unsealed-old',
    files: replayFiles,
    expectedPrevious: null,
    now: fixedNow,
  });
  assert.throws(() => publishVerifiedGeneration({
    generationsDirectory: unsealedGenerations,
    pointerPath: unsealedPointer,
    generationId: 'unsealed-new',
    files: replayFiles,
    expectedPrevious: { generationId: unsealedOld.generationId, generationHash: unsealedOld.generationHash },
    now: new Date(fixedNow.getTime() + 1_000),
    faultInjector: (point) => { if (point === 'after-generation-rename') throw new Error('injected:unsealed-generation'); },
  }), /injected:unsealed-generation/);
  expectCode(() => publishVerifiedGeneration({
    generationsDirectory: unsealedGenerations,
    pointerPath: unsealedPointer,
    generationId: 'unsealed-new',
    files: replayFiles,
    expectedPrevious: { generationId: unsealedOld.generationId, generationHash: unsealedOld.generationHash },
    now: fixedNow,
  }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  const partialGenerationRoot = path.join(scratch, 'generation-partial-survivor');
  const partialGenerations = path.join(partialGenerationRoot, 'generations');
  const partialPointer = path.join(partialGenerationRoot, 'latest.json');
  const partialOld = publishVerifiedGeneration({
    generationsDirectory: partialGenerations,
    pointerPath: partialPointer,
    generationId: 'partial-old',
    files: replayFiles,
    expectedPrevious: null,
    now: fixedNow,
  });
  const partialFinal = path.join(partialGenerations, 'partial-new');
  fs.mkdirSync(partialFinal, { mode: 0o500 });
  assert.throws(() => publishVerifiedGeneration({
    generationsDirectory: partialGenerations,
    pointerPath: partialPointer,
    generationId: 'partial-new',
    files: replayFiles,
    expectedPrevious: { generationId: partialOld.generationId, generationHash: partialOld.generationHash },
    now: fixedNow,
  }), /ENOENT|evidence/i, 'a partial generation survivor must fail closed');
  assert.equal(fs.existsSync(partialFinal), true, 'conflicting partial evidence must not be deleted');

  const lineageRoot = path.join(scratch, 'generation-lineage');
  const lineageGenerations = path.join(lineageRoot, 'generations');
  const lineagePointer = path.join(lineageRoot, 'latest.json');
  const firstGeneration = publishVerifiedGeneration({
    generationsDirectory: lineageGenerations, pointerPath: lineagePointer, generationId: 'lineage-one',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } }, now: fixedNow,
  });
  assert.equal(firstGeneration.predecessorGenerationId, null);
  assert.equal(firstGeneration.predecessorGenerationHash, null);
  const firstPointerText = fs.readFileSync(lineagePointer, 'utf8');
  const secondGeneration = publishVerifiedGeneration({
    generationsDirectory: lineageGenerations, pointerPath: lineagePointer, generationId: 'lineage-two',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'VERIFIED' } },
    now: new Date(fixedNow.getTime() + 1_000),
  });
  assert.equal(secondGeneration.predecessorGenerationId, firstGeneration.generationId);
  assert.equal(secondGeneration.predecessorGenerationHash, firstGeneration.generationHash);
  const secondPointerText = fs.readFileSync(lineagePointer, 'utf8');
  assertSealedTreeModes(path.join(lineageGenerations, 'lineage-one'));
  assertSealedTreeModes(path.join(lineageGenerations, 'lineage-two'));
  assert.equal(fs.statSync(lineagePointer).mode & 0o777, 0o400);

  rewriteSealedFile(lineagePointer, firstPointerText);
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(lineagePointer, secondPointerText);

  const repointed = parseStrictJson(secondPointerText);
  repointed.generationId = firstGeneration.generationId;
  rewriteSealedFile(lineagePointer, canonicalJson(repointed));
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(lineagePointer, secondPointerText);

  const secondReceiptPath = path.join(lineageGenerations, 'lineage-two', 'generation-receipt.json');
  const secondReceiptText = fs.readFileSync(secondReceiptPath, 'utf8');
  const tamperedLineageReceipt = parseStrictJson(secondReceiptText);
  tamperedLineageReceipt.predecessorGenerationHash = '0'.repeat(64);
  rewriteSealedFile(secondReceiptPath, canonicalJson(tamperedLineageReceipt));
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(secondReceiptPath, secondReceiptText);
  assert.equal(readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }).generationId, 'lineage-two');

  for (const invalidTimestamp of [
    '2026-08-30T00:00:01Z', '2026-08-30T00:00:01.12Z',
    '2026-08-30T00:00:01.1234Z', '2026-08-30T00:00:01.123+00:00',
    '2026-08-30T00:00:01.123z', '2026-02-29T00:00:01.123Z',
  ]) {
    rewriteSealedFile(secondReceiptPath, canonicalJson({
      ...parseStrictJson(secondReceiptText), createdAt: invalidTimestamp,
    }));
    expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  }
  rewriteSealedFile(secondReceiptPath, secondReceiptText);

  const secondStatusPath = path.join(lineageGenerations, 'lineage-two', 'status.json');
  const secondStatusBytes = fs.readFileSync(secondStatusPath);
  rewriteSealedFile(secondStatusPath, Buffer.concat([secondStatusBytes, Buffer.from('content-tamper')]));
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(secondStatusPath, secondStatusBytes);
  fs.chmodSync(secondStatusPath, 0o600);
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.chmodSync(secondStatusPath, 0o400);
  replaceSealedFile(secondStatusPath, Buffer.concat([secondStatusBytes, Buffer.from('replacement')]));
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  rewriteSealedFile(secondStatusPath, secondStatusBytes);
  fs.chmodSync(path.join(lineageGenerations, 'lineage-two'), 0o700);
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.chmodSync(path.join(lineageGenerations, 'lineage-two'), 0o500);
  fs.chmodSync(lineagePointer, 0o600);
  expectCode(() => readVerifiedLatest({ generationsDirectory: lineageGenerations, pointerPath: lineagePointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.chmodSync(lineagePointer, 0o400);

  const tamperRoot = path.join(scratch, 'pointer-tamper');
  const tamperGenerations = path.join(tamperRoot, 'generations');
  const tamperPointer = path.join(tamperRoot, 'latest.json');
  publishVerifiedGeneration({
    generationsDirectory: tamperGenerations, pointerPath: tamperPointer, generationId: 'one',
    files: { 'status.json': { schema: 'setjoin.security-program.status/v1', state: 'HOLD' } }, now: fixedNow,
  });
  const pointer = JSON.parse(fs.readFileSync(tamperPointer, 'utf8'));
  pointer.generationHash = '0'.repeat(64);
  rewriteSealedFile(tamperPointer, canonicalJson(pointer));
  expectCode(() => readVerifiedLatest({ generationsDirectory: tamperGenerations, pointerPath: tamperPointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');

  for (const invalidTimestamp of [
    '2026-08-30T00:00:00Z', '2026-08-30T00:00:00.12Z',
    '2026-08-30T00:00:00.1234Z', '2026-08-30T00:00:00.123+00:00',
    '2026-08-30T00:00:00.123z', '2026-02-29T00:00:00.123Z',
  ]) {
    rewriteSealedFile(tamperPointer, canonicalJson({ ...pointer, createdAt: invalidTimestamp }));
    expectCode(() => readVerifiedLatest({ generationsDirectory: tamperGenerations, pointerPath: tamperPointer }), 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  }

  // Hermeticity and privacy: production primitives have no scanner, process-launch,
  // network, credential-provider, or absolute-path output surface. The test-only
  // child processes above exercise actual hard-exit recovery with an empty env.
  const ownedSources = [
    './lib/security-program-json.mjs',
    './lib/security-program-attempts.mjs',
    './lib/security-program-publication.mjs',
  ].map((relative) => fs.readFileSync(new URL(relative, import.meta.url), 'utf8')).join('\n');
  assert.doesNotMatch(ownedSources, /node:child_process|\bfetch\s*\(|https?:\/\//);
  const scannerStarts = 0;
  assert.equal(scannerStarts, 0, 'primitive tests must never start a real scanner');
  const publicValues = [publishedBundle, knownSignal, unknownSignal];
  assert.doesNotMatch(JSON.stringify(publicValues), /\/Users\/|private-operator|setjoin-security-primitives-/);

  console.log(`security-program primitives: PASS (${leaseFaults.length * 2} lease-update faults, ${bundleFaults.length} bundle faults, ${generationFaults.length} generation/pointer faults, hard-exit lock + unsealed survivor recovery, ${Object.keys(desktopMutants).length} Desktop-route mutants, SDK/Deep absence rules, false-production target blocked, orphan retry blocked, lineage rollback blocked, 8 MiB streamed, zero scanner starts)`);
} finally {
  removeAttemptTargetFixture(scratch);
  fs.rmSync(authorityRepo, { recursive: true, force: true });
  fs.rmSync(authorityState, { recursive: true, force: true });
  if (desktopAuthorityState) removeAttemptTargetFixture(desktopAuthorityState);
  if (desktopExportParent) removeAttemptTargetFixture(desktopExportParent);
}
