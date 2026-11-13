#!/usr/bin/env node

import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
  SecurityProgramError,
  canonicalJson,
  sha256Hex,
} from './lib/security-program-json.mjs';
import {
  EXCLUSION_POLICY_SCHEMA,
  INVENTORY_DECISION_SCHEMA,
  INVENTORY_DECISION_VERSION,
  compileInventory,
  hashInventory,
  hashJson,
} from './lib/security-program-inventory.mjs';
import {
  ADMISSION_INPUT_SCHEMA,
  DEEP_PROMOTION_SCHEMA,
  EPOCH_SCHEMA,
  PILOT_BUDGET_SCHEMA,
  RECORD_ROLES,
  RESULT_CLAIM_SCHEMA,
  buildDeepPromotionRecord,
  buildEpochRecord,
  buildObservationRecord,
  buildPilotBudgetRecord,
  buildPilotVerdictRecord,
  buildReconciliationRecord,
  buildResultClaimRecord,
  buildReviewedSetRecord,
  buildSectionsRecord,
  buildShardGenerationRecord,
  buildStatusRecord,
  hashReviewedFilePaths,
  issueVerifiedAdmissionCapability,
  issueVerifiedDeepFallbackAuthority,
  validateDeepPromotions,
  validateAdmissionInputRecord,
  validateEpochRecord,
  validateObservationRecords,
  validatePilotBudgetRecord,
  validatePilotVerdictRecord,
  validateReconciliationRecord,
  validateResultClaimRecord,
  validateReviewedSetExtension,
  validateSectionsRecord,
  validateStatusRecord,
} from './lib/security-program-records.mjs';
import { ATTEMPT_EVENT_SCHEMA, ATTEMPT_JOURNAL_SCHEMA } from './lib/security-program-attempts.mjs';
import { publishImmutableBundle } from './lib/security-program-publication.mjs';
import {
  PINNED_STANDARD_ROUTE_CONTRACT_SHA256,
  STANDARD_TARGET_ROUTES,
  TARGET_ADAPTER_VERSION,
  prepareDeepTarget,
  prepareStandardTarget,
  verifyPreparedTarget,
} from './lib/security-program-targets.mjs';

const fixedTime = '2026-08-30T00:00:00.000Z';
const sourceCommittedAt = '2026-08-29T00:00:00.000Z';
const revision = '7'.repeat(40);
const sha = (value) => sha256Hex(value);
const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-records-'));
const attemptsDirectory = path.join(evidenceRoot, 'attempt-bundles');
const syntheticBundles = new Map();

function removeFixtureTree(directory) {
  if (!fs.existsSync(directory)) return;
  const metadata = fs.lstatSync(directory);
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    fs.chmodSync(directory, 0o700);
    for (const name of fs.readdirSync(directory)) removeFixtureTree(path.join(directory, name));
  } else if (!metadata.isSymbolicLink()) fs.chmodSync(directory, 0o600);
  fs.rmSync(directory, { recursive: true, force: true });
}

function reviewedSetExtension(reviewedFiles) {
  return {
    'setjoin.security-program.reviewed-set/v1': {
      fully_reviewed_files: [...reviewedFiles],
      count: reviewedFiles.length,
      path_list_sha256: hashReviewedFilePaths(reviewedFiles),
    },
  };
}

function registerSyntheticBundle(
  attemptId,
  scanId,
  reviewedFiles,
  targetAuthority,
  completeness = 'complete',
  { scopePaths = reviewedFiles, mutateCoverage, mutateManifest } = {},
) {
  const desktop = targetAuthority.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT;
  const includePaths = desktop ? ['.'] : [...scopePaths];
  const coverageDocument = {
    documentType: 'codex-security.coverage',
    schemaVersion: '1.0',
    scanId,
    mode: desktop ? 'repository' : 'scoped_path',
    completeness,
    inventoryStrategy: desktop ? 'directory' : 'scoped_path',
    includePaths,
    excludePaths: [],
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
    extensions: reviewedSetExtension(reviewedFiles),
  };
  mutateCoverage?.(coverageDocument);
  const coverageBytes = canonicalJson(coverageDocument);
  const findingsBytes = canonicalJson({ documentType: 'codex-security.findings', schemaVersion: '1.0', findings: [] });
  const manifestDocument = {
    schemaVersion: '1.0',
    documentType: 'codex-security.scan-manifest',
    scan: {
      id: scanId,
      producer: { name: 'codex-security-plugin', version: '0.1.24' },
      status: 'completed',
      startedAt: fixedTime,
      completedAt: fixedTime,
      sealedAt: fixedTime,
      target: {
        kind: targetAuthority.targetKind,
        targetId: revision,
        displayName: 'synthetic-fixture',
        ...(desktop ? { snapshotDigest: targetAuthority.directorySnapshotDigest } : { revision }),
      },
      scope: { includePaths, excludePaths: [] },
      coverageRef: 'coverage.json',
      findingsRef: 'findings.json',
      artifacts: [
        { path: 'findings.json', sha256: sha256Hex(findingsBytes), mediaType: 'application/json' },
        { path: 'coverage.json', sha256: sha256Hex(coverageBytes), mediaType: 'application/json' },
      ],
    },
  };
  mutateManifest?.(manifestDocument);
  const documents = {
    'coverage.json': coverageBytes,
    'findings.json': findingsBytes,
    'scan-manifest.json': canonicalJson(manifestDocument),
  };
  const sourceDirectory = path.join(evidenceRoot, `source-${attemptId}`);
  fs.mkdirSync(sourceDirectory, { recursive: true });
  for (const [pathname, bytes] of Object.entries(documents)) fs.writeFileSync(path.join(sourceDirectory, pathname), bytes);
  const published = publishImmutableBundle({
    sourceDirectory, attemptsDirectory, attemptId, now: new Date(fixedTime),
  });
  syntheticBundles.set(attemptId, {
    scanId, reviewedFiles: [...reviewedFiles], documents,
    bundleHash: published.bundleHash,
  });
}

function expectCode(action, code = 'E_SECURITY_PROGRAM_EVIDENCE_INVALID') {
  assert.throws(action, (error) => error instanceof SecurityProgramError && error.code === code);
}

function pathEntry(path, objectId = sha(path).slice(0, 40), mode = '100644', kind = 'file') {
  return { path, objectId, mode, kind };
}

function inventoryHash(entries) {
  return hashInventory(entries.map((entry) => ({
    ...entry,
    pathBytes: Buffer.from(entry.path, 'utf8'),
    objectType: entry.mode === '160000' ? 'commit' : 'blob',
  })));
}

const smallContents = new Map([
  ['shared/a.go', 'package shared\n'],
  ['shared/b.go', 'package shared\nvar B = true\n'],
  ['shared/threat/c.go', 'package threat\n'],
]);
function gitBlobId(contents) {
  const bytes = Buffer.from(contents);
  return crypto.createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}
const authorizedPaths = [...smallContents].map(([pathname, contents]) => pathEntry(pathname, gitBlobId(contents)));
const exclusionPolicy = {
  schema: EXCLUSION_POLICY_SCHEMA,
  policyVersion: 'fixture/exclusions/v1',
  classes: [],
};

// Exercise the real compiler without starting an OS process: its three Git
// reads are served by a deterministic in-memory adapter.
const compilerTree = Buffer.concat(authorizedPaths.map((entry) => (
  Buffer.from(`${entry.mode} blob ${entry.objectId}\t${entry.path}\0`)
)));
const compilerDecision = {
  schema: INVENTORY_DECISION_SCHEMA,
  decisionVersion: INVENTORY_DECISION_VERSION,
  decidedAt: fixedTime,
  revision,
  historicalCandidateCount: 2,
  acceptedAuthorizedCount: authorizedPaths.length,
  exclusionPolicySha256: hashJson(exclusionPolicy),
  inventorySha256: inventoryHash(authorizedPaths),
  rationaleToken: 'SECURITY-INVENTORY-FIXTURE-ALTERNATE',
};
const actualSpawnSync = childProcess.spawnSync;
let compilerGitReads = 0;
let compilerOutput;
try {
  childProcess.spawnSync = (_command, args, options) => {
    compilerGitReads += 1;
    const operation = args[2];
    if (operation === 'rev-parse') return { status: 0, stdout: `${revision}\n`, stderr: '' };
    if (operation === 'show') {
      return { status: 0, stdout: `${Date.parse(sourceCommittedAt) / 1000}\n`, stderr: '' };
    }
    if (operation === 'ls-tree') return { status: 0, stdout: compilerTree, stderr: Buffer.alloc(0) };
    throw new Error(`unexpected in-memory Git operation ${operation} (${options?.encoding ?? 'buffer'})`);
  };
  compilerOutput = compileInventory({
    repoRoot: '/fixture/repository',
    revision,
    exclusionPolicy,
    sectionCatalog: [
      { id: 'S01', title: 'Threat authority', provenance: 'fixture', matches: (pathname) => pathname.startsWith('shared/threat/') },
      { id: 'S02', title: 'Shared authority', provenance: 'fixture', matches: (pathname) => !pathname.startsWith('shared/threat/') },
    ],
    historicalCandidateCount: compilerDecision.historicalCandidateCount,
    inventoryDecision: compilerDecision,
  });
} finally {
  childProcess.spawnSync = actualSpawnSync;
}
assert.equal(compilerGitReads, 3);
const alternateDenominatorEpoch = buildEpochRecord(compilerOutput.epoch);
assert.deepEqual(alternateDenominatorEpoch.inventoryDecision, compilerDecision);
assert.equal(validateEpochRecord(alternateDenominatorEpoch), alternateDenominatorEpoch);

const epoch = buildEpochRecord({
  revision,
  sourceCommittedAt,
  historicalCandidateCount: authorizedPaths.length,
  treePathCount: authorizedPaths.length,
  authorizedCount: authorizedPaths.length,
  excludedCount: 0,
  inventorySha256: inventoryHash(authorizedPaths),
  exclusionPolicy,
  exclusionPolicySha256: hashJson(exclusionPolicy),
  authorizedPaths,
  excludedPaths: [],
});

const sections = buildSectionsRecord({
  revision,
  inventorySha256: epoch.inventorySha256,
  catalogVersion: 'fixture-catalog/v1',
  sections: [
    {
      id: 'S01',
      title: 'Threat authority',
      selectorProvenance: 'shared/threat paths',
      pathCount: 1,
      paths: [authorizedPaths[2]],
    },
    {
      id: 'S02',
      title: 'Shared foundations',
      selectorProvenance: 'remaining shared paths',
      pathCount: 2,
      paths: authorizedPaths.slice(0, 2),
    },
  ],
}, { epoch });

const shards = buildShardGenerationRecord({
  revision,
  inventorySha256: epoch.inventorySha256,
  generationId: 'fixture-shards/v1',
  shards: [
    {
      id: 'S01/P01',
      ownerSectionId: 'S01',
      pathCount: 1,
      pathListSha256: inventoryHash([authorizedPaths[2]]),
      paths: [authorizedPaths[2]],
    },
    {
      id: 'S02/P01',
      ownerSectionId: 'S02',
      pathCount: 2,
      pathListSha256: inventoryHash(authorizedPaths.slice(0, 2)),
      paths: authorizedPaths.slice(0, 2),
    },
  ],
}, { epoch, sections });

const pilotContents = (index) => `package pilot${index}\n`;
const pilotPaths = Array.from({ length: 219 }, (_, index) => {
  const pathname = `shared/pilot-${String(index).padStart(3, '0')}.go`;
  const bytes = Buffer.from(pilotContents(index));
  const objectId = crypto.createHash('sha1')
    .update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
  return pathEntry(pathname, objectId);
});
const pilotEpoch = buildEpochRecord({
  revision,
  sourceCommittedAt,
  historicalCandidateCount: pilotPaths.length,
  treePathCount: pilotPaths.length,
  authorizedCount: pilotPaths.length,
  excludedCount: 0,
  inventorySha256: inventoryHash(pilotPaths),
  exclusionPolicy,
  exclusionPolicySha256: hashJson(exclusionPolicy),
  authorizedPaths: pilotPaths,
  excludedPaths: [],
});
const pilotSections = buildSectionsRecord({
  revision,
  inventorySha256: pilotEpoch.inventorySha256,
  catalogVersion: 'fixture-pilot-catalog/v1',
  sections: [{
    id: 'S02', title: 'Pilot authority', selectorProvenance: 'fixture pilot paths',
    pathCount: pilotPaths.length, paths: pilotPaths,
  }],
}, { epoch: pilotEpoch });
const pilotShards = buildShardGenerationRecord({
  revision,
  inventorySha256: pilotEpoch.inventorySha256,
  generationId: 'fixture-pilot-shards/v1',
  shards: [{
    id: 'S02/P01', ownerSectionId: 'S02', pathCount: pilotPaths.length,
    pathListSha256: inventoryHash(pilotPaths), paths: pilotPaths,
  }],
}, { epoch: pilotEpoch, sections: pilotSections });
const pilotRepo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-records-pilot-repo-')));
const pilotState = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-records-pilot-state-')));
for (const [index, entry] of pilotPaths.entries()) {
  const filename = path.join(pilotRepo, entry.path);
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  fs.writeFileSync(filename, pilotContents(index));
}
const pilotTree = Buffer.concat(pilotPaths.map((entry) => (
  Buffer.from(`${entry.mode} blob ${entry.objectId}\t${entry.path}\0`)
)));
const pilotHelper = path.join(
  os.homedir(), '.codex/plugins/cache/openai-curated-remote/codex-security/0.1.24/scripts/generate_rank_input.py',
);
const pilotVerificationGitRunner = ({ args }) => {
  const key = args.join('\0');
  if (key === ['rev-parse', '--is-inside-work-tree'].join('\0')) return { status: 0, stdout: 'true\n' };
  if (key === ['rev-parse', '--show-toplevel'].join('\0')) return { status: 0, stdout: `${pilotRepo}\n` };
  if (key === ['rev-parse', '--verify', 'HEAD^{commit}'].join('\0')) return { status: 0, stdout: `${revision}\n` };
  if (args[0] === 'symbolic-ref') return { status: 1, stdout: Buffer.alloc(0) };
  if (args[0] === 'status') return { status: 0, stdout: Buffer.alloc(0) };
  if (args[0] === 'ls-tree') return { status: 0, stdout: pilotTree };
  throw new Error(`unexpected pilot Git operation ${args.join(' ')}`);
};
const pilotGitRunner = async (request) => pilotVerificationGitRunner(request);
const pilotPreparedTarget = await prepareStandardTarget({
  repoRoot: pilotRepo,
  shardGeneration: pilotShards,
  shardId: 'S02/P01',
  stateDir: pilotState,
  helperScriptPath: pilotHelper,
  gitRunner: pilotGitRunner,
  scopeRunner: async ({ args }) => {
    const scopesFile = args[args.indexOf('--scopes-file') + 1];
    const outputFile = args[args.indexOf('--out') + 1];
    const requested = JSON.parse(fs.readFileSync(scopesFile, 'utf8'));
    fs.writeFileSync(outputFile, `${requested.map((pathname) => JSON.stringify({ path: pathname })).join('\n')}\n`);
    return { status: 0, stdout: '', stderr: '' };
  },
});
const pilotDeepPreparedTarget = await prepareDeepTarget({
  repoRoot: pilotRepo,
  shardGeneration: pilotShards,
  shardId: 'S02/P01',
  scope: 'shared',
  gitRunner: pilotGitRunner,
  verificationGitRunner: pilotVerificationGitRunner,
});

const smallRepo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-records-small-repo-')));
const smallState = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-records-small-state-')));
for (const [pathname, contents] of smallContents) {
  const filename = path.join(smallRepo, pathname);
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  fs.writeFileSync(filename, contents);
}
const smallTree = Buffer.concat(authorizedPaths.map((entry) => (
  Buffer.from(`${entry.mode} blob ${entry.objectId}\t${entry.path}\0`)
)));
async function prepareSmallTarget(shardId) {
  return prepareStandardTarget({
    repoRoot: smallRepo,
    shardGeneration: shards,
    shardId,
    stateDir: smallState,
    helperScriptPath: pilotHelper,
    gitRunner: async ({ args }) => {
      const key = args.join('\0');
      if (key === ['rev-parse', '--is-inside-work-tree'].join('\0')) return { status: 0, stdout: 'true\n' };
      if (key === ['rev-parse', '--show-toplevel'].join('\0')) return { status: 0, stdout: `${smallRepo}\n` };
      if (key === ['rev-parse', '--verify', 'HEAD^{commit}'].join('\0')) return { status: 0, stdout: `${revision}\n` };
      if (args[0] === 'symbolic-ref') return { status: 1, stdout: Buffer.alloc(0) };
      if (args[0] === 'status') return { status: 0, stdout: Buffer.alloc(0) };
      if (args[0] === 'ls-tree') return { status: 0, stdout: smallTree };
      throw new Error(`unexpected small-target Git operation ${args.join(' ')}`);
    },
    scopeRunner: async ({ args }) => {
      const scopesFile = args[args.indexOf('--scopes-file') + 1];
      const outputFile = args[args.indexOf('--out') + 1];
      const requested = JSON.parse(fs.readFileSync(scopesFile, 'utf8'));
      fs.writeFileSync(outputFile, `${requested.map((pathname) => JSON.stringify({ path: pathname })).join('\n')}\n`);
      return { status: 0, stdout: '', stderr: '' };
    },
  });
}
const preparedTargets = new Map([
  ['S01/P01', await prepareSmallTarget('S01/P01')],
  ['S02/P01', await prepareSmallTarget('S02/P01')],
]);

const pilotBudget = buildPilotBudgetRecord({
  budgetId: 'pilot-fixture-v1',
  registeredAt: fixedTime,
  epochRevision: revision,
  inventorySha256: pilotEpoch.inventorySha256,
  shardGenerationId: pilotShards.generationId,
  pilotShardId: 'S02/P01',
  shardPathListSha256: pilotShards.shards[0].pathListSha256,
  controlGenerationHash: sha('pilot-control'),
  pilotPathCount: 219,
  limits: {
    maxElapsedSeconds: 7200,
    maxArtifactBytes: 1_000_000_000,
    maxPeakRssBytes: 2_000_000_000,
    maxOperatorSeconds: 600,
    minCreditedFilesPerHour: 100,
    minFreeBytesAfter: 10_000_000_000,
    maxRetries: 0,
    wholeEpochMaxElapsedSeconds: 200_000,
    wholeEpochMaxArtifactBytes: 30_000_000_000,
  },
  host: {
    hostClass: 'fixture-host',
    os: 'darwin',
    architecture: 'arm64',
    cpuCount: 10,
    ramBytes: 64_000_000_000,
    diskFreeBytes: 100_000_000_000,
    volumeId: 'fixture-volume',
  },
  scanner: {
    adapterVersion: TARGET_ADAPTER_VERSION,
    scannerSchemaVersion: 'scanner-schema/v1',
    configSha256: sha('fixture-config'),
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    routeContractSha256: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS],
    pluginVersion: '0.1.24',
    targetForm: 'exact-paths-file',
    targetKind: 'git_revision',
    productionEligible: true,
    deepScanMaxTimeHours: 6,
  },
}, { epoch: pilotEpoch, shards: pilotShards });

const desktopExportCapacity = {
  schema: 'setjoin.security-program.export-capacity/v1',
  maxEntries: 500,
  maxBytes: 64_000_000,
  minimumFreeBytes: 10_000_000_000,
  maxBuildElapsedMs: 120_000,
  maxBuildPeakRssBytes: 2_000_000_000,
  maxSnapshotElapsedMs: 60_000,
  maxSnapshotPeakRssBytes: 2_000_000_000,
};
const desktopPilotBudget = buildPilotBudgetRecord({
  budgetId: 'pilot-desktop-fixture-v1',
  registeredAt: fixedTime,
  epochRevision: revision,
  inventorySha256: pilotEpoch.inventorySha256,
  shardGenerationId: pilotShards.generationId,
  pilotShardId: 'S02/P01',
  shardPathListSha256: pilotShards.shards[0].pathListSha256,
  controlGenerationHash: sha('pilot-desktop-control'),
  pilotPathCount: 219,
  limits: {
    maxElapsedSeconds: 7200,
    maxArtifactBytes: 1_000_000_000,
    maxPeakRssBytes: 2_000_000_000,
    maxOperatorSeconds: 600,
    minCreditedFilesPerHour: 100,
    minFreeBytesAfter: desktopExportCapacity.minimumFreeBytes,
    maxRetries: 0,
    wholeEpochMaxElapsedSeconds: 200_000,
    wholeEpochMaxArtifactBytes: 30_000_000_000,
    maxExportBytes: desktopExportCapacity.maxBytes,
    maxExportEntries: desktopExportCapacity.maxEntries,
    maxExportBuildSeconds: desktopExportCapacity.maxBuildElapsedMs / 1000,
    maxSnapshotSeconds: desktopExportCapacity.maxSnapshotElapsedMs / 1000,
  },
  host: {
    hostClass: 'fixture-host', os: 'darwin', architecture: 'arm64', cpuCount: 10,
    ramBytes: 64_000_000_000, diskFreeBytes: 100_000_000_000, volumeId: 'fixture-volume',
  },
  scanner: {
    adapterVersion: TARGET_ADAPTER_VERSION,
    scannerSchemaVersion: 'scanner-schema/v1',
    configSha256: sha('fixture-config'),
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    routeContractSha256: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT],
    pluginVersion: '0.1.24',
    targetForm: 'attested-directory-export',
    targetKind: 'directory_snapshot',
    productionEligible: true,
    deepScanMaxTimeHours: 6,
  },
  exportCapacity: desktopExportCapacity,
}, { epoch: pilotEpoch, shards: pilotShards });
assert.equal(
  validatePilotBudgetRecord(desktopPilotBudget, { epoch: pilotEpoch, shards: pilotShards }),
  desktopPilotBudget,
);

function sdkRoute(scannerSchemaVersion = 'scanner-schema/v1') {
  return {
    mode: 'Standard',
    adapterVersion: TARGET_ADAPTER_VERSION,
    targetForm: 'exact-paths-file',
    targetKind: 'git_revision',
    scannerSchemaVersion,
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    routeContractSha256: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS],
    pluginVersion: '0.1.24',
    productionEligible: true,
  };
}

function desktopRoute(overrides = {}) {
  return {
    mode: 'Standard',
    adapterVersion: TARGET_ADAPTER_VERSION,
    targetForm: 'attested-directory-export',
    targetKind: 'directory_snapshot',
    scannerSchemaVersion: 'scanner-schema/v1',
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    routeContractSha256: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT],
    pluginVersion: '0.1.24',
    productionEligible: true,
    directorySnapshotDigest: `codex-security-snapshot/v1:sha256:${sha('desktop-directory')}`,
    exportTreeSha256: sha('desktop-export-tree'),
    stableSnapshotSha256: sha('desktop-stable-snapshot'),
    budgetId: desktopPilotBudget.budgetId,
    budgetSha256: desktopPilotBudget.budgetSha256,
    exportCapacity: desktopPilotBudget.exportCapacity,
    ...overrides,
  };
}

function resultClaim({
  claimId,
  attemptId,
  sectionId,
  shardId,
  scanId,
  reviewedPathCount,
  missingPathCount = 0,
  claimedFileCoverage = 'complete',
  claimedProofCompleteness = 'complete',
  claimedObservationCount = 0,
  controlGenerationHash = sha('control'),
  overrides = {},
}) {
  const synthetic = syntheticBundles.get(attemptId);
  const artifacts = synthetic === undefined
    ? [{ artifactRef: `attempt-file:${attemptId}/coverage.json`, sha256: sha(`${attemptId}-coverage`), size: 17 }]
    : Object.entries(synthetic.documents)
      .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map(([pathname, bytes]) => ({
        artifactRef: `attempt-file:${attemptId}/${pathname}`,
        sha256: sha256Hex(bytes),
        size: Buffer.byteLength(bytes),
      }));
  const bundleHash = synthetic?.bundleHash ?? sha(`${attemptId}-bundle`);
  return buildResultClaimRecord({
    claimId,
    attemptId,
    sectionId,
    shardId,
    scanId,
    claimedAt: fixedTime,
    scannerState: 'SEALED',
    bundleRef: `attempt:${attemptId}`,
    bundleHash,
    artifacts,
    reviewedPathCount,
    missingPathCount,
    claimedFileCoverage,
    claimedProofCompleteness,
    sourceRevision: revision,
    sourceFingerprint: `v2:${revision}:${sha('source')}`,
    controlGenerationHash,
    elapsedSeconds: 12.5,
    artifactBytes: artifacts.reduce((sum, artifact) => sum + artifact.size, 0),
    operatorSeconds: 3,
    peakRssBytes: 100_000_000,
    freeBytesAfter: 50_000_000_000,
    retryCount: 0,
    workerCount: 1,
    tokenUsage: { availability: 'unavailable' },
    claimedObservationCount,
    ...sdkRoute(),
    ...overrides,
  });
}

function failedResultClaim() {
  return buildResultClaimRecord({
    claimId: 'claim-failed',
    attemptId: 'attempt-failed',
    sectionId: 'S02',
    shardId: 'S02/P01',
    scanId: 'scan-failed',
    claimedAt: fixedTime,
    scannerState: 'TERMINAL_FAILED',
    reviewedPathCount: 1,
    missingPathCount: 1,
    claimedFileCoverage: 'partial',
    claimedProofCompleteness: 'blocked',
    sourceRevision: revision,
    sourceFingerprint: `v2:${revision}:${sha('source')}`,
    controlGenerationHash: sha('control'),
    elapsedSeconds: 12.5,
    artifactBytes: 0,
    operatorSeconds: 3,
    peakRssBytes: 100_000_000,
    freeBytesAfter: 50_000_000_000,
    retryCount: 0,
    workerCount: 1,
    tokenUsage: { availability: 'unavailable' },
    claimedObservationCount: 0,
    ...sdkRoute(),
  });
}

function reviewedSet({ evidenceId, attemptId, sectionId, shardId, scanId, paths, controlGenerationHash = sha('control') }) {
  return buildReviewedSetRecord({
    evidenceId,
    attemptId,
    sectionId,
    shardId,
    scanId,
    verifiedAt: fixedTime,
    bundleRef: `attempt:${attemptId}`,
    bundleHash: syntheticBundles.get(attemptId)?.bundleHash ?? sha(`${attemptId}-bundle`),
    sourceRevision: revision,
    inventorySha256: epoch.inventorySha256,
    sourceFingerprint: `v2:${revision}:${sha('source')}`,
    controlGenerationHash,
    sealed: true,
    hashesValid: true,
    sourceFingerprintMatches: true,
    reviewedPathsPresent: true,
    reviewedPaths: paths,
  });
}

function admissionFor({
  attemptId,
  sectionId,
  shardId,
  scanId,
  controlGenerationHash = sha('control'),
  authorityEpoch = epoch,
  authorityShards = shards,
  overrides = {},
}) {
  const sourceFingerprint = `v2:${revision}:${sha('source')}`;
  const bundleHash = syntheticBundles.get(attemptId)?.bundleHash ?? sha(`${attemptId}-bundle`);
  const journalEvent = admittedAttemptEvent({
    attemptId, sectionId, shardId, scanId, controlGenerationHash,
    targetArtifactSha256: overrides.targetArtifactSha256,
    inventorySha256: overrides.inventorySha256 ?? authorityEpoch.inventorySha256,
    shardGenerationId: overrides.shardGenerationId ?? authorityShards.generationId,
    shardPathCount: overrides.shardPathCount ?? authorityShards.shards.find((item) => item.id === shardId)?.pathCount ?? 1,
    shardPathListSha256: overrides.shardPathListSha256
      ?? authorityShards.shards.find((item) => item.id === shardId)?.pathListSha256 ?? sha('unknown-shard'),
  });
  return {
    schema: ADMISSION_INPUT_SCHEMA,
    recordRole: RECORD_ROLES.VERIFIED_EVIDENCE,
    admissionId: `admission-${attemptId}`,
    admittedAt: fixedTime,
    attemptId,
    sectionId,
    shardId,
    scanId,
    journalEventId: journalEvent.eventId,
    journalEventHash: sha256Hex(canonicalJson(journalEvent)),
    journalState: 'ADMITTED',
    bundleRef: `attempt:${attemptId}`,
    bundleHash,
    verifiedBundleHash: bundleHash,
    controlGenerationHash,
    currentControlGenerationHash: controlGenerationHash,
    inventorySha256: journalEvent.inventorySha256,
    shardGenerationId: journalEvent.shardGenerationId,
    shardPathCount: journalEvent.shardPathCount,
    shardPathListSha256: journalEvent.shardPathListSha256,
    targetArtifactSha256: journalEvent.targetArtifactSha256,
    targetPathCount: journalEvent.targetPathCount,
    targetPathListSha256: journalEvent.targetPathListSha256,
    sourceRevision: revision,
    currentSourceRevision: revision,
    sourceFingerprint,
    currentSourceFingerprint: sourceFingerprint,
    ...sdkRoute(),
    ...overrides,
  };
}

function admittedAttemptEvent({
  attemptId,
  sectionId,
  shardId,
  scanId,
  controlGenerationHash,
  inventorySha256,
  shardGenerationId,
  shardPathCount,
  shardPathListSha256,
  targetArtifactSha256,
}) {
  return {
    schema: ATTEMPT_EVENT_SCHEMA,
    eventId: `journal-${attemptId}`,
    attemptId,
    sequence: 8,
    state: 'ADMITTED',
    recordedAt: fixedTime,
    epochRevision: revision,
    sourceFingerprint: `v2:${revision}:${sha('source')}`,
    inventorySha256,
    shardGenerationId,
    sectionId,
    shardId,
    shardPathCount,
    shardPathListSha256,
    targetArtifactSha256: targetArtifactSha256 ?? sha(`${attemptId}-target-artifact`),
    targetPathCount: shardPathCount,
    targetPathListSha256: shardPathListSha256,
    mode: 'Standard',
    targetForm: 'exact-paths-file',
    targetKind: 'git_revision',
    controlGenerationHash,
    leaseOwner: 'fixture-coordinator',
    coordinatorVersion: 'fixture/v1',
    adapterVersion: TARGET_ADAPTER_VERSION,
    scannerSchemaVersion: 'scanner-schema/v1',
    fingerprintVersion: 'fingerprint/v2',
    controlSchemaSetVersion: 'control/v1',
    scanId,
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    routeContractSha256: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS],
    pluginVersion: '0.1.24',
  };
}

function verifiedAdmissionCapability(admission, claim, target, {
  authorityEpoch = epoch,
  authorityShards = shards,
  budget,
} = {}) {
  const journalEvent = admittedAttemptEvent({
    attemptId: admission.attemptId,
    sectionId: admission.sectionId,
    shardId: admission.shardId,
    scanId: admission.scanId,
    controlGenerationHash: admission.controlGenerationHash,
    inventorySha256: authorityEpoch.inventorySha256,
    shardGenerationId: authorityShards.generationId,
    shardPathCount: authorityShards.shards.find((item) => item.id === admission.shardId)?.pathCount ?? 1,
    shardPathListSha256: authorityShards.shards.find((item) => item.id === admission.shardId)?.pathListSha256 ?? sha('unknown-shard'),
    targetArtifactSha256: admission.targetArtifactSha256,
  });
  const targetAuthority = verifyPreparedTarget(target);
  assert.equal(journalEvent.targetArtifactSha256, targetAuthority.artifactSha256);
  const synthetic = syntheticBundles.get(admission.attemptId);
  assert(synthetic, `missing synthetic canonical bundle for ${admission.attemptId}`);
  if (!fs.existsSync(path.join(attemptsDirectory, admission.attemptId))) {
    const sourceDirectory = path.join(evidenceRoot, `source-${admission.attemptId}`);
    fs.mkdirSync(sourceDirectory, { recursive: true });
    for (const [pathname, bytes] of Object.entries(synthetic.documents)) {
      fs.writeFileSync(path.join(sourceDirectory, pathname), bytes);
    }
    const published = publishImmutableBundle({
      sourceDirectory, attemptsDirectory, attemptId: admission.attemptId, now: new Date(fixedTime),
    });
    assert.equal(published.bundleHash, admission.bundleHash);
  }
  const states = [
    'RESERVED', 'START_REQUESTED', 'RUNNING', 'COMPLETION_REQUESTED', 'SEALED',
    'SOURCE_VERIFIED', 'PUBLICATION_PENDING', 'PUBLISHED', 'ADMITTED',
  ];
  const events = states.map((state, sequence) => ({
    ...journalEvent,
    eventId: state === 'ADMITTED' ? journalEvent.eventId : `journal-${admission.attemptId}-${sequence}`,
    sequence,
    state,
    ...(sequence < 2 ? { scanId: undefined } : {}),
  })).map((event) => Object.fromEntries(Object.entries(event).filter(([, value]) => value !== undefined)));
  const journalPath = path.join(evidenceRoot, `journal-${admission.attemptId}.json`);
  fs.writeFileSync(journalPath, canonicalJson({ schema: ATTEMPT_JOURNAL_SCHEMA, events }));
  return issueVerifiedAdmissionCapability({
    admission,
    resultClaim: claim,
    budget,
    epoch: authorityEpoch,
    shards: authorityShards,
    target,
    journalPath,
    attemptsDirectory,
  });
}

registerSyntheticBundle(
  'attempt-s01', 'scan-s01', ['shared/threat/c.go'],
  { ...sdkRoute(), ...verifyPreparedTarget(preparedTargets.get('S01/P01')) },
);
registerSyntheticBundle(
  'attempt-s02', 'scan-s02', ['shared/a.go', 'shared/b.go'],
  { ...sdkRoute(), ...verifyPreparedTarget(preparedTargets.get('S02/P01')) },
);
registerSyntheticBundle(
  'attempt-pilot', 'scan-pilot', pilotPaths.map((item) => item.path),
  { ...sdkRoute(), ...verifyPreparedTarget(pilotPreparedTarget) },
);

const claimS01 = resultClaim({
  claimId: 'claim-s01', attemptId: 'attempt-s01', sectionId: 'S01', shardId: 'S01/P01',
  scanId: 'scan-s01', reviewedPathCount: 1,
});
const claimS02 = resultClaim({
  claimId: 'claim-s02', attemptId: 'attempt-s02', sectionId: 'S02', shardId: 'S02/P01',
  scanId: 'scan-s02', reviewedPathCount: 2,
});
const admissionS01 = admissionFor({
  attemptId: 'attempt-s01', sectionId: 'S01', shardId: 'S01/P01', scanId: 'scan-s01',
  overrides: { targetArtifactSha256: verifyPreparedTarget(preparedTargets.get('S01/P01')).artifactSha256 },
});
const admissionS02 = admissionFor({
  attemptId: 'attempt-s02', sectionId: 'S02', shardId: 'S02/P01', scanId: 'scan-s02',
  overrides: { targetArtifactSha256: verifyPreparedTarget(preparedTargets.get('S02/P01')).artifactSha256 },
});
validateAdmissionInputRecord(admissionS01);
validateAdmissionInputRecord(admissionS02);
const admissionCapabilityS01 = verifiedAdmissionCapability(
  admissionS01, claimS01, preparedTargets.get('S01/P01'),
);
const admissionCapabilityS02 = verifiedAdmissionCapability(
  admissionS02, claimS02, preparedTargets.get('S02/P01'),
);
const pilotClaim = resultClaim({
  claimId: 'claim-pilot', attemptId: 'attempt-pilot', sectionId: 'S02', shardId: 'S02/P01',
  scanId: 'scan-pilot', reviewedPathCount: 219, controlGenerationHash: pilotBudget.controlGenerationHash,
});
const pilotTargetAuthority = verifyPreparedTarget(pilotPreparedTarget);
const pilotAdmission = admissionFor({
  attemptId: pilotClaim.attemptId,
  sectionId: 'S02',
  shardId: 'S02/P01',
  scanId: pilotClaim.scanId,
  controlGenerationHash: pilotBudget.controlGenerationHash,
  authorityEpoch: pilotEpoch,
  authorityShards: pilotShards,
  overrides: { targetArtifactSha256: pilotTargetAuthority.artifactSha256 },
});
const pilotAdmissionCapability = verifiedAdmissionCapability(
  pilotAdmission,
  pilotClaim,
  pilotPreparedTarget,
  { authorityEpoch: pilotEpoch, authorityShards: pilotShards, budget: pilotBudget },
);
const pilotAuthorityOptions = { admissionCapability: pilotAdmissionCapability };
const pilotVerdict = buildPilotVerdictRecord({
  evaluatedAt: fixedTime,
}, pilotAuthorityOptions);
assert.equal(pilotVerdict.recordRole, RECORD_ROLES.DERIVED);
assert.equal(pilotVerdict.verdict, 'GO_STANDARD');
assert.equal(pilotVerdict.measurements.creditedPathCount, 219);

function createPilotAdmissionCapability(label, budget, resultOverrides = {}, {
  reviewedPaths = pilotPaths.map((item) => item.path),
  completeness = 'complete',
} = {}) {
  const attemptId = `attempt-pilot-${label}`;
  const scanId = `scan-pilot-${label}`;
  registerSyntheticBundle(
    attemptId,
    scanId,
    reviewedPaths,
    { ...sdkRoute(), ...verifyPreparedTarget(pilotPreparedTarget) },
    completeness,
    { scopePaths: pilotPaths.map((item) => item.path) },
  );
  const claim = resultClaim({
    claimId: `claim-pilot-${label}`,
    attemptId,
    sectionId: 'S02',
    shardId: 'S02/P01',
    scanId,
    reviewedPathCount: reviewedPaths.length,
    missingPathCount: pilotPaths.length - reviewedPaths.length,
    claimedFileCoverage: reviewedPaths.length === pilotPaths.length ? 'complete' : 'partial',
    claimedProofCompleteness: reviewedPaths.length === pilotPaths.length ? 'complete' : 'blocked',
    controlGenerationHash: budget.controlGenerationHash,
    overrides: resultOverrides,
  });
  const admission = admissionFor({
    attemptId,
    sectionId: 'S02',
    shardId: 'S02/P01',
    scanId,
    controlGenerationHash: budget.controlGenerationHash,
    authorityEpoch: pilotEpoch,
    authorityShards: pilotShards,
    overrides: { targetArtifactSha256: pilotTargetAuthority.artifactSha256 },
  });
  return verifiedAdmissionCapability(admission, claim, pilotPreparedTarget, {
    authorityEpoch: pilotEpoch,
    authorityShards: pilotShards,
    budget,
  });
}

const repartitionCapability = createPilotAdmissionCapability(
  'operator-limit', pilotBudget, { operatorSeconds: pilotBudget.limits.maxOperatorSeconds + 1 },
);
const repartitionVerdict = buildPilotVerdictRecord(
  { evaluatedAt: fixedTime }, { admissionCapability: repartitionCapability },
);
assert.equal(repartitionVerdict.verdict, 'REPARTITION');
assert.equal(repartitionVerdict.checks.attemptLimitsPass, false);

const uneconomicalBudget = buildPilotBudgetRecord({
  ...pilotBudget,
  budgetId: 'pilot-uneconomical-v1',
  limits: { ...pilotBudget.limits, minCreditedFilesPerHour: 100_000 },
}, { epoch: pilotEpoch, shards: pilotShards });
const holdCapability = createPilotAdmissionCapability('uneconomical', uneconomicalBudget);
const holdVerdict = buildPilotVerdictRecord(
  { evaluatedAt: fixedTime }, { admissionCapability: holdCapability },
);
assert.equal(holdVerdict.verdict, 'HOLD');
assert.equal(holdVerdict.checks.standardEconomical, false);
assert(holdVerdict.reasonCodes.includes('DEEP_FALLBACK_AUTHORITY_REQUIRED'));

const fallbackPromotion = buildDeepPromotionRecord({
  promotionId: 'promotion-pilot-deep-fallback',
  createdAt: fixedTime,
  sectionId: 'S02',
  targetDirectory: 'shared',
  reasonCodes: ['STANDARD_UNECONOMICAL'],
  standardEvidenceRefs: ['claim:claim-pilot-uneconomical'],
  programPromotionCap: 8,
  deepRunCap: 1,
  deepScanMaxTimeHours: 6,
  state: 'PLANNED',
  conflictCount: 0,
  disposition: 'pending',
});
const deepFallbackAuthority = issueVerifiedDeepFallbackAuthority({
  standardAdmissionCapability: holdCapability,
  promotions: [fallbackPromotion],
  promotionId: fallbackPromotion.promotionId,
  target: pilotDeepPreparedTarget,
});
const fallbackVerdict = buildPilotVerdictRecord({ evaluatedAt: fixedTime }, {
  admissionCapability: holdCapability,
  deepFallbackAuthority,
});
assert.equal(fallbackVerdict.verdict, 'BOUNDED_DEEP_FALLBACK');
assert.equal(fallbackVerdict.deepPromotionId, fallbackPromotion.promotionId);
assert.equal(fallbackVerdict.deepDirectoryTarget, 'shared');
assert.equal(validatePilotVerdictRecord(JSON.parse(canonicalJson(fallbackVerdict)), {
  admissionCapability: holdCapability,
  deepFallbackAuthority,
}).verdict, 'BOUNDED_DEEP_FALLBACK');

const partialCapability = createPilotAdmissionCapability(
  'partial-credit',
  pilotBudget,
  {},
  { reviewedPaths: pilotPaths.slice(0, 100).map((item) => item.path), completeness: 'partial' },
);
const partialPromotion = buildDeepPromotionRecord({
  ...fallbackPromotion,
  promotionId: 'promotion-pilot-partial-fallback',
  reasonCodes: ['STANDARD_EVIDENCE_NOT_DEFENSIBLE'],
  standardEvidenceRefs: ['claim:claim-pilot-partial-credit'],
});
const partialFallbackAuthority = issueVerifiedDeepFallbackAuthority({
  standardAdmissionCapability: partialCapability,
  promotions: [partialPromotion],
  promotionId: partialPromotion.promotionId,
  target: pilotDeepPreparedTarget,
});
const partialFallbackVerdict = buildPilotVerdictRecord({ evaluatedAt: fixedTime }, {
  admissionCapability: partialCapability,
  deepFallbackAuthority: partialFallbackAuthority,
});
assert.equal(partialFallbackVerdict.verdict, 'BOUNDED_DEEP_FALLBACK');
assert.equal(partialFallbackVerdict.checks.exactReviewedSet, false);
assert.equal(partialFallbackVerdict.checks.standardEconomical, true);
expectCode(() => issueVerifiedDeepFallbackAuthority({
  standardAdmissionCapability: pilotAdmissionCapability,
  promotions: [fallbackPromotion],
  promotionId: fallbackPromotion.promotionId,
  target: pilotDeepPreparedTarget,
}));
for (const [label, mutation] of [
  ['wrong-evidence', { standardEvidenceRefs: ['claim:claim-other'] }],
  ['wrong-reason', { reasonCodes: ['AUTHORITY_BOUNDARY'] }],
  ['wrong-directory', { targetDirectory: 'shared/other' }],
]) {
  const invalidPromotion = buildDeepPromotionRecord({
    ...fallbackPromotion,
    promotionId: `promotion-pilot-${label}`,
    ...mutation,
  });
  expectCode(() => issueVerifiedDeepFallbackAuthority({
    standardAdmissionCapability: holdCapability,
    promotions: [invalidPromotion],
    promotionId: invalidPromotion.promotionId,
    target: pilotDeepPreparedTarget,
  }));
}
expectCode(() => buildDeepPromotionRecord({
  ...fallbackPromotion,
  promotionId: 'promotion-pilot-wrong-cap',
  deepRunCap: 2,
}));
expectCode(() => issueVerifiedDeepFallbackAuthority({
  standardAdmissionCapability: holdCapability,
  promotions: [fallbackPromotion],
  promotionId: fallbackPromotion.promotionId,
  target: pilotPreparedTarget,
}));
expectCode(() => buildPilotVerdictRecord({ evaluatedAt: fixedTime }, {
  admissionCapability: holdCapability,
  deepFallbackAuthority: Object.freeze(Object.create(null)),
}));
expectCode(() => buildPilotVerdictRecord({ evaluatedAt: fixedTime }, {
  admissionCapability: pilotAdmissionCapability,
  deepFallbackAuthority,
}));

// The Setjoin reviewed-set extension is a closed, versioned authority. It is
// validated by the same function before draft submission and after sealing.
const validReviewedExtension = reviewedSetExtension(['shared/a.go', 'shared/b.go']);
assert.deepEqual(
  validateReviewedSetExtension(validReviewedExtension).reviewedFiles,
  ['shared/a.go', 'shared/b.go'],
);
for (const absentOrUnknown of [
  undefined,
  {},
  { 'setjoin.security-program.reviewed-set/v2': validReviewedExtension['setjoin.security-program.reviewed-set/v1'] },
  { ...validReviewedExtension, 'setjoin.security-program.other/v1': {} },
]) {
  expectCode(() => validateReviewedSetExtension(absentOrUnknown), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
}
const validReviewedMembers = validReviewedExtension['setjoin.security-program.reviewed-set/v1'];
expectCode(() => validateReviewedSetExtension({
  'setjoin.security-program.reviewed-set/v1': { ...validReviewedMembers, unknown_member: true },
}), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
for (const mutatedMembers of [
  { ...validReviewedMembers, fully_reviewed_files: ['shared/b.go', 'shared/a.go'] },
  { ...validReviewedMembers, fully_reviewed_files: ['shared/a.go', 'shared/a.go'] },
  { ...validReviewedMembers, count: validReviewedMembers.count + 1 },
  { ...validReviewedMembers, path_list_sha256: sha('wrong-reviewed-path-list') },
]) {
  expectCode(() => validateReviewedSetExtension({
    'setjoin.security-program.reviewed-set/v1': mutatedMembers,
  }));
}

function expectCanonicalBundleRejected(label, mutation, expectedCode) {
  const attemptId = `attempt-canonical-${label}`;
  const scanId = `scan-canonical-${label}`;
  const target = preparedTargets.get('S01/P01');
  registerSyntheticBundle(
    attemptId,
    scanId,
    ['shared/threat/c.go'],
    { ...sdkRoute(), ...verifyPreparedTarget(target) },
    'complete',
    mutation,
  );
  const claim = resultClaim({
    claimId: `claim-canonical-${label}`,
    attemptId,
    sectionId: 'S01',
    shardId: 'S01/P01',
    scanId,
    reviewedPathCount: 1,
  });
  const admission = admissionFor({
    attemptId,
    sectionId: 'S01',
    shardId: 'S01/P01',
    scanId,
    overrides: { targetArtifactSha256: verifyPreparedTarget(target).artifactSha256 },
  });
  expectCode(() => verifiedAdmissionCapability(admission, claim, target), expectedCode);
}

for (const [label, mutation, expectedCode] of [
  ['producer-name', { mutateManifest: (value) => { value.scan.producer.name = 'other-producer'; } }, 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED'],
  ['producer-version', { mutateManifest: (value) => { value.scan.producer.version = '0.1.23'; } }, 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED'],
  ['manifest-type', { mutateManifest: (value) => { value.documentType = 'other.manifest'; } }],
  ['manifest-schema', { mutateManifest: (value) => { value.schemaVersion = '2.0'; } }],
  ['manifest-time-order', { mutateManifest: (value) => {
    value.scan.startedAt = '2026-08-30T00:00:00.123999Z';
    value.scan.completedAt = '2026-08-30T00:00:00.123001Z';
    value.scan.sealedAt = '2026-08-30T00:00:00.124000Z';
  } }],
  ['coverage-type', { mutateCoverage: (value) => { value.documentType = 'other.coverage'; } }],
  ['coverage-schema', { mutateCoverage: (value) => { value.schemaVersion = '2.0'; } }],
  ['coverage-mode', { mutateCoverage: (value) => { value.mode = 'repository'; } }],
  ['coverage-inventory', { mutateCoverage: (value) => { value.inventoryStrategy = 'directory'; } }],
  ['coverage-scope', { mutateCoverage: (value) => { value.includePaths = ['shared/other.go']; } }],
  ['manifest-scope', { mutateManifest: (value) => { value.scan.scope.includePaths = ['shared/other.go']; } }],
  ['coverage-exclusions', { mutateCoverage: (value) => { value.explicitExclusions = [{ path: 'shared/threat/c.go' }]; } }],
  ['coverage-deferred', { mutateCoverage: (value) => { value.deferred = [{ path: 'shared/threat/c.go' }]; } }],
  ['coverage-core-reviewed-field', { mutateCoverage: (value) => { value.reviewedFiles = ['shared/threat/c.go']; } }],
  ['target-kind', { mutateManifest: (value) => { value.scan.target.kind = 'directory_snapshot'; } }],
  ['target-revision', { mutateManifest: (value) => { value.scan.target.revision = '8'.repeat(40); } }],
  ['target-snapshot-digest', { mutateManifest: (value) => { value.scan.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${sha('unexpected-sdk-snapshot')}`; } }],
]) {
  expectCanonicalBundleRejected(label, mutation, expectedCode);
}

registerSyntheticBundle(
  'attempt-canonical-microseconds',
  'scan-canonical-microseconds',
  ['shared/threat/c.go'],
  { ...sdkRoute(), ...verifyPreparedTarget(preparedTargets.get('S01/P01')) },
  'complete',
  {
    mutateManifest: (value) => {
      value.scan.startedAt = '2026-08-30T00:00:00.123456Z';
      value.scan.completedAt = '2026-08-30T00:00:01.234567Z';
      value.scan.sealedAt = '2026-08-30T00:00:02.345678Z';
    },
  },
);
const microsecondClaim = resultClaim({
  claimId: 'claim-canonical-microseconds',
  attemptId: 'attempt-canonical-microseconds',
  sectionId: 'S01',
  shardId: 'S01/P01',
  scanId: 'scan-canonical-microseconds',
  reviewedPathCount: 1,
});
const microsecondAdmission = admissionFor({
  attemptId: 'attempt-canonical-microseconds',
  sectionId: 'S01',
  shardId: 'S01/P01',
  scanId: 'scan-canonical-microseconds',
  overrides: { targetArtifactSha256: verifyPreparedTarget(preparedTargets.get('S01/P01')).artifactSha256 },
});
assert.equal(typeof verifiedAdmissionCapability(
  microsecondAdmission, microsecondClaim, preparedTargets.get('S01/P01'),
), 'object');

// Budget thresholds are immutable once hashed, and the human-readable export
// ceilings must exactly correlate with the adapter's millisecond/byte limits.
expectCode(() => validatePilotBudgetRecord({
  ...desktopPilotBudget,
  limits: { ...desktopPilotBudget.limits, maxArtifactBytes: desktopPilotBudget.limits.maxArtifactBytes + 1 },
}, { epoch: pilotEpoch, shards: pilotShards }));
expectCode(() => validatePilotBudgetRecord({
  ...desktopPilotBudget,
  budgetSha256: sha('forged-budget-hash'),
}, { epoch: pilotEpoch, shards: pilotShards }));
for (const fields of [
  {
    ...desktopPilotBudget,
    budgetId: 'pilot-desktop-capacity-bytes-v2',
    limits: { ...desktopPilotBudget.limits, maxExportBytes: desktopPilotBudget.limits.maxExportBytes + 1 },
  },
  {
    ...desktopPilotBudget,
    budgetId: 'pilot-desktop-capacity-entries-v2',
    limits: { ...desktopPilotBudget.limits, maxExportEntries: desktopPilotBudget.limits.maxExportEntries + 1 },
  },
  {
    ...desktopPilotBudget,
    budgetId: 'pilot-desktop-capacity-build-v2',
    limits: { ...desktopPilotBudget.limits, maxExportBuildSeconds: desktopPilotBudget.limits.maxExportBuildSeconds + 1 },
  },
  {
    ...desktopPilotBudget,
    budgetId: 'pilot-desktop-capacity-snapshot-v2',
    limits: { ...desktopPilotBudget.limits, maxSnapshotSeconds: desktopPilotBudget.limits.maxSnapshotSeconds + 1 },
  },
  {
    ...desktopPilotBudget,
    budgetId: 'pilot-desktop-capacity-free-v2',
    exportCapacity: {
      ...desktopPilotBudget.exportCapacity,
      minimumFreeBytes: desktopPilotBudget.exportCapacity.minimumFreeBytes + 1,
    },
  },
  {
    ...desktopPilotBudget,
    budgetId: 'pilot-desktop-capacity-build-rss-v2',
    exportCapacity: {
      ...desktopPilotBudget.exportCapacity,
      maxBuildPeakRssBytes: desktopPilotBudget.exportCapacity.maxBuildPeakRssBytes + 1,
    },
  },
  {
    ...desktopPilotBudget,
    budgetId: 'pilot-desktop-capacity-snapshot-rss-v2',
    exportCapacity: {
      ...desktopPilotBudget.exportCapacity,
      maxSnapshotPeakRssBytes: desktopPilotBudget.exportCapacity.maxSnapshotPeakRssBytes + 1,
    },
  },
]) {
  expectCode(() => buildPilotBudgetRecord(fields, { epoch: pilotEpoch, shards: pilotShards }));
}

const desktopCanonicalRoute = desktopRoute();
registerSyntheticBundle(
  'attempt-desktop-shape',
  'scan-desktop-shape',
  pilotPaths.map((item) => item.path),
  desktopCanonicalRoute,
);
const desktopManifest = JSON.parse(syntheticBundles.get('attempt-desktop-shape').documents['scan-manifest.json']);
const desktopCoverage = JSON.parse(syntheticBundles.get('attempt-desktop-shape').documents['coverage.json']);
assert.equal(Object.hasOwn(desktopManifest.scan.target, 'revision'), false);
assert.equal(desktopManifest.scan.target.snapshotDigest, desktopCanonicalRoute.directorySnapshotDigest);
assert.deepEqual(desktopManifest.scan.scope, { includePaths: ['.'], excludePaths: [] });
assert.deepEqual(desktopCoverage.includePaths, ['.']);
assert.deepEqual(desktopCoverage.excludePaths, []);
assert.equal(Object.hasOwn(desktopCoverage, 'reviewedFiles'), false);
assert.equal(Object.hasOwn(desktopCoverage, 'reviewedPaths'), false);
assert.deepEqual(
  validateReviewedSetExtension(desktopCoverage.extensions).reviewedFiles,
  pilotPaths.map((item) => item.path),
);
const desktopResultClaim = resultClaim({
  claimId: 'claim-desktop-shape',
  attemptId: 'attempt-desktop-shape',
  sectionId: 'S02',
  shardId: 'S02/P01',
  scanId: 'scan-desktop-shape',
  reviewedPathCount: pilotPaths.length,
  controlGenerationHash: desktopPilotBudget.controlGenerationHash,
  overrides: desktopCanonicalRoute,
});
for (const [routeMutation, expectedCode] of [
  [{ pluginVersion: '0.1.23' }, 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED'],
  [{ adapterVersion: 'security-target-adapter/v2' }, 'E_SECURITY_PROGRAM_EVIDENCE_INVALID'],
  [{ routeContractSha256: sha('wrong-route-contract') }, 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED'],
]) {
  expectCode(() => buildResultClaimRecord({ ...desktopResultClaim, ...routeMutation }), expectedCode);
}
expectCode(() => buildResultClaimRecord({
  ...pilotClaim,
  claimId: 'claim-sdk-desktop-confusion',
  targetForm: 'attested-directory-export',
}));
expectCode(() => buildResultClaimRecord({
  ...pilotClaim,
  claimId: 'claim-sdk-desktop-digest-confusion',
  directorySnapshotDigest: desktopCanonicalRoute.directorySnapshotDigest,
}));
expectCode(() => buildResultClaimRecord({
  ...desktopResultClaim,
  claimId: 'claim-desktop-sdk-confusion',
  standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
}), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => buildResultClaimRecord((({ exportCapacity: _omitted, ...rest }) => ({
  ...rest,
  claimId: 'claim-desktop-missing-capacity',
}))(desktopResultClaim)), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
const failedClaim = failedResultClaim();
assert.equal(failedClaim.scannerState, 'TERMINAL_FAILED');
assert.equal(Object.hasOwn(failedClaim, 'bundleRef'), false);
assert.equal(Object.hasOwn(failedClaim, 'bundleHash'), false);
assert.equal(Object.hasOwn(failedClaim, 'artifacts'), false);
const reviewedS01 = reviewedSet({
  evidenceId: 'evidence-s01', attemptId: 'attempt-s01', sectionId: 'S01', shardId: 'S01/P01',
  scanId: 'scan-s01', paths: ['shared/threat/c.go'],
});
const reviewedS02 = reviewedSet({
  evidenceId: 'evidence-s02', attemptId: 'attempt-s02', sectionId: 'S02', shardId: 'S02/P01',
  scanId: 'scan-s02', paths: ['shared/a.go', 'shared/b.go'],
});

const promotion = buildDeepPromotionRecord({
  promotionId: 'promotion-auth',
  createdAt: fixedTime,
  sectionId: 'S03',
  targetDirectory: 'authserver/internal/handlers',
  reasonCodes: ['AUTHORITY_BOUNDARY'],
  standardEvidenceRefs: ['claim:claim-s03'],
  programPromotionCap: 8,
  deepRunCap: 1,
  deepScanMaxTimeHours: 6,
  state: 'PLANNED',
  conflictCount: 0,
  disposition: 'pending',
});
validateDeepPromotions([promotion]);

const observation = buildObservationRecord({
  recordId: 'observation-one',
  sourceKey: { path: 'shared/a.go', line: 12, symbol: 'Verify' },
  sectionId: 'S02',
  attemptId: 'attempt-s02',
  scanId: 'scan-s02',
  bundleRef: 'attempt:attempt-s02',
  type: 'open-question',
  disposition: 'open',
  observedAt: fixedTime,
});
validateObservationRecords([observation], { liveAttemptIds: ['attempt-s02'] });

for (const canonicalTimestamp of [
  '2026-09-04T01:02:03.456Z',
  '2026-09-04T01:02:03.456789Z',
  '2024-02-29T23:59:59.000000Z',
]) {
  const timestampRecord = buildObservationRecord({
    ...observation,
    recordId: `observation-time-${sha(canonicalTimestamp).slice(0, 12)}`,
    observedAt: canonicalTimestamp,
  });
  assert.equal(timestampRecord.observedAt, canonicalTimestamp);
  assert.equal(JSON.parse(canonicalJson(timestampRecord)).observedAt, canonicalTimestamp);
}
for (const rejectedTimestamp of [
  '2026-09-04T01:02:03Z',
  '2026-09-04T01:02:03.4Z',
  '2026-09-04T01:02:03.4567Z',
  '2026-09-04T01:02:03.4567890Z',
  '2026-09-04T01:02:03.456789',
  '2026-09-04T01:02:03.456789+00:00',
  '2026-09-04T01:02:03.456789z',
  '2026-09-04 01:02:03.456789Z',
  '2026-02-29T01:02:03.456789Z',
  '2026-04-31T01:02:03.456789Z',
  '2026-09-04T24:02:03.456789Z',
  '2026-09-04T01:60:03.456789Z',
  '2026-09-04T01:02:60.456789Z',
  '0000-09-04T01:02:03.456789Z',
]) {
  expectCode(() => buildObservationRecord({
    ...observation,
    recordId: `observation-bad-time-${sha(rejectedTimestamp).slice(0, 12)}`,
    observedAt: rejectedTimestamp,
  }));
}

const complete = buildReconciliationRecord({
  generationId: 'generation-complete',
  generatedAt: fixedTime,
  epoch,
  sections,
  shards,
  resultClaims: [claimS01, claimS02],
  reviewedSets: [reviewedS01, reviewedS02],
  admissionCapabilities: [admissionCapabilityS01, admissionCapabilityS02],
});
assert.equal(complete.claimed.state, 'COMPLETE');
assert.equal(complete.verified.fileCoverage, 'complete');
assert.equal(complete.verified.gateVerdict, 'PASS');

// Operational claims never award verified credit. A complete claim without a
// machine-extractable reviewed set remains an explicit HOLD.
const contradicted = buildReconciliationRecord({
  generationId: 'generation-contradicted',
  generatedAt: fixedTime,
  epoch,
  sections,
  shards,
  resultClaims: [claimS02],
  reviewedSets: [],
});
assert.equal(contradicted.claimed.state, 'COMPLETE');
assert.equal(contradicted.verified.fileCoverage, 'none');
assert.equal(contradicted.verified.gateVerdict, 'HOLD');
assert(contradicted.verified.blockerCodes.includes('MISSING_REVIEWED_SET'));

const explicitlyMissing = buildReviewedSetRecord({
  evidenceId: 'evidence-missing',
  attemptId: 'attempt-s02',
  sectionId: 'S02',
  shardId: 'S02/P01',
  scanId: 'scan-s02',
  verifiedAt: fixedTime,
  bundleRef: 'attempt:attempt-s02',
  bundleHash: sha('attempt-s02-bundle'),
  sourceRevision: revision,
  inventorySha256: epoch.inventorySha256,
  sourceFingerprint: `v2:${revision}:${sha('source')}`,
  controlGenerationHash: sha('control'),
  sealed: true,
  hashesValid: true,
  sourceFingerprintMatches: true,
  reviewedPathsPresent: false,
});
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-missing-set', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], reviewedSets: [explicitlyMissing],
  admissionCapabilities: [admissionCapabilityS02],
}));

// A reviewed-set record cannot self-admit. It earns no credit without exactly
// one sealed claim and one independently supplied admission proof.
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-standalone-forgery', generatedAt: fixedTime,
  epoch, sections, shards, reviewedSets: [reviewedS02],
}));
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-not-admitted', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], reviewedSets: [reviewedS02],
}));
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-caller-authored-admission', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], reviewedSets: [reviewedS02],
  admissions: [admissionS02],
}));
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-forged-capability', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], reviewedSets: [reviewedS02],
  admissionCapabilities: [Object.freeze(Object.create(null))],
}));
const substitutedResultClaim = buildResultClaimRecord({
  ...claimS02,
  claimId: 'claim-s02-substituted-after-admission',
});
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-substituted-result-claim', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [substitutedResultClaim], reviewedSets: [reviewedS02],
  admissionCapabilities: [admissionCapabilityS02],
}));
const receiptSubstitutedResultClaim = buildResultClaimRecord({
  ...claimS02,
  claimId: 'claim-s02-receipt-substitution',
  artifacts: claimS02.artifacts.map((artifact, index) => (
    index === 0 ? { ...artifact, sha256: sha('substituted-retained-artifact') } : artifact
  )),
});
expectCode(() => verifiedAdmissionCapability(
  admissionS02, receiptSubstitutedResultClaim, preparedTargets.get('S02/P01'),
));
const callerForgedReviewedPaths = buildReviewedSetRecord({
  ...reviewedS02,
  reviewedPaths: ['shared/b.go'],
});
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-caller-forged-reviewed-paths', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], reviewedSets: [callerForgedReviewedPaths],
  admissionCapabilities: [admissionCapabilityS02],
}));
expectCode(() => issueVerifiedAdmissionCapability({
  admission: admissionS02,
  resultClaim: claimS02,
  epoch,
  shards,
  target: preparedTargets.get('S02/P01'),
  journalPath: '/fixture/tampered/journal.json',
  attemptsDirectory: '/fixture/tampered/bundles',
}));
const wrongBundleEvidence = buildReviewedSetRecord({
  ...reviewedS02,
  bundleRef: 'attempt:wrong-bundle',
});
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-wrong-bundle', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], reviewedSets: [wrongBundleEvidence],
  admissionCapabilities: [admissionCapabilityS02],
}));

const status = buildStatusRecord({
  generationId: 'status-generation',
  generatedAt: fixedTime,
  milestones: [
    { id: 'C0', claimedState: 'COMPLETE', verifiedState: 'HOLD', blockerCodes: ['DENOMINATOR_DECISION'] },
    { id: 'C0.5', claimedState: 'NOT_STARTED', verifiedState: 'NOT_VERIFIED', blockerCodes: [] },
    { id: 'C1', claimedState: 'NOT_STARTED', verifiedState: 'NOT_VERIFIED', blockerCodes: [] },
    { id: 'D1', claimedState: 'NOT_STARTED', verifiedState: 'NOT_VERIFIED', blockerCodes: [] },
    { id: 'C2', claimedState: 'NOT_STARTED', verifiedState: 'NOT_VERIFIED', blockerCodes: [] },
    { id: 'C3', claimedState: 'NOT_STARTED', verifiedState: 'NOT_VERIFIED', blockerCodes: [] },
  ],
});
assert.equal(status.programClaimedState, 'INCOMPLETE');
assert.equal(status.programVerifiedState, 'HOLD');
assert.equal(status.nextMilestone, 'C0');

// Closed schemas, exact identities, hashes, counts and paths fail closed.
expectCode(() => validateEpochRecord({ ...epoch, schema: 'setjoin.security-program.epoch/v2' }), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => validateEpochRecord({ ...epoch, surprise: true }), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => validateEpochRecord((({ sourceCommittedAt: _omitted, ...rest }) => rest)(epoch)), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => validateEpochRecord((({ historicalCandidateCount: _omitted, ...rest }) => rest)(epoch)), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => validateEpochRecord({ ...epoch, historicalCandidateCount: epoch.authorizedCount - 1 }));
expectCode(() => validateEpochRecord({ ...epoch, inventorySha256: '0'.repeat(64) }));
expectCode(() => validateEpochRecord({ ...epoch, authorizedCount: 99 }));
expectCode(() => validateEpochRecord({ ...epoch, authorizedPaths: [{ ...authorizedPaths[0], path: '/Users/operator/private.go' }, ...authorizedPaths.slice(1)] }));
expectCode(() => validateEpochRecord({
  ...alternateDenominatorEpoch,
  inventoryDecision: { ...compilerDecision, unknownDecisionField: true },
}));
expectCode(() => validateEpochRecord({
  ...alternateDenominatorEpoch,
  inventoryDecision: { ...compilerDecision, decidedAt: '1970-01-01T00:00:00.000Z' },
}));
for (const mutation of [
  { revision: '8'.repeat(40) },
  { acceptedAuthorizedCount: 2 },
  { exclusionPolicySha256: sha('wrong-policy') },
  { inventorySha256: sha('wrong-inventory') },
]) {
  expectCode(() => validateEpochRecord({
    ...alternateDenominatorEpoch,
    inventoryDecision: { ...compilerDecision, ...mutation },
  }));
}
expectCode(() => validateEpochRecord({
  ...alternateDenominatorEpoch,
  inventoryDecision: { ...compilerDecision, historicalCandidateCount: authorizedPaths.length },
}));
expectCode(() => validateSectionsRecord({ ...sections, sections: [...sections.sections, sections.sections[0]] }, { epoch }));
expectCode(() => validateSectionsRecord({
  ...sections,
  sections: [
    sections.sections[0],
    {
      ...sections.sections[1],
      paths: [{ ...sections.sections[1].paths[0], objectId: 'a'.repeat(40) }, sections.sections[1].paths[1]],
    },
  ],
}, { epoch }));
const changedShardPaths = [{ ...authorizedPaths[0], objectId: 'a'.repeat(40) }, authorizedPaths[1]];
expectCode(() => buildShardGenerationRecord({
  ...shards,
  shards: [
    shards.shards[0],
    {
      ...shards.shards[1],
      paths: changedShardPaths,
      pathListSha256: inventoryHash(changedShardPaths),
    },
  ],
}, { epoch, sections }));
expectCode(() => validateResultClaimRecord({ ...claimS01, claimHash: '0'.repeat(64) }));
expectCode(() => validateResultClaimRecord({ ...claimS01, sourceFingerprint: `v2:${sha('source')}` }));
expectCode(() => buildResultClaimRecord((({ peakRssBytes: _omitted, ...rest }) => rest)(claimS01)), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => buildResultClaimRecord({ ...claimS01, peakRssBytes: -1 }));
expectCode(() => buildResultClaimRecord({ ...claimS01, freeBytesAfter: -1 }));
expectCode(() => buildResultClaimRecord({ ...claimS01, retryCount: -1 }));
expectCode(() => buildResultClaimRecord({ ...claimS01, callerApprovedLimits: true }), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => buildResultClaimRecord({
  ...failedClaim,
  bundleRef: 'attempt:placeholder',
  artifacts: [],
}));
expectCode(() => buildReviewedSetRecord({
  ...reviewedS01,
  sourceFingerprint: `v2:${'8'.repeat(40)}:${sha('source')}`,
}));
expectCode(() => validateAdmissionInputRecord({ ...admissionS02, journalState: 'PUBLISHED' }));
expectCode(() => validateAdmissionInputRecord({
  ...admissionS02,
  verifiedBundleHash: sha('wrong-bundle'),
}));
expectCode(() => validateAdmissionInputRecord({
  ...admissionS02,
  currentControlGenerationHash: sha('stale-control'),
}));
expectCode(() => validateAdmissionInputRecord({
  ...admissionS02,
  currentSourceFingerprint: `v2:${revision}:${sha('stale-source')}`,
}));
expectCode(() => validatePilotBudgetRecord({ ...pilotBudget, schema: 'setjoin.security-program.pilot-budget/v2' }), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => validatePilotBudgetRecord({ ...pilotBudget, secret: 'do-not-accept' }), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => buildPilotBudgetRecord({ ...pilotBudget }));
expectCode(() => buildPilotBudgetRecord({ ...pilotBudget, inventorySha256: sha('stale-inventory') }, {
  epoch: pilotEpoch, shards: pilotShards,
}));
expectCode(() => buildPilotBudgetRecord({ ...pilotBudget, shardPathListSha256: sha('stale-shard') }, {
  epoch: pilotEpoch, shards: pilotShards,
}));
// Verdict identity, booleans, measurements, reasons, and route fields are
// projections of the opaque admission capability, never caller authority.
for (const attemptedOverride of [
  { verdict: 'HOLD' },
  { checks: { ...pilotVerdict.checks, reviewedSetPresent: false } },
  { measurements: { ...pilotVerdict.measurements, elapsedSeconds: 0 } },
  { reasonCodes: ['CALLER_DECIDES'] },
  { resultClaimHash: sha('wrong-result') },
  { pluginVersion: '0.1.23' },
]) {
  expectCode(() => buildPilotVerdictRecord({ evaluatedAt: fixedTime, ...attemptedOverride }, pilotAuthorityOptions));
}
expectCode(() => buildPilotVerdictRecord({ evaluatedAt: fixedTime }));

function expectPostCapabilityTamperRejected(label, tamper) {
  const attemptId = `attempt-post-capability-${label}`;
  const scanId = `scan-post-capability-${label}`;
  const target = preparedTargets.get('S01/P01');
  registerSyntheticBundle(
    attemptId,
    scanId,
    ['shared/threat/c.go'],
    { ...sdkRoute(), ...verifyPreparedTarget(target) },
  );
  const claim = resultClaim({
    claimId: `claim-post-capability-${label}`,
    attemptId,
    sectionId: 'S01',
    shardId: 'S01/P01',
    scanId,
    reviewedPathCount: 1,
  });
  const admission = admissionFor({
    attemptId,
    sectionId: 'S01',
    shardId: 'S01/P01',
    scanId,
    overrides: { targetArtifactSha256: verifyPreparedTarget(target).artifactSha256 },
  });
  const capability = verifiedAdmissionCapability(admission, claim, target);
  const evidence = reviewedSet({
    evidenceId: `evidence-post-capability-${label}`,
    attemptId,
    sectionId: 'S01',
    shardId: 'S01/P01',
    scanId,
    paths: ['shared/threat/c.go'],
  });
  tamper(path.join(attemptsDirectory, attemptId, 'canonical', 'coverage.json'));
  expectCode(() => buildReconciliationRecord({
    generationId: `generation-post-capability-${label}`,
    generatedAt: fixedTime,
    epoch,
    sections,
    shards,
    resultClaims: [claim],
    reviewedSets: [evidence],
    admissionCapabilities: [capability],
  }));
}

expectPostCapabilityTamperRejected('content', (filename) => {
  fs.chmodSync(filename, 0o600);
  fs.appendFileSync(filename, '\n');
});
expectPostCapabilityTamperRejected('replacement', (filename) => {
  const bytes = fs.readFileSync(filename);
  const mode = fs.statSync(filename).mode & 0o777;
  const directory = path.dirname(filename);
  const directoryMode = fs.statSync(directory).mode & 0o777;
  fs.chmodSync(directory, 0o700);
  try {
    fs.unlinkSync(filename);
    fs.writeFileSync(filename, bytes, { mode });
  } finally {
    fs.chmodSync(directory, directoryMode);
  }
});
expectPostCapabilityTamperRejected('mode', (filename) => {
  fs.chmodSync(filename, 0o400);
});

expectCode(() => buildObservationRecord({
  recordId: 'private-observation',
  sourceKey: { path: '/Users/private-operator/finding.txt' },
  sectionId: 'S02', attemptId: 'attempt-s02', scanId: 'scan-s02',
  bundleRef: 'attempt:attempt-s02', type: 'finding', disposition: 'open', observedAt: fixedTime,
}));
expectCode(() => buildObservationRecord({
  ...observation,
  recordId: 'observation-with-body',
  findingBody: 'raw finding content is not a control-record field',
}), 'E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED');
expectCode(() => validateSectionsRecord({
  ...sections,
  sections: [{ ...sections.sections[0], title: 'password=private-value' }, sections.sections[1]],
}, { epoch }));
expectCode(() => buildResultClaimRecord({
  ...claimS01,
  bundleRef: '/private/tmp/protected-bundle',
}));
expectCode(() => validateObservationRecords([observation, { ...observation }]));
expectCode(() => validateDeepPromotions(Array.from({ length: 9 }, (_, index) => buildDeepPromotionRecord({
  ...promotion,
  schema: DEEP_PROMOTION_SCHEMA,
  promotionId: `promotion-${index}`,
  targetDirectory: `authserver/internal/area-${index}`,
}))));
expectCode(() => validateReconciliationRecord({
  ...complete,
  verified: { ...complete.verified, gateVerdict: 'HOLD', blockerCodes: ['CLAIM_ONLY'] },
}));
expectCode(() => validateStatusRecord({ ...status, programVerifiedState: 'VERIFIED' }));

// A reviewed path must belong to the exact named shard. Same-owner paths from
// another shard remain uncredited and mechanically named.
const splitShards = buildShardGenerationRecord({
  revision,
  inventorySha256: epoch.inventorySha256,
  generationId: 'fixture-split-shards/v1',
  shards: [
    {
      id: 'S01/P01', ownerSectionId: 'S01', pathCount: 1,
      pathListSha256: inventoryHash([authorizedPaths[2]]), paths: [authorizedPaths[2]],
    },
    {
      id: 'S02/P01', ownerSectionId: 'S02', pathCount: 1,
      pathListSha256: inventoryHash([authorizedPaths[0]]), paths: [authorizedPaths[0]],
    },
    {
      id: 'S02/P02', ownerSectionId: 'S02', pathCount: 1,
      pathListSha256: inventoryHash([authorizedPaths[1]]), paths: [authorizedPaths[1]],
    },
  ],
}, { epoch, sections });
registerSyntheticBundle(
  'attempt-wrong-shard', 'scan-wrong-shard', ['shared/b.go'],
  { ...sdkRoute(), ...verifyPreparedTarget(preparedTargets.get('S02/P01')) }, 'partial',
  { scopePaths: ['shared/a.go', 'shared/b.go'] },
);
const wrongShardEvidence = reviewedSet({
  evidenceId: 'evidence-wrong-shard', attemptId: 'attempt-wrong-shard',
  sectionId: 'S02', shardId: 'S02/P01', scanId: 'scan-wrong-shard', paths: ['shared/b.go'],
});
const wrongShardClaim = resultClaim({
  claimId: 'claim-wrong-shard', attemptId: 'attempt-wrong-shard',
  sectionId: 'S02', shardId: 'S02/P01', scanId: 'scan-wrong-shard', reviewedPathCount: 1,
  missingPathCount: 1, claimedFileCoverage: 'partial', claimedProofCompleteness: 'blocked',
});
const wrongShardAdmission = admissionFor({
  attemptId: 'attempt-wrong-shard', sectionId: 'S02', shardId: 'S02/P01', scanId: 'scan-wrong-shard',
  overrides: { targetArtifactSha256: verifyPreparedTarget(preparedTargets.get('S02/P01')).artifactSha256 },
});
const wrongShardAdmissionCapability = verifiedAdmissionCapability(
  wrongShardAdmission, wrongShardClaim, preparedTargets.get('S02/P01'),
);
const wrongShard = buildReconciliationRecord({
  generationId: 'generation-wrong-shard', generatedAt: fixedTime,
  epoch, sections, shards: splitShards,
  resultClaims: [wrongShardClaim], reviewedSets: [wrongShardEvidence],
  admissionCapabilities: [wrongShardAdmissionCapability],
});
assert.deepEqual(wrongShard.outOfShardPaths, ['shared/b.go']);
assert.equal(wrongShard.uniqueReviewedCount, 0);
assert(wrongShard.verified.blockerCodes.includes('REVIEWED_OUTSIDE_SHARD'));

// Observation preservation is reconciled per attempt. A surplus for S01 may
// not offset a missing observation from S02.
const observationsForS01 = [
  buildObservationRecord({
    recordId: 'observation-s01-one', sourceKey: { path: 'shared/threat/c.go', line: 1 },
    sectionId: 'S01', attemptId: 'attempt-s01', scanId: 'scan-s01',
    bundleRef: 'attempt:attempt-s01', type: 'finding', disposition: 'accepted', observedAt: fixedTime,
  }),
  buildObservationRecord({
    recordId: 'observation-s01-two', sourceKey: { path: 'shared/threat/c.go', line: 2 },
    sectionId: 'S01', attemptId: 'attempt-s01', scanId: 'scan-s01',
    bundleRef: 'attempt:attempt-s01', type: 'rejection', disposition: 'rejected', observedAt: fixedTime,
  }),
];
const claimOneObservationS01 = resultClaim({
  claimId: 'claim-s01-observations', attemptId: 'attempt-s01', sectionId: 'S01', shardId: 'S01/P01',
  scanId: 'scan-s01', reviewedPathCount: 1, claimedObservationCount: 1,
});
const claimOneObservationS02 = resultClaim({
  claimId: 'claim-s02-observations', attemptId: 'attempt-s02', sectionId: 'S02', shardId: 'S02/P01',
  scanId: 'scan-s02', reviewedPathCount: 2, claimedObservationCount: 1,
});
const observationAdmissionCapabilityS01 = verifiedAdmissionCapability(
  admissionS01, claimOneObservationS01, preparedTargets.get('S01/P01'),
);
const observationAdmissionCapabilityS02 = verifiedAdmissionCapability(
  admissionS02, claimOneObservationS02, preparedTargets.get('S02/P01'),
);
const perAttemptObservations = buildReconciliationRecord({
  generationId: 'generation-observation-offset', generatedAt: fixedTime,
  epoch, sections, shards,
  resultClaims: [claimOneObservationS01, claimOneObservationS02],
  reviewedSets: [reviewedS01, reviewedS02],
  admissionCapabilities: [observationAdmissionCapabilityS01, observationAdmissionCapabilityS02],
  observations: observationsForS01,
});
assert.equal(perAttemptObservations.observationCount, 2);
assert.equal(perAttemptObservations.lostObservationCount, 1);
assert(perAttemptObservations.verified.blockerCodes.includes('LOST_OBSERVATION'));

const orphanObservation = buildObservationRecord({
  recordId: 'observation-orphan', sourceKey: { path: 'shared/a.go', line: 5 },
  sectionId: 'S02', attemptId: 'attempt-unknown', scanId: 'scan-unknown',
  bundleRef: 'attempt:attempt-unknown', type: 'deferred', disposition: 'open', observedAt: fixedTime,
});
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-orphan-observation', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], observations: [orphanObservation],
}));
const mismatchedObservation = buildObservationRecord({
  recordId: 'observation-mismatched', sourceKey: { path: 'shared/a.go', line: 6 },
  sectionId: 'S02', attemptId: 'attempt-s02', scanId: 'scan-other',
  bundleRef: 'attempt:attempt-s02', type: 'deferred', disposition: 'open', observedAt: fixedTime,
});
expectCode(() => buildReconciliationRecord({
  generationId: 'generation-mismatched-observation', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS02], observations: [mismatchedObservation],
}));

// Builders pin their schema and role; caller-supplied aliases cannot weaken them.
assert.equal(buildEpochRecord({ ...epoch, schema: 'ignored', recordRole: 'derived' }).schema, EPOCH_SCHEMA);
assert.equal(buildResultClaimRecord({ ...claimS01, schema: 'ignored', recordRole: 'authority' }).schema, RESULT_CLAIM_SCHEMA);
assert.equal(pilotBudget.schema, PILOT_BUDGET_SCHEMA);
assert.equal(promotion.schema, DEEP_PROMOTION_SCHEMA);

// This module is a pure record boundary. Instrument common process/network
// launch surfaces while exercising another full derivation and prove no call.
let processLaunches = 0;
let networkLaunches = 0;
let scannerStarts = 0;
const originalProcess = {
  spawn: childProcess.spawn,
  spawnSync: childProcess.spawnSync,
  exec: childProcess.exec,
  execFile: childProcess.execFile,
  execFileSync: childProcess.execFileSync,
};
const originalNetwork = {
  httpRequest: http.request,
  httpGet: http.get,
  httpsRequest: https.request,
  httpsGet: https.get,
  connect: net.connect,
  createConnection: net.createConnection,
  fetch: globalThis.fetch,
};
const rejectProcess = () => { processLaunches += 1; throw new Error('unexpected process launch'); };
const rejectNetwork = () => { networkLaunches += 1; throw new Error('unexpected network launch'); };
try {
  childProcess.spawn = rejectProcess;
  childProcess.spawnSync = rejectProcess;
  childProcess.exec = rejectProcess;
  childProcess.execFile = rejectProcess;
  childProcess.execFileSync = rejectProcess;
  http.request = rejectNetwork;
  http.get = rejectNetwork;
  https.request = rejectNetwork;
  https.get = rejectNetwork;
  net.connect = rejectNetwork;
  net.createConnection = rejectNetwork;
  globalThis.fetch = rejectNetwork;
  const rerun = buildReconciliationRecord({
    generationId: 'generation-no-launch', generatedAt: fixedTime,
    epoch, sections, shards, resultClaims: [claimS01, claimS02], reviewedSets: [reviewedS01, reviewedS02],
    admissionCapabilities: [admissionCapabilityS01, admissionCapabilityS02],
  });
  assert.equal(rerun.verified.gateVerdict, 'PASS');
} finally {
  Object.assign(childProcess, originalProcess);
  http.request = originalNetwork.httpRequest;
  http.get = originalNetwork.httpGet;
  https.request = originalNetwork.httpsRequest;
  https.get = originalNetwork.httpsGet;
  net.connect = originalNetwork.connect;
  net.createConnection = originalNetwork.createConnection;
  globalThis.fetch = originalNetwork.fetch;
}
assert.equal(processLaunches, 0);
assert.equal(networkLaunches, 0);
assert.equal(scannerStarts, 0);
assert.equal(canonicalJson(complete), canonicalJson(buildReconciliationRecord({
  generationId: 'generation-complete', generatedAt: fixedTime,
  epoch, sections, shards, resultClaims: [claimS01, claimS02], reviewedSets: [reviewedS01, reviewedS02],
  admissionCapabilities: [admissionCapabilityS01, admissionCapabilityS02],
})));

removeFixtureTree(evidenceRoot);
removeFixtureTree(pilotRepo);
removeFixtureTree(pilotState);

console.log('security-program-records test: PASS (scanner=0 network=0 process=0)');
