#!/usr/bin/env node

import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { SecurityProgramError, sha256Hex } from './lib/security-program-json.mjs';
import { createStreamingInventoryHasher, hashInventory } from './lib/security-program-inventory.mjs';
import { ATTEMPT_EVENT_SCHEMA, validateAttemptEvent } from './lib/security-program-attempts.mjs';
import {
  EXPORT_CAPACITY_SCHEMA,
  TARGET_ADAPTER_VERSION,
  enforceMeasuredExportCapacity,
  projectExportCapacity,
  runDesktopExportStreamingPass,
} from './lib/security-program-targets.mjs';

const SHARD_PATHS = 219;
const DIRECTORY_FANOUT = 64;
const FILE_PAYLOAD_BYTES = 128;
const RETAINED_SPACE_COPIES = 4;
const FIXED_RESERVE_BYTES = 8 * 1024 * 1024 * 1024;
const MAX_PEAK_RSS_BYTES = 512 * 1024 * 1024;
const MAX_DELTA_RSS_BYTES = 192 * 1024 * 1024;
const REVISION = '7'.repeat(40);

const scaleSeries = [
  { name: 'authoritative-epoch', baseFileCount: 5_824, counts: [5_824, 58_240, 582_400] },
  { name: 'historical-candidate', baseFileCount: 6_163, counts: [6_163, 61_630, 616_300] },
];

function gitBlobId(bytes) {
  return crypto.createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8')).update(bytes).digest('hex');
}

function generatedFileBytes(pathname) {
  const fileBytes = Buffer.alloc(FILE_PAYLOAD_BYTES, 0x2e);
  const prefix = Buffer.from(`scale export fixture\n${pathname}\n`, 'utf8');
  assert(prefix.length <= fileBytes.length, 'scale fixture prefix exceeds its deterministic payload');
  prefix.copy(fileBytes);
  return fileBytes;
}

function generatedEntry(seriesName, index) {
  const directoryIndex = Math.floor(index / DIRECTORY_FANOUT);
  const directory = `scale/${seriesName}/${String(directoryIndex).padStart(10, '0')}`;
  const pathname = `${directory}/${String(index).padStart(12, '0')}.go`;
  const fileBytes = generatedFileBytes(pathname);
  return {
    path: pathname,
    pathBytes: Buffer.from(pathname, 'utf8'),
    objectId: gitBlobId(fileBytes),
    mode: '100644',
    objectType: 'blob',
    kind: 'file',
  };
}

function capacity(maxEntries, maxBytes, overrides = {}) {
  return {
    schema: EXPORT_CAPACITY_SCHEMA,
    maxEntries,
    maxBytes,
    minimumFreeBytes: FIXED_RESERVE_BYTES,
    maxBuildElapsedMs: 60_000,
    maxBuildPeakRssBytes: MAX_PEAK_RSS_BYTES,
    maxSnapshotElapsedMs: 60_000,
    maxSnapshotPeakRssBytes: MAX_PEAK_RSS_BYTES,
    ...overrides,
  };
}

function projectionVerdict(projection) {
  return projection.entryLimitPass
    && projection.byteLimitPass
    && projection.volumes.every((volume) => volume.spaceLimitPass)
    ? 'PASS' : 'HOLD';
}

function attemptRecord({ series, multiplier, inventorySha256, shardIndex, shard }) {
  const identity = `${series}-${multiplier}x-p${shardIndex}`;
  return {
    schema: ATTEMPT_EVENT_SCHEMA,
    eventId: `event-${identity}`,
    attemptId: `attempt-${identity}`,
    sequence: 0,
    state: 'RESERVED',
    recordedAt: '2026-09-04T00:00:00.000Z',
    epochRevision: REVISION,
    sourceFingerprint: `v2:${REVISION}:${sha256Hex(`source-${series}-${multiplier}x`)}`,
    inventorySha256,
    shardGenerationId: `scale-${series}-${multiplier}x/v1`,
    sectionId: 'S02',
    shardId: `S02/P${shardIndex}`,
    shardPathCount: shard.pathCount,
    shardPathListSha256: shard.pathListSha256,
    targetArtifactSha256: sha256Hex(`target-${identity}`),
    targetPathCount: shard.pathCount,
    targetPathListSha256: shard.pathListSha256,
    mode: 'Deep',
    targetForm: 'real-directory',
    targetKind: 'git_revision',
    controlGenerationHash: sha256Hex(`control-${series}-${multiplier}x`),
    leaseOwner: 'scale-fixture',
    coordinatorVersion: 'scale-fixture/v1',
    adapterVersion: TARGET_ADAPTER_VERSION,
    scannerSchemaVersion: 'scanner-schema/v1',
    fingerprintVersion: 'fingerprint/v2',
    controlSchemaSetVersion: 'control/v1',
  };
}

function generatedShardChunks({ series, fileCount, expectedShards, retainedShards, inventoryHasher }) {
  return (function* chunks() {
    const shardCount = Math.ceil(fileCount / SHARD_PATHS);
    const pathsPerShard = Math.floor(fileCount / shardCount);
    const shardsWithExtraPath = fileCount % shardCount;
    let generatedPaths = 0;
    for (let shardIndex = 1; shardIndex <= shardCount; shardIndex += 1) {
      const shardPathCount = pathsPerShard + (shardIndex <= shardsWithExtraPath ? 1 : 0);
      assert(shardPathCount >= 150 && shardPathCount <= 350,
        'every generated scale shard must remain inside the 150-350 path design range');
      const entries = new Array(shardPathCount);
      for (let offset = 0; offset < shardPathCount; offset += 1) {
        entries[offset] = generatedEntry(series.name, generatedPaths + offset);
      }
      const shardHasher = createStreamingInventoryHasher();
      shardHasher.updateChunk(entries);
      const shard = Object.freeze({
        pathCount: shardPathCount,
        pathListSha256: shardHasher.finalize().inventorySha256,
      });
      if (shardIndex === 1 || shardIndex === shardCount) {
        assert.equal(shard.pathListSha256, hashInventory([...entries].reverse()),
          'bounded first/last shard samples must preserve compatibility with the sorting array API');
      }
      if (expectedShards !== undefined) assert.deepEqual(shard, expectedShards[shardIndex - 1]);
      retainedShards.push(shard);
      inventoryHasher.updateChunk(entries);
      generatedPaths += shardPathCount;
      yield entries;
    }
    assert.equal(generatedPaths, fileCount);
  }());
}

function runStreamingPass({ series, multiplier, fileCount, phase, expected }) {
  const startedRssBytes = process.memoryUsage().rss;
  let peakRssBytes = startedRssBytes;
  const started = process.hrtime.bigint();
  const shards = [];
  const inventoryHasher = createStreamingInventoryHasher();
  let backendDirectoryCalls = 0;
  let backendFileCalls = 0;
  let backendBytes = 0;
  const directoryCount = Math.ceil(fileCount / DIRECTORY_FANOUT) + 2;
  const exportBytes = fileCount * FILE_PAYLOAD_BYTES;
  const entryCount = fileCount + directoryCount;
  const projectedPeakSpaceBytes = BigInt(FIXED_RESERVE_BYTES)
    + (BigInt(exportBytes) * BigInt(RETAINED_SPACE_COPIES));
  const volumeId = `${series.name}-${multiplier}x`;
  const result = runDesktopExportStreamingPass({
    entryChunks: generatedShardChunks({
      series, fileCount, expectedShards: expected?.shards, retainedShards: shards, inventoryHasher,
    }),
    phase,
    capacity: capacity(entryCount, exportBytes),
    volumes: [{
      volumeId,
      copies: RETAINED_SPACE_COPIES,
      availableBytes: projectedPeakSpaceBytes,
    }],
    backend: {
      rootIdentity: () => `generated-root:${series.name}:${multiplier}x`,
      directory({ relativePath, expectedMode }) {
        assert.equal(expectedMode, 0o500);
        backendDirectoryCalls += 1;
        return { identity: `generated-directory:${relativePath}` };
      },
      file({ entry, expectedFilesystemMode, begin, write }) {
        assert.equal(expectedFilesystemMode, 0o400);
        const bytes = generatedFileBytes(entry.path);
        begin(bytes.length);
        write(bytes);
        backendFileCalls += 1;
        backendBytes += bytes.length;
        return {
          filesystemMode: expectedFilesystemMode,
          identity: `generated-file:${entry.path}:${entry.objectId}`,
        };
      },
    },
  });
  const inventoryResult = inventoryHasher.finalize();
  assert.equal(inventoryResult.pathCount, fileCount);
  assert.equal(result.fileCount, fileCount);
  assert.equal(result.directoryCount, directoryCount);
  assert.equal(result.byteCount, exportBytes);
  assert.equal(backendFileCalls, fileCount);
  assert.equal(backendDirectoryCalls, directoryCount);
  assert.equal(backendBytes, exportBytes);
  assert.equal(shards.length, Math.ceil(fileCount / SHARD_PATHS));

  let attemptRecords = 0;
  let attemptRecordBytes = 0;
  if (phase === 'build') {
    for (const [index, shard] of shards.entries()) {
      const attempt = attemptRecord({
        series: series.name,
        multiplier,
        inventorySha256: inventoryResult.inventorySha256,
        shardIndex: index + 1,
        shard,
      });
      assert.equal(validateAttemptEvent(attempt), attempt);
      assert.equal(attempt.shardPathCount, shard.pathCount);
      assert.equal(attempt.targetPathCount, shard.pathCount);
      assert.equal(attempt.shardPathListSha256, shard.pathListSha256);
      assert.equal(attempt.targetPathListSha256, shard.pathListSha256);
      attemptRecordBytes += Buffer.byteLength(JSON.stringify(attempt), 'utf8');
      attemptRecords += 1;
    }
    assert.equal(attemptRecords, shards.length, 'one closed attempt event must validate per design-size shard');
  } else {
    assert(expected !== undefined, 'snapshot replay requires independent build authority');
    assert.equal(shards.length, expected.shards.length);
    assert.equal(inventoryResult.inventorySha256, expected.inventorySha256);
    assert.equal(result.exportTreeSha256, expected.exportTreeSha256);
    assert.equal(result.stableSnapshotSha256, expected.stableSnapshotSha256);
    assert.equal(result.byteCount, expected.byteCount);
    assert.equal(result.fileCount, expected.fileCount);
    assert.equal(result.directoryCount, expected.directoryCount);
  }
  peakRssBytes = Math.max(peakRssBytes, result.peakRssBytes, process.memoryUsage().rss);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1_000_000;
  const deltaRssBytes = Math.max(0, peakRssBytes - startedRssBytes);
  const elapsedCeilingMs = 2_500 + (fileCount * 0.08);
  assert(elapsedMs <= elapsedCeilingMs,
    `${series.name} ${multiplier}x ${phase} elapsed ${elapsedMs.toFixed(1)}ms exceeds ${elapsedCeilingMs.toFixed(1)}ms`);
  assert(peakRssBytes <= MAX_PEAK_RSS_BYTES,
    `${series.name} ${multiplier}x ${phase} peak RSS exceeds ${MAX_PEAK_RSS_BYTES}`);
  assert(deltaRssBytes <= MAX_DELTA_RSS_BYTES,
    `${series.name} ${multiplier}x ${phase} delta RSS exceeds ${MAX_DELTA_RSS_BYTES}`);
  return Object.freeze({
    authority: Object.freeze({
      shards: Object.freeze(shards),
      inventorySha256: inventoryResult.inventorySha256,
      exportTreeSha256: result.exportTreeSha256,
      stableSnapshotSha256: result.stableSnapshotSha256,
      byteCount: result.byteCount,
      fileCount: result.fileCount,
      directoryCount: result.directoryCount,
    }),
    metrics: Object.freeze({
      phase,
      executionKind: 'production-engine-nonmaterializing-sink',
      scannerExecuted: false,
      filesystemMaterialized: false,
      diskIoMeasured: false,
      chmodMeasured: false,
      fsyncMeasured: false,
      mountLatencyMeasured: false,
      generatedPathRecords: fileCount,
      validatedShards: shards.length,
      targetShardPaths: SHARD_PATHS,
      smallestShardPaths: Math.min(...shards.map((shard) => shard.pathCount)),
      largestShardPaths: Math.max(...shards.map((shard) => shard.pathCount)),
      attemptRecords,
      attemptRecordBytes,
      backendDirectoryCalls,
      backendFileCalls,
      inventorySha256: inventoryResult.inventorySha256,
      exportTreeSha256: result.exportTreeSha256,
      stableSnapshotSha256: result.stableSnapshotSha256,
      engineElapsedMs: Number(result.elapsedMs.toFixed(3)),
      elapsedMs: Number(elapsedMs.toFixed(3)),
      elapsedCeilingMs,
      startedRssBytes,
      peakRssBytes,
      deltaRssBytes,
      engineStartedRssBytes: result.startedRssBytes,
      enginePeakRssBytes: result.peakRssBytes,
      engineDeltaRssBytes: result.deltaRssBytes,
      peakRssCeilingBytes: MAX_PEAK_RSS_BYTES,
      deltaRssCeilingBytes: MAX_DELTA_RSS_BYTES,
      directoryCount,
      fileEntries: fileCount,
      totalEntries: entryCount,
      exportBytes,
    }),
  });
}

function exerciseScale(series, multiplier, expectedFileCount) {
  const fileCount = series.baseFileCount * multiplier;
  assert.equal(fileCount, expectedFileCount, `${series.name} ${multiplier}x count`);
  const build = runStreamingPass({ series, multiplier, fileCount, phase: 'build' });
  const snapshot = runStreamingPass({
    series, multiplier, fileCount, phase: 'snapshot', expected: build.authority,
  });
  const directoryCount = build.metrics.directoryCount;
  const exportBytes = build.metrics.exportBytes;
  const expectedEntries = fileCount + directoryCount;
  const copyAndQuarantineBytes = BigInt(exportBytes) * BigInt(RETAINED_SPACE_COPIES);
  const projectedPeakSpaceBytes = BigInt(FIXED_RESERVE_BYTES) + copyAndQuarantineBytes;
  const exactCapacity = capacity(expectedEntries, exportBytes);
  const projectionInput = {
    fileCount,
    directoryCount,
    exportBytes,
    volumes: [{
      volumeId: `${series.name}-${multiplier}x`,
      copies: RETAINED_SPACE_COPIES,
      availableBytes: projectedPeakSpaceBytes,
    }],
  };
  const exactProjection = projectExportCapacity(projectionInput, exactCapacity);
  assert.equal(projectionVerdict(exactProjection), 'PASS');
  assert.equal(projectionVerdict(projectExportCapacity(
    projectionInput, capacity(expectedEntries - 1, exportBytes),
  )), 'HOLD');
  assert.equal(projectionVerdict(projectExportCapacity(
    projectionInput, capacity(expectedEntries, exportBytes - 1),
  )), 'HOLD');
  assert.equal(projectionVerdict(projectExportCapacity({
    ...projectionInput,
    volumes: [{ ...projectionInput.volumes[0], availableBytes: projectedPeakSpaceBytes - 1n }],
  }, exactCapacity)), 'HOLD');
  const measured = {
    exportFileCount: fileCount,
    exportDirectoryCount: directoryCount,
    exportBytes,
    buildElapsedMs: build.metrics.elapsedMs,
    buildPeakRssBytes: build.metrics.peakRssBytes,
    snapshotElapsedMs: snapshot.metrics.elapsedMs,
    snapshotPeakRssBytes: snapshot.metrics.peakRssBytes,
  };
  const measuredCapacity = capacity(expectedEntries, exportBytes, {
    maxBuildElapsedMs: Math.ceil(measured.buildElapsedMs),
    maxBuildPeakRssBytes: measured.buildPeakRssBytes,
    maxSnapshotElapsedMs: Math.ceil(measured.snapshotElapsedMs),
    maxSnapshotPeakRssBytes: measured.snapshotPeakRssBytes,
  });
  assert.deepEqual(enforceMeasuredExportCapacity(measuredCapacity, measured), { disposition: 'PASS' });
  const measuredMutants = [
    ['maxBuildElapsedMs', 'buildElapsedMs', 'E_SECURITY_TARGET_HOLD_BUILD_ELAPSED'],
    ['maxBuildPeakRssBytes', 'buildPeakRssBytes', 'E_SECURITY_TARGET_HOLD_BUILD_RSS'],
    ['maxSnapshotElapsedMs', 'snapshotElapsedMs', 'E_SECURITY_TARGET_HOLD_SNAPSHOT_ELAPSED'],
    ['maxSnapshotPeakRssBytes', 'snapshotPeakRssBytes', 'E_SECURITY_TARGET_HOLD_SNAPSHOT_RSS'],
  ];
  for (const [capacityField, metricField, code] of measuredMutants) {
    const limit = Math.ceil(measured[metricField]) - 1;
    assert(limit >= 1, `${series.name} ${multiplier}x ${metricField} must permit a positive minus-one limit`);
    assert.throws(() => enforceMeasuredExportCapacity({
      ...measuredCapacity,
      [capacityField]: limit,
    }, measured), (error) => error instanceof SecurityProgramError
      && error.code === code && error.details?.disposition === 'HOLD');
  }
  return Object.freeze({
    series: series.name,
    multiplier,
    fileCount,
    scanExecuted: false,
    scanExecution: 'NOT_RUN',
    scaleExecutionPolicy: '10X_100X_REQUIRE_NEW_CAPACITY_DECISION',
    passes: Object.freeze({ build: build.metrics, snapshot: snapshot.metrics }),
    entries: expectedEntries,
    exportBytes,
    liveExportBytes: exportBytes,
    workbenchArtifactBytes: exportBytes,
    destinationTemporaryCopyBytes: exportBytes,
    quarantinedIncompleteCopyBytes: exportBytes,
    copyAndQuarantineBytes: String(copyAndQuarantineBytes),
    fixedReserveBytes: FIXED_RESERVE_BYTES,
    projectedPeakSpaceBytes: String(projectedPeakSpaceBytes),
    outcomes: Object.freeze({
      exact: 'PASS', entryMinusOne: 'HOLD', byteMinusOne: 'HOLD', spaceMinusOne: 'HOLD',
      buildElapsedMinusOne: 'HOLD', buildRssMinusOne: 'HOLD',
      snapshotElapsedMinusOne: 'HOLD', snapshotRssMinusOne: 'HOLD',
    }),
  });
}

const allMetrics = [];
for (const series of scaleSeries) {
  const seriesMetrics = [1, 10, 100].map((multiplier, index) => (
    exerciseScale(series, multiplier, series.counts[index])
  ));
  for (let index = 1; index < seriesMetrics.length; index += 1) {
    const prior = seriesMetrics[index - 1];
    const current = seriesMetrics[index];
    const scaleRatio = current.fileCount / prior.fileCount;
    for (const phase of ['build', 'snapshot']) {
      const priorPass = prior.passes[phase];
      const currentPass = current.passes[phase];
      assert.equal(currentPass.exportBytes, priorPass.exportBytes * scaleRatio,
        `${series.name} ${phase} generated export bytes must grow exactly linearly`);
      assert(currentPass.validatedShards <= Math.ceil(priorPass.validatedShards * scaleRatio),
        `${series.name} ${phase} shard validation work must remain linear`);
      const elapsedGrowthCeilingMs = (priorPass.elapsedMs * scaleRatio * 1.75) + 1_000;
      assert(currentPass.elapsedMs <= elapsedGrowthCeilingMs,
        `${series.name} ${phase} measured elapsed growth exceeded the generous linear class ceiling`);
    }
  }
  allMetrics.push(...seriesMetrics);
}

for (const metrics of allMetrics) console.log(`SCALE_METRICS ${JSON.stringify(metrics)}`);
console.log('security-program-scale test: PASS (shared production engine, nonmaterializing sinks, scanner=0 network=0)');
