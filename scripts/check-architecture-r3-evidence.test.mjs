#!/usr/bin/env node

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const checker = path.join(root, 'scripts/check-architecture-r3-evidence.mjs');
const registrySource = path.join(root, 'docs/verification/architecture-r3-cases.json');

function writeJson(filename, value) { fs.writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`); }
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function run(args, status, text) {
  const result = spawnSync(process.execPath, [checker, ...args], { encoding: 'utf8' });
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.status, status, output);
  assert.match(output, new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), output);
}

function git(args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-architecture-r3-evidence-'));
try {
  const registry = JSON.parse(fs.readFileSync(registrySource, 'utf8'));
  const registryFile = path.join(temporary, 'registry.json');
  writeJson(registryFile, registry);
  run([registryFile], 0, 'PASS');

  const sourceBinding = {
    commit: git(['rev-parse', 'HEAD']).trim(),
    dirtyDigest: crypto.createHash('sha256').update(git(['status', '--porcelain=v1', '-uall'])).digest('hex'),
  };
  const releaseRoot = path.join(temporary, 'release');
  for (const filename of ['devices/ios/visible-readiness.png', 'devices/android/visible-readiness.png', 'devices/harmonyos/visible-readiness.png']) {
    const absolute = path.join(releaseRoot, filename);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, Buffer.from('89504e470d0a1a0a00000000', 'hex'));
  }
  fs.mkdirSync(path.join(releaseRoot, 'live-media'), { recursive: true });
  fs.writeFileSync(path.join(releaseRoot, 'live-media/output.log'), 'real live-media run\n');
  const previousFile = path.join(releaseRoot, 'compatibility/previous-binary-evidence.json');
  fs.mkdirSync(path.dirname(previousFile), { recursive: true });
  writeJson(previousFile, { schemaVersion: 1, verdict: 'pass', source: sourceBinding,
    binarySha256: 'a'.repeat(64), retainedBinaryVersion: 'n-1-test', currentSchemaVersion: 212 });
  const previousHash = crypto.createHash('sha256').update(fs.readFileSync(previousFile)).digest('hex');
  for (const filename of ['compatibility/legacy-projection.json', 'compatibility/residue-drain.json']) {
    writeJson(path.join(releaseRoot, filename), { schemaVersion: 1, verdict: 'pass', source: sourceBinding,
      previousBinaryEvidenceSha256: previousHash });
  }
  for (const platform of ['ios', 'android', 'harmonyos']) {
    const png = fs.readFileSync(path.join(releaseRoot, `devices/${platform}/visible-readiness.png`));
    writeJson(path.join(releaseRoot, `devices/${platform}/device-receipt.json`), {
      schemaVersion: 1, verdict: 'pass', source: sourceBinding, platform, deviceClass: 'physical',
      visibleReadinessSha256: crypto.createHash('sha256').update(png).digest('hex'),
    });
  }
  writeJson(path.join(releaseRoot, 'live-media/live-media-receipt.json'), {
    schemaVersion: 1, verdict: 'pass', source: sourceBinding,
    outputSha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(releaseRoot, 'live-media/output.log'))).digest('hex'),
    stack: { livekit: 'test-digest', opus: 'test-version', funasr: 'test-digest' },
  });
  for (const group of ['compatibility', 'devices', 'live-media']) run([registryFile, '--release-group', group, releaseRoot], 0, `${group} evidence`);

  const laneDirectory = path.join(temporary, 'lane');
  fs.mkdirSync(laneDirectory);
  fs.writeFileSync(path.join(laneDirectory, 'output.log'), 'lane output\n');
  writeJson(path.join(laneDirectory, 'manifest.json'), {
    schemaVersion: 1, lane: 'aal2', mode: 'verdict', verdict: 'pass', diagnosticCode: null,
    source: sourceBinding, cases: [{ caseId: 'ARCH-R3-R1-FRESH-AAL2', verdict: 'pass' }],
    artifacts: [{ path: 'output.log', sha256: crypto.createHash('sha256').update('lane output\n').digest('hex') }],
  });
  run([registryFile, '--lane-manifest', path.join(laneDirectory, 'manifest.json')], 0, 'lane evidence');

  const benchmarkDirectory = path.join(temporary, 'benchmark');
  fs.mkdirSync(path.join(benchmarkDirectory, 'samples'), { recursive: true });
  const populationKey = 'c'.repeat(64);
  const benchmarkArtifacts = [];
  for (let ordinal = 1; ordinal <= 2; ordinal += 1) {
    for (const extension of ['json', 'log']) {
      const relative = `samples/${String(ordinal).padStart(3, '0')}.${extension}`;
      fs.writeFileSync(path.join(benchmarkDirectory, relative), `${ordinal}:${extension}\n`);
      benchmarkArtifacts.push({ path: relative, sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(benchmarkDirectory, relative))).digest('hex') });
    }
  }
  const benchmark = {
    schemaVersion: 1, verdict: 'pass', qualification: 'diagnostic', expectedSamples: 2, recordedSamples: 2, warmupCount: 0,
    fingerprint: { ...sourceBinding, populationKey }, formula: { name: 'nearest-rank', p95Index: 2 },
    metrics: { p95DurationMs: 20, maxDurationMs: 20 },
    samples: [{ ordinal: 1, durationMs: 10, verdict: 'pass', populationKey }, { ordinal: 2, durationMs: 20, verdict: 'pass', populationKey }],
    artifacts: benchmarkArtifacts,
  };
  const benchmarkFile = path.join(benchmarkDirectory, 'aggregate.json');
  writeJson(benchmarkFile, benchmark);
  run([registryFile, '--benchmark', benchmarkFile], 0, 'benchmark evidence');
  const badBenchmark = clone(benchmark);
  badBenchmark.metrics.p95DurationMs = 1;
  writeJson(path.join(benchmarkDirectory, 'bad-aggregate.json'), badBenchmark);
  run([registryFile, '--benchmark', path.join(benchmarkDirectory, 'bad-aggregate.json')], 1, 'invalid timing formula');

  for (const entry of registry.cases.filter((candidate) => candidate.release_gate === 'merge')) {
    for (const artifact of entry.required_artifacts) {
      const absolute = path.join(temporary, artifact);
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.writeFileSync(absolute, `${entry.case_id}:${artifact}`);
    }
  }
  const artifact = (filename) => ({ path: filename, sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(temporary, filename))).digest('hex') });
  const mergeCases = registry.cases.filter((entry) => entry.release_gate === 'merge').map((entry) => ({
    case_id: entry.case_id,
    verdict: 'passed',
    missing_reason: 'none',
    artifacts: entry.required_artifacts.map((filename) => artifact(filename)),
  }));
  const result = {
    schema_version: 1,
    registry_version: 1,
    source: {
      commit: git(['rev-parse', 'HEAD']).trim(),
      dirty_digest: crypto.createHash('sha256').update(git(['status', '--porcelain=v1', '-uall'])).digest('hex'),
    },
    environment: { host: 'self-test', tools: { node: process.version } },
    started_at: '2026-08-13T00:00:00Z',
    ended_at: '2026-08-13T00:00:01Z',
    cases: mergeCases,
  };
  const resultFile = path.join(temporary, 'result.json');
  writeJson(resultFile, result);
  run([registryFile, resultFile, '--gate', 'merge'], 0, 'gate=merge');
  run([registryFile, resultFile, '--gate', 'release'], 1, 'missing result');

  const negative = [
    ['source-mismatch', (copy) => { copy.source.dirty_digest = 'b'.repeat(64); }, 'does not match current working tree'],
    ['duplicate', (copy) => copy.cases.push(clone(copy.cases[0])), 'duplicate'],
    ['skipped', (copy) => { copy.cases[0].verdict = 'skipped'; copy.cases[0].missing_reason = 'planted'; }, 'is skipped'],
    ['bad-hash', (copy) => { copy.cases[0].artifacts[0].sha256 = 'b'.repeat(64); }, 'hash mismatch'],
    ['missing-artifact', (copy) => { copy.cases[0].artifacts.pop(); }, 'missing required artifact'],
  ];
  for (const [name, mutate, expected] of negative) {
    const copy = clone(result);
    mutate(copy);
    const filename = path.join(temporary, `${name}.json`);
    writeJson(filename, copy);
    run([registryFile, filename, '--gate', 'merge'], 1, expected);
  }

  const badRegistry = clone(registry);
  badRegistry.cases[1].case_id = badRegistry.cases[0].case_id;
  badRegistry.cases[1].workstream = badRegistry.cases[0].workstream;
  const badRegistryFile = path.join(temporary, 'bad-registry.json');
  writeJson(badRegistryFile, badRegistry);
  run([badRegistryFile], 1, 'duplicate');
  const duplicateKeyFile = path.join(temporary, 'duplicate-key.json');
  fs.writeFileSync(duplicateKeyFile, '{"schema_version":1,"schema_version":1}');
  run([duplicateKeyFile], 1, 'duplicate JSON field');

  const badReceipt = path.join(releaseRoot, 'compatibility/legacy-projection.json');
  writeJson(badReceipt, { schemaVersion: 1, verdict: 'pass', source: { ...sourceBinding, dirtyDigest: 'b'.repeat(64) } });
  run([registryFile, '--release-group', 'compatibility', releaseRoot], 1, 'does not match current working tree');
  console.log('architecture-r3 evidence checker self-test: PASS');
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
