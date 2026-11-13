#!/usr/bin/env node

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const aggregate = path.join(root, 'scripts/aggregate-architecture-r3-evidence.mjs');
const checker = path.join(root, 'scripts/check-architecture-r3-evidence.mjs');
const registry = path.join(root, 'docs/verification/architecture-r3-cases.json');
const lanes = ['aal2', 'auth-completion', 'migration-checkpoint', 'webhook-outbox', 'mam-lifecycle', 'chat-reconcile', 'compose-state', 'caption-pipeline'];
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function git(args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}
function run(command, args, expectedStatus) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, expectedStatus, `${result.stdout}${result.stderr}`);
  return result;
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-architecture-r3-aggregate-'));
try {
  const sourceRoot = path.join(temporary, 'source');
  const outputRoot = path.join(temporary, 'output');
  fs.mkdirSync(sourceRoot, { recursive: true });
  const source = {
    commit: git(['rev-parse', 'HEAD']).trim(),
    dirtyDigest: sha256(git(['status', '--porcelain=v1', '-uall'])),
  };
  for (const [index, lane] of lanes.entries()) {
    const directory = path.join(sourceRoot, `${String(index).padStart(2, '0')}-${lane}`);
    fs.mkdirSync(directory);
    const output = `passing ${lane}\n`;
    fs.writeFileSync(path.join(directory, 'output.log'), output);
    fs.writeFileSync(path.join(directory, 'manifest.json'), `${JSON.stringify({
      schemaVersion: 1,
      lane,
      mode: 'verdict',
      command: `bash scripts/verify-architecture-r3.sh ${lane}`,
      verdict: 'pass',
      diagnosticCode: null,
      source,
      startedAt: `2026-08-13T00:00:${String(index).padStart(2, '0')}Z`,
      endedAt: `2026-08-13T00:00:${String(index).padStart(2, '0')}Z`,
      durationMs: 1,
      environment: { os: 'self-test', architecture: 'test' },
      tools: { node: process.version },
      cases: [{ caseId: `R3.${lane}.verdict`, verdict: 'pass' }],
      artifacts: [{ path: 'output.log', sha256: sha256(output) }],
    })}\n`);
  }
  const result = run(process.execPath, [aggregate, '--source-root', sourceRoot, '--output-root', outputRoot], 0);
  const resultFile = result.stdout.trim();
  run(process.execPath, [checker, registry, resultFile, '--gate', 'merge'], 0);

  const releaseRoot = path.join(temporary, 'release');
  for (const filename of ['devices/ios/visible-readiness.png', 'devices/android/visible-readiness.png', 'devices/harmonyos/visible-readiness.png']) {
    const absolute = path.join(releaseRoot, filename);
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, Buffer.from('89504e470d0a1a0a00000000', 'hex'));
  }
  fs.mkdirSync(path.join(releaseRoot, 'live-media'), { recursive: true });
  fs.writeFileSync(path.join(releaseRoot, 'live-media/output.log'), 'live media output\n');
  const previousFile = path.join(releaseRoot, 'compatibility/previous-binary-evidence.json');
  fs.mkdirSync(path.dirname(previousFile), { recursive: true });
  fs.writeFileSync(previousFile, `${JSON.stringify({ schemaVersion: 1, verdict: 'pass', source,
    binarySha256: 'a'.repeat(64), retainedBinaryVersion: 'n-1-test', currentSchemaVersion: 212 })}\n`);
  const previousHash = sha256(fs.readFileSync(previousFile));
  for (const filename of ['compatibility/legacy-projection.json', 'compatibility/residue-drain.json']) {
    fs.writeFileSync(path.join(releaseRoot, filename), `${JSON.stringify({ schemaVersion: 1, verdict: 'pass', source,
      previousBinaryEvidenceSha256: previousHash })}\n`);
  }
  for (const platform of ['ios', 'android', 'harmonyos']) {
    const png = fs.readFileSync(path.join(releaseRoot, `devices/${platform}/visible-readiness.png`));
    fs.writeFileSync(path.join(releaseRoot, `devices/${platform}/device-receipt.json`), `${JSON.stringify({
      schemaVersion: 1, verdict: 'pass', source, platform, deviceClass: 'physical', visibleReadinessSha256: sha256(png),
    })}\n`);
  }
  fs.writeFileSync(path.join(releaseRoot, 'live-media/live-media-receipt.json'), `${JSON.stringify({
    schemaVersion: 1, verdict: 'pass', source,
    outputSha256: sha256(fs.readFileSync(path.join(releaseRoot, 'live-media/output.log'))),
    stack: { livekit: 'test-digest', opus: 'test-version', funasr: 'test-digest' },
  })}\n`);
  const releaseOutput = path.join(temporary, 'release-output');
  const releaseResult = run(process.execPath, [aggregate, '--source-root', sourceRoot, '--output-root', releaseOutput,
    '--gate', 'release', '--release-root', releaseRoot], 0).stdout.trim();
  run(process.execPath, [checker, registry, releaseResult, '--gate', 'release'], 0);
  const harmonyReceipt = path.join(releaseRoot, 'devices/harmonyos/device-receipt.json');
  const harmonyBytes = fs.readFileSync(harmonyReceipt);
  fs.rmSync(harmonyReceipt);
  const incompleteRelease = run(process.execPath, [aggregate, '--source-root', sourceRoot, '--output-root', path.join(temporary, 'incomplete-release'),
    '--gate', 'release', '--release-root', releaseRoot], 1);
  assert.match(incompleteRelease.stderr, /ARCH-R3-R5-PHYSICAL-HARMONY/);
  fs.writeFileSync(harmonyReceipt, harmonyBytes);

  fs.rmSync(path.join(sourceRoot, '03-webhook-outbox'), { recursive: true });
  const missingOutput = path.join(temporary, 'missing-output');
  const missing = run(process.execPath, [aggregate, '--source-root', sourceRoot, '--output-root', missingOutput], 1);
  assert.match(missing.stderr, /merge aggregate incomplete.*ARCH-R3-R4-WEBHOOK-OUTBOX/);
  assert.equal(fs.existsSync(path.join(missingOutput, 'latest.json')), false, 'an incomplete aggregate replaced latest');

  const tampered = path.join(sourceRoot, '00-aal2', 'output.log');
  fs.appendFileSync(tampered, 'tampered');
  const tamperedRun = run(process.execPath, [aggregate, '--source-root', sourceRoot, '--output-root', path.join(temporary, 'tampered-output')], 1);
  assert.match(tamperedRun.stderr, /hash mismatch/);

  console.log('architecture-r3 evidence aggregator self-test: PASS');
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
