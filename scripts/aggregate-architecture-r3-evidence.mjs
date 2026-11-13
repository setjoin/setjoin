#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

const repositoryRoot = path.resolve(import.meta.dirname, '..');
const laneCases = new Map([
  ['aal2', 'ARCH-R3-R1-FRESH-AAL2'],
  ['auth-completion', 'ARCH-R3-R2-AUTH-COMPLETION'],
  ['migration-checkpoint', 'ARCH-R3-R3-CHECKPOINT'],
  ['webhook-outbox', 'ARCH-R3-R4-WEBHOOK-OUTBOX'],
  ['mam-lifecycle', 'ARCH-R3-R5-MAM-CONFORMANCE'],
  ['chat-reconcile', 'ARCH-R3-R6-CHAT-RECONCILE'],
  ['compose-state', 'ARCH-R3-R7-COMPOSE-STATE'],
  ['caption-pipeline', 'ARCH-R3-R8-CAPTION-HERMETIC'],
]);
const releaseCases = new Map([
  ['ARCH-R3-R3-PREVIOUS-BINARY', ['compatibility/previous-binary-evidence.json', 'compatibility/legacy-projection.json']],
  ['ARCH-R3-R4-RESIDUE-COMPATIBILITY', ['compatibility/previous-binary-evidence.json', 'compatibility/residue-drain.json']],
  ['ARCH-R3-R5-PHYSICAL-IOS', ['devices/ios/device-receipt.json', 'devices/ios/visible-readiness.png']],
  ['ARCH-R3-R5-PHYSICAL-ANDROID', ['devices/android/device-receipt.json', 'devices/android/visible-readiness.png']],
  ['ARCH-R3-R5-PHYSICAL-HARMONY', ['devices/harmonyos/device-receipt.json', 'devices/harmonyos/visible-readiness.png']],
  ['ARCH-R3-R8-LIVE-MEDIA', ['live-media/live-media-receipt.json', 'live-media/output.log']],
]);

function fail(message) { throw new Error(`E_ARCH_R3_EVIDENCE ${message}`); }
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function git(args) {
  const result = spawnSync('git', args, { cwd: repositoryRoot, encoding: 'utf8' });
  if (result.status !== 0) fail(`git ${args.join(' ')} failed`);
  return result.stdout;
}
function currentSource() {
  return {
    commit: git(['rev-parse', 'HEAD']).trim(),
    dirtyDigest: sha256(git(['status', '--porcelain=v1', '-uall'])),
  };
}
function parse(filename) {
  try { return JSON.parse(fs.readFileSync(filename, 'utf8')); }
  catch (error) { fail(`${filename}: ${error.message}`); }
}
function validateLaneManifest(manifest, filename) {
  const required = ['schemaVersion', 'lane', 'mode', 'command', 'source', 'verdict', 'diagnosticCode', 'startedAt', 'endedAt', 'durationMs', 'environment', 'tools', 'cases', 'artifacts'];
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) fail(`${filename}: manifest must be an object`);
  for (const field of required) if (!Object.prototype.hasOwnProperty.call(manifest, field)) fail(`${filename}: missing field ${field}`);
  if (manifest.schemaVersion !== 1 || !laneCases.has(manifest.lane)) fail(`${filename}: invalid schema or lane`);
  if (manifest.mode !== 'verdict' || manifest.verdict !== 'pass' || manifest.diagnosticCode !== null) fail(`${filename}: not a passing verdict manifest`);
  if (typeof manifest.command !== 'string' || !manifest.command.includes(manifest.lane)) fail(`${filename}: invalid command`);
  if (typeof manifest.source?.commit !== 'string' || !/^[0-9a-f]{64}$/.test(manifest.source?.dirtyDigest ?? '')) fail(`${filename}: invalid source binding`);
  if (!Number.isFinite(Date.parse(manifest.startedAt)) || !Number.isFinite(Date.parse(manifest.endedAt)) || !Number.isInteger(manifest.durationMs) || manifest.durationMs < 0) fail(`${filename}: invalid timing`);
  if (manifest.environment === null || typeof manifest.environment !== 'object' || manifest.tools === null || typeof manifest.tools !== 'object') fail(`${filename}: invalid environment fingerprint`);
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) fail(`${filename}: missing exact case verdict`);
  for (const entry of manifest.cases) if (typeof entry?.caseId !== 'string' || entry.verdict !== 'pass') fail(`${filename}: malformed or non-passing exact case`);
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) fail(`${filename}: missing artifacts`);
}
function readCandidates(sourceRoot, source) {
  const candidates = new Map([...laneCases.keys()].map((lane) => [lane, []]));
  if (!fs.existsSync(sourceRoot)) return candidates;
  for (const entry of fs.readdirSync(sourceRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === 'aggregate' || entry.name.startsWith('.')) continue;
    const directory = path.join(sourceRoot, entry.name);
    const manifestFile = path.join(directory, 'manifest.json');
    const outputFile = path.join(directory, 'output.log');
    if (!fs.existsSync(manifestFile) || !fs.existsSync(outputFile)) continue;
    const manifest = parse(manifestFile);
    if (!laneCases.has(manifest.lane)) continue;
    if (manifest.source?.commit !== source.commit || manifest.source?.dirtyDigest !== source.dirtyDigest) continue;
    validateLaneManifest(manifest, manifestFile);
    const artifact = manifest.artifacts?.find((candidate) => candidate.path === 'output.log');
    const outputBytes = fs.readFileSync(outputFile);
    if (!artifact || artifact.sha256 !== sha256(outputBytes)) fail(`${manifestFile}: output.log hash mismatch`);
    const endedAt = Date.parse(manifest.endedAt);
    if (!Number.isFinite(endedAt)) fail(`${manifestFile}: invalid endedAt`);
    candidates.get(manifest.lane).push({ directory, manifestFile, outputFile, manifest, endedAt });
  }
  return candidates;
}
function selectLatest(candidates) {
  const selected = new Map();
  for (const [lane, entries] of candidates) {
    entries.sort((left, right) => right.endedAt - left.endedAt || right.directory.localeCompare(left.directory));
    if (entries.length > 0) selected.set(lane, entries[0]);
  }
  return selected;
}
function copyArtifact(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  return sha256(fs.readFileSync(destination));
}
function validateReleaseReceipt(filename, source, releaseRoot) {
  if (!filename.endsWith('.json')) return;
  const receipt = parse(filename);
  if ((receipt.schemaVersion ?? receipt.schema_version) !== 1) fail(`${filename}: unsupported receipt schema`);
  if ((receipt.verdict ?? receipt.status) !== 'pass') fail(`${filename}: receipt is not passing`);
  const dirtyDigest = receipt.source?.dirtyDigest ?? receipt.source?.dirty_digest;
  if (receipt.source?.commit !== source.commit || dirtyDigest !== source.dirtyDigest) fail(`${filename}: source binding mismatch`);
  const relative = path.relative(releaseRoot, filename);
  if (relative === 'compatibility/previous-binary-evidence.json') {
    if (!/^[0-9a-f]{64}$/.test(receipt.binarySha256 ?? '') || !Number.isInteger(receipt.currentSchemaVersion) || typeof receipt.retainedBinaryVersion !== 'string' || !receipt.retainedBinaryVersion) fail(`${filename}: invalid retained-binary binding`);
  } else if (relative.startsWith('compatibility/')) {
    const previous = fs.readFileSync(path.join(releaseRoot, 'compatibility/previous-binary-evidence.json'));
    if (receipt.previousBinaryEvidenceSha256 !== sha256(previous)) fail(`${filename}: previous-binary evidence hash mismatch`);
  } else if (relative.startsWith('devices/')) {
    const platform = relative.split(path.sep)[1];
    const screenshot = fs.readFileSync(path.join(releaseRoot, 'devices', platform, 'visible-readiness.png'));
    if (receipt.platform !== platform || receipt.deviceClass !== 'physical' || receipt.visibleReadinessSha256 !== sha256(screenshot)) fail(`${filename}: invalid physical-device binding`);
  } else if (relative === 'live-media/live-media-receipt.json') {
    const output = fs.readFileSync(path.join(releaseRoot, 'live-media/output.log'));
    if (receipt.outputSha256 !== sha256(output) || !['livekit', 'opus', 'funasr'].every((key) => typeof receipt.stack?.[key] === 'string' && receipt.stack[key])) fail(`${filename}: invalid live-media binding`);
  }
}
function aggregate(sourceRoot, outputRoot, gate, releaseRoot) {
  const source = currentSource();
  const selected = selectLatest(readCandidates(sourceRoot, source));
  const startedAt = new Date().toISOString();
  const runID = `${startedAt.replaceAll(/[-:.]/g, '').replace('Z', 'Z')}-${source.commit.slice(0, 8)}-${process.pid}`;
  fs.mkdirSync(outputRoot, { recursive: true });
  const temporary = fs.mkdtempSync(path.join(outputRoot, '.aggregate.'));
  const cases = [];
  for (const [lane, caseID] of laneCases) {
    const candidate = selected.get(lane);
    if (!candidate) {
      cases.push({ case_id: caseID, verdict: 'missing', missing_reason: 'no current-source passing lane manifest', artifacts: [] });
      continue;
    }
    const relativeManifest = `lanes/${lane}/manifest.json`;
    const relativeOutput = `lanes/${lane}/output.log`;
    cases.push({
      case_id: caseID,
      verdict: 'passed',
      missing_reason: 'none',
      artifacts: [
        { path: relativeManifest, sha256: copyArtifact(candidate.manifestFile, path.join(temporary, relativeManifest)) },
        { path: relativeOutput, sha256: copyArtifact(candidate.outputFile, path.join(temporary, relativeOutput)) },
      ],
    });
  }
  if (gate === 'release') {
    for (const [caseID, artifacts] of releaseCases) {
      const missingArtifacts = artifacts.filter((relative) => !fs.existsSync(path.join(releaseRoot, relative)));
      if (missingArtifacts.length > 0) {
        cases.push({ case_id: caseID, verdict: 'missing', missing_reason: `missing release artifacts: ${missingArtifacts.join(', ')}`, artifacts: [] });
        continue;
      }
      const copied = [];
      for (const relative of artifacts) {
        const sourceFile = path.join(releaseRoot, relative);
        const bytes = fs.readFileSync(sourceFile);
        if (bytes.length === 0) fail(`${sourceFile}: empty release artifact`);
        validateReleaseReceipt(sourceFile, source, releaseRoot);
        copied.push({ path: relative, sha256: copyArtifact(sourceFile, path.join(temporary, relative)) });
      }
      cases.push({ case_id: caseID, verdict: 'passed', missing_reason: 'none', artifacts: copied });
    }
  }
  const result = {
    schema_version: 1,
    registry_version: 1,
    source: { commit: source.commit, dirty_digest: source.dirtyDigest },
    environment: {
      host: `${os.platform()}-${os.arch()}`,
      tools: { node: process.version },
    },
    started_at: startedAt,
    ended_at: new Date().toISOString(),
    cases,
  };
  fs.writeFileSync(path.join(temporary, 'result.json.tmp'), `${JSON.stringify(result, null, 2)}\n`);
  fs.renameSync(path.join(temporary, 'result.json.tmp'), path.join(temporary, 'result.json'));
  const finalDirectory = path.join(outputRoot, runID);
  fs.renameSync(temporary, finalDirectory);
  const resultFile = path.join(finalDirectory, 'result.json');
  const missing = cases.filter((entry) => entry.verdict !== 'passed').map((entry) => entry.case_id);
  if (missing.length > 0) return { resultFile, missing };
  const pointerTemporary = path.join(outputRoot, `.latest.json.${process.pid}`);
  fs.writeFileSync(pointerTemporary, `${JSON.stringify({ schema_version: 1, result: path.relative(repositoryRoot, resultFile) }, null, 2)}\n`);
  fs.renameSync(pointerTemporary, path.join(outputRoot, 'latest.json'));
  return { resultFile, missing };
}

function argumentsFrom(argv) {
  let sourceRoot = path.join(repositoryRoot, 'test-results/architecture-r3');
  let outputRoot = path.join(sourceRoot, 'aggregate');
  let releaseRoot = path.join(sourceRoot, 'release-evidence');
  let gate = 'merge';
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!['--source-root', '--output-root', '--release-root', '--gate'].includes(argument)) fail('usage: aggregate-architecture-r3-evidence.mjs [--source-root DIR] [--output-root DIR] [--gate merge|release] [--release-root DIR]');
    const value = argv[++index];
    if (!value) fail(`${argument}: requires a value`);
    if (argument === '--source-root') sourceRoot = path.resolve(value);
    else if (argument === '--output-root') outputRoot = path.resolve(value);
    else if (argument === '--release-root') releaseRoot = path.resolve(value);
    else {
      if (!['merge', 'release'].includes(value)) fail('--gate: expected merge or release');
      gate = value;
    }
  }
  return { sourceRoot, outputRoot, releaseRoot, gate };
}

try {
  const options = argumentsFrom(process.argv.slice(2));
  const aggregated = aggregate(options.sourceRoot, options.outputRoot, options.gate, options.releaseRoot);
  if (aggregated.missing.length > 0) fail(`merge aggregate incomplete (${aggregated.missing.join(', ')}); artifact=${aggregated.resultFile}`);
  console.log(aggregated.resultFile);
} catch (error) {
  console.error(error.message);
  process.exitCode = error.message.includes('usage:') || error.message.includes('requires a directory') ? 2 : 1;
}
