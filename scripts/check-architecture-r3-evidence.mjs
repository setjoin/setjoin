#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

const caseIdPattern = /^ARCH-R3-R[1-8]-[A-Z0-9-]+$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const safePathPattern = /^[^\\\0]+$/;
const verdicts = new Set(['passed', 'failed', 'missing', 'unsupported', 'skipped', 'malformed', 'flaky-after-retry']);
const gates = new Set(['merge', 'release']);
const caseKeys = new Set(['case_id', 'workstream', 'owner', 'command', 'required_environment', 'mutation_boundary', 'timeout_seconds', 'required_artifacts', 'release_gate']);
const repositoryRoot = path.resolve(import.meta.dirname, '..');
const releaseGroups = new Map([
  ['compatibility', [
    'compatibility/previous-binary-evidence.json',
    'compatibility/legacy-projection.json',
    'compatibility/residue-drain.json',
  ]],
  ['devices', [
    'devices/ios/device-receipt.json', 'devices/ios/visible-readiness.png',
    'devices/android/device-receipt.json', 'devices/android/visible-readiness.png',
    'devices/harmonyos/device-receipt.json', 'devices/harmonyos/visible-readiness.png',
  ]],
  ['live-media', ['live-media/live-media-receipt.json', 'live-media/output.log']],
]);

function fail(message) {
  throw new Error(`E_ARCH_R3_EVIDENCE ${message}`);
}

function object(value, location) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${location}: expected object`);
}

function exactKeys(value, location, keys) {
  object(value, location);
  for (const key of Object.keys(value)) if (!keys.has(key)) fail(`${location}: unknown field ${JSON.stringify(key)}`);
  for (const key of keys) if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`${location}: missing field ${JSON.stringify(key)}`);
}

function string(value, location) {
  if (typeof value !== 'string' || value.trim() === '') fail(`${location}: expected non-empty string`);
}

function relativePath(value, location) {
  string(value, location);
  if (path.isAbsolute(value) || value === '..' || value.startsWith('../') || value.includes('/../') || !safePathPattern.test(value)) fail(`${location}: unsafe path`);
}

function unique(values, location) {
  if (new Set(values).size !== values.length) fail(`${location}: duplicate value`);
}

function rejectDuplicateJsonKeys(text, location) {
  let index = 0;
  const parseError = (message) => fail(`${location}: invalid JSON near character ${index + 1} (${message})`);
  const skipWhitespace = () => { while (index < text.length && /\s/.test(text[index])) index += 1; };
  function parseString() {
    if (text[index] !== '"') parseError('expected string');
    index += 1;
    let value = '';
    while (index < text.length) {
      const character = text[index++];
      if (character === '"') return value;
      if (character === '\\') {
        if (index >= text.length) parseError('unterminated escape');
        const escaped = text[index++];
        const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (Object.prototype.hasOwnProperty.call(simple, escaped)) value += simple[escaped];
        else if (escaped === 'u') {
          const hex = text.slice(index, index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) parseError('invalid unicode escape');
          value += String.fromCharCode(Number.parseInt(hex, 16));
          index += 4;
        } else parseError('invalid escape');
      } else {
        if (character < ' ') parseError('control character in string');
        value += character;
      }
    }
    parseError('unterminated string');
  }
  function parseValue() {
    skipWhitespace();
    const character = text[index];
    if (character === '{') return parseObject();
    if (character === '[') return parseArray();
    if (character === '"') { parseString(); return; }
    for (const literal of ['true', 'false', 'null']) {
      if (text.slice(index, index + literal.length) === literal) { index += literal.length; return; }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (number) { index += number[0].length; return; }
    parseError('expected value');
  }
  function parseObject() {
    index += 1;
    skipWhitespace();
    const keys = new Set();
    if (text[index] === '}') { index += 1; return; }
    while (index < text.length) {
      skipWhitespace();
      const key = parseString();
      if (keys.has(key)) fail(`${location}: duplicate JSON field ${JSON.stringify(key)}`);
      keys.add(key);
      skipWhitespace();
      if (text[index++] !== ':') parseError('expected colon');
      parseValue();
      skipWhitespace();
      if (text[index] === '}') { index += 1; return; }
      if (text[index++] !== ',') parseError('expected comma');
    }
    parseError('unterminated object');
  }
  function parseArray() {
    index += 1;
    skipWhitespace();
    if (text[index] === ']') { index += 1; return; }
    while (index < text.length) {
      parseValue();
      skipWhitespace();
      if (text[index] === ']') { index += 1; return; }
      if (text[index++] !== ',') parseError('expected comma');
    }
    parseError('unterminated array');
  }
  skipWhitespace();
  parseValue();
  skipWhitespace();
  if (index !== text.length) parseError('trailing data');
}

function parseJson(filename) {
  let parsed;
  try {
    const text = fs.readFileSync(filename, 'utf8');
    rejectDuplicateJsonKeys(text, filename);
    parsed = JSON.parse(text);
  }
  catch (error) { fail(`${filename}: invalid JSON (${error.message})`); }
  return parsed;
}

function currentSource() {
  const runGit = (args) => {
    const result = spawnSync('git', args, { cwd: repositoryRoot, encoding: 'utf8' });
    if (result.status !== 0) fail(`source: git ${args.join(' ')} failed`);
    return result.stdout;
  };
  return {
    commit: runGit(['rev-parse', 'HEAD']).trim(),
    dirtyDigest: crypto.createHash('sha256').update(runGit(['status', '--porcelain=v1', '-uall'])).digest('hex'),
  };
}

function validateSourceBinding(source, location) {
  object(source, `${location}.source`);
  const commit = source.commit;
  const dirtyDigest = source.dirtyDigest ?? source.dirty_digest;
  string(commit, `${location}.source.commit`);
  if (!sha256Pattern.test(dirtyDigest ?? '')) fail(`${location}.source.dirtyDigest: invalid SHA-256`);
  const expected = currentSource();
  if (commit !== expected.commit) fail(`${location}.source.commit: expected current ${expected.commit}`);
  if (dirtyDigest !== expected.dirtyDigest) fail(`${location}.source.dirtyDigest: does not match current working tree`);
}

function validateReleaseGroup(group, root) {
  const required = releaseGroups.get(group);
  if (!required) fail(`release group: unknown ${JSON.stringify(group)}`);
  const parsed = new Map();
  for (const relative of required) {
    const filename = path.join(root, relative);
    if (!fs.existsSync(filename)) fail(`release group=${group}: missing ${filename}`);
    const bytes = fs.readFileSync(filename);
    if (bytes.length === 0) fail(`release group=${group}: empty ${filename}`);
    if (relative.endsWith('.json')) {
      const receipt = parseJson(filename);
      object(receipt, filename);
      if ((receipt.schemaVersion ?? receipt.schema_version) !== 1) fail(`${filename}: unsupported receipt schema`);
      if ((receipt.verdict ?? receipt.status) !== 'pass') fail(`${filename}: receipt is not passing`);
      validateSourceBinding(receipt.source, filename);
      parsed.set(relative, receipt);
    } else if (relative.endsWith('.png')) {
      if (bytes.length < 8 || bytes.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') fail(`${filename}: invalid PNG receipt`);
    }
  }
  if (group === 'compatibility') {
    const previousPath = path.join(root, 'compatibility/previous-binary-evidence.json');
    const previous = parsed.get('compatibility/previous-binary-evidence.json');
    if (!sha256Pattern.test(previous.binarySha256 ?? '') || !Number.isInteger(previous.currentSchemaVersion) || previous.currentSchemaVersion < 1) fail(`${previousPath}: invalid retained-binary binding`);
    string(previous.retainedBinaryVersion, `${previousPath}.retainedBinaryVersion`);
    const previousHash = crypto.createHash('sha256').update(fs.readFileSync(previousPath)).digest('hex');
    for (const relative of ['compatibility/legacy-projection.json', 'compatibility/residue-drain.json']) {
      if (parsed.get(relative).previousBinaryEvidenceSha256 !== previousHash) fail(`${path.join(root, relative)}: previous-binary evidence hash mismatch`);
    }
  } else if (group === 'devices') {
    for (const platform of ['ios', 'android', 'harmonyos']) {
      const relative = `devices/${platform}/device-receipt.json`;
      const receipt = parsed.get(relative);
      if (receipt.platform !== platform || receipt.deviceClass !== 'physical') fail(`${path.join(root, relative)}: receipt is not a physical ${platform} device`);
      const screenshot = fs.readFileSync(path.join(root, `devices/${platform}/visible-readiness.png`));
      if (receipt.visibleReadinessSha256 !== crypto.createHash('sha256').update(screenshot).digest('hex')) fail(`${path.join(root, relative)}: readiness screenshot hash mismatch`);
    }
  } else {
    const relative = 'live-media/live-media-receipt.json';
    const receipt = parsed.get(relative);
    const output = fs.readFileSync(path.join(root, 'live-media/output.log'));
    if (receipt.outputSha256 !== crypto.createHash('sha256').update(output).digest('hex')) fail(`${path.join(root, relative)}: output hash mismatch`);
    object(receipt.stack, `${path.join(root, relative)}.stack`);
    for (const component of ['livekit', 'opus', 'funasr']) string(receipt.stack[component], `${path.join(root, relative)}.stack.${component}`);
  }
  console.log(`architecture-r3 ${group} evidence: PASS (${required.length} artifacts)`);
}

function validateLaneManifest(manifest, filename) {
  object(manifest, filename);
  if (manifest.schemaVersion !== 1 || typeof manifest.lane !== 'string') fail(`${filename}: invalid lane manifest`);
  if (!['verdict', 'self-test'].includes(manifest.mode) || manifest.verdict !== 'pass' || manifest.diagnosticCode !== null) fail(`${filename}: lane manifest is not passing`);
  validateSourceBinding(manifest.source, filename);
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) fail(`${filename}: missing cases`);
  const directory = path.dirname(path.resolve(filename));
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) fail(`${filename}: missing artifacts`);
  for (const artifact of manifest.artifacts) {
    relativePath(artifact?.path, `${filename}.artifacts.path`);
    if (!sha256Pattern.test(artifact?.sha256 ?? '')) fail(`${filename}: invalid artifact hash`);
    const artifactFile = path.resolve(directory, artifact.path);
    if (!artifactFile.startsWith(`${directory}${path.sep}`) || !fs.existsSync(artifactFile)) fail(`${filename}: missing artifact ${artifact.path}`);
    const actual = crypto.createHash('sha256').update(fs.readFileSync(artifactFile)).digest('hex');
    if (actual !== artifact.sha256) fail(`${filename}: artifact hash mismatch ${artifact.path}`);
  }
  console.log(`architecture-r3 lane evidence: PASS (${manifest.lane}/${manifest.mode})`);
}

function validateBenchmark(result, filename) {
  object(result, filename);
  if (result.schemaVersion !== 1 || result.verdict !== 'pass') fail(`${filename}: benchmark is not passing schema v1`);
  if (!Number.isInteger(result.expectedSamples) || result.expectedSamples < 1 || result.recordedSamples !== result.expectedSamples) fail(`${filename}: incomplete sample population`);
  if (!Number.isInteger(result.warmupCount) || result.warmupCount < 0) fail(`${filename}: invalid warmup count`);
  validateSourceBinding(result.fingerprint, `${filename}.fingerprint`);
  string(result.fingerprint.populationKey, `${filename}.fingerprint.populationKey`);
  if (!Array.isArray(result.samples) || result.samples.length !== result.expectedSamples) fail(`${filename}: sample count mismatch`);
  const ordinals = result.samples.map((entry) => entry.ordinal);
  unique(ordinals, `${filename}.samples.ordinals`);
  for (const entry of result.samples) {
    if (!Number.isInteger(entry.ordinal) || !Number.isInteger(entry.durationMs) || entry.durationMs < 0 || entry.verdict !== 'pass' || entry.populationKey !== result.fingerprint.populationKey) fail(`${filename}: malformed, failed, or mixed-fingerprint sample`);
  }
  const durations = result.samples.map((entry) => entry.durationMs).sort((left, right) => left - right);
  const index = Math.ceil(0.95 * durations.length);
  const p95 = durations[index - 1];
  if (result.formula?.name !== 'nearest-rank' || result.formula?.p95Index !== index || result.metrics?.p95DurationMs !== p95 || result.metrics?.maxDurationMs !== Math.max(...durations)) fail(`${filename}: invalid timing formula or aggregate`);
  if (p95 > 300000) fail(`${filename}: p95 ${p95}ms exceeds 300000ms`);
  if (result.qualification === 'scheduled_p95' && (result.expectedSamples !== 20 || result.warmupCount !== 2)) fail(`${filename}: scheduled p95 requires 2 warmups and 20 samples`);
  if (!Array.isArray(result.artifacts) || result.artifacts.length !== result.expectedSamples * 2) fail(`${filename}: incomplete sample artifact set`);
  const directory = path.dirname(path.resolve(filename));
  for (const artifact of result.artifacts) {
    relativePath(artifact.path, `${filename}.artifacts.path`);
    const absolute = path.resolve(directory, artifact.path);
    if (!absolute.startsWith(`${directory}${path.sep}`) || !fs.existsSync(absolute)) fail(`${filename}: missing sample artifact ${artifact.path}`);
    if (crypto.createHash('sha256').update(fs.readFileSync(absolute)).digest('hex') !== artifact.sha256) fail(`${filename}: sample artifact hash mismatch ${artifact.path}`);
  }
  console.log(`architecture-r3 benchmark evidence: PASS (${result.recordedSamples} samples; p95=${p95}ms)`);
}

function validateRegistry(registry) {
  exactKeys(registry, 'registry', new Set(['schema_version', 'registry_version', 'program', 'authority', 'cases']));
  if (registry.schema_version !== 1 || registry.registry_version !== 1) fail('registry: unsupported version');
  string(registry.program, 'registry.program');
  relativePath(registry.authority, 'registry.authority');
  if (!Array.isArray(registry.cases) || registry.cases.length === 0) fail('registry.cases: expected non-empty array');
  const ids = [];
  const byId = new Map();
  for (const [index, entry] of registry.cases.entries()) {
    const location = `registry.cases[${index}]`;
    exactKeys(entry, location, caseKeys);
    if (!caseIdPattern.test(entry.case_id)) fail(`${location}.case_id: invalid`);
    if (entry.workstream !== entry.case_id.split('-')[2]) fail(`${location}.workstream: does not match case ID`);
    for (const key of ['owner', 'command', 'required_environment', 'mutation_boundary']) string(entry[key], `${location}.${key}`);
    if (!entry.command.startsWith('bash scripts/verify-architecture-r3.sh ')) fail(`${location}.command: must use the architecture R3 front door`);
    if (!Number.isInteger(entry.timeout_seconds) || entry.timeout_seconds < 1 || entry.timeout_seconds > 3600) fail(`${location}.timeout_seconds: invalid`);
    if (!Array.isArray(entry.required_artifacts) || entry.required_artifacts.length === 0) fail(`${location}.required_artifacts: expected non-empty array`);
    for (const [artifactIndex, artifact] of entry.required_artifacts.entries()) relativePath(artifact, `${location}.required_artifacts[${artifactIndex}]`);
    unique(entry.required_artifacts, `${location}.required_artifacts`);
    if (!gates.has(entry.release_gate)) fail(`${location}.release_gate: invalid`);
    ids.push(entry.case_id);
    byId.set(entry.case_id, entry);
  }
  unique(ids, 'registry case IDs');
  return byId;
}

function validateResult(result, registry, gate, resultFile) {
  exactKeys(result, 'result', new Set(['schema_version', 'registry_version', 'source', 'environment', 'started_at', 'ended_at', 'cases']));
  if (result.schema_version !== 1 || result.registry_version !== 1) fail('result: unsupported version');
  exactKeys(result.source, 'result.source', new Set(['commit', 'dirty_digest']));
  string(result.source.commit, 'result.source.commit');
  if (!sha256Pattern.test(result.source.dirty_digest)) fail('result.source.dirty_digest: invalid SHA-256');
  const expectedSource = currentSource();
  if (result.source.commit !== expectedSource.commit) fail(`result.source.commit: expected current ${expectedSource.commit}`);
  if (result.source.dirty_digest !== expectedSource.dirtyDigest) fail('result.source.dirty_digest: does not match current working tree');
  exactKeys(result.environment, 'result.environment', new Set(['host', 'tools']));
  string(result.environment.host, 'result.environment.host');
  object(result.environment.tools, 'result.environment.tools');
  for (const [tool, version] of Object.entries(result.environment.tools)) { string(tool, 'result.environment.tools key'); string(version, `result.environment.tools.${tool}`); }
  for (const key of ['started_at', 'ended_at']) if (!Number.isFinite(Date.parse(result[key]))) fail(`result.${key}: invalid timestamp`);
  if (Date.parse(result.ended_at) < Date.parse(result.started_at)) fail('result: ended before start');
  if (!Array.isArray(result.cases)) fail('result.cases: expected array');
  const seen = new Set();
  const resultDirectory = path.dirname(path.resolve(resultFile));
  for (const [index, entry] of result.cases.entries()) {
    const location = `result.cases[${index}]`;
    exactKeys(entry, location, new Set(['case_id', 'verdict', 'missing_reason', 'artifacts']));
    if (!registry.has(entry.case_id)) fail(`${location}.case_id: unknown ${JSON.stringify(entry.case_id)}`);
    if (seen.has(entry.case_id)) fail(`${location}.case_id: duplicate ${JSON.stringify(entry.case_id)}`);
    seen.add(entry.case_id);
    if (!verdicts.has(entry.verdict)) fail(`${location}.verdict: invalid`);
    string(entry.missing_reason, `${location}.missing_reason`);
    if (entry.verdict === 'passed' && entry.missing_reason !== 'none') fail(`${location}: passed case must use missing_reason=none`);
    if (entry.verdict !== 'passed' && entry.missing_reason === 'none') fail(`${location}: non-passing case must explain missing evidence`);
    if (!Array.isArray(entry.artifacts)) fail(`${location}.artifacts: expected array`);
    const artifactNames = new Set();
    for (const [artifactIndex, artifact] of entry.artifacts.entries()) {
      const artifactLocation = `${location}.artifacts[${artifactIndex}]`;
      exactKeys(artifact, artifactLocation, new Set(['path', 'sha256']));
      relativePath(artifact.path, `${artifactLocation}.path`);
      if (!sha256Pattern.test(artifact.sha256)) fail(`${artifactLocation}.sha256: invalid`);
      if (artifactNames.has(artifact.path)) fail(`${artifactLocation}.path: duplicate`);
      artifactNames.add(artifact.path);
      const absoluteArtifact = path.resolve(resultDirectory, artifact.path);
      if (!absoluteArtifact.startsWith(`${resultDirectory}${path.sep}`)) fail(`${artifactLocation}.path: escapes result directory`);
      if (!fs.existsSync(absoluteArtifact)) fail(`${artifactLocation}.path: missing artifact`);
      const actual = crypto.createHash('sha256').update(fs.readFileSync(absoluteArtifact)).digest('hex');
      if (actual !== artifact.sha256) fail(`${artifactLocation}.sha256: hash mismatch`);
    }
    if (entry.verdict === 'passed') {
      for (const required of registry.get(entry.case_id).required_artifacts) if (!artifactNames.has(required)) fail(`${location}: missing required artifact ${JSON.stringify(required)}`);
    }
  }
  const requiredCases = [...registry.values()].filter((entry) => gate === 'release' || entry.release_gate === 'merge');
  for (const entry of requiredCases) {
    if (!seen.has(entry.case_id)) fail(`gate=${gate}: missing result for ${entry.case_id}`);
    const resultEntry = result.cases.find((candidate) => candidate.case_id === entry.case_id);
    if (resultEntry.verdict !== 'passed') fail(`gate=${gate}: ${entry.case_id} is ${resultEntry.verdict} (${resultEntry.missing_reason})`);
  }
}

function run(argumentsList) {
  const registryFile = argumentsList.shift();
  if (!registryFile) fail('usage: check-architecture-r3-evidence.mjs REGISTRY [RESULT --gate merge|release | --release-group GROUP ROOT | --lane-manifest FILE]');
  const registry = validateRegistry(parseJson(registryFile));
  if (argumentsList[0] === '--release-group') {
    if (argumentsList.length !== 3) fail('invalid arguments');
    validateReleaseGroup(argumentsList[1], path.resolve(argumentsList[2]));
    return;
  }
  if (argumentsList[0] === '--lane-manifest') {
    if (argumentsList.length !== 2) fail('invalid arguments');
    validateLaneManifest(parseJson(argumentsList[1]), argumentsList[1]);
    return;
  }
  if (argumentsList[0] === '--benchmark') {
    if (argumentsList.length !== 2) fail('invalid arguments');
    validateBenchmark(parseJson(argumentsList[1]), argumentsList[1]);
    return;
  }
  if (argumentsList.length === 0) {
    console.log(`architecture-r3 evidence registry: PASS (${registry.size} exact cases)`);
    return;
  }
  const resultFile = argumentsList.shift();
  let gate = 'merge';
  if (argumentsList.length > 0) {
    if (argumentsList.length !== 2 || argumentsList[0] !== '--gate' || !gates.has(argumentsList[1])) fail('invalid arguments');
    gate = argumentsList[1];
  }
  validateResult(parseJson(resultFile), registry, gate, resultFile);
  console.log(`architecture-r3 evidence: PASS (gate=${gate})`);
}

try {
  run(process.argv.slice(2));
} catch (error) {
  console.error(error.message);
  process.exitCode = error.message.includes('usage:') || error.message.includes('invalid arguments') ? 2 : 1;
}
