#!/usr/bin/env node
// Bind a completed generation to case receipts without rewriting its evidence.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { readRetainedE6Generation, E6_RUNTIME_CASE_GATES as cases } from './run-connectivity-e6-harness.mjs';
export { readRetainedE6Generation as readGeneration } from './run-connectivity-e6-harness.mjs';
import { validateE6ProfileDocument } from './check-connectivity-aware-sync-cases.mjs';

const root = path.resolve(import.meta.dirname, '..');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function consumeGeneration({ generation, expectedDigest, caseId, outputRoot = root }) {
  if (caseId) assert.ok(cases.has(caseId), `unsupported retained-generation case ${caseId}`);
  const { aggregate, profile, checks, profileQualified, evidenceFiles } = readRetainedE6Generation(generation, expectedDigest);
  validateE6ProfileDocument(profile.document);
  if (process.env.RUN_ID) assert.equal(process.env.RUN_ID, aggregate.runId, 'RUN_ID must match the retained generation');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'docs/verification/connectivity-aware-sync-cases.json')));
  const results = [];
  const runId = aggregate.runId;
  const relativeDirectory = `test-results/connectivity-aware-sync/${runId}/e6`;
  const finalDirectory = path.join(outputRoot, relativeDirectory);
  const resultPath = path.join(finalDirectory, `results${caseId ? '-' + caseId : ''}.json`);
  const existingIndex = path.join(finalDirectory, 'results.json');
  const utcTime = fs.existsSync(existingIndex) ? JSON.parse(fs.readFileSync(existingIndex)).utcTime : new Date().toISOString();
  const planned = [];
  for (const [id, gate] of cases) {
    const entry = manifest.cases.find(item => item.id === id);
    const binding = manifest.evidenceRegistry.find(item => item.caseId === id);
    assert.ok(entry && binding);
    assert.equal(entry.fixtureDigest, profile.digest, 'current case fixture differs; retain this generation as history, never rebind it to a newer profile');
    assert.equal(digest(fs.readFileSync(path.join(root, entry.fixture))), profile.digest);
    assert.ok(entry.requiredProfiles.includes(profile.selected.profileId));
    const status = aggregate.verdict[gate].pass ? 'passed' : 'failed';
    const retainedArtifacts = entry.retainedArtifacts.map(item => item.replaceAll('<run-id>', runId));
    const detail = `${gate}: ${status}; profile qualification ${profileQualified ? 'matched' : 'unavailable (exact host product/build not established)'}; overall ${aggregate.verdict.overallPass ? 'PASS' : 'FAIL'}; unavailable class claims: ${aggregate.verdict.claimsUnavailableClasses.join(', ') || 'none'}`;
    const receipt = {
      schemaVersion: 1, caseId: id, status, lane: 'core', runId, utcTime,
      fixture: entry.fixture, fixtureDigest: profile.digest, seed: entry.seed,
      observations: { aggregatePath: `${relativeDirectory}/generation/aggregate.json`, aggregateSha256: expectedDigest, source: aggregate.seal.git, harness: aggregate.seal.harness, profile: aggregate.profile, profileQualified, schemaAssertions: checks, gate: aggregate.verdict[gate], overallPass: aggregate.verdict.overallPass, claimsUnavailableClasses: aggregate.verdict.claimsUnavailableClasses, pairDocDigests: aggregate.seal.pairDocDigests },
    };
    for (const artifact of retainedArtifacts) {
      assert.ok(artifact.startsWith(`test-results/connectivity-aware-sync/${runId}/e6/`));
      assert.ok(!artifact.split('/').includes('..'));
      planned.push([path.join(outputRoot, artifact), receipt]);
    }
    results.push({ caseId: id, status, resultId: binding.resultId, lane: 'core', retainedArtifacts, detail });
  }
  const index = { schemaVersion: 1, results, runId, utcTime };
  planned.push([existingIndex, index]);
  for (const result of results) {
    planned.push([path.join(finalDirectory, `results-${result.caseId}.json`), { ...index, results: [result] }]);
  }
  const files = [
    ...evidenceFiles.map(([relative, bytes]) => [path.join('generation', relative), bytes]),
    ...planned.map(([file, value]) => [path.relative(finalDirectory, file), JSON.stringify(value, null, 2) + '\n']),
  ];
  // Publish a complete directory with one rename. The lock serializes consumers;
  // failure removes only this call's staging directory, so retry is safe. Existing
  // output is accepted only byte-for-byte, never replaced or repaired in place.
  const parent = path.dirname(finalDirectory);
  fs.mkdirSync(parent, { recursive: true });
  const lock = path.join(parent, '.e6-consumer-lock');
  fs.mkdirSync(lock);
  const staging = path.join(parent, `.e6-consumer-${randomUUID()}`);
  try {
    if (fs.existsSync(finalDirectory)) {
      for (const [relative, bytes] of files) {
        assert.deepEqual(fs.readFileSync(path.join(finalDirectory, relative)), Buffer.from(bytes), `existing receipt/evidence differs: ${relative}`);
      }
    } else {
      fs.mkdirSync(staging);
      for (const [relative, bytes] of files) {
        const file = path.join(staging, relative);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, bytes, { flag: 'wx' });
      }
      assert.ok(!fs.existsSync(finalDirectory), 'receipt directory appeared during publication');
      fs.renameSync(staging, finalDirectory);
    }
  } finally {
    if (fs.existsSync(staging)) fs.rmSync(staging, { recursive: true });
    fs.rmdirSync(lock);
  }
  const selectedResults = caseId ? results.filter(item => item.caseId === caseId) : results;
  return { runId, results: selectedResults, resultPath, profileQualified, pass: profileQualified && selectedResults.every(item => item.status === 'passed') };

}

if (import.meta.main) {
  try {
    const args = process.argv.slice(2);
    assert.ok(args.length === 2 || (args.length === 4 && args[2] === '--case'), 'usage: consume-connectivity-e6-results.mjs GENERATION AGGREGATE_SHA256 [--case ID]');
    const result = consumeGeneration({ generation: path.resolve(args[0]), expectedDigest: args[1], caseId: args[3] });
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.pass ? 0 : 3;
  } catch (error) {
    console.error(`E6 receipt binding: ${error.message}`);
    process.exitCode = 1;
  }
}
