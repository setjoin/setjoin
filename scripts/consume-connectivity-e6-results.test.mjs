// Retained-evidence integration test. Supply an actual completed generation and
// its independently recorded digest; absence is an error, never a skipped pass.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { readGeneration, consumeGeneration } from './consume-connectivity-e6-results.mjs';
import { validateManifest, validateResults } from './check-connectivity-aware-sync-cases.mjs';

const [generation, expectedDigest, evidenceRoot] = process.argv.slice(2);
assert.ok(generation && expectedDigest && evidenceRoot, 'usage: test.mjs GENERATION SHA256 OWNED_EVIDENCE_ROOT');
const sha = value => createHash('sha256').update(value).digest('hex');
const temp = path.join(evidenceRoot, `e6-consumer-${randomUUID()}`);
const ledger = path.join(evidenceRoot, 'e6-consumer-test-resource.json');
fs.writeFileSync(ledger, JSON.stringify({ path: temp, preexisting: false, owner: 'root', purpose: 'retained E6 consumption/tamper proof', state: 'planned' }, null, 2));
fs.mkdirSync(temp);
try {
  const checked = readGeneration(generation, expectedDigest);
  assert.equal(checked.aggregate.verdict.overallPass, false);
  assert.equal(checked.aggregate.verdict.failedRequestAccounting.pass, true);
  assert.equal(checked.profileQualified, false, 'legacy run lacks exact product/build proof');
  const bound = consumeGeneration({ generation, expectedDigest, outputRoot: temp });
  assert.equal(bound.pass, false);
  assert.deepEqual(bound.results.map(item => item.status), ['failed', 'failed', 'passed', 'failed']);
  assert.match(bound.results[1].detail, /unavailable class claims: queued-send/);
  assert.ok(bound.results.every(item => item.caseId !== 'CAS-E6-PROFILE-FROZEN'));
  const originalReceipt = fs.readFileSync(bound.resultPath);
  assert.equal(consumeGeneration({ generation, expectedDigest, outputRoot: temp }).resultPath, bound.resultPath, 'identical repeat returns immutable publication');
  assert.deepEqual(fs.readFileSync(bound.resultPath), originalReceipt, 'rerun cannot overwrite receipt');
  const repo = path.resolve(import.meta.dirname, '..');
  const manifest = JSON.parse(fs.readFileSync(path.join(repo, 'docs/verification/connectivity-aware-sync-cases.json')));
  const manifestInfo = validateManifest(manifest);
  const accountingId = 'CAS-E6-FAILED-REQUEST-ACCOUNTING';
  const accounting = bound.results.find(item => item.caseId === accountingId);
  const receiptPath = path.join(temp, accounting.retainedArtifacts[0]);
  const originalAccounting = fs.readFileSync(receiptPath);
  const fixture = JSON.parse(originalAccounting).fixture;
  fs.mkdirSync(path.dirname(path.join(temp, fixture)), { recursive: true });
  fs.copyFileSync(path.join(repo, fixture), path.join(temp, fixture));
  const accountingResults = { ...JSON.parse(originalReceipt), results: [accounting] };
  const validateAccounting = () => validateResults(accountingResults, manifestInfo, accountingId, temp);
  assert.throws(validateAccounting, /exact host\/profile qualification/);
  const receiptMutant = (edit, pattern) => {
    const receipt = JSON.parse(originalAccounting);
    edit(receipt);
    fs.writeFileSync(receiptPath, JSON.stringify(receipt));
    assert.throws(validateAccounting, pattern);
    fs.writeFileSync(receiptPath, originalAccounting);
  };
  receiptMutant(r => { r.observations.profileQualified = true; }, /observations differ/);
  receiptMutant(r => { r.observations.gate = checked.aggregate.verdict.pairedRegression; }, /observations differ/);
  receiptMutant(r => { r.observations.source.head = 'f'.repeat(40); }, /observations differ/);
  receiptMutant(r => { r.observations.aggregateSha256 = '0'.repeat(64); }, /retained digest/);
  receiptMutant(r => { r.observations.aggregatePath = 'other/aggregate.json'; }, /must belong to this run/);
  const publishedAggregate = path.join(temp, JSON.parse(originalAccounting).observations.aggregatePath);
  fs.renameSync(publishedAggregate, publishedAggregate + '.saved');
  assert.throws(validateAccounting, /ENOENT/);
  fs.renameSync(publishedAggregate + '.saved', publishedAggregate);
  // A failed gate cannot become evidence by swapping in the passing accounting gate.
  const floor = bound.results[0];
  const floorPath = path.join(temp, floor.retainedArtifacts[0]);
  const originalFloor = fs.readFileSync(floorPath);
  const floorReceipt = JSON.parse(originalFloor);
  floorReceipt.status = 'passed'; floorReceipt.observations.gate = checked.aggregate.verdict.failedRequestAccounting;
  fs.writeFileSync(floorPath, JSON.stringify(floorReceipt));
  assert.throws(() => validateResults({ ...accountingResults, results: [{ ...floor, status: 'passed' }] }, manifestInfo, floor.caseId, temp), /observations differ/);
  fs.writeFileSync(floorPath, originalFloor);
  // Deterministic storage failure after a receipt has actually been written to
  // staging must expose no final generation and leave retry usable.
  const failureRoot = path.join(temp, 'write-failure');
  const write = fs.writeFileSync;
  let injected = false;
  try {
    fs.writeFileSync = function(file, ...args) {
      const result = write.call(this, file, ...args);
      if (String(file).includes('.e6-consumer-') && String(file).endsWith('/critical-sample-floor.json')) {
        injected = true; throw new Error('injected storage failure after first receipt');
      }
      return result;
    };
    assert.throws(() => consumeGeneration({ generation, expectedDigest, outputRoot: failureRoot }), /injected storage failure/);
  } finally { fs.writeFileSync = write; }
  assert.equal(injected, true);
  const failedRun = path.join(failureRoot, `test-results/connectivity-aware-sync/${bound.runId}`);
  assert.deepEqual(fs.readdirSync(failedRun), [], 'no partial final directory, lock or staging survives write error');
  const recovered = consumeGeneration({ generation, expectedDigest, outputRoot: failureRoot });
  assert.equal(recovered.pass, false);
  assert.deepEqual(fs.readFileSync(receiptPath), originalAccounting, 'existing publication was untouched');
  const failedReceipt = path.join(failureRoot, accounting.retainedArtifacts[0]);
  fs.appendFileSync(failedReceipt, ' ');
  assert.throws(() => consumeGeneration({ generation, expectedDigest, outputRoot: failureRoot }), /existing receipt\/evidence differs/);
  assert.ok(fs.readFileSync(failedReceipt, 'utf8').endsWith(' '), 'changed existing data is never overwritten');
  assert.throws(() => readGeneration(generation, '0'.repeat(64)), /retained digest/);
  const copy = path.join(temp, 'mutated');
  fs.cpSync(generation, copy, { recursive: true });
  const originalAggregate = fs.readFileSync(path.join(copy, 'aggregate.json'));
  const mutate = (edit, pattern) => {
    const value = JSON.parse(originalAggregate);
    edit(value);
    const bytes = JSON.stringify(value);
    fs.writeFileSync(path.join(copy, 'aggregate.json'), bytes);
    assert.throws(() => readGeneration(copy, sha(bytes)), pattern);
  };
  mutate(value => { value.kind = 'e6-harness-smoke'; }, /smoke\/partial/);
  mutate(value => { value.pairs.pop(); }, /incomplete pair/);
  mutate(value => { value.pairs[0].docPath = '../outside.json'; }, /canonical in-generation/);
  mutate(value => { value.seal.seeds.run = 'post-result-seed'; }, /Expected values/);
  mutate(value => { value.verdict.overallPass = true; }, /recorded verdict/);
  fs.writeFileSync(path.join(copy, 'aggregate.json'), originalAggregate);
  const qualified = JSON.parse(originalAggregate);
  qualified.binding.host.profileOS = checked.profile.selected.host.os;
  const qualifiedBytes = JSON.stringify(qualified);
  fs.writeFileSync(path.join(copy, 'aggregate.json'), qualifiedBytes);
  const positiveRoot = path.join(temp, 'synthetic-qualified-control');
  const positive = consumeGeneration({ generation: copy, expectedDigest: sha(qualifiedBytes), caseId: accountingId, outputRoot: positiveRoot });
  assert.equal(positive.pass, true, 'synthetic selected accounting gate positive control');
  fs.mkdirSync(path.dirname(path.join(positiveRoot, fixture)), { recursive: true });
  fs.copyFileSync(path.join(repo, fixture), path.join(positiveRoot, fixture));
  validateResults(JSON.parse(fs.readFileSync(positive.resultPath)), manifestInfo, accountingId, positiveRoot);
  fs.writeFileSync(path.join(copy, 'aggregate.json'), originalAggregate);
  fs.appendFileSync(path.join(copy, 'pairs/pair-01.json'), '\n');
  assert.throws(() => readGeneration(copy, expectedDigest), /Expected values/);
  assert.equal(sha(fs.readFileSync(path.join(generation, 'aggregate.json'))), expectedDigest, 'original evidence unchanged');
  console.log('E6 retained consumption: PASS (four honest outcomes, unqualified host retained, atomic recoverable publication, immutable receipts, full-checker receipt-only tampering refused, synthetic qualified control, digest/seed/pair/path/verdict tampering refused)');
} finally {
  fs.rmSync(temp, { recursive: true });
  fs.writeFileSync(ledger, JSON.stringify({ path: temp, owner: 'root', state: fs.existsSync(temp) ? 'cleanup-failed' : 'removed', originalEvidence: 'retained unchanged' }, null, 2));
}
