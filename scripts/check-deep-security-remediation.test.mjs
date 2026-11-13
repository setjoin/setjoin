import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { readEr3Contract, validateEr3Row } from './check-deep-security-remediation.mjs';

const artifactURL = new URL('../docs/verification/deep-security-remediation-transitions.json', import.meta.url);
const artifact = JSON.parse(fs.readFileSync(artifactURL, 'utf8'));
const grammarErrors = [];
const grammar = readEr3Contract(grammarErrors, artifact);
assert.deepEqual(grammarErrors, []);

// Independent contract examples: SEC-DP1 A–E and remediation-quickstart §5.
// These literal states/expectations are not calculated from the grammar under
// test. Go's TestSerializedTransitionProof separately supplies real wire output.
const state = (disposition, localStatus, verificationStatus, releaseStatus = 'not_ready') => ({ disposition, localStatus, verificationStatus, releaseStatus });
const open = state('blocked', 'unmapped', 'none');
const traced = state('blocked', 'traced', 'none');
const fixed = state('fixed', 'proof_patched', 'receipt_bound');
const blocked = state('blocked', 'blocked', 'none');
const opening = '2026-09-22T00:00:00Z';
const closing = '2026-09-22T00:01:00Z';
const evidenceManifest = 'test-results/er3/independent-proof.json';
const transition = (op, from, to, at, extra = {}) => ({
  op, contract: 'setjoin.sec.security-program-remediation/v1',
  occurrenceId: 'occ_independent', attemptId: 'attempt-1', runId: 'run-1',
  authority: 'service_role', from: structuredClone(from), to: structuredClone(to), at, ...extra,
});
const example = (outcome = 'fixed') => {
  const noChange = outcome === 'no_change';
  const from = noChange ? state('blocked', 'no_change_candidate', 'none') : open;
  const started = noChange ? from : traced;
  const end = outcome === 'active' ? started : outcome === 'rejected' ? blocked : state(outcome, 'proof_patched', 'receipt_bound');
  const transitions = [transition('start', from, started, opening)];
  if (outcome === 'rejected') transitions.push(transition('reject', started, end, closing, { reason: 'independent bypass test remains red' }));
  else if (outcome !== 'active') transitions.push(transition('complete', started, end, closing, { evidenceManifest, evidenceSha256: 'a'.repeat(64) }));
  return {
    occurrenceId: 'occ_independent', ...end,
    closurePatch: { trigger: 'trigger proof', legitimate: 'legitimate proof', bypass: 'bypass proof' },
    tests: ['independent trigger, legitimate and bypass test'], evidence: { manifest: evidenceManifest },
    remediation: { attemptId: 'attempt-1', runId: 'run-1', state: outcome === 'active' ? 'active' : outcome === 'rejected' ? 'rejected' : 'completed', openedAt: opening, ...(outcome === 'active' ? {} : { closedAt: closing }) },
    remediationTransitions: transitions,
  };
};
const errorsFor = (row) => {
  const errors = [];
  validateEr3Row(errors, row, grammar);
  return errors;
};

test('direct and symlink CLI entry points retain help while imports remain inert', (t) => {
  const checker = fileURLToPath(new URL('./check-deep-security-remediation.mjs', import.meta.url));
  const temp = fs.mkdtempSync(path.join(tmpdir(), 'er3-entry-'));
  t.after(() => fs.rmSync(temp, { recursive: true }));
  const alias = path.join(temp, 'check.mjs');
  fs.symlinkSync(checker, alias);
  for (const filename of [checker, alias]) {
    assert.match(execFileSync(process.execPath, [filename, '--help'], { encoding: 'utf8', timeout: 10000 }), /usage: node scripts\/check-deep-security-remediation.mjs/);
  }
});

for (const outcome of ['active', 'fixed', 'no_change', 'rejected']) {
  test(`independent valid ${outcome} history`, () => assert.deepEqual(errorsFor(example(outcome)), []));
}

test('forbidden enum-valid first start fails only its two named pre-state constraints', () => {
  const row = example('active');
  for (const value of [row, row.remediationTransitions[0].from, row.remediationTransitions[0].to]) {
    value.disposition = 'fixed';
    value.verificationStatus = 'receipt_bound';
  }
  assert.deepEqual(errorsFor(row).map(({ rule }) => rule).sort(), ['start.from.disposition', 'start.from.verificationStatus']);
});

// Start-output preservation: each state axis mutated on the start row's `to`
// must refuse with EXACTLY its named rule and no dependent continuity or
// terminal-row diagnosis. The active history has a single transition, and the
// row's own final state is aligned with the mutated axis so the terminal-row
// check cannot mask the isolated refusal.
for (const [axis, value, rule] of [
  ['localStatus', 'unmapped', 'start.to.localStatus'],
  ['releaseStatus', 'release_ready', 'start.to.releaseStatus'],
  ['disposition', 'fixed', 'start.to.disposition'],
  ['verificationStatus', 'receipt_bound', 'start.to.verificationStatus'],
]) {
  test(`start preserves its ${axis} axis in isolation`, () => {
    const row = example('active');
    row.remediationTransitions[0].to[axis] = value;
    row[axis] = value;
    assert.deepEqual(errorsFor(row).map(({ rule }) => rule), [rule]);
  });
}

// Each mutant is independently expected to violate a named rule, even when a
// dependent final-state/continuity check also diagnoses the resulting history.
const mutants = [
  ['history required', 'history.required', (r) => { delete r.remediationTransitions; }],
  ['empty history', 'history.nonempty', (r) => { r.remediationTransitions = []; }],
  ['unknown operation', 'operation.recorded', (r) => { r.remediationTransitions[0].op = 'publish'; }],
  ['status cannot be recorded', 'operation.recorded', (r) => { r.remediationTransitions[0].op = 'status'; }],
  ['unknown history version', 'contract.version', (r) => { r.remediationTransitions[0].contract += '9'; }],
  ['caller authority', 'authority.accepted', (r) => { r.remediationTransitions[0].authority = 'user'; }],
  ['occurrence binding', 'occurrence.binding', (r) => { r.remediationTransitions[0].occurrenceId = 'occ_other'; }],
  ['timestamp', 'transition.time', (r) => { r.remediationTransitions[0].at = 'yesterday'; }],
  ['four axes required', 'state.vocabulary', (r) => { delete r.remediationTransitions[0].from.localStatus; }],
  ['closed enum', 'state.vocabulary', (r) => { r.remediationTransitions[0].to.releaseStatus = 'unknown'; }],
  ['history continuity', 'history.continuity', (r) => { r.remediationTransitions[1].from.localStatus = 'patched'; }],
  ['start rewrite', 'start.to.localStatus', (r) => { r.remediationTransitions[0].to.localStatus = 'unmapped'; }],
  ['start preserves release axis', 'start.to.releaseStatus', (r) => { r.remediationTransitions[0].to.releaseStatus = 'release_ready'; }],
  ['start identity', 'start.requires.attemptId', (r) => { r.remediationTransitions[0].attemptId = ''; }],
  ['start run', 'start.requires.runId', (r) => { r.remediationTransitions[0].runId = ''; }],
  ['already active', 'start.attempt', (r) => { r.remediationTransitions.splice(1, 0, transition('start', traced, traced, opening)); }],
  ['complete must be open', 'complete.from.disposition', (r) => { r.remediationTransitions[1].from.disposition = 'fixed'; }],
  ['complete must be unverified', 'complete.from.verificationStatus', (r) => { r.remediationTransitions[1].from.verificationStatus = 'receipt_bound'; }],
  ['complete outcome', 'complete.outcome', (r) => { r.remediationTransitions[1].to.disposition = 'blocked'; }],
  ['no-change eligibility', 'complete.outcomeFrom.no_change.localStatus', (r) => { r.remediationTransitions[1].to.disposition = 'no_change'; }],
  ['completion proof state', 'complete.to.localStatus', (r) => { r.remediationTransitions[1].to.localStatus = 'patched'; }],
  ['completion receipt', 'complete.to.verificationStatus', (r) => { r.remediationTransitions[1].to.verificationStatus = 'none'; }],
  ['completion is not release', 'complete.to.releaseStatus', (r) => { r.remediationTransitions[1].to.releaseStatus = 'release_ready'; }],
  ['complete identity', 'complete.requires.attemptId', (r) => { r.remediationTransitions[1].attemptId = ''; }],
  ['complete run', 'complete.requires.runId', (r) => { r.remediationTransitions[1].runId = ''; }],
  ['complete active identity', 'complete.attempt', (r) => { r.remediationTransitions[1].attemptId = 'someone-else'; }],
  ['complete without start', 'complete.attempt', (r) => { r.remediationTransitions.shift(); }],
  ['closure evidence', 'complete.requires.closurePatch', (r) => { r.closurePatch.bypass = ''; }],
  ['tests required', 'complete.requires.tests', (r) => { r.tests = []; }],
  ['manifest required', 'complete.requires.evidenceManifest', (r) => { delete r.remediationTransitions[1].evidenceManifest; }],
  ['manifest absolute', 'complete.requires.evidenceManifest', (r) => { r.remediationTransitions[1].evidenceManifest = '/tmp/proof'; }],
  ['manifest traversal', 'complete.requires.evidenceManifest', (r) => { r.remediationTransitions[1].evidenceManifest = 'proof/../../outside'; }],
  ['manifest backslash', 'complete.requires.evidenceManifest', (r) => { r.remediationTransitions[1].evidenceManifest = 'proof\\outside'; }],
  ['receipt hash', 'complete.requires.evidenceSha256', (r) => { r.remediationTransitions[1].evidenceSha256 = 'abc'; }],
  ['attempt required', 'attempt.record', (r) => { delete r.remediation; }],
  ['attempt terminal state', 'attempt.state', (r) => { r.remediation.state = 'active'; }],
  ['attempt identity', 'attempt.identity', (r) => { r.remediation.attemptId = 'someone-else'; }],
  ['attempt run identity', 'attempt.runId', (r) => { r.remediation.runId = 'someone-else'; }],
  ['attempt opened time', 'attempt.openedAt', (r) => { r.remediation.openedAt = closing; }],
  ['attempt closed time', 'attempt.closedAt', (r) => { r.remediation.closedAt = opening; }],
  ['terminal row', 'history.terminal', (r) => { r.disposition = 'blocked'; }],
  ['manifest pointer', 'evidence.manifest', (r) => { r.evidence.manifest = 'other.json'; }],
];
for (const [name, rule, mutate] of mutants) {
  test(`refuses ${name}: ${rule}`, () => {
    const row = example();
    mutate(row);
    const errors = errorsFor(row);
    assert.ok(errors.some((error) => error.code === 'E_SEC_REM_ER3' && error.rule === rule), JSON.stringify(errors));
  });
}

for (const [name, rule, mutate] of [
  ['open disposition', 'reject.from.disposition', (r) => { r.remediationTransitions[1].from.disposition = 'fixed'; }],
  ['open verification', 'reject.from.verificationStatus', (r) => { r.remediationTransitions[1].from.verificationStatus = 'receipt_bound'; }],
  ['blocked disposition', 'reject.to.disposition', (r) => { r.remediationTransitions[1].to.disposition = 'fixed'; }],
  ['blocked local', 'reject.to.localStatus', (r) => { r.remediationTransitions[1].to.localStatus = 'patched'; }],
  ['unverified', 'reject.to.verificationStatus', (r) => { r.remediationTransitions[1].to.verificationStatus = 'receipt_bound'; }],
  ['not ready', 'reject.to.releaseStatus', (r) => { r.remediationTransitions[1].to.releaseStatus = 'release_ready'; }],
  ['cited reason', 'reject.requires.reason', (r) => { r.remediationTransitions[1].reason = ' '; }],
  ['identity', 'reject.requires.attemptId', (r) => { r.remediationTransitions[1].attemptId = ''; }],
  ['run', 'reject.requires.runId', (r) => { r.remediationTransitions[1].runId = ''; }],
  ['active identity', 'reject.attempt', (r) => { r.remediationTransitions[1].attemptId = 'someone-else'; }],
]) {
  test(`reject requires ${name}`, () => {
    const row = example('rejected');
    mutate(row);
    assert.ok(errorsFor(row).some((error) => error.rule === rule));
  });
}

test('active attempt cannot carry a closing timestamp', () => {
  const row = example('active');
  row.remediation.closedAt = closing;
  assert.ok(errorsFor(row).some(({ rule }) => rule === 'attempt.closedAt'));
});

test('closed grammar fails unknown versions and unsupported rule descriptors with actionable diagnostics', () => {
  for (const schema of ['setjoin.sec.deep-security-remediation-transitions/v1', 'setjoin.sec.deep-security-remediation-transitions/v999']) {
    const errors = [];
    assert.equal(readEr3Contract(errors, { ...artifact, schema }), null);
    assert.match(errors[0].message, /unsupported grammar schema.*regenerate and review.*history contract remains v1/);
  }
  for (const mutate of [
    (a) => { a.operations[0].from.futureAxis = 'blocked'; },
    (a) => { a.operations[0].requires.push('futureField'); },
    (a) => { a.operations[0].futureRule = true; },
    (a) => { a.operations[0].receiptRequires = ['futureReceipt']; },
    (a) => { a.operations[0].from.disposition = 'futureState'; },
    (a) => { a.operations[3].readonly = false; },
    (a) => { a.operations.push(a.operations[0]); },
  ]) {
    const changed = structuredClone(artifact);
    mutate(changed);
    const errors = [];
    assert.equal(readEr3Contract(errors, changed), null);
    assert.ok(errors.every(({ code }) => code === 'E_SEC_REM_ER3_CONTRACT'));
  }
});

test('historical v1 grammar bytes are retained while v1 histories remain readable under v2', () => {
  const oldBytes = fs.readFileSync(new URL('../shared/securityprogram/testdata/transitions-v1.json', import.meta.url));
  assert.equal(crypto.createHash('sha256').update(oldBytes).digest('hex'), 'ddadb2ad45372d5da0669d22d938c3b325ddf32e50db92c4ea040acfc87d1add');
  assert.equal(artifact.contract, JSON.parse(oldBytes).contract);
  const ledgerURL = new URL('../docs/verification/deep-security-remediation-ledger.json', import.meta.url);
  const before = fs.readFileSync(ledgerURL);
  const ledger = JSON.parse(before);
  assert.ok(ledger.rows.length > 0);
  const differences = ledger.rows.flatMap((row) => errorsFor(row));
  assert.deepEqual(differences, [], 'Any difference requires explicit checker/artifact/version adjudication; never edit historical records to pass');
  assert.deepEqual(fs.readFileSync(ledgerURL), before, 'historical inspection must remain read-only');
});
