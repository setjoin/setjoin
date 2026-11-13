import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { SecurityProgramError } from './lib/security-program-json.mjs';
import {
  readRuntimeResumeAuthority,
  resumeStateDecision,
  selectRuntimeResumeEvent,
  validateResumeAction,
} from './lib/security-program-resume.mjs';

const scratch = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-resume-')));
const emptyState = path.join(scratch, 'empty-state');
fs.mkdirSync(emptyState, { mode: 0o700 });
fs.writeFileSync(path.join(emptyState, 'attempt-journal.json'), '', { mode: 0o600 });

function expectCode(code, action) {
  assert.throws(action, (error) => error instanceof SecurityProgramError && error.code === code);
}

try {
  assert.deepEqual(readRuntimeResumeAuthority({ repoRoot: process.cwd() }), { state: 'fresh' });
  assert.deepEqual(readRuntimeResumeAuthority({ repoRoot: process.cwd(), stateDirectory: emptyState }), { state: 'fresh' });
  expectCode('E_SECURITY_PROGRAM_EVIDENCE_INVALID', () => selectRuntimeResumeEvent([
    { state: 'RUNNING', attemptId: 'attempt-a' }, { state: 'DETACHED', attemptId: 'attempt-b' },
  ]));

  const eligibilityState = path.join(scratch, 'eligible-state');
  fs.mkdirSync(eligibilityState, { mode: 0o700 });
  const expected = { revision: '7'.repeat(40), inventorySha256: 'a'.repeat(64), shardGenerationId: 'fixture/v1' };
  fs.writeFileSync(path.join(eligibilityState, 'eligibility.json'), `${JSON.stringify({
    schema: 'setjoin.security-program.eligibility/v1', ...expected,
    shardId: 'S01/P01', approvalId: 'approval-a',
  })}\n`, { mode: 0o600 });
  assert.deepEqual(readRuntimeResumeAuthority({
    repoRoot: process.cwd(), stateDirectory: eligibilityState, expected,
  }), { state: 'eligible', shardId: 'S01/P01', approvalId: 'approval-a' });

  const fixtures = [
    [{ state: 'active', attemptId: 'attempt-a', scanId: 'scan-a', shardId: 'S01/P01' }, { action: 'attach', attemptId: 'attempt-a' }],
    [{ state: 'detached', attemptId: 'attempt-a', scanId: 'scan-a', shardId: 'S01/P01' }, { action: 'attach', attemptId: 'attempt-a' }],
    [{ state: 'orphaned', attemptId: 'attempt-a', scanId: null, shardId: 'S01/P01' }, { action: 'reconcile-start', attemptId: 'attempt-a' }],
    [{ state: 'completion-unknown', attemptId: 'attempt-a', scanId: 'scan-a', shardId: 'S01/P01' }, { action: 'reconcile-completion', attemptId: 'attempt-a' }],
    [{ state: 'eligible', shardId: 'S01/P01', approvalId: 'approval-a' }, { action: 'start-dry-run', shardId: 'S01/P01', approvalId: 'approval-a' }],
  ];
  for (const [authority, request] of fixtures) {
    const decision = resumeStateDecision(authority);
    assert.equal(validateResumeAction(decision, request).actionValidated, true);
  }

  const uncertain = resumeStateDecision({ state: 'orphaned', attemptId: 'attempt-a', scanId: null, shardId: 'S01/P01' });
  assert.equal(uncertain.next.argv.includes('start'), false);
  expectCode('E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN', () => validateResumeAction(uncertain, {
    action: 'reconcile-start', attemptId: 'attempt-b',
  }));
  expectCode('E_SECURITY_PROGRAM_APPROVAL_REQUIRED', () => validateResumeAction(
    resumeStateDecision({ state: 'fresh' }),
    { action: 'start-dry-run', shardId: 'S01/P01', approvalId: 'approval-a' },
  ));

  fs.chmodSync(emptyState, 0o755);
  expectCode('E_SECURITY_PROGRAM_EVIDENCE_INVALID', () => readRuntimeResumeAuthority({
    repoRoot: process.cwd(), stateDirectory: emptyState,
  }));
  console.log('security-program resume: PASS (external state boundary, shared five-action resolver, uncertain-start fence, scanner=0 network=0)');
} finally {
  fs.chmodSync(emptyState, 0o700);
  fs.rmSync(scratch, { recursive: true, force: true });
}
