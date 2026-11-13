import fs from 'node:fs';
import path from 'node:path';

import {
  ACTIVE_ATTEMPT_STATES,
  latestAttemptEvents,
  loadAttemptJournal,
} from './security-program-attempts.mjs';
import { SecurityProgramError } from './security-program-json.mjs';

const LOGICAL_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const ELIGIBILITY_SCHEMA = 'setjoin.security-program.eligibility/v1';

function fail(code, message) {
  throw new SecurityProgramError(code, message);
}

export function resumeLogicalToken(value, name) {
  if (typeof value !== 'string' || !LOGICAL_TOKEN.test(value)) {
    fail('E_SECURITY_PROGRAM_USAGE', `${name} must be a privacy-safe logical token`);
  }
  return value;
}

function assertPrivateStateDirectory(repoRoot, stateDirectory) {
  if (!path.isAbsolute(stateDirectory)) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security-program state directory must be absolute');
  let metadata;
  try { metadata = fs.lstatSync(stateDirectory); }
  catch { fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security-program state directory is unavailable'); }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security-program state directory must be a real directory');
  }
  const canonical = fs.realpathSync.native(stateDirectory);
  const relative = path.relative(fs.realpathSync.native(repoRoot), canonical);
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security-program state directory must be outside the worktree');
  }
  if ((metadata.mode & 0o777) !== 0o700) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security-program state directory must use mode 0700');
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'security-program state directory must be caller-owned');
  }
  return canonical;
}

function assertPrivateJournal(journalPath) {
  if (!fs.existsSync(journalPath)) return;
  const metadata = fs.lstatSync(journalPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o600) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt journal must be a real mode-0600 file');
  }
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt journal must be caller-owned');
  }
}

function readEligibility(stateDirectory, expected) {
  const filename = path.join(stateDirectory, 'eligibility.json');
  if (!fs.existsSync(filename)) return null;
  assertPrivateJournal(filename);
  let value;
  try { value = JSON.parse(fs.readFileSync(filename, 'utf8')); }
  catch { fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'eligibility evidence is not valid JSON'); }
  const keys = Object.keys(value ?? {}).sort();
  const required = ['approvalId', 'inventorySha256', 'revision', 'schema', 'shardGenerationId', 'shardId'];
  if (JSON.stringify(keys) !== JSON.stringify(required) || value.schema !== ELIGIBILITY_SCHEMA) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'eligibility evidence has an unsupported shape');
  }
  resumeLogicalToken(value.approvalId, 'approval ID');
  if (!/^S(?:0[1-9]|[12][0-9]|30)\/P(?:0[1-9]|[1-9][0-9]*)$/.test(value.shardId)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'eligibility shard ID is invalid');
  }
  if (!expected || value.revision !== expected.revision
      || value.inventorySha256 !== expected.inventorySha256
      || value.shardGenerationId !== expected.shardGenerationId) {
    fail('E_SECURITY_PROGRAM_SOURCE_CHANGED', 'eligibility evidence does not bind the current C0 authority');
  }
  return Object.freeze({ state: 'eligible', shardId: value.shardId, approvalId: value.approvalId });
}

function stateFromEvent(event) {
  if (event.state === 'RUNNING') return 'active';
  if (event.state === 'DETACHED') return 'detached';
  if (['START_REQUESTED', 'ORPHANED_START', 'HOLD'].includes(event.state)) return 'orphaned';
  if (['COMPLETION_REQUESTED', 'COMPLETION_UNKNOWN'].includes(event.state)) return 'completion-unknown';
  if (event.state === 'ADMITTED') return 'complete';
  if (['RESERVED', 'SEALED', 'SOURCE_VERIFIED', 'PUBLICATION_PENDING', 'PUBLISHED'].includes(event.state)) return 'blocked';
  return 'fresh';
}

export function selectRuntimeResumeEvent(latest) {
  const active = latest.filter((event) => ACTIVE_ATTEMPT_STATES.has(event.state));
  const uncertain = latest.filter((event) => ['ORPHANED_START', 'HOLD'].includes(event.state));
  if (active.length > 1 || uncertain.length > 1 || (active.length > 0 && uncertain.length > 0)) {
    fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'attempt journal has ambiguous active or uncertain authority');
  }
  return active[0] ?? uncertain[0] ?? latest.at(-1);
}

export function readRuntimeResumeAuthority({ repoRoot, expected, stateDirectory = process.env.SETJOIN_SECURITY_PROGRAM_STATE_DIR } = {}) {
  if (stateDirectory === undefined || stateDirectory === '') return Object.freeze({ state: 'fresh' });
  const canonical = assertPrivateStateDirectory(repoRoot, stateDirectory);
  const journalPath = path.join(canonical, 'attempt-journal.json');
  assertPrivateJournal(journalPath);
  const events = loadAttemptJournal(journalPath);
  if (events.length === 0) return readEligibility(canonical, expected) ?? Object.freeze({ state: 'fresh' });
  const latest = [...latestAttemptEvents(events).values()];
  const event = selectRuntimeResumeEvent(latest);
  if (expected && (event.epochRevision !== expected.revision
      || event.inventorySha256 !== expected.inventorySha256
      || event.shardGenerationId !== expected.shardGenerationId)) {
    fail('E_SECURITY_PROGRAM_SOURCE_CHANGED', 'attempt journal does not bind the current C0 authority');
  }
  return Object.freeze({
    state: stateFromEvent(event),
    journalState: event.state,
    attemptId: event.attemptId,
    scanId: event.scanId ?? null,
    shardId: event.shardId,
  });
}

export function resumeStateDecision(authority) {
  const command = (...args) => ({ argv: ['bash', 'scripts/verify-security-program.sh', 'coverage', ...args] });
  const attemptId = authority.attemptId ?? 'attempt-fixture';
  const shardId = authority.shardId ?? 'S01/P01';
  const approvalId = authority.approvalId ?? 'approval-fixture';
  const decisions = {
    fresh: { exitFamily: 'HOLD', stateBranch: 'FRESH', action: 'WAIT_FOR_DX', targetVerdict: 'SAFE_HOLD', whySafe: 'No admitted attempt or shard authority exists, so no scanner may start', next: null },
    active: { exitFamily: 'OK', stateBranch: 'ACTIVE', action: 'REJOIN_EXISTING', targetVerdict: 'SAFE_ATTACH', whySafe: 'The journal binds the existing scan ID to the current revision, inventory, and shard generation', next: command('attach', '--attempt', attemptId) },
    detached: { exitFamily: 'OK', stateBranch: 'DETACHED', action: 'REJOIN_EXISTING', targetVerdict: 'SAFE_ATTACH', whySafe: 'The detached journal entry retains one bound scan ID, so attach cannot create a replacement scan', next: command('attach', '--attempt', attemptId) },
    orphaned: { exitFamily: 'HOLD', stateBranch: 'ORPHANED_START', action: 'RECONCILE_START', targetVerdict: 'SAFE_RECONCILE', whySafe: 'The journal proves a start request but no scan ID; reconciliation cannot launch a replacement', next: command('reconcile-start', '--attempt', attemptId) },
    'completion-unknown': { exitFamily: 'HOLD', stateBranch: 'COMPLETION_UNKNOWN', action: 'RECONCILE_COMPLETION', targetVerdict: 'SAFE_RECONCILE', whySafe: 'The journal retains the existing scan ID while terminal evidence is unknown, so only reconciliation is allowed', next: command('reconcile-completion', '--attempt', attemptId) },
    blocked: { exitFamily: 'BLOCKED', stateBranch: 'BLOCKED', action: 'RESOLVE_PREREQUISITE', targetVerdict: 'SAFE_BLOCKED', whySafe: 'Persisted authority is readable but not eligible; the next command is read-only doctor', next: { argv: ['bash', 'scripts/verify-security-program.sh', '--doctor', '--offline'] } },
    eligible: { exitFamily: 'OK', stateBranch: 'ELIGIBLE', action: 'START_DRY_RUN', targetVerdict: 'SAFE_DRY_RUN', whySafe: 'Eligibility binds the approved shard to the current revision, inventory, and shard generation; dry-run starts nothing', next: command('start', '--shard', shardId, '--approval', approvalId, '--dry-run') },
    complete: { exitFamily: 'OK', stateBranch: 'COMPLETE', action: 'ALL_COVERAGE_RECONCILED', targetVerdict: 'SAFE_TERMINAL', whySafe: 'The retained attempt reached verified admission and has no remaining transition', next: null },
  };
  const decision = decisions[authority.state];
  if (!decision) fail('E_SECURITY_PROGRAM_EVIDENCE_INVALID', 'resume authority has an unknown state');
  const resolved = { ...decision };
  if (authority.attemptId !== undefined) resolved.attemptId = authority.attemptId;
  if (authority.scanId !== undefined) resolved.scanId = authority.scanId;
  if (authority.shardId !== undefined) resolved.shardId = authority.shardId;
  return Object.freeze(resolved);
}

export function validateResumeAction(decision, { action, attemptId, shardId, approvalId } = {}) {
  if (action === 'attach') {
    resumeLogicalToken(attemptId, 'attempt ID');
    if (decision.action !== 'REJOIN_EXISTING' || decision.attemptId !== attemptId || !decision.scanId) {
      fail('E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN', 'attempt is not the current verified attachable scan');
    }
  } else if (action === 'reconcile-start') {
    resumeLogicalToken(attemptId, 'attempt ID');
    if (decision.action !== 'RECONCILE_START' || decision.attemptId !== attemptId) {
      fail('E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN', 'attempt is not the current orphaned start');
    }
  } else if (action === 'reconcile-completion') {
    resumeLogicalToken(attemptId, 'attempt ID');
    if (decision.action !== 'RECONCILE_COMPLETION' || decision.attemptId !== attemptId || !decision.scanId) {
      fail('E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN', 'attempt is not the current completion-unknown scan');
    }
  } else if (action === 'start-dry-run') {
    if (typeof shardId !== 'string' || !/^S(?:0[1-9]|[12][0-9]|30)\/P(?:0[1-9]|[1-9][0-9]*)$/.test(shardId)) {
      fail('E_SECURITY_PROGRAM_USAGE', 'shard ID must identify an S01-S30 shard');
    }
    resumeLogicalToken(approvalId, 'approval ID');
    if (decision.action !== 'START_DRY_RUN' || decision.shardId !== shardId) {
      fail('E_SECURITY_PROGRAM_APPROVAL_REQUIRED', 'shard is not currently eligible for the supplied approval');
    }
  } else {
    fail('E_SECURITY_PROGRAM_USAGE', 'unknown resume action');
  }
  return Object.freeze({ actionValidated: true, scannerStarts: 0, networkStarts: 0 });
}
