import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
	buildRehearsalReceipt,
	buildTimingReceipt,
	PerfEvidenceError,
	parsePhases,
	REHEARSAL_KIND,
	REHEARSAL_RECEIPT_NAME,
	selfTest,
	TIMING_KIND,
	TIMING_RECEIPT_NAME,
	validatePriorArtifact,
	writeRehearsalReceipt,
	writeTimingReceipt,
} from './performance-receipts.mjs';

const HOST_CLASS = `${process.platform}-${process.arch}`;

function timingReceipt(overrides = {}) {
	return buildTimingReceipt({
		runId: 'run-timing',
		mode: 'ci',
		samples: 5,
		warmup: 1,
		buildId: 'candidate-1',
		commit: 'abcdef123456',
		fixtureSha256: 'f'.repeat(64),
		hostClass: HOST_CLASS,
		nodeVersion: process.version,
		hostSupported: true,
		startedAt: new Date().toISOString(),
		finishedAt: new Date(Date.now() + 1000).toISOString(),
		evidence: 'runs/run-timing',
		...overrides,
	});
}

function rehearsalReceiptArgs(overrides = {}) {
	return {
		runId: 'run-rehearsal',
		commit: 'abcdef123456',
		candidateBuildId: 'candidate-1',
		priorBuildId: 'prior-1',
		priorArtifact: { artifactSetSha256: 'a'.repeat(64), ledgerSha256: 'b'.repeat(64), assetCount: 3 },
		candidateLedger: { artifactSetSha256: 'c'.repeat(64) },
		phases: [
			{ name: 'phase-prior', servedBuildId: 'prior-1', summary: 'runs/run-rehearsal/phase-prior/performance-summary.v1.json' },
			{ name: 'phase-candidate', servedBuildId: 'candidate-1', summary: 'runs/run-rehearsal/phase-candidate/performance-summary.v1.json' },
		],
		hostClass: HOST_CLASS,
		nodeVersion: process.version,
		hostSupported: true,
		fixtureSha256: 'f'.repeat(64),
		startedAt: new Date().toISOString(),
		finishedAt: new Date(Date.now() + 1000).toISOString(),
		evidence: 'runs/run-rehearsal',
		...overrides,
	};
}

function rehearsalReceipt(overrides = {}) {
	return buildRehearsalReceipt(rehearsalReceiptArgs(overrides));
}

function policyViolation(call) {
	try {
		call();
	} catch (error) {
		assert.ok(error instanceof PerfEvidenceError, `expected PerfEvidenceError, got ${String(error)}`);
		assert.equal(error.code, 'POLICY_VIOLATION');
		assert.match(error.grammarLine(), /^E_WEBMAIL_PERF_POLICY_VIOLATION /);
		return;
	}
	assert.fail('expected the guarded write to be refused');
}

test('timing and rehearsal receipts are distinct evidence kinds', () => {
	assert.notEqual(TIMING_RECEIPT_NAME, REHEARSAL_RECEIPT_NAME);
	assert.notEqual(TIMING_KIND, REHEARSAL_KIND);
	assert.equal(timingReceipt().kind, TIMING_KIND);
	assert.equal(rehearsalReceipt().kind, REHEARSAL_KIND);
	assert.equal(rehearsalReceipt().reportVersion, 'webmail-performance-rehearsal-receipt-v1');
});

test('timing receipt keeps the established run.json fields and adds kind/duration', () => {
	const receipt = timingReceipt();
	assert.equal(receipt.schemaVersion, 1);
	assert.equal(receipt.verdict, 'pass');
	assert.equal(receipt.samples, 5);
	assert.equal(receipt.warmup, 1);
	assert.match(receipt.summary, /performance-summary\.v1\.json$/);
	assert.equal(typeof receipt.durationSeconds, 'number');
	assert.equal(typeof receipt.hostSupported, 'boolean');
});

test('rehearsal receipt records the prior-to-candidate binding and phases', () => {
	const receipt = rehearsalReceipt();
	assert.equal(receipt.priorBuildId, 'prior-1');
	assert.equal(receipt.candidateBuildId, 'candidate-1');
	assert.equal(receipt.candidateArtifactSetSha256, 'c'.repeat(64));
	assert.equal(receipt.phases.length, 2);
	assert.throws(() => buildRehearsalReceipt(rehearsalReceiptArgs({ phases: [] })), PerfEvidenceError);
	assert.throws(
		() => buildRehearsalReceipt(rehearsalReceiptArgs({ startedAt: 'not-a-timestamp' })),
		(error) => error instanceof PerfEvidenceError && error.code === 'INVALID_EVIDENCE',
	);
});

test('timing writer refuses rehearsal receipts and rehearsal run directories', () => {
	policyViolation(() => writeTimingReceipt({ root: '.', runDir: join('.', 'run'), receipt: rehearsalReceipt() }));
});

test('rehearsal writer refuses timing receipts and timing run directories', () => {
	policyViolation(() => writeRehearsalReceipt({ runDir: join('.', 'run'), receipt: timingReceipt() }));
});

test('phase records must bind each phase to its expected served build', () => {
	const phases = rehearsalReceipt().phases;
	assert.equal(parsePhases(JSON.stringify(phases), { priorBuildId: 'prior-1', candidateBuildId: 'candidate-1' }).length, 2);
	assert.throws(
		() => parsePhases(JSON.stringify(phases), { priorBuildId: 'prior-1', candidateBuildId: 'other' }),
		(error) => error instanceof PerfEvidenceError && error.code === 'INVALID_EVIDENCE',
	);
	assert.throws(
		() => parsePhases('null', { priorBuildId: 'prior-1', candidateBuildId: 'candidate-1' }),
		(error) => error instanceof PerfEvidenceError && error.code === 'INVALID_EVIDENCE',
	);
});

test('the embedded guard self-test passes end to end', () => {
	const checks = selfTest();
	assert.ok(checks.length >= 20, `expected the full guard matrix, ran ${checks.length}`);
});

test('retained prior artifact validation refuses an empty bundle', () => {
	const artifactDir = mkdtempSync(join(tmpdir(), 'setjoin-prior-artifact-'));
	try {
		let refused = null;
		try {
			validatePriorArtifact({ artifactDir, candidateBuildId: 'candidate-1' });
		} catch (error) {
			refused = error;
		}
		assert.ok(refused instanceof PerfEvidenceError);
		assert.equal(refused.code, 'INPUTS_ABSENT');
		assert.match(refused.grammarLine(), /problem=retained_prior_artifact_incomplete/);
	} finally {
		rmSync(artifactDir, { recursive: true, force: true });
	}
});
