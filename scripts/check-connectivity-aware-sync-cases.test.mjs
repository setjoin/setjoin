#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { hasRetainedE6Generation } from './run-connectivity-e6-harness.mjs';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..');
const checker = path.join(scriptDirectory, 'check-connectivity-aware-sync-cases.mjs');
const manifestSource = path.join(repositoryRoot, 'docs/verification/connectivity-aware-sync-cases.json');
const decisionSchema = path.join(repositoryRoot, 'docs/verification/connectivity-aware-sync-decision.schema.json');
const cleanupSchema = path.join(repositoryRoot, 'docs/verification/connectivity-aware-sync-cleanup.schema.json');

function clone(value) {
	return JSON.parse(JSON.stringify(value));
}

function own(object, key) {
	return Object.prototype.hasOwnProperty.call(object, key);
}

function writeJson(filename, value) {
	fs.writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function runChecker(argumentsList, expectedStatus, label, expectedText = '') {
	const result = spawnSync(process.execPath, [checker, ...argumentsList], { encoding: 'utf8' });
	const output = `${result.stdout}${result.stderr}`;
	assert.equal(result.status, expectedStatus, `${label}: expected exit ${expectedStatus}, got ${result.status}\n${output}`);
	if (expectedText) assert.match(output, new RegExp(expectedText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `${label}: diagnostic did not contain ${expectedText}\n${output}`);
	return output;
}

// B62 fail-closed results: an entry is an identity-bound record (registry
// resultId + lane + run-scoped retained artifacts), and only cases whose
// fixture file exists (bound by content digest) may report evidence at all.
function bindableCases(manifest) {
	return manifest.cases.filter((entry) => fs.existsSync(path.join(repositoryRoot, entry.fixture)));
}

function identityResult(manifest, registryByCase, runId, entry) {
	return {
		caseId: entry.id,
		status: 'passed',
		resultId: registryByCase.get(entry.id).resultId,
		lane: registryByCase.get(entry.id).lane,
		retainedArtifacts: entry.retainedArtifacts.map((artifact) => artifact.replace('<run-id>', runId)),
	};
}

function focusedResultsDoc(manifest, registryByCase, runId, caseId, mutate = () => {}) {
	const entry = manifest.cases.find((candidate) => candidate.id === caseId);
	const result = identityResult(manifest, registryByCase, runId, entry);
	mutate(result);
	return {
		schemaVersion: 1,
		runId,
		utcTime: '2026-08-11T00:00:00Z',
		results: [result],
	};
}

function makeDecision() {
	return {
		schemaVersion: 1,
		requested: {
			mode: 'execute',
			networkCost: 'unmetered',
			power: 'charging',
			thermal: 'nominal',
			storagePressure: 'normal',
			maxBytes: 2097152,
		},
		effective: {
			mode: 'observe',
			networkCost: 'unmetered',
			power: 'charging',
			thermal: 'nominal',
			storagePressure: 'normal',
			maxBytes: 1048576,
		},
		policySource: { kind: 'global', rule: 'observe', revision: 4 },
		capabilitySource: { kind: 'native-snapshot', contractVersion: 1 },
		eligibility: 'eligible',
		queue: { class: 'background', ageSeconds: 12 },
		pauseReason: 'none',
	};
}

function makeCleanup(status = 'cleaned') {
	const actions = {};
	for (const action of ['qdisc', 'isolatedDatabase', 'portsProcesses', 'tempFiles', 'firewall']) {
		actions[action] = {
			before: { state: status === 'already_clean' ? 'absent' : 'present' },
			after: { state: 'absent' },
			status,
		};
	}
	return {
		schemaVersion: 1,
		runId: 'self-test-run',
		utcTime: '2026-08-11T00:00:00Z',
		actions,
	};
}

const tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-connectivity-aware-sync-'));
try {
	const manifest = JSON.parse(fs.readFileSync(manifestSource, 'utf8'));
	const registryByCase = new Map(manifest.evidenceRegistry.map((binding) => [binding.caseId, binding]));

	// B62 E4-I binding: the manifest-only check binds every real fixture by
	// content. A focused results run may cover exactly one bound case.
	const bindable = bindableCases(manifest);
	assert.ok(bindable.length >= 2, 'self-test: at least two manifest cases must have real fixtures');
	const focusedCase = bindable.find((entry) => entry.requiredState === 'required').id;
	const focusedEntry = manifest.cases.find((candidate) => candidate.id === focusedCase);
	// The focused-flow fabrication must stay OUT of the real retained receipts
	// tree: manifest-only receipt validation keys on the presence of a REAL
	// retained generation there, and a self-test scratch run inside it would
	// flip the checker (and the receipt-negative expectations below) from
	// tolerated to fail-closed mid-run on fresh checkouts. The self-test-scoped
	// subtree is gitignored with the rest of test-results/ and removed in the
	// finally block.
	const receiptCaseIds = new Set(manifest.cases.filter((entry) => own(entry, 'generationReceipt')).map((entry) => entry.id));
	assert.ok(!receiptCaseIds.has(focusedCase), 'self-test: the focused case must not be an executed E6 receipt case');
	const SELFTEST_EVIDENCE_ROOT = 'test-results/selftest-connectivity';
	focusedEntry.retainedArtifacts = focusedEntry.retainedArtifacts.map((artifact) => artifact.replace('test-results/connectivity-aware-sync/', `${SELFTEST_EVIDENCE_ROOT}/`));
	registryByCase.get(focusedCase).retainedArtifact = registryByCase.get(focusedCase).retainedArtifact.replace('test-results/connectivity-aware-sync/', `${SELFTEST_EVIDENCE_ROOT}/`);
	assert.ok(focusedEntry.retainedArtifacts.every((artifact) => artifact.startsWith(`${SELFTEST_EVIDENCE_ROOT}/`)), 'self-test: focused artifact templates must be relocated out of the real receipts tree');
	assert.ok(registryByCase.get(focusedCase).retainedArtifact.startsWith(`${SELFTEST_EVIDENCE_ROOT}/`), 'self-test: focused registry binding must be relocated out of the real receipts tree');

	const manifestFile = path.join(tempDirectory, 'manifest.json');
	writeJson(manifestFile, manifest);

	assert.equal(JSON.parse(fs.readFileSync(decisionSchema, 'utf8')).$defs.normalizedValues.additionalProperties, false);
	assert.equal(JSON.parse(fs.readFileSync(cleanupSchema, 'utf8')).$defs.action.additionalProperties, false);

	runChecker([manifestFile], 0, 'manifest-only validation', 'PASS');

	// E4-I Astra correction (finding 20): retained evidence must EXIST and its
	// contents must prove the pass. The self-test writes the REAL receipt the
	// lane contract produces (run-scoped, digest-bound) under the
	// self-test-scoped evidence root and removes it again afterwards.
	const focusedRunId = 'self-test-run';
	const focusedArtifact = focusedEntry.retainedArtifacts[0].replace('<run-id>', focusedRunId);
	const focusedArtifactPath = path.join(repositoryRoot, focusedArtifact);
	const focusedFixtureDigest = createHash('sha256')
		.update(fs.readFileSync(path.join(repositoryRoot, focusedEntry.fixture)))
		.digest('hex');
	function writeFocusedReceipt(overrides = {}) {
		fs.mkdirSync(path.dirname(focusedArtifactPath), { recursive: true });
		writeJson(focusedArtifactPath, {
			schemaVersion: 1,
			caseId: focusedCase,
			status: 'passed',
			lane: focusedEntry.lane,
			runId: focusedRunId,
			utcTime: '2026-08-11T00:00:00Z',
			fixture: focusedEntry.fixture,
			fixtureDigest: focusedFixtureDigest,
			...(own(focusedEntry, 'seed') ? { seed: focusedEntry.seed } : {}),
			observations: {},
			...overrides,
		});
	}
	writeFocusedReceipt();

	const focusedResultsFile = path.join(tempDirectory, 'focused-results.json');
	writeJson(focusedResultsFile, focusedResultsDoc(manifest, registryByCase, 'self-test-run', focusedCase));
	runChecker([manifestFile, focusedResultsFile, '--case', focusedCase], 0, 'exact focused case selection with bound evidence', focusedCase);
	runChecker([manifestFile, '--case', 'CAS-NOT-IN-MANIFEST'], 1, 'unknown focused case rejection', 'CAS-NOT-IN-MANIFEST');

	// A fabricated PASS citing a NONEXISTENT artifact fails; so does evidence
	// whose contents do not prove this run's pass.
	fs.rmSync(focusedArtifactPath, { force: true });
	runChecker([manifestFile, focusedResultsFile, '--case', focusedCase], 1, 'nonexistent retained artifact rejection', 'does not exist for run');
	writeFocusedReceipt({ status: 'failed' });
	runChecker([manifestFile, focusedResultsFile, '--case', focusedCase], 1, 'non-passing retained receipt rejection', 'did not itself pass');
	writeFocusedReceipt({ runId: 'other-run' });
	runChecker([manifestFile, focusedResultsFile, '--case', focusedCase], 1, 'foreign-run retained receipt rejection', 'is not this run');
	writeFocusedReceipt({ fixtureDigest: '0'.repeat(64) });
	runChecker([manifestFile, focusedResultsFile, '--case', focusedCase], 1, 'stale retained receipt digest rejection', 'stale binding');
	writeFocusedReceipt();

	const negativeManifestCases = [
		['duplicate case ID', (copy) => { copy.cases[1].id = copy.cases[0].id; }, 'duplicate case ID'],
		['invalid lane', (copy) => { copy.cases[0].lane = 'side-channel'; }, 'lane'],
		['invalid required state', (copy) => { copy.cases[0].requiredState = 'skipped'; }, 'requiredState'],
		['nonpositive timeout', (copy) => { copy.cases[0].timeoutSeconds = 0; }, 'timeoutSeconds'],
		['empty retained artifact list', (copy) => { copy.cases[0].retainedArtifacts = []; }, 'retainedArtifacts'],
		['empty retained artifact entry', (copy) => { copy.cases[0].retainedArtifacts = ['']; }, 'retainedArtifacts[0]'],
		['unknown manifest field', (copy) => { copy.cases[0].unexpected = true; }, 'unknown field'],
	];
	for (const [label, mutate, diagnostic] of negativeManifestCases) {
		const copy = clone(manifest);
		mutate(copy);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-')}.json`);
		writeJson(filename, copy);
		runChecker([filename], 1, label, diagnostic);
	}

	// B62 binding fields fail closed: a bound fixture requires a sha-256
	// digest matching the ACTUAL file content — syntax alone never passes.
	const existingFixtureCase = () => manifest.cases.find((entry) => fs.existsSync(path.join(repositoryRoot, entry.fixture)));
	const bindingNegativeCases = [
		['missing fixture digest binding', (copy) => {
			const entry = copy.cases.find((candidate) => candidate.id === existingFixtureCase().id);
			delete entry.fixtureDigest;
		}, 'fixtureDigest'],
		['stale fixture digest binding', (copy) => {
			const entry = copy.cases.find((candidate) => candidate.id === existingFixtureCase().id);
			entry.fixtureDigest = '0'.repeat(64);
		}, 'stale binding'],
		['digest over a missing fixture file', (copy) => {
			const entry = copy.cases.find((candidate) => !fs.existsSync(path.join(repositoryRoot, candidate.fixture)));
			entry.expectedDisposition = 'enforced';
		}, 'requires the fixture file'],
	];
	for (const [label, mutate, diagnostic] of bindingNegativeCases) {
		const copy = clone(manifest);
		mutate(copy);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-')}.json`);
		writeJson(filename, copy);
		runChecker([filename], 1, label, diagnostic);
	}

	// E4-I binding fields: dashed introducedBy grammar, sha-256 fixture digest,
	// seed, and contract.symbols all validate; malformed values fail closed.
	const e4iCase = manifest.cases.find((entry) => entry.id === 'CAS-E4I-TRIGGER-STEP-BOUNDS');
	assert.ok(e4iCase, 'self-test: manifest must carry the E4-I binding cases');
	assert.equal(e4iCase.introducedBy, 'E4-I');
	assert.match(e4iCase.fixtureDigest, /^[0-9a-f]{64}$/);
	assert.ok(Array.isArray(e4iCase.contract.symbols) && e4iCase.contract.symbols.length > 0);
	const e4iNegativeCases = [
		['malformed dashed introducedBy', (copy) => { copy.cases.find((entry) => entry.id === 'CAS-E4I-TRIGGER-STEP-BOUNDS').introducedBy = 'E4I-'; }, 'invalid state'],
		['malformed fixture digest', (copy) => { copy.cases.find((entry) => entry.id === 'CAS-E4I-TRIGGER-STEP-BOUNDS').fixtureDigest = 'abc123'; }, 'fixtureDigest'],
		['empty symbols entry', (copy) => { copy.cases.find((entry) => entry.id === 'CAS-E4I-TRIGGER-STEP-BOUNDS').contract.symbols = ['']; }, 'symbols[0]'],
		['empty seed', (copy) => { copy.cases.find((entry) => entry.id === 'CAS-E4I-TRIGGER-STEP-BOUNDS').seed = ' '; }, 'seed'],
		// E4-I Astra correction (finding 20): removing the E4-I identity fields
		// is itself a failure — the binding cannot be silently weakened.
		['removed E4-I seed', (copy) => { delete copy.cases.find((entry) => entry.id === 'CAS-E4I-TRIGGER-STEP-BOUNDS').seed; }, 'must bind their deterministic seed'],
		['removed E4-I contract symbols', (copy) => { delete copy.cases.find((entry) => entry.id === 'CAS-E4I-TRIGGER-STEP-BOUNDS').contract.symbols; }, 'must bind their contract symbols'],
	];
	for (const [label, mutate, diagnostic] of e4iNegativeCases) {
		const copy = clone(manifest);
		mutate(copy);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-')}.json`);
		writeJson(filename, copy);
		runChecker([filename], 1, label, diagnostic);
	}

	// E6 comparison-profile bindings: the canonical frozen profile document
	// validates standalone, every E6 case binds owner/fixture/digest/seed/
	// command/required-profile per the ownership table, and tampering with any
	// of those fields (or with the pinned profile numbers) fails closed.
	const e6CaseIds = [
		'CAS-E6-PROFILE-FROZEN',
		'CAS-E6-CRITICAL-SAMPLE-FLOOR',
		'CAS-E6-PAIRED-REGRESSION',
		'CAS-E6-FAILED-REQUEST-ACCOUNTING',
		'CAS-E6-CROSSPROCESS-CRITICAL-SATURATION',
		'CAS-E6-DIAGNOSTIC-BOUNDS',
		'CAS-E6-EXPORTER-FAILURE',
		'CAS-E6-METRIC-LABEL-ALLOWLIST',
		'CAS-E6-SMALL-COHORT-SUPPRESSION',
	];
	for (const caseId of e6CaseIds) {
		const entry = manifest.cases.find((candidate) => candidate.id === caseId);
		assert.ok(entry, `self-test: manifest must carry ${caseId}`);
		assert.equal(entry.introducedBy, 'E6');
		assert.match(entry.fixtureDigest, /^[0-9a-f]{64}$/);
		assert.ok(entry.seed && entry.seed.startsWith('e6-'));
		assert.ok(entry.command.includes(caseId), `self-test: ${caseId} command must name its case`);
	}
	const profileFrozen = manifest.cases.find((candidate) => candidate.id === 'CAS-E6-PROFILE-FROZEN');
	assert.equal(profileFrozen.fixture, 'docs/verification/connectivity-e6-profile.json');
	for (const sustained of ['CAS-E6-CRITICAL-SAMPLE-FLOOR', 'CAS-E6-PAIRED-REGRESSION', 'CAS-E6-FAILED-REQUEST-ACCOUNTING', 'CAS-E6-CROSSPROCESS-CRITICAL-SATURATION']) {
		const entry = manifest.cases.find((candidate) => candidate.id === sustained);
		assert.deepEqual(entry.requiredProfiles, ['e6-electron-macos-arm64-v3']);
	}
	const diagnosticCase = manifest.cases.find((candidate) => candidate.id === 'CAS-E6-DIAGNOSTIC-BOUNDS');
	assert.ok(Array.isArray(diagnosticCase.contract.symbols) && diagnosticCase.contract.symbols.length > 0);
	const profileFile = path.join(repositoryRoot, 'docs/verification/connectivity-e6-profile.json');
	runChecker(['--profile', profileFile], 0, 'canonical frozen E6 profile');
	const profileDocument = JSON.parse(fs.readFileSync(profileFile, 'utf8'));
	const e6NegativeCases = [
		['E6 requiredProfiles bind an unknown profile', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-PAIRED-REGRESSION').requiredProfiles = ['e6-electron-macos-arm64-v2'];
		}, 'is not a frozen selected profile'],
		['E6 command does not name its case', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-PAIRED-REGRESSION').command = 'RUN_ID=<run-id> bash scripts/verify-connectivity-aware-sync.sh core';
		}, 'must contain the exact case ID'],
		['E6 command is not one line', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-DIAGNOSTIC-BOUNDS').command = 'cd mailserver/webmail\nnpx vitest run';
		}, 'one exact non-empty command line'],
		['E6 case loses its identity seed', (copy) => {
			delete copy.cases.find((entry) => entry.id === 'CAS-E6-METRIC-LABEL-ALLOWLIST').seed;
		}, 'seed'],
	];
	for (const [label, mutate, diagnostic] of e6NegativeCases) {
		const copy = clone(manifest);
		mutate(copy);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-')}.json`);
		writeJson(filename, copy);
		runChecker([filename], 1, label, diagnostic);
	}
	const profileMutations = [
		['bootstrap resamples below the frozen gate', (copy) => { copy.protocol.bootstrap.resamples = 100; }, 'expected exactly 10000'],
		['warmup window below the frozen gate', (copy) => { copy.protocol.warmupSeconds = 60; }, 'expected exactly 120'],
		['regression ceiling above the frozen gate', (copy) => { copy.regressionCeilings.criticalP95MaxPercent = 10; }, 'expected exactly 5'],
		['unfrozen profile status inside profiles', (copy) => { copy.profiles[0].status = 'draft'; }, 'expected exactly "frozen"'],
		['post-result changes marked permitted', (copy) => { copy.freezeSemantics.postResultChangesProhibited = false; }, 'post-result workload/metric/seed/stopping changes are prohibited'],
		['Critical class mix not totaling 100', (copy) => { copy.profiles[0].criticalRequestClasses[0].mixPercent = 50; }, 'exactly 100 percent'],
		['platform neither selected nor unselected', (copy) => { copy.unselectedPlatforms.pop(); }, 'neither selected nor explicitly unselected'],
		['unknown profile document field', (copy) => { copy.extra = true; }, 'unknown field "extra"'],
	];
	for (const [label, mutate, diagnostic] of profileMutations) {
		const copy = clone(profileDocument);
		mutate(copy);
		const filename = path.join(tempDirectory, `profile-${label.replaceAll(' ', '-').replaceAll(',', '')}.json`);
		writeJson(filename, copy);
		runChecker(['--profile', filename], 1, label, diagnostic);
	}

function makeHarnessInstrumentFixture() {
	return {
		basis: 'harness-saturation-instrument',
		executor: {
			launchOwner: 'harness',
			window: 'comparator',
			scope: 'run-scoped-comparator-window',
			processCount: 1,
			measuredProcess: false,
			credentials: 'comparator-session',
			deliveryPath: 'window-fault-proxy',
			criticalPopulation: 'separate-from-driver-schedule',
			metricMapping: {
				'mailserver-gateway': 'equal-attributed-load',
				'setjoin-desktop-electron-main': 'production-execute-engine-residual',
				'setjoin-desktop-electron-renderer': 'production-execute-engine-residual',
			},
		},
		workload: {
			routes: [{
				method: 'POST',
				path: '/jmap',
				weight: 1,
				body: '[["Core/echo",{},"e6-instrument-' + String.fromCharCode(36) + '{seq}"]]',
			}],
			classMix: { interactive: 0, background: 1, opportunistic: 1 },
			accounts: 2,
			globalConcurrency: 2,
			perAccountConcurrency: 1,
			equivalenceRule: 'same-declared-routes-mix-and-limits',
		},
		engagement: {
			limit: 2,
			pollIntervalMs: 1000,
			freshnessPollIntervals: 2,
			observedBases: { candidate: 'engine-queue-observed', comparator: 'harness-saturation-instrument' },
			observationFields: ['basis', 'optionalRunning', 'optionalQueued', 'limit', 'holdReason', 'holdSinceUtc', 'observedAtUtc', 'saturating'],
			reasonShape: 'single-effective-hold-or-null',
			reasonSource: 'current-consistent-production-admission-observation',
			reasonTimestamp: 'same-observation',
			pendingSet: 'queued-and-unexpired-backoff',
			atLimitPredicate: 'optionalRunning>=limit',
			admissionHoldCodes: ['backoff', 'criticalActivity', 'criticalQuiet', 'accountSaturation', 'deficit'],
			heldRequiresPendingWork: true,
			refutingClasses: ['empty', 'below-limit-no-reason', 'unknown-hold', 'fallback-basis', 'stale-observation', 'missing-observation', 'unreachable-observation', 'malformed-observation', 'reason-counter-contradiction'],
			admissionImplementation: 'production-module-imports',
			productionModules: ['mailserver/webmail/src/lib/offline/scheduler.ts', 'mailserver/webmail/src/lib/offline/work-contract.ts'],
			backoffRules: ['retryableFailure-arms-backoff', 'networkFlap-observation-only', 'committed-progress-or-newer-authenticated-trigger-resets', 'run-seeded-randomness'],
		},
		quiescence: { drainSettleDeadlineMs: 2000, settledIntervalMs: 5000 },
		phaseBarrier: {
			rosters: {
				candidate: ['proxy', 'driver', 'sampler', 'coordinator'],
				comparator: ['proxy', 'driver', 'sampler', 'instrument'],
			},
			transports: {
				proxy: 'in-process',
				sampler: 'in-process',
				driver: 'stdio-control-fd-through-wrapper',
				instrument: 'stdio-control-fd-direct',
				coordinator: 'pair-state-loopback-main-renderer',
			},
			acknowledgedPhases: ['warmup', 'measurement'],
			candidateRouteRules: ['candidate-only', 'loopback-endpoint', 'run-scoped-nonce-handshake', 'main-renderer-push-and-ack', 'boot-dispatch-queued-until-common-start', 'trigger-ingestion-remains-active', 'absent-without-harness-seam', 'absent-in-off-comparator'],
			preActivationAttempts: 0,
			preActivationRules: ['warmup-starts-at-window-start', 'later-phase-starts-at-observed-pause-ack-after-closure', 'ends-at-common-start-minus-participant-rtt-half', 'dedicated-counter-outside-workload-and-control-ledgers', 'fail-fast-without-upstream-draw-or-bandwidth'],
			pauseDrainRules: ['pause-before-measurement-handshake', 'warmup-pause-vacuous', 'per-request-admission', 'synchronous-generation-read-at-dispatch-and-await-resumption', 'settle-existing-work', 'await-launched-executions-in-finally', 'defensive-zero-ack-guard', 'ack-gated-rearm-after-ledger-closure', 'reopen-at-common-executable-start'],
			requestHeaders: ['x-e6-dispatch-phase-epoch', 'x-e6-attempt-id', 'x-e6-request-seq'],
			attemptIdentityFields: ['dispatchPhaseEpoch', 'attemptId', 'requestSeq'],
			attemptIdentityRules: ['stamps-read-in-authorizing-synchronous-segment', 'request-sequence-starts-at-one', 'closed-epoch-terminal-identity-is-duplicate', 'unseen-closed-epoch-identity-is-halting-drain-breach', 'unstamped-forbidden-arrival-is-preactivation-failure'],
			corsAllowedHeaders: ['content-type', 'x-e6-proxy-source', 'x-e6-dispatch-phase-epoch', 'x-e6-attempt-id', 'x-e6-request-seq'],
			corsRules: ['declared-loopback-origin-only', 'credentials-enabled', 'preflight-and-actual-responses', 'config-digest-bound', 'options-only-control-exclusion', 'post-fully-accounted-and-body-readable'],
			phaseTime: {
				steps: ['delivery-acknowledgment', 'epoch-establishment-and-alignment', 'work-release'],
				clock: 'harness-local-monotonic',
				alignmentExchangesPerParticipantPerPhase: 1,
				phaseAnchorRoundTripDeadlineMs: 250,
				workReleaseDeliveryDeadlineMs: 250,
				rules: ['delivery-ack-clock-free', 'epoch-after-all-delivery-acks', 'release-after-all-alignment-acks', 'start-equals-broadcast-plus-delivery-lead', 'local-start-equals-local-origin-plus-carried-start', 'permission-delivered-strictly-before-start', 'early-recipients-hold-until-start', 'all-grids-stages-and-timers-share-start', 'participant-tolerance-rtt-half', 'broadcast-bound-independent-of-delivery-bound', 'alignment-bound-independent-of-drain-bound', 'alignment-reply-precedes-broadcast', 'slot-stage-mapping-and-equal-stage-exposure'],
			},
			pairState: {
				schemaVersion: 2,
				states: ['declared', 'launching', 'ready', 'complete', 'released'],
				stagedStateDeadlineMs: 30000,
				armedAckDeadlineMs: 10000,
				haltReferenceFields: ['failureClass', 'haltedAtUtc', 'haltRecordRef'],
				rules: ['both-shells-at-creation', 'listeners-bound-before-launch', 'declared-null-readiness', 'launching-valid-main-pid-other-readiness-pending', 'ready-complete-distinct-identity', 'complete-preserves-ready-identity', 'halted-handshake-requires-window-halt-reference', 'complete-handshake-halt-reference-only-for-own-transition-failed-result', 'halt-reference-binds-sealed-window-record-never-pair-aggregate', 'released-preserves-halt-reference', 'released-attachment-variants-require-teardown-outcome-reference', 'released-transition-failed-forbids-teardown-outcome-reference-uses-inline-receipt', 'complete-after-measurement-or-sealed-window-halt', 'released-preserves-identity-adds-absence-evidence', 'next-launch-after-prior-release', 'comparator-has-no-candidate-seam'],
			},
			reservationRules: ['reference-identity-ownership', 'selection-install-same-synchronous-segment', 'expired-writes-after-install-inside-wrapper', 'single-transfer-at-execution-push', 'every-exit-releases-only-owned-untransferred', 'all-releases-by-reference', 'preserve-other-cycles-and-global-per-account-limits', 'backoff-pre-await-reference-release', 'post-await-backoff-queue-only', 'live-readmission-suppresses-mirror', 'fresh-same-segment-terminal-read-suppresses-enqueue', 'preserve-backoff-envelope-and-queue-age'],
			handshakeStatuses: ['complete', 'halted'],
			handshakeRules: ['complete-has-all-phase-acks-and-clock-evidence', 'halted-has-failure-observation-and-completed-prefix', 'unexecuted-steps-marked-halted-before-step', 'prefix-and-remainder-crosschecked-with-ledger-and-acks', 'missing-or-contradicting-evidence-refuses-publication', 'well-formed-operational-failure-publishes-fail'],
			operationalFailures: ['late-broadcast', 'late-delivery', 'alignment-overrun', 'drain-breach', 'slot-stage-mismatch'],
			accountingRules: ['scheduled-from-built-plan', 'attempted-from-terminal-ledger', 'unexecuted-enumerated-schedule-complement', 'complete-attempted-equals-scheduled-and-unexecuted-zero', 'halted-attempted-plus-unexecuted-equals-scheduled', 'sampler-lifecycle-independent-counts', 'never-admitted-participant-zero', 'post-admission-legitimate-attempts-retained', 'closure-zero-scoped-to-closedAdmissionEpoch', 'current-epoch-before-halt-remains-legitimate', 'nonclosing-partition-refuses-publication'],
			haltRecord: {
				kind: 'e6-window-halt',
				schemaVersion: 1,
				variants: ['before-start', 'after-partial-start', 'transition-failed'],
				haltPhases: ['warmup', 'measurement', 'teardown'],
				measurementPhases: ['entered', 'unentered'],
				rules: ['phase-draining-entry-before-step-zero', 'phase-aware-machinery-and-halt-latch', 'unentered-measurement-unarmed-no-measurement-evidence', 'entered-unarmed-has-breach-entry-no-armed-evidence', 'armed-before-start-honest-zero-sample-lifecycle', 'partial-start-retains-timestamped-samples-and-recomputed-peaks', 'warmup-halt-preserves-own-lifecycle-measurement-unentered', 'transition-failed-binds-valid-completed-result', 'transition-failed-teardown-entered-and-armed', 'h2-seals-window-record-before-teardown-ack', 'parent-record-immutable', 'capture-inadequacy-recorded-false-when-honest', 'observation-floor-computed-never-waived', 'seals-bindings-ledger-and-statistics-still-validated', 'fabricated-evidence-refuses-publication'],
			},
			teardownOutcome: {
				kind: 'e6-teardown-outcome',
				schemaVersion: 1,
				attachmentVariants: ['before-start', 'after-partial-start'],
				inlineOnlyVariants: ['transition-failed'],
				outcomeClasses: ['passed', 'failed'],
				parentBindingFields: ['haltRecordRef', 'haltRecordDigest'],
				releaseReferenceFields: ['outcomeClass', 'teardownOutcomeRef', 'teardownOutcomeDigest'],
				rules: ['same-generation-window-binding-as-parent', 'exactly-one-attachment-for-attachment-variant', 'inline-complete-receipt-for-transition-failed', 'transition-failed-attachment-is-double-binding-refusal', 'complete-receipt-all-applicable-assertions', 'passed-all-assertions-ok', 'failed-at-least-one-evidence-consistent-not-ok', 'no-measurement-evidence-in-attachment', 'parent-seal-before-outcome-seal-before-release', 'parent-never-rewritten-or-resealed', 'pair-binds-parent-and-outcome-digests', 'failed-outcome-adds-quiescence-false-other-parent-evidence-preserved'],
			},
			pairTerminalCombinations: ['full/full', 'halt/full', 'full/halt', 'halt/halt', 'failed-transition-terminal/unentered', 'unentered/failed-transition-terminal', 'full/failed-transition-terminal', 'failed-transition-terminal/full', 'halt/failed-transition-terminal', 'failed-transition-terminal/halt'],
			pairTerminalRules: ['first-boundary-failure-preempts-next-launch', 'final-boundary-failure-preserves-existing-peer', 'failed-slot-accepts-inline-transition-failure-or-halt-with-failed-outcome', 'unentered-only-with-failed-transition-terminal', 'never-two-failed-transition-terminals', 'unentered-declared-only-null-pids-zero-traffic-attempts-samples', 'aggregate-after-both-member-terminals-and-teardowns', 'eligibility-conjoins-own-member-evidence-both-gates-fail-on-ineligible-pair'],
			unenteredMember: {
				kind: 'e6-member-unentered',
				schemaVersion: 1,
				bindingFields: ['runId', 'pairIndex', 'windowId', 'member', 'profileDigest', 'scheduleDigest'],
				requiredMarkerFields: ['declaredEntryRef', 'launchingFlipAtUtc', 'neverLaunched'],
				declaredEntryState: 'declared',
				forbiddenStateFlips: ['launching', 'ready', 'complete', 'released'],
				launchingFlipAtUtc: null,
				neverLaunched: true,
				nullIdentityFields: ['mainPid', 'rendererPid', 'saturationUrl'],
				attemptedPerClass: 0,
				scheduleEnumeration: 'all-built-schedule-identities',
				samplerEvidence: 'explicit-absence-no-machinery-ever-registered',
				issueOrdering: 'failed-window-halt-seal-before-unentered-issue',
				rules: ['only-never-launched-successor-of-failed-transition-terminal', 'same-generation-member-profile-and-schedule-binding', 'declared-entry-reference-resolves', 'no-forbidden-flip-anywhere-in-pair-document', 'null-pids-and-saturation-url', 'no-spawn-launch-or-consumed-ready-record', 'zero-attributed-requests-bytes-and-attempts', 'attempted-zero-plus-exact-schedule-complement-closes', 'sampler-absence-record-never-fabricated-zeros', 'no-fault-clock-handshake-evidence', 'own-content-digest-and-seal-required', 'projection-preserves-evidence-and-empty-retained-sets', 'engagement-and-saturation-unavailable-never-passing', 'any-machine-check-failure-refuses-publication'],
			},
			statistics: {
				functions: ['pooledQuantilePair', 'peakBootstrapBound'],
				nullDifferenceAndBoundFields: ['pointAbsMs', 'pointRelPercent', 'upper95AbsMs', 'upper95RelPercent'],
				availabilityField: 'statisticAvailable',
				unavailableReasonField: 'statisticUnavailableReason',
				emptyPopulationReason: 'emptyPopulation',
				rules: ['either-empty-side-short-circuits-before-arithmetic-and-resampling', 'empty-differences-and-bounds-null', 'empty-side-percentiles-remain-null', 'unavailable-marker-false-and-empty-side-disclosed', 'singleton-recomputes-exactly', 'unavailable-never-passes-ceiling', 'validator-recomputes-null-aware-shape', 'aggregate-and-both-receipts-propagate-verbatim', 'retained-generations-unchanged'],
			},
		},
		comparability: {
			optionalRequestTolerancePercent: 5,
			optionalByteTolerancePercent: 10,
			disclosure: ['pair-documents-per-window-per-population', 'paired-regression-gate', 'crossprocess-critical-saturation-gate'],
		},
	};
}

let harnessSchemaCaseNumber = 0;
function checkHarnessProfile(label, document, expectedStatus, expectedText = '') {
	const number = String(++harnessSchemaCaseNumber).padStart(4, '0');
	const filename = path.join(tempDirectory, 'harness-schema-' + number + '.json');
	writeJson(filename, document);
	runChecker(['--profile', filename], expectedStatus, label, expectedText);
}

function makeHarnessProfile(version = 3, includeHarness = true, includeCanonicalV1 = false) {
	const document = clone(profileDocument);
	const synthetic = clone(profileDocument.profiles[0]);
	synthetic.profileId = 'e6-electron-linux-harness-v' + version;
	synthetic.profileVersion = version;
	synthetic.platform = 'electron-linux';
	synthetic.host.os = 'linux';
	synthetic.host.arch = 'x64';
	if (version === 1) delete synthetic.attemptsPerCriticalClassPerRun;
	else synthetic.attemptsPerCriticalClassPerRun = 2000;
	delete synthetic.harnessInstrument;
	if (includeHarness) synthetic.harnessInstrument = makeHarnessInstrumentFixture();
	document.profiles = includeCanonicalV1 ? [synthetic, clone(profileDocument.profiles[0])] : [synthetic];
	document.unselectedPlatforms = document.unselectedPlatforms.filter((entry) => entry.platform !== 'electron-linux');
	if (!includeCanonicalV1) {
		document.unselectedPlatforms.push({
			platform: 'electron-macos',
			status: 'unselected',
			rule: 'freeze-before-any-results-qualify',
		});
	}
	return document;
}

function harnessAt(document, pathSegments) {
	return pathSegments.reduce((value, key) => value[key], document.profiles[0].harnessInstrument);
}

function setHarnessAt(document, pathSegments, value) {
	if (pathSegments.length === 0) {
		document.profiles[0].harnessInstrument = value;
		return;
	}
	const parent = harnessAt(document, pathSegments.slice(0, -1));
	parent[pathSegments[pathSegments.length - 1]] = value;
}

function checkHarnessMutation(label, pathSegments, mutate, expectedText = '') {
	const document = makeHarnessProfile();
	mutate(harnessAt(document, pathSegments), document);
	checkHarnessProfile(label, document, 1, expectedText);
}

// Post-Commit A, profiles[0] is the canonical v3 entry; the synthetic suite
// clones it as the identity baseline the fixture must preserve byte-for-byte
// (the canonical v1 entry lives at profiles[1] and is covered by the
// canonical-document checks below).
const canonicalFirstEntry = clone(profileDocument.profiles[0]);
const validV3Document = makeHarnessProfile(3, true, true);
assert.deepEqual(validV3Document.profiles[1], canonicalFirstEntry, 'synthetic v3 fixture must preserve the first canonical entry byte-shape');
checkHarnessProfile('canonical v1 profile remains valid', clone(profileDocument), 0);
checkHarnessProfile('v1 profile without harnessInstrument remains valid', makeHarnessProfile(1, false), 0);
checkHarnessProfile('v2 profile without harnessInstrument remains valid', makeHarnessProfile(2, false), 0);
checkHarnessProfile('v1 profile with optional harnessInstrument validates', makeHarnessProfile(1, true), 0);
checkHarnessProfile('v2 profile with optional harnessInstrument validates', makeHarnessProfile(2, true), 0);
checkHarnessProfile('complete v3 profile prepended while retaining canonical v1', validV3Document, 0);
checkHarnessProfile('later profile version with harnessInstrument validates', makeHarnessProfile(4, true), 0);
checkHarnessProfile('v3 profile requires harnessInstrument', makeHarnessProfile(3, false), 1, 'harnessInstrument');
for (const version of [1, 2]) {
	const document = makeHarnessProfile(version, true);
	document.profiles[0].harnessInstrument.basis = '';
	checkHarnessProfile(`v${version} present malformed harnessInstrument is rejected`, document, 1, '.basis');
}

const reservedClientBases = [
	'policy-mode-configured',
	'mode-admits-no-optional-work',
	'engine-queue-observed',
	'saturation-endpoint-verified',
	'saturation-endpoint-refuted',
	'policy-mode-configured-unverified',
	'flag-off-comparator-admits-no-optional-work',
];
for (const basis of reservedClientBases) {
	checkHarnessMutation('basis collision rejected: ' + basis, [], (harness) => {
		harness.basis = basis;
		harness.engagement.observedBases.comparator = basis;
	}, 'client basis');
}
checkHarnessProfile('distinct synthetic basis acceptance control', (() => {
	const document = makeHarnessProfile();
	document.profiles[0].harnessInstrument.basis = 'test-only-distinct-harness-basis';
	document.profiles[0].harnessInstrument.engagement.observedBases.comparator = 'test-only-distinct-harness-basis';
	return document;
})(), 0);

const harnessObjectPaths = [];
const harnessStringArrayPaths = [];
const harnessScalarPaths = [];
function collectHarnessPaths(value, segments = []) {
	if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
		harnessObjectPaths.push(segments);
		for (const [key, child] of Object.entries(value)) collectHarnessPaths(child, [...segments, key]);
		return;
	}
	if (Array.isArray(value)) {
		if (value.length > 0 && value.every((entry) => typeof entry === 'string')) harnessStringArrayPaths.push(segments);
		for (const [index, child] of value.entries()) collectHarnessPaths(child, [...segments, index]);
		return;
	}
	harnessScalarPaths.push(segments);
}
collectHarnessPaths(makeHarnessInstrumentFixture());

for (const objectPath of harnessObjectPaths) {
	const base = harnessAt(makeHarnessProfile(), objectPath);
	const display = objectPath.length ? objectPath.join('.') : 'harnessInstrument';
	for (const key of Object.keys(base)) {
		checkHarnessMutation('missing required field ' + display + '.' + key, objectPath, (value) => { delete value[key]; }, 'missing field "' + key + '"');
	}
	checkHarnessMutation('unknown field rejected in ' + display, objectPath, (value) => { value.unexpectedHarnessField = true; }, 'unknown field "unexpectedHarnessField"');
	checkHarnessMutation('non-object rejected at ' + display, objectPath, (_value, document) => { setHarnessAt(document, objectPath, null); }, 'expected an object');
}

const orderedArrayPaths = new Set([
	'phaseBarrier.acknowledgedPhases',
	'phaseBarrier.attemptIdentityFields',
	'phaseBarrier.phaseTime.steps',
	'phaseBarrier.pairState.states',
]);
const exactSetPaths = harnessStringArrayPaths.filter((segments) => !orderedArrayPaths.has(segments.join('.')));
for (const arrayPath of exactSetPaths) {
	const baseline = harnessAt(makeHarnessProfile(), arrayPath);
	for (let index = 0; index < baseline.length; index += 1) {
		checkHarnessMutation('exact set rejects missing ' + arrayPath.join('.') + '[' + index + ']', arrayPath, (value) => { value.splice(index, 1); }, 'expected exact string set');
		checkHarnessMutation('exact set rejects same-type replacement ' + arrayPath.join('.') + '[' + index + ']', arrayPath, (value) => { value[index] = 'unexpected-test-only-rule'; }, 'expected exact string set');
	}
	checkHarnessMutation('exact set rejects unknown member ' + arrayPath.join('.'), arrayPath, (value) => { value.push('unexpected-test-only-rule'); }, 'expected exact string set');
	checkHarnessMutation('exact set rejects duplicate member ' + arrayPath.join('.'), arrayPath, (value) => { value.push(value[0]); }, 'duplicate');
}
const reorderedExactSets = makeHarnessProfile();
for (const arrayPath of exactSetPaths) harnessAt(reorderedExactSets, arrayPath).reverse();
checkHarnessProfile('reordering exact-set arrays remains valid', reorderedExactSets, 0);
for (const arrayPath of orderedArrayPaths) {
	checkHarnessMutation('ordered array rejects reorder ' + arrayPath, arrayPath.split('.'), (value) => { value.reverse(); }, 'expected exactly');
}

const exactArrayPathKeys = new Set(harnessStringArrayPaths.map((segments) => segments.join('.')));
const variableScalarPaths = new Set([
	'basis',
	'workload.routes.0.method',
	'workload.routes.0.path',
	'workload.routes.0.weight',
	'workload.routes.0.body',
	'workload.classMix.interactive',
	'workload.classMix.background',
	'workload.classMix.opportunistic',
	'phaseBarrier.pairState.stagedStateDeadlineMs',
	'phaseBarrier.pairState.armedAckDeadlineMs',
]);
for (const scalarPath of harnessScalarPaths) {
	const key = scalarPath.join('.');
	const original = harnessAt(makeHarnessProfile(), scalarPath);
	const wrongType = original === null ? 'not-null' : typeof original === 'string' ? 7 : 'wrong-type';
	checkHarnessMutation('wrong scalar type rejected: ' + key, scalarPath, (_value, document) => { setHarnessAt(document, scalarPath, wrongType); });
	const parentArrayKey = scalarPath.length > 1 ? scalarPath.slice(0, -1).join('.') : '';
	if (exactArrayPathKeys.has(parentArrayKey) || orderedArrayPaths.has(parentArrayKey) || variableScalarPaths.has(key) || original === null) continue;
	const differentSameType = typeof original === 'string' ? 'different-same-type' : typeof original === 'number' ? original + 1 : !original;
	checkHarnessMutation('fixed scalar rejects alternate value: ' + key, scalarPath, (_value, document) => { setHarnessAt(document, scalarPath, differentSameType); });
}

for (const classMix of [
	{ interactive: 1, background: 1, opportunistic: 1 },
	{ interactive: 0, background: 1, opportunistic: 0 },
	{ interactive: 0, background: 0, opportunistic: 1 },
	{ interactive: 1, background: 0, opportunistic: 0 },
]) {
	const document = makeHarnessProfile();
	document.profiles[0].harnessInstrument.workload.classMix = classMix;
	checkHarnessProfile('admissible nonnegative class mix ' + JSON.stringify(classMix), document, 0);
}
for (const invalidMix of [
	{ interactive: -1, background: 1, opportunistic: 1 },
	{ interactive: 0.5, background: 1, opportunistic: 1 },
	{ interactive: Number.MAX_SAFE_INTEGER + 1, background: 1, opportunistic: 1 },
	{ interactive: 0, background: 0, opportunistic: 0 },
]) {
	const document = makeHarnessProfile();
	document.profiles[0].harnessInstrument.workload.classMix = invalidMix;
	checkHarnessProfile('invalid class mix rejected ' + JSON.stringify(invalidMix), document, 1, 'classMix');
}
const nullBodyDocument = makeHarnessProfile();
nullBodyDocument.profiles[0].harnessInstrument.workload.routes[0].body = null;
checkHarnessProfile('route body null union variant is valid', nullBodyDocument, 0);
const alternateRoutesDocument = makeHarnessProfile();
alternateRoutesDocument.profiles[0].harnessInstrument.workload.routes = [
	{ method: 'POST', path: '/jmap', weight: 2, body: null },
	{ method: 'PUT', path: '/rpc', weight: 3, body: 'synthetic' },
];
alternateRoutesDocument.profiles[0].harnessInstrument.workload.routes.reverse();
alternateRoutesDocument.profiles[0].harnessInstrument.phaseBarrier.pairState.stagedStateDeadlineMs = 45000;
alternateRoutesDocument.profiles[0].harnessInstrument.phaseBarrier.pairState.armedAckDeadlineMs = 15000;
checkHarnessProfile('alternative positive routes weights and prospective deadlines are valid', alternateRoutesDocument, 0);
const distinctBasisDocument = makeHarnessProfile();
distinctBasisDocument.profiles[0].harnessInstrument.basis = 'test-only-distinct-harness-basis';
distinctBasisDocument.profiles[0].harnessInstrument.engagement.observedBases.comparator = 'test-only-distinct-harness-basis';
checkHarnessProfile('second distinct synthetic basis is valid', distinctBasisDocument, 0);

for (const method of ['post', 'POST /jmap', 'POST\n']) {
	checkHarnessMutation('invalid route method rejected ' + JSON.stringify(method), ['workload', 'routes'], (routes) => { routes[0].method = method; }, '.method');
}
for (const routePath of ['', 'jmap', '//other.example/jmap', 'https://other.example/jmap', '/jmap\\admin', '/jmap#fragment', '/jmap\n']) {
	checkHarnessMutation('invalid route path rejected ' + JSON.stringify(routePath), ['workload', 'routes'], (routes) => { routes[0].path = routePath; }, '.path');
}
checkHarnessMutation('empty routes rejected', ['workload'], (workload) => { workload.routes = []; }, 'must not be empty');
checkHarnessMutation('duplicate route tuple rejected', ['workload'], (workload) => { workload.routes.push({ ...workload.routes[0], weight: 2 }); }, 'duplicate method/path/body');
for (const weight of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
	checkHarnessMutation('invalid route weight rejected ' + weight, ['workload', 'routes'], (routes) => { routes[0].weight = weight; }, 'weight');
}
for (const path of [['phaseBarrier', 'pairState', 'stagedStateDeadlineMs'], ['phaseBarrier', 'pairState', 'armedAckDeadlineMs']]) {
	for (const deadline of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
		checkHarnessMutation('invalid prospective deadline rejected ' + path.join('.') + '=' + deadline, path, (_value, document) => { setHarnessAt(document, path, deadline); }, 'safe integer');
	}
}
checkHarnessMutation('comparator basis must echo harness basis', ['engagement', 'observedBases'], (value) => { value.comparator = 'other-distinct-basis'; }, 'expected exactly');
checkHarnessMutation('engagement limit must equal workload concurrency', ['engagement'], (value) => { value.limit = 1; }, 'expected exactly');
checkHarnessMutation('workload accounts must equal profile corpus', ['workload'], (value, document) => {
	value.accounts = 2;
	document.profiles[0].corpus.accounts = 3;
}, 'must equal profile corpus accounts');
checkHarnessMutation('global concurrency must be reachable', ['workload'], (value) => { value.globalConcurrency = 3; }, 'limit is unreachable');
for (const measured of [
	['setjoin-desktop-electron-main'],
	['mailserver-gateway', 'setjoin-desktop-electron-main', 'unexpected-process'],
	['mailserver-gateway', 'mailserver-gateway', 'setjoin-desktop-electron-renderer'],
]) {
	const document = makeHarnessProfile();
	document.profiles[0].processMetricBoundaries.measuredProcesses = measured;
	const expectedDiagnostic = new Set(measured).size === measured.length ? 'metricMapping keys' : 'duplicate ';
	checkHarnessProfile('metric mapping must agree with measured process set ' + JSON.stringify(measured), document, 1, expectedDiagnostic);
}
{
	const document = makeHarnessProfile();
	document.profiles[0].processMetricBoundaries.measuredProcesses = ['mailserver-gateway', 'setjoin-desktop-electron-renderer', 'setjoin-desktop-electron-main'];
	checkHarnessProfile('measured process set permutation remains valid', document, 0);
}
for (const variantChange of [
	{ attachment: ['before-start', 'after-partial-start', 'transition-failed'], inline: [] },
	{ attachment: ['after-partial-start'], inline: ['transition-failed', 'before-start'] },
	{ attachment: ['before-start'], inline: ['transition-failed', 'after-partial-start'] },
]) {
	const document = makeHarnessProfile();
	document.profiles[0].harnessInstrument.phaseBarrier.teardownOutcome.attachmentVariants = variantChange.attachment;
	document.profiles[0].harnessInstrument.phaseBarrier.teardownOutcome.inlineOnlyVariants = variantChange.inline;
	checkHarnessProfile('teardown variant flip rejected while preserving disjoint complete union', document, 1, 'expected exact string set');
}

function replaceHarnessArrayValue(values, oldValue, newValue) {
	const index = values.indexOf(oldValue);
	assert.notEqual(index, -1, 'regression fixture must contain ' + oldValue);
	values[index] = newValue;
}
const namedHarnessRegressions = [
	['old halted-only reference enum', (h) => replaceHarnessArrayValue(h.phaseBarrier.pairState.rules, 'halted-handshake-requires-window-halt-reference', 'halt-reference-required-only-for-halted-arm')],
	['aggregateRef is not a halt reference field', (h) => replaceHarnessArrayValue(h.phaseBarrier.pairState.haltReferenceFields, 'haltRecordRef', 'aggregateRef')],
	['completed transition-failure handshake rule is mandatory', (h) => replaceHarnessArrayValue(h.phaseBarrier.pairState.rules, 'complete-handshake-halt-reference-only-for-own-transition-failed-result', 'complete-handshake-reference-required-for-every-result')],
	['sixth admission hold code is rejected', (h) => h.engagement.admissionHoldCodes.push('networkUnavailable')],
	['plural holdReasons is not an observation field', (h) => h.engagement.observationFields.push('holdReasons')],
	['extra plural holdReasons property is rejected', (h) => { h.engagement.holdReasons = ['backoff']; }],
	['local-copy admission implementation is rejected', (h) => { h.engagement.admissionImplementation = 'local-copy'; }],
	['held branch must require pending work', (h) => { h.engagement.heldRequiresPendingWork = false; }],
	['held pending-work rule may not be omitted', (h) => { delete h.engagement.heldRequiresPendingWork; }],
	['receipt-time phase declaration is rejected', (h) => replaceHarnessArrayValue(h.phaseBarrier.phaseTime.rules, 'delivery-ack-clock-free', 'receipt-time-delivery')],
	['raw-epoch phase declaration is rejected', (h) => replaceHarnessArrayValue(h.phaseBarrier.phaseTime.rules, 'local-start-equals-local-origin-plus-carried-start', 'raw-epoch-start')],
	['broadcast-only phase declaration is rejected', (h) => replaceHarnessArrayValue(h.phaseBarrier.phaseTime.rules, 'broadcast-bound-independent-of-delivery-bound', 'broadcast-only-bound')],
	['strict alignment reply causality is mandatory', (h) => replaceHarnessArrayValue(h.phaseBarrier.phaseTime.rules, 'alignment-reply-precedes-broadcast', 'alignment-reply-may-follow-broadcast')],
	['job-id reservation ownership is rejected', (h) => replaceHarnessArrayValue(h.phaseBarrier.reservationRules, 'reference-identity-ownership', 'by-job-id-ownership')],
	['stale-read mirror rule is rejected', (h) => replaceHarnessArrayValue(h.phaseBarrier.reservationRules, 'live-readmission-suppresses-mirror', 'stale-read-mirror')],
	['closure zero must be scoped to the closed admission epoch', (h) => replaceHarnessArrayValue(h.phaseBarrier.accountingRules, 'closure-zero-scoped-to-closedAdmissionEpoch', 'closure-zero-scoped-to-phase')],
	['unentered member kind is exact', (h) => { h.phaseBarrier.unenteredMember.kind = 'e6-member-halted'; }],
	['unentered member schema version is exact', (h) => { h.phaseBarrier.unenteredMember.schemaVersion = 2; }],
	['unentered member cannot claim a launch timestamp', (h) => { h.phaseBarrier.unenteredMember.launchingFlipAtUtc = '2026-09-26T00:00:00Z'; }],
	['unentered member must affirm neverLaunched', (h) => { h.phaseBarrier.unenteredMember.neverLaunched = false; }],
	['unentered marker fields are exact', (h) => h.phaseBarrier.unenteredMember.requiredMarkerFields.pop()],
	['unentered binding fields are exact', (h) => h.phaseBarrier.unenteredMember.bindingFields.pop()],
	['unentered forbidden flips remain closed', (h) => h.phaseBarrier.unenteredMember.forbiddenStateFlips.pop()],
	['unentered null identity fields remain closed', (h) => h.phaseBarrier.unenteredMember.nullIdentityFields.pop()],
	['unentered schedule must enumerate identities', (h) => { h.phaseBarrier.unenteredMember.scheduleEnumeration = 'counts-only'; }],
	['unentered sampler absence cannot use synthetic zeros', (h) => { h.phaseBarrier.unenteredMember.samplerEvidence = 'synthetic-zero-samples'; }],
	['unentered issue ordering must be strict', (h) => { h.phaseBarrier.unenteredMember.issueOrdering = 'haltRecordSealedAtUtc<=unenteredIssuedAtUtc'; }],
	['unentered projection rule is mandatory', (h) => h.phaseBarrier.unenteredMember.rules.pop()],
	['released attachment variants require an outcome reference', (h) => h.phaseBarrier.pairState.rules.splice(h.phaseBarrier.pairState.rules.indexOf('released-attachment-variants-require-teardown-outcome-reference'), 1)],
	['released transition-failed forbids an outcome reference', (h) => h.phaseBarrier.pairState.rules.splice(h.phaseBarrier.pairState.rules.indexOf('released-transition-failed-forbids-teardown-outcome-reference-uses-inline-receipt'), 1)],
	['released attachment rule rejects weakened wording', (h) => replaceHarnessArrayValue(h.phaseBarrier.pairState.rules, 'released-attachment-variants-require-teardown-outcome-reference', 'released-attachment-variants-allow-missing-teardown-outcome-reference')],
	['released transition-failed rule rejects inverse wording', (h) => replaceHarnessArrayValue(h.phaseBarrier.pairState.rules, 'released-transition-failed-forbids-teardown-outcome-reference-uses-inline-receipt', 'released-transition-failed-requires-teardown-outcome-reference')],
	['transition-failed does not add an attached outcome declaration', (h) => { h.phaseBarrier.teardownOutcome.transitionFailedAttachment = true; }],
	['release references stay exact', (h) => h.phaseBarrier.teardownOutcome.releaseReferenceFields.pop()],
	['inline transition-failed receipt is mandatory', (h) => h.phaseBarrier.teardownOutcome.rules.splice(h.phaseBarrier.teardownOutcome.rules.indexOf('inline-complete-receipt-for-transition-failed'), 1)],
	['double-binding refusal is mandatory', (h) => h.phaseBarrier.teardownOutcome.rules.splice(h.phaseBarrier.teardownOutcome.rules.indexOf('transition-failed-attachment-is-double-binding-refusal'), 1)],
	['null-aware empty differences are mandatory', (h) => h.phaseBarrier.statistics.rules.splice(h.phaseBarrier.statistics.rules.indexOf('empty-differences-and-bounds-null'), 1)],
	['unavailable statistics cannot pass ceilings', (h) => h.phaseBarrier.statistics.rules.splice(h.phaseBarrier.statistics.rules.indexOf('unavailable-never-passes-ceiling'), 1)],
	['aggregate and both receipt propagation is mandatory', (h) => h.phaseBarrier.statistics.rules.splice(h.phaseBarrier.statistics.rules.indexOf('aggregate-and-both-receipts-propagate-verbatim'), 1)],
	['null-aware statistic availability field is exact', (h) => { h.phaseBarrier.statistics.availabilityField = 'coercedZero'; }],
	['null-aware unavailable reason field is exact', (h) => { h.phaseBarrier.statistics.unavailableReasonField = 'fallbackZero'; }],
];
for (const [label, mutate] of namedHarnessRegressions) checkHarnessMutation('named regression rejected: ' + label, [], mutate);

const harnessSchemaCaseSummary = ' E6-harness-schema cases=' + harnessSchemaCaseNumber;


	// E6 verdict consumption, Commit A of the two-commit transition (scheme
	// v24 §5.3): the four sustained-run runtime gate cases are honestly
	// planned with history — their retained v1 generationReceipt bindings
	// were REMOVED from active binding (the v1 receipts stay on disk,
	// untouched, never reattached) and requiredProfiles rebind to the frozen
	// v3 profile. Manifest-only validation proves that state: planned
	// disposition, the v3 binding, the unchanged identity seed, and NO
	// generationReceipt key.
	const sustainedGates = {
		'CAS-E6-CRITICAL-SAMPLE-FLOOR': 'e6-pair-runbook-v1',
		'CAS-E6-PAIRED-REGRESSION': 'e6-pair-runbook-v1',
		'CAS-E6-FAILED-REQUEST-ACCOUNTING': 'e6-attempt-accounting-v1',
		'CAS-E6-CROSSPROCESS-CRITICAL-SATURATION': 'e6-saturation-v1',
	};
	for (const [caseId, seed] of Object.entries(sustainedGates)) {
		const entry = manifest.cases.find((candidate) => candidate.id === caseId);
		assert.ok(entry, `self-test: manifest must carry ${caseId}`);
		assert.equal(entry.expectedDisposition, 'planned', `self-test: ${caseId} must be honestly planned between Commit A and Commit B`);
		assert.deepEqual(entry.requiredProfiles, ['e6-electron-macos-arm64-v3']);
		assert.equal(entry.seed, seed, `self-test: ${caseId} identity seed is unchanged by the rebind`);
		assert.equal(own(entry, 'generationReceipt'), false, `self-test: ${caseId} must not bind a retained generation receipt`);
	}
	const lastV1GenerationReceipt = {
		runId: 'e6h-20260922t024022z-9915a0663542',
		aggregateSha256: '5cb56112f7b7b8603b4281c92c0fba83e8b4d8083c4e2c51f5768eb6e22e1f18',
		gate: 'criticalSampleFloor',
		gatePass: false,
		overallPass: false,
	};
	const receiptNegativeCases = [
		// Both mutations are caught by the manifest walk itself, on any
		// checkout, independent of any retained tree: a generation receipt
		// binds executed evidence, so it may only exist on a sustained-run
		// runtime case with an enforced disposition — the planned-with-history
		// Commit A state can never silently reattach the retained v1 receipt
		// as active binding.
		['E6 generation receipt reattached onto a planned runtime case', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-CRITICAL-SAMPLE-FLOOR').generationReceipt = clone(lastV1GenerationReceipt);
		}, 'expectedDisposition must be "enforced"', false],
		['E6 generation receipt drifted onto a non-runtime case', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-DIAGNOSTIC-BOUNDS').generationReceipt = clone(lastV1GenerationReceipt);
		}, 'may bind a generation receipt', false],
	];
	// The checker's environment signal is a REAL retained generation — a run
	// directory carrying the canonical e6/generation/aggregate.json layout —
	// never the tree root: lane runs create scratch run directories under the
	// same root before invoking the checker. Unit-pin the predicate on
	// synthetic fixtures so it can never silently widen back to root presence.
	const predicateRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-e6-generation-predicate-'));
	try {
		assert.equal(hasRetainedE6Generation(path.join(predicateRoot, 'absent')), false, 'an absent root is not a retained generation');
		fs.mkdirSync(path.join(predicateRoot, 'lane-scratch-run'));
		fs.writeFileSync(path.join(predicateRoot, 'lane-scratch-run', 'run.txt'), 'lane scratch\n');
		assert.equal(hasRetainedE6Generation(predicateRoot), false, 'a lane scratch run is not a retained generation');
		fs.mkdirSync(path.join(predicateRoot, 'e6h-synthetic', 'e6', 'generation'), { recursive: true });
		fs.writeFileSync(path.join(predicateRoot, 'e6h-synthetic', 'e6', 'generation', 'aggregate.json'), '{}\n');
		assert.equal(hasRetainedE6Generation(predicateRoot), true, 'a canonical aggregate layout is a retained generation');
	} finally {
		fs.rmSync(predicateRoot, { recursive: true, force: true });
	}
	const retainedGenerationPresent = hasRetainedE6Generation(path.join(repositoryRoot, 'test-results', 'connectivity-aware-sync'));
	for (const [label, mutate, diagnostic, needsRetainedGeneration] of receiptNegativeCases) {
		const copy = clone(manifest);
		mutate(copy);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-').replaceAll(',', '').replaceAll('(', '').replaceAll(')', '')}.json`);
		writeJson(filename, copy);
		if (needsRetainedGeneration && !retainedGenerationPresent) {
			// Fresh checkout: the retained generation is absent, so manifest-only
			// mode tolerates the citation; the fail-closed arm is pinned by the
			// explicit-results rejections above and wherever a generation exists.
			runChecker([filename], 0, `${label} (fresh-checkout tolerance)`);
			continue;
		}
		runChecker([filename], 1, label, diagnostic);
	}

	// E7 useful-outcome contract freeze: the canonical frozen contract document
	// validates standalone, the four CAS-E7 cases bind owner/fixture/digest/
	// seed/command per the E7 ownership row, and tampering with the contract
	// (outcome-name drift, incomplete-outcome rule, capability scope escape,
	// safety-only substitution) or with the case bindings fails closed.
	const e7CaseIds = [
		'CAS-E7-OUTCOME-CONTRACT-FROZEN',
		'CAS-E7-USEFULNESS-NOT-SAFETY-ONLY',
		'CAS-E7-INCOMPLETE-OUTCOME-NO-EXPANSION',
		'CAS-E7-CAPABILITY-SCOPED-OUTCOME',
	];
	for (const caseId of e7CaseIds) {
		const entry = manifest.cases.find((candidate) => candidate.id === caseId);
		assert.ok(entry, `self-test: manifest must carry ${caseId}`);
		assert.equal(entry.introducedBy, 'E7');
		assert.equal(entry.fixture, 'docs/verification/connectivity-e7-outcome-contract.json');
		assert.match(entry.fixtureDigest, /^[0-9a-f]{64}$/);
		assert.ok(entry.seed && entry.seed.startsWith('e7-'));
		assert.ok(entry.command.includes(caseId), `self-test: ${caseId} command must name its case`);
		assert.equal(entry.expectedDisposition, 'planned');
	}
	const e7ContractFile = path.join(repositoryRoot, 'docs/verification/connectivity-e7-outcome-contract.json');
	runChecker(['--outcome-contract', e7ContractFile], 0, 'canonical frozen E7 outcome contract');
	const e7ContractDocument = JSON.parse(fs.readFileSync(e7ContractFile, 'utf8'));

	// E7 DX/E7 ownership row: the two plan-named E7 cases are manifest-bound
	// (planned, digest-bound fixtures, own seed and rerun command) —
	// CAS-E7-LOCAL-ALL-NOT-RELEASE binds the frozen E6 profile document (the
	// selection/freezing truth) and CAS-E7-CAPABILITY-EVIDENCE-BINDING binds
	// the frozen outcome contract (the capability registry).
	const e7OwnershipCases = [
		['CAS-E7-LOCAL-ALL-NOT-RELEASE', 'docs/verification/connectivity-e6-profile.json', 'e0f441195858370dcf1026a7987126f7c82ef6f3988354a45c62ab5d9f9f9516'],
		['CAS-E7-CAPABILITY-EVIDENCE-BINDING', 'docs/verification/connectivity-e7-outcome-contract.json', '180eee16b7091dad7ef21ef64971a69a450df89950ea9a81f3df660bddbcbb67'],
	];
	for (const [caseId, fixture, digest] of e7OwnershipCases) {
		const entry = manifest.cases.find((candidate) => candidate.id === caseId);
		assert.ok(entry, `self-test: manifest must carry ${caseId}`);
		assert.equal(entry.introducedBy, 'E7');
		assert.equal(entry.fixture, fixture);
		assert.equal(entry.fixtureDigest, digest);
		assert.ok(entry.seed && entry.seed.startsWith('e7-'));
		assert.ok(entry.command.includes(caseId), `self-test: ${caseId} command must name its case`);
		assert.equal(entry.lane, 'quick');
		assert.equal(entry.requiredState, 'required');
		assert.equal(entry.expectedDisposition, 'planned');
		assert.ok(registryByCase.has(caseId), `self-test: ${caseId} must carry an evidence-registry binding`);
	}
	const e7ContractMutations = [
		// CAS-E7-OUTCOME-CONTRACT-FROZEN: plan-derived name membership.
		['E7 outcome name drifts off the plan list', (copy) => { copy.outcomeBindings[0].name = 'time to an instant magic inbox'; }, 'not in the plan'],
		['E7 outcome loses its sample rule', (copy) => { delete copy.outcomeBindings[0].sampleRule; }, 'missing field "sampleRule"'],
		['E7 threshold claims justification without a number', (copy) => { copy.outcomeBindings[1].threshold = { status: 'baseline-justified', basis: 'asserted without a baseline' }; }, 'missing field "value"'],
		// CAS-E7-INCOMPLETE-OUTCOME-NO-EXPANSION: required fields fail closed.
		['E7 incomplete-outcome begin gate disabled', (copy) => { copy.incompleteOutcomeRule.pilotMayNotBeginWithUnspecifiedFields = false; }, 'cannot begin'],
		['E7 rule names an unknown required field', (copy) => { copy.incompleteOutcomeRule.requiredOutcomeFields.push('vibes'); }, 'unknown required outcome field'],
		['E7 pilot scope claimed already executed', (copy) => { copy.pilotScope.status = 'executed'; }, 'expected exactly "planned"'],
		// CAS-E7-CAPABILITY-SCOPED-OUTCOME: scope escape fails closed.
		['E7 outcome escapes its capability scope', (copy) => { copy.outcomeBindings[2].capabilities.push('server-worker-priorities'); }, 'unknown capability'],
		['E7 outcome has no capability scope', (copy) => { copy.outcomeBindings[3].capabilities = []; }, 'must not be empty'],
		['E7 contract binds an unfrozen pilot profile', (copy) => { copy.pilotScope.capabilityProfileBinding.requiredProfileIds = ['e6-electron-macos-arm64-v2']; }, 'is not a frozen selected profile'],
		// CAS-E7-USEFULNESS-NOT-SAFETY-ONLY: safety substitution fails closed.
		['E7 usefulness substituted for safety gates', (copy) => { copy.usefulnessNotSafetyOnly.usefulnessOutcomesSubstituteForSafetyGates = true; }, 'must stay false'],
		['E7 marks the E6 safety gates waivable', (copy) => { copy.usefulnessNotSafetyOnly.e6SafetyGatesRemainNonwaivable = false; }, 'nonwaivable'],
		// Expansion rule, freeze semantics, and structural drift.
		['E7 expansion without a retained pilot decision', (copy) => { copy.expansionRule.retainedPilotDecisionPrecedesExpansion = false; }, 'retained pilot decision precedes expansion'],
		['E7 outcome evidence claimed already executed', (copy) => { copy.freezeSemantics.allOutcomeEvidencePlanned = false; }, 'outcome evidence is planned'],
		['unknown E7 contract document field', (copy) => { copy.extra = true; }, 'unknown field "extra"'],
	];
	for (const [label, mutate, diagnostic] of e7ContractMutations) {
		const copy = clone(e7ContractDocument);
		mutate(copy);
		const filename = path.join(tempDirectory, `e7-${label.replaceAll(' ', '-').replaceAll(',', '')}.json`);
		writeJson(filename, copy);
		runChecker(['--outcome-contract', filename], 1, label, diagnostic);
	}
	// Manifest-side E7 binding drift fails closed even when the document itself
	// is untouched: the digest binds the cases to the exact frozen content.
	const e7ManifestNegativeCases = [
		['E7 case cites a stale contract digest', (copy) => { copy.cases.find((entry) => entry.id === 'CAS-E7-OUTCOME-CONTRACT-FROZEN').fixtureDigest = '0'.repeat(64); }, 'stale binding'],
		['E7 command does not name its case', (copy) => { copy.cases.find((entry) => entry.id === 'CAS-E7-CAPABILITY-SCOPED-OUTCOME').command = 'node scripts/check-connectivity-aware-sync-cases.mjs docs/verification/connectivity-aware-sync-cases.json'; }, 'must contain the exact case ID'],
	];
	for (const [label, mutate, diagnostic] of e7ManifestNegativeCases) {
		const copy = clone(manifest);
		mutate(copy);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-')}.json`);
		writeJson(filename, copy);
		runChecker([filename], 1, label, diagnostic);
	}

	// E7 DX/E7 ownership-row bindings fail closed in both directions the
	// dossier names: capability-scoped outcomes bind only to capability
	// evidence that exists, and the `all` profile selection is a local
	// deterministic aggregate, never E7 release readiness.
	const localAllCaseId = 'CAS-E7-LOCAL-ALL-NOT-RELEASE';
	const capabilityEvidenceCaseId = 'CAS-E7-CAPABILITY-EVIDENCE-BINDING';
	const e7OwnershipNegativeCases = [
		// Admitted-without-evidence: the frozen registry claims a pilot-admitted
		// capability whose owning unit has no actual evidence binding left.
		['E7 capability admitted without E4-I evidence bindings', (copy) => {
			for (const binding of copy.evidenceRegistry) {
				binding.requirementId = binding.requirementId.replace('/e4i/', '/e4i-unbound/');
			}
		}, 'no E4-I capability evidence binding'],
		['E7 capability admitted without E5 evidence bindings', (copy) => {
			for (const binding of copy.evidenceRegistry) {
				binding.requirementId = binding.requirementId.replace('/e5/', '/e5-unbound/');
			}
		}, 'no E5 capability evidence binding'],
		// Ownership-table binding integrity: seed, rerun command, digest,
		// registry binding, and contract kind cannot be silently weakened.
		['E7 ownership case loses its identity seed', (copy) => {
			delete copy.cases.find((entry) => entry.id === localAllCaseId).seed;
		}, 'E7 cases must bind their deterministic seed'],
		['E7 ownership case loses its rerun command', (copy) => {
			delete copy.cases.find((entry) => entry.id === capabilityEvidenceCaseId).command;
		}, 'E7 cases must bind their exact rerun command'],
		['E7 ownership case command does not name its case', (copy) => {
			copy.cases.find((entry) => entry.id === capabilityEvidenceCaseId).command = 'node scripts/check-connectivity-aware-sync-cases.mjs docs/verification/connectivity-aware-sync-cases.json';
		}, 'must contain the exact case ID'],
		['E7 ownership case cites a stale profile digest', (copy) => {
			copy.cases.find((entry) => entry.id === localAllCaseId).fixtureDigest = '0'.repeat(64);
		}, 'stale binding'],
		['E7 ownership case loses its evidence-registry binding', (copy) => {
			copy.evidenceRegistry = copy.evidenceRegistry.filter((binding) => binding.caseId !== localAllCaseId);
		}, 'missing evidence binding for case ID'],
		['E7 ownership case loses its contract', (copy) => {
			delete copy.cases.find((entry) => entry.id === capabilityEvidenceCaseId).contract;
		}, 'E7 cases must bind their contract'],
		['E7 ownership case drifts to an unknown contract kind', (copy) => {
			copy.cases.find((entry) => entry.id === capabilityEvidenceCaseId).contract.kind = 'e7-bogus';
		}, 'unknown E7 contract kind'],
		// Each ownership case binds exactly its canonical document: the local-all
		// case the frozen E6 profile document, the capability-evidence case the
		// frozen E7 outcome contract (digests swapped to keep only the fixture
		// binding under test).
		['E7 local-all case bound to the wrong canonical document', (copy) => {
			const entry = copy.cases.find((candidate) => candidate.id === localAllCaseId);
			entry.fixture = 'docs/verification/connectivity-e7-outcome-contract.json';
			entry.fixtureDigest = '180eee16b7091dad7ef21ef64971a69a450df89950ea9a81f3df660bddbcbb67';
		}, 'must bind the frozen E6 profile document'],
		['E7 capability-evidence case bound to the wrong canonical document', (copy) => {
			const entry = copy.cases.find((candidate) => candidate.id === capabilityEvidenceCaseId);
			entry.fixture = 'docs/verification/connectivity-e6-profile.json';
			entry.fixtureDigest = 'e0f441195858370dcf1026a7987126f7c82ef6f3988354a45c62ab5d9f9f9516';
		}, 'must bind the frozen E7 outcome contract'],
		// `all` is a local deterministic aggregate, not E7 release readiness:
		// the sustained selected-profile runtime evidence cases stay required
		// and profile-bound, a pseudo-profile `all` binding is rejected, and a
		// profile-bound case can never carry the local checker as its evidence.
		['E7 sustained runtime gate removed from the manifest', (copy) => {
			copy.cases = copy.cases.filter((entry) => entry.id !== 'CAS-E6-CROSSPROCESS-CRITICAL-SATURATION');
			copy.evidenceRegistry = copy.evidenceRegistry.filter((binding) => binding.caseId !== 'CAS-E6-CROSSPROCESS-CRITICAL-SATURATION');
		}, 'CAS-E6-CROSSPROCESS-CRITICAL-SATURATION'],
		['E7 sustained runtime gate downgraded to conditional', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-PAIRED-REGRESSION').requiredState = 'conditional';
		}, 'CAS-E6-PAIRED-REGRESSION'],
		['E7 all selection rejected as a pseudo-profile binding', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-PAIRED-REGRESSION').requiredProfiles = ['all'];
		}, 'local deterministic aggregate, not a frozen profile'],
		['E7 local aggregate command cannot be runtime evidence', (copy) => {
			copy.cases.find((entry) => entry.id === 'CAS-E6-PAIRED-REGRESSION').command = 'node scripts/check-connectivity-aware-sync-cases.mjs docs/verification/connectivity-aware-sync-cases.json --case CAS-E6-PAIRED-REGRESSION';
		}, 'not selected-profile runtime evidence'],
	];
	for (const [label, mutate, diagnostic] of e7OwnershipNegativeCases) {
		const copy = clone(manifest);
		mutate(copy);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-')}.json`);
		writeJson(filename, copy);
		runChecker([filename], 1, label, diagnostic);
	}
	// A capability that is not admitted to the pilot cannot inherit a usefulness
	// claim: a primary-usefulness outcome must bind at least one pilot-admitted
	// capability from the frozen registry.
	const e7AdmissionMutations = [
		['E7 primary-usefulness outcome claims only a non-admitted capability', (copy) => {
			copy.outcomeBindings[0].capabilities = ['attachment-prefetch'];
		}, 'pilot-admitted capability'],
	];
	for (const [label, mutate, diagnostic] of e7AdmissionMutations) {
		const copy = clone(e7ContractDocument);
		mutate(copy);
		const filename = path.join(tempDirectory, `e7-${label.replaceAll(' ', '-').replaceAll(',', '')}.json`);
		writeJson(filename, copy);
		runChecker(['--outcome-contract', filename], 1, label, diagnostic);
	}

	// Results identity: every bound field is required and validated.
	const focusedResults = () => focusedResultsDoc(manifest, registryByCase, 'self-test-run', focusedCase);
	const resultsNegativeCases = [
		['results run identity missing', (document) => { delete document.runId; }, 'missing field "runId"'],
		['results utc time missing', (document) => { delete document.utcTime; }, 'missing field "utcTime"'],
		['unbound result entry', (document) => { delete document.results[0].resultId; }, 'missing field "resultId"'],
		['result lane missing', (document) => { delete document.results[0].lane; }, 'missing field "lane"'],
		['result artifacts missing', (document) => { delete document.results[0].retainedArtifacts; }, 'missing field "retainedArtifacts"'],
		['result artifacts empty', (document) => { document.results[0].retainedArtifacts = []; }, 'retainedArtifacts'],
		['stale result identity', (document) => { document.results[0].resultId = 'result-forged'; }, 'does not match the evidence registry binding'],
		['result lane mismatch', (document) => { document.results[0].lane = 'browser'; }, 'does not match the evidence registry binding lane'],
		['artifact not bound to run', (document) => { document.results[0].retainedArtifacts = ['test-results/connectivity-aware-sync/<run-id>/e4i/other.json']; }, 'is not a retained artifact declared by case'],
		['artifact bound to another run', (document) => { document.results[0].retainedArtifacts = [document.results[0].retainedArtifacts[0].replace('self-test-run', 'other-run')]; }, 'is not a retained artifact declared by case'],
	];
	for (const [label, mutate, diagnostic] of resultsNegativeCases) {
		const document = focusedResults();
		mutate(document);
		const filename = path.join(tempDirectory, `${label.replaceAll(' ', '-')}.json`);
		writeJson(filename, document);
		runChecker([manifestFile, filename, '--case', focusedCase], 1, label, diagnostic);
	}

	// Evidence can never exist for a planned fixture that has no file.
	const plannedCase = manifest.cases.find((entry) => !fs.existsSync(path.join(repositoryRoot, entry.fixture)));
	assert.ok(plannedCase, 'self-test: manifest must carry planned fixture cases');
	const fabricated = {
		schemaVersion: 1,
		runId: 'self-test-run',
		utcTime: '2026-08-11T00:00:00Z',
		results: [{
			caseId: plannedCase.id,
			status: 'passed',
			resultId: registryByCase.get(plannedCase.id).resultId,
			lane: registryByCase.get(plannedCase.id).lane,
			retainedArtifacts: plannedCase.retainedArtifacts.map((artifact) => artifact.replace('<run-id>', 'self-test-run')),
		}],
	};
	const fabricatedFile = path.join(tempDirectory, 'fabricated-planned-result.json');
	writeJson(fabricatedFile, fabricated);
	runChecker([manifestFile, fabricatedFile, '--case', plannedCase.id], 1, 'evidence for a planned fixture rejection', 'fixture');

	for (const status of ['skipped', 'ambiguous', 'malformed', 'flaky-after-retry', 'failed']) {
		const document = focusedResults();
		document.results[0].status = status;
		const filename = path.join(tempDirectory, `result-${status}.json`);
		writeJson(filename, document);
		runChecker([manifestFile, filename, '--case', focusedCase], 1, `required ${status} rejection`, `required evidence reported ${status}`);
	}

	// A non-focused run must cover every bindable required case: a document
	// that covers only one bindable case is missing the rest.
	const partialCoverage = focusedResults();
	partialCoverage.results = partialCoverage.results.filter((result) => result.caseId === focusedCase);
	const partialCoverageFile = path.join(tempDirectory, 'partial-coverage.json');
	writeJson(partialCoverageFile, partialCoverage);
	runChecker([manifestFile, partialCoverageFile], 1, 'missing result case rejection', 'missing result case ID');

	runChecker([manifestFile, focusedResultsFile, '--case', focusedCase], 0, 'focused bound evidence still passes after negatives');

	const unknownResults = focusedResults();
	unknownResults.results[0].caseId = 'CAS-UNKNOWN';
	const unknownResultsFile = path.join(tempDirectory, 'unknown-results.json');
	writeJson(unknownResultsFile, unknownResults);
	runChecker([manifestFile, unknownResultsFile], 1, 'unknown result case rejection', 'CAS-UNKNOWN');

	const duplicateResults = focusedResults();
	duplicateResults.results.push({ ...duplicateResults.results[0] });
	const duplicateResultsFile = path.join(tempDirectory, 'duplicate-results.json');
	writeJson(duplicateResultsFile, duplicateResults);
	runChecker([manifestFile, duplicateResultsFile, '--case', focusedCase], 1, 'duplicate result case rejection', 'duplicate result case ID');

	const extraFocusedResults = focusedResults();
	extraFocusedResults.results.push({ ...extraFocusedResults.results[0], caseId: 'CAS-E4I-PERSISTENCE-RECOVERY', resultId: registryByCase.get('CAS-E4I-PERSISTENCE-RECOVERY').resultId });
	const extraFocusedResultsFile = path.join(tempDirectory, 'extra-focused-results.json');
	writeJson(extraFocusedResultsFile, extraFocusedResults);
	runChecker([manifestFile, extraFocusedResultsFile, '--case', focusedCase], 1, 'focused extra case rejection', 'outside exact');

	const duplicateKeyFile = path.join(tempDirectory, 'duplicate-key.json');
	fs.writeFileSync(duplicateKeyFile, '{"schemaVersion":1,"schemaVersion":1,"program":"x","authority":"x","cases":[],"evidenceRegistry":[]}', 'utf8');
	runChecker([duplicateKeyFile], 1, 'duplicate JSON key rejection', 'duplicate JSON field "schemaVersion"');

	const decisionFile = path.join(tempDirectory, 'decision.json');
	writeJson(decisionFile, makeDecision());
	runChecker(['--decision', decisionFile], 0, 'privacy-safe decision record');
	for (const forbiddenField of ['accountId', 'userId', 'deviceId', 'jobId', 'ssid', 'carrier', 'ipAddress', 'subject', 'sender', 'filename', 'token', 'url', 'content']) {
		const decision = makeDecision();
		decision[forbiddenField] = 'forbidden';
		const filename = path.join(tempDirectory, `decision-${forbiddenField}.json`);
		writeJson(filename, decision);
		runChecker(['--decision', filename], 1, `forbidden decision field ${forbiddenField}`, forbiddenField);
	}
	for (const [container, forbiddenField] of [['requested', 'jobId'], ['effective', 'filename'], ['policySource', 'deviceId'], ['capabilitySource', 'token'], ['queue', 'accountId']]) {
		const decision = makeDecision();
		decision[container][forbiddenField] = 'forbidden';
		const filename = path.join(tempDirectory, `decision-${container}-${forbiddenField}.json`);
		writeJson(filename, decision);
		runChecker(['--decision', filename], 1, `nested forbidden decision field ${container}.${forbiddenField}`, forbiddenField);
	}

	const cleanupFile = path.join(tempDirectory, 'cleanup.json');
	writeJson(cleanupFile, makeCleanup('cleaned'));
	runChecker(['--cleanup', cleanupFile], 0, 'first cleanup receipt');
	const secondCleanupFile = path.join(tempDirectory, 'cleanup-second.json');
	writeJson(secondCleanupFile, makeCleanup('already_clean'));
	runChecker(['--cleanup', secondCleanupFile], 0, 'idempotent second cleanup receipt');

	const failedCleanup = makeCleanup('failed');
	for (const action of Object.values(failedCleanup.actions)) {
		action.manualRecoveryCommand = 'RUN_ID=self-test bash scripts/verify-connectivity-aware-sync.sh --cleanup';
	}
	const failedCleanupFile = path.join(tempDirectory, 'cleanup-failed.json');
	writeJson(failedCleanupFile, failedCleanup);
	runChecker(['--cleanup', failedCleanupFile], 0, 'failed cleanup with recovery command');

	const invalidCleanup = makeCleanup('failed');
	const invalidCleanupFile = path.join(tempDirectory, 'cleanup-invalid.json');
	writeJson(invalidCleanupFile, invalidCleanup);
	runChecker(['--cleanup', invalidCleanupFile], 1, 'failed cleanup without recovery command', 'manualRecoveryCommand');

	console.log('connectivity-aware-sync self-test: PASS (positive, duplicate, missing, unknown, invalid-state, result-status, binding-digest, result-identity, evidence-existence, planned-fabrication, privacy, idempotent-cleanup, E6-profile-freeze, E6-generation-receipt-binding, E7-outcome-contract-freeze, and E7-ownership-row-binding fixtures)' + harnessSchemaCaseSummary);
} finally {
	// The self-test owns exactly the run-scoped evidence it created under the
	// repository root; nothing else in test-results is touched. The focused
	// receipts live in the self-test-scoped subtree so the real retained
	// receipts tree (test-results/connectivity-aware-sync/) is only ever
	// present when a real generation is.
	fs.rmSync(path.join(repositoryRoot, 'test-results', 'selftest-connectivity'), { recursive: true, force: true });
	fs.rmSync(tempDirectory, { recursive: true, force: true });
}
