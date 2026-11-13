#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readRetainedE6Generation, hasRetainedE6Generation, E6_RUNTIME_CASE_GATES } from './run-connectivity-e6-harness.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RUN_ID_PLACEHOLDER = /<run-id>/g;

const LANES = new Set(['quick', 'core', 'browser', 'native', 'ubuntu', 'all']);
const REQUIRED_STATES = new Set(['required', 'conditional']);
const EXPECTED_DISPOSITIONS = new Set(['planned', 'enforced']);
const RESULT_STATUSES = new Set(['passed', 'skipped', 'ambiguous', 'malformed', 'flaky-after-retry', 'failed', 'not-run']);
const GATES = new Set(['merge', 'release', 'local']);
const CASE_ID_RE = /^[A-Z][A-Z0-9-]+$/;
// E4-I names its owning implementation unit with a dashed suffix; the E0/DX0
// hyphenless forms remain valid (2026-09-08 verification bindings, E4-I row).
const INTRODUCED_BY_RE = /^(?:E|DX)[0-9]+(?:-[A-Z0-9]+)?$/;
const SAFE_PATH_RE = /^[^\\\0]+$/;
const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const FORBIDDEN_DECISION_FIELD_RE = /account|user|device|job|ssid|carrier|ip|subject|sender|filename|token|url|content/i;
const SHA256_RE = /^[0-9a-f]{64}$/;

const CONTRACT_KEYS = new Set(['kind', 'version', 'featureFlag', 'assertions', 'values', 'thresholds', 'symbols']);
const THRESHOLD_KEYS = new Set([
	'quietResumeSeconds',
	'minimumRuns',
	'minimumSamples',
	'maxP95RegressionPercent',
	'maxP95RegressionMilliseconds',
	'maxP99RegressionPercent',
	'maxP99RegressionMilliseconds',
	'maxCpuRssRegressionPercent',
	// E6 comparison/diagnostics freeze numbers (plan R4 E6 + section 8).
	'minimumObservations',
	'warmupSeconds',
	'measurementSeconds',
	'maxDiagnosticRecords',
	'maxDiagnosticBytes',
	'diagnosticExpiryDays',
	'maximumExportBytes',
	'maxExportAttempts',
	'minimumAggregateContributors',
]);
// E6 profile bindings live in one canonical versioned document; freeze
// discipline is repo-wide, so a manifest that binds profiles at all fails
// closed unless this exact document exists and validates.
const E6_PROFILE_REL = 'docs/verification/connectivity-e6-profile.json';
// The manifest-only rerun command prefix: machinery that validates admission/
// report logic locally. A case bound to requiredProfiles (selected-profile
// runtime evidence) can never carry it as its runtime evidence.
const LOCAL_MANIFEST_CHECKER_COMMAND = 'node scripts/check-connectivity-aware-sync-cases.mjs';
const E6_PLATFORMS = new Set(['electron-macos', 'electron-windows', 'electron-linux', 'ios', 'android', 'harmonyos']);
const CRITICAL_REQUEST_CLASSES = new Set(['queued-send', 'draft-commit', 'auth-revocation', 'security-state', 'delivery-receipt']);
// E7 outcome-contract bindings live in one canonical versioned document. The
// pilot itself is a later, separately gated run: until then every field is
// honestly planned/unexecuted, and the checker freezes the contract STRUCTURE —
// names, capability scopes and the three fail-closed rules — not results.
const E7_CONTRACT_REL = 'docs/verification/connectivity-e7-outcome-contract.json';
// Verbatim durable-metric names from the plan's "Metrics and initial success
// criteria" section. CAS-E7-OUTCOME-CONTRACT-FROZEN rejects an outcome name
// absent from that list, so drift off the plan cannot validate.
const E7_PLAN_OUTCOME_NAMES = new Set([
	'time to useful cached list and time to server-current state',
	'bytes transferred per useful opened item',
	'delta-to-full-window sync ratio and fallback reason',
	'cache hit, stale age, occupancy, eviction, and storage pressure',
	'resumed bytes versus restarted bytes, resume success, and verified attachment completions/failures per attempt',
	'work completion/age by class, including critical starvation count (target zero)',
	'foreground latency/CPU contention while background work runs',
	'background grant/useful-progress/cancellation rates by platform',
	'aggregate battery/runtime/network-cost buckets without content or location',
]);
const E7_CAPABILITY_OWNERS = new Set(['E4-I', 'E5']);
const E7_OUTCOME_ROLES = new Set(['primary-usefulness', 'secondary']);
const E7_OUTCOME_CONTRACT_KINDS = new Set([
	'e7-outcome-contract-frozen',
	'e7-usefulness-not-safety-only',
	'e7-incomplete-outcome-no-expansion',
	'e7-capability-scoped-outcome',
	'e7-capability-evidence-binding',
]);
// Every contract kind an E7-introduced manifest case may bind. The plan's
// DX/E7 ownership row adds CAS-E7-LOCAL-ALL-NOT-RELEASE, which binds the E6
// profile document (the selection/freezing truth), not the outcome contract —
// so it is an E7 kind but deliberately not an E7 outcome-contract kind.
const E7_CASE_KINDS = new Set([...E7_OUTCOME_CONTRACT_KINDS, 'e7-local-all-not-release']);
// The sustained selected-profile runtime evidence cases the E7 release gate
// consumes (E7 dossier §3 status vocabulary). "`all` is a local deterministic
// aggregate, not E7 release readiness": these required, profile-bound cases
// are the runtime evidence the aggregate can never substitute for.
const E7_RELEASE_RUNTIME_CASE_IDS = new Set([
	'CAS-E6-CRITICAL-SAMPLE-FLOOR',
	'CAS-E6-PAIRED-REGRESSION',
	'CAS-E6-FAILED-REQUEST-ACCOUNTING',
	'CAS-E6-CROSSPROCESS-CRITICAL-SATURATION',
]);
// Executed E6 consumption: the sustained-run cases move from planned to
// enforced only with a manifest `generationReceipt` binding the exact sealed
// generation (run ID + aggregate sha-256 + verdict fields). The checker
// validates the receipt against the retained generation on disk, so a receipt
// that was never published, or whose verdict fields were altered without a new
// sealed generation, fails closed.
const GENERATION_RECEIPT_KEYS = ['runId', 'aggregateSha256', 'gate', 'gatePass', 'overallPass'];
// Gates whose recorded PASS asserts a measured performance claim: such a pass
// additionally requires exact host/profile qualification. The accounting gate
// asserts only the attempt partition (bookkeeping), so its pass records
// qualification unavailability in the receipt instead of claiming admission.
const E6_PROFILE_CLAIM_GATES = new Set(['criticalSampleFloor', 'pairedRegression', 'crossprocessCriticalSaturation']);
// Capability-scoped outcomes bind only to capability evidence that exists: a
// pilot-admitted capability's owning unit must have actual evidence bindings
// in the manifest evidence registry under that unit's requirement-id segment.
const E7_OWNER_EVIDENCE_SEGMENTS = new Map([['E4-I', 'e4i'], ['E5', 'e5']]);
const E7_REQUIRED_OUTCOME_FIELDS = new Set(['threshold', 'sampleRule', 'missingDataRule', 'cohort', 'observationWindow', 'denominator', 'offComparator']);
const E7_SCOPE_FIELD_STATUSES = new Set(['specified', 'planned-until-pilot-admission']);

function fail(message) {
	throw new Error(message);
}

function own(object, key) {
	return Object.prototype.hasOwnProperty.call(object, key);
}

function expectObject(value, location) {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${location}: expected an object`);
}

function expectArray(value, location) {
	if (!Array.isArray(value)) fail(`${location}: expected an array`);
}

function expectString(value, location) {
	if (typeof value !== 'string' || value.trim() === '') fail(`${location}: expected a non-empty string`);
}

function expectInteger(value, location, { minimum = Number.MIN_SAFE_INTEGER, maximum = Number.MAX_SAFE_INTEGER, positive = false } = {}) {
	if (!Number.isInteger(value) || (positive ? value <= 0 : value < minimum) || value > maximum) {
		fail(`${location}: expected an integer ${positive ? '> 0' : `>= ${minimum}`} and <= ${maximum}`);
	}
}

function exactKeys(value, location, required, optional = []) {
	expectObject(value, location);
	const allowed = new Set([...required, ...optional]);
	for (const key of Object.keys(value)) {
		if (!allowed.has(key)) {
			if (location === 'decision' || location.startsWith('decision.')) {
				if (FORBIDDEN_DECISION_FIELD_RE.test(key)) fail(`${location}: forbidden field "${key}"`);
			}
			fail(`${location}: unknown field "${key}"`);
		}
	}
	for (const key of required) {
		if (!own(value, key)) fail(`${location}: missing field "${key}"`);
	}
}

function expectEnum(value, location, values) {
	if (typeof value !== 'string' || !values.has(value)) fail(`${location}: invalid value ${JSON.stringify(value)}`);
}

function expectSafeRelativePath(value, location) {
	expectString(value, location);
	if (path.posix.isAbsolute(value) || value.startsWith('/') || value === '..' || value.startsWith('../') || value.includes('/../') || !SAFE_PATH_RE.test(value)) {
		fail(`${location}: path must be a safe repository-relative path`);
	}
}

function expectUnique(values, label) {
	const seen = new Set();
	for (const value of values) {
		if (seen.has(value)) fail(`duplicate ${label} "${value}"`);
		seen.add(value);
	}
}

function expectStringArray(value, location, { nonEmpty = true } = {}) {
	expectArray(value, location);
	if (nonEmpty && value.length === 0) fail(`${location}: must not be empty`);
	for (const [index, item] of value.entries()) expectString(item, `${location}[${index}]`);
}

function validateContract(value, location) {
	exactKeys(value, location, ['kind'], ['version', 'featureFlag', 'assertions', 'values', 'thresholds', 'symbols']);
	expectString(value.kind, `${location}.kind`);
	if (own(value, 'version')) expectInteger(value.version, `${location}.version`, { positive: true });
	if (own(value, 'featureFlag')) expectString(value.featureFlag, `${location}.featureFlag`);
	if (own(value, 'assertions')) expectStringArray(value.assertions, `${location}.assertions`);
	if (own(value, 'values')) {
		expectStringArray(value.values, `${location}.values`);
		expectUnique(value.values, `${location}.values entry`);
	}
	if (own(value, 'thresholds')) {
		expectObject(value.thresholds, `${location}.thresholds`);
		for (const key of Object.keys(value.thresholds)) {
			if (!THRESHOLD_KEYS.has(key)) fail(`${location}.thresholds: unknown field "${key}"`);
			expectInteger(value.thresholds[key], `${location}.thresholds.${key}`, { positive: true });
		}
	}
	if (own(value, 'symbols')) {
		expectStringArray(value.symbols, `${location}.symbols`);
		expectUnique(value.symbols, `${location}.symbols entry`);
	}
}

function validateUtc(value, location) {
	expectString(value, location);
	if (!UTC_RE.test(value) || !Number.isFinite(Date.parse(value))) fail(`${location}: expected a canonical UTC timestamp ending in Z`);
}

function expectPositiveInt(value, location, { minimum = 1 } = {}) {
	if (!Number.isInteger(value) || value < minimum) fail(`${location}: expected an integer >= ${minimum}`);
}

function expectExact(value, location, expected) {
	if (value !== expected) fail(`${location}: expected exactly ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`);
}

function expectExactStringSet(value, location, expected) {
	expectStringArray(value, location, { nonEmpty: false });
	expectUnique(value, location + ' entry');
	if (value.length !== expected.length || expected.some((entry) => !value.includes(entry))) {
		fail(location + ': expected exact string set ' + JSON.stringify(expected));
	}
}

function expectExactOrderedStrings(value, location, expected) {
	expectArray(value, location);
	if (value.length !== expected.length) fail(location + ': expected exactly ' + JSON.stringify(expected));
	for (let index = 0; index < expected.length; index += 1) {
		expectExact(value[index], location + '[' + index + ']', expected[index]);
	}
}

function expectSafeInteger(value, location, minimum) {
	if (!Number.isSafeInteger(value) || value < minimum) {
		fail(location + ': expected a safe integer >= ' + minimum);
	}
}

function validateHarnessInstrument(harness, profile, location) {
	exactKeys(harness, location, ['basis', 'executor', 'workload', 'engagement', 'quiescence', 'phaseBarrier', 'comparability']);

	const clientBases = [
		'policy-mode-configured',
		'mode-admits-no-optional-work',
		'engine-queue-observed',
		'saturation-endpoint-verified',
		'saturation-endpoint-refuted',
		'policy-mode-configured-unverified',
		'flag-off-comparator-admits-no-optional-work',
	];
	expectString(harness.basis, location + '.basis');
	if (clientBases.includes(harness.basis)) fail(location + '.basis: collides with client basis ' + JSON.stringify(harness.basis));

	const executorLocation = location + '.executor';
	exactKeys(harness.executor, executorLocation, [
		'launchOwner', 'window', 'scope', 'processCount', 'measuredProcess',
		'credentials', 'deliveryPath', 'criticalPopulation', 'metricMapping',
	]);
	for (const [key, expected] of Object.entries({
		launchOwner: 'harness',
		window: 'comparator',
		scope: 'run-scoped-comparator-window',
		credentials: 'comparator-session',
		deliveryPath: 'window-fault-proxy',
		criticalPopulation: 'separate-from-driver-schedule',
	})) expectExact(harness.executor[key], executorLocation + '.' + key, expected);
	expectExact(harness.executor.processCount, executorLocation + '.processCount', 1);
	expectExact(harness.executor.measuredProcess, executorLocation + '.measuredProcess', false);
	const mappingLocation = executorLocation + '.metricMapping';
	const metricRoles = [
		'mailserver-gateway',
		'setjoin-desktop-electron-main',
		'setjoin-desktop-electron-renderer',
	];
	exactKeys(harness.executor.metricMapping, mappingLocation, metricRoles);
	expectExact(harness.executor.metricMapping['mailserver-gateway'], mappingLocation + '.mailserver-gateway', 'equal-attributed-load');
	expectExact(harness.executor.metricMapping['setjoin-desktop-electron-main'], mappingLocation + '.setjoin-desktop-electron-main', 'production-execute-engine-residual');
	expectExact(harness.executor.metricMapping['setjoin-desktop-electron-renderer'], mappingLocation + '.setjoin-desktop-electron-renderer', 'production-execute-engine-residual');
	const measuredProcesses = profile && profile.processMetricBoundaries && profile.processMetricBoundaries.measuredProcesses;
	if (!Array.isArray(measuredProcesses)) fail(location + ': processMetricBoundaries.measuredProcesses must be an array');
	expectExactStringSet(Object.keys(harness.executor.metricMapping), mappingLocation + ' keys', measuredProcesses);
	expectExactStringSet(measuredProcesses, location + '.processMetricBoundaries.measuredProcesses', metricRoles);

	const workloadLocation = location + '.workload';
	exactKeys(harness.workload, workloadLocation, [
		'routes', 'classMix', 'accounts', 'globalConcurrency', 'perAccountConcurrency', 'equivalenceRule',
	]);
	expectArray(harness.workload.routes, workloadLocation + '.routes');
	if (harness.workload.routes.length === 0) fail(workloadLocation + '.routes: must not be empty');
	const routeTuples = new Set();
	for (const [index, route] of harness.workload.routes.entries()) {
		const routeLocation = workloadLocation + '.routes[' + index + ']';
		exactKeys(route, routeLocation, ['method', 'path', 'weight', 'body']);
		expectString(route.method, routeLocation + '.method');
		if (!/^[A-Z0-9!#$%&'*+.^_\x60|~-]+$/.test(route.method)) {
			fail(routeLocation + '.method: expected a non-empty uppercase HTTP token');
		}
		expectString(route.path, routeLocation + '.path');
		if (!route.path.startsWith('/') || route.path.startsWith('//') || route.path.includes('\\') ||
			route.path.includes('#') || /[\u0000-\u001f\u007f]/.test(route.path)) {
			fail(routeLocation + '.path: expected a safe origin-relative path');
		}
		let resolvedRoute;
		try {
			resolvedRoute = new URL(route.path, 'http://e6.invalid');
		} catch {
			fail(routeLocation + '.path: expected a valid origin-relative path');
		}
		if (resolvedRoute.origin !== 'http://e6.invalid') fail(routeLocation + '.path: must not change proxy origin');
		expectSafeInteger(route.weight, routeLocation + '.weight', 1);
		if (route.body !== null && typeof route.body !== 'string') fail(routeLocation + '.body: expected a string or null');
		const tuple = JSON.stringify([route.method, route.path, route.body]);
		if (routeTuples.has(tuple)) fail(routeLocation + ': duplicate method/path/body route tuple');
		routeTuples.add(tuple);
	}
	const classMixLocation = workloadLocation + '.classMix';
	exactKeys(harness.workload.classMix, classMixLocation, ['interactive', 'background', 'opportunistic']);
	let classMixTotal = 0;
	for (const key of ['interactive', 'background', 'opportunistic']) {
		const value = harness.workload.classMix[key];
		expectSafeInteger(value, classMixLocation + '.' + key, 0);
		classMixTotal += value;
	}
	if (classMixTotal === 0) fail(classMixLocation + ': at least one class weight must be greater than zero');
	if (harness.workload.globalConcurrency > harness.workload.accounts * harness.workload.perAccountConcurrency) {
		fail(workloadLocation + '.globalConcurrency: limit is unreachable with the declared accounts and per-account concurrency');
	}
	expectExact(harness.workload.accounts, workloadLocation + '.accounts', 2);
	expectExact(harness.workload.globalConcurrency, workloadLocation + '.globalConcurrency', 2);
	expectExact(harness.workload.perAccountConcurrency, workloadLocation + '.perAccountConcurrency', 1);
	if (harness.workload.accounts !== profile.corpus.accounts) fail(workloadLocation + '.accounts: must equal profile corpus accounts');
	expectExact(harness.workload.equivalenceRule, workloadLocation + '.equivalenceRule', 'same-declared-routes-mix-and-limits');

	const engagementLocation = location + '.engagement';
	exactKeys(harness.engagement, engagementLocation, [
		'limit', 'pollIntervalMs', 'freshnessPollIntervals', 'observedBases', 'observationFields',
		'reasonShape', 'reasonSource', 'reasonTimestamp', 'pendingSet', 'atLimitPredicate',
		'admissionHoldCodes', 'heldRequiresPendingWork', 'refutingClasses', 'admissionImplementation',
		'productionModules', 'backoffRules',
	]);
	expectExact(harness.engagement.limit, engagementLocation + '.limit', harness.workload.globalConcurrency);
	expectExact(harness.engagement.pollIntervalMs, engagementLocation + '.pollIntervalMs', 1000);
	expectExact(harness.engagement.freshnessPollIntervals, engagementLocation + '.freshnessPollIntervals', 2);
	exactKeys(harness.engagement.observedBases, engagementLocation + '.observedBases', ['candidate', 'comparator']);
	expectExact(harness.engagement.observedBases.candidate, engagementLocation + '.observedBases.candidate', 'engine-queue-observed');
	expectExact(harness.engagement.observedBases.comparator, engagementLocation + '.observedBases.comparator', harness.basis);
	expectExactStringSet(harness.engagement.observationFields, engagementLocation + '.observationFields', [
		'basis', 'optionalRunning', 'optionalQueued', 'limit', 'holdReason', 'holdSinceUtc', 'observedAtUtc', 'saturating',
	]);
	expectExact(harness.engagement.reasonShape, engagementLocation + '.reasonShape', 'single-effective-hold-or-null');
	expectExact(harness.engagement.reasonSource, engagementLocation + '.reasonSource', 'current-consistent-production-admission-observation');
	expectExact(harness.engagement.reasonTimestamp, engagementLocation + '.reasonTimestamp', 'same-observation');
	expectExact(harness.engagement.pendingSet, engagementLocation + '.pendingSet', 'queued-and-unexpired-backoff');
	expectExact(harness.engagement.atLimitPredicate, engagementLocation + '.atLimitPredicate', 'optionalRunning>=limit');
	expectExactStringSet(harness.engagement.admissionHoldCodes, engagementLocation + '.admissionHoldCodes', [
		'backoff', 'criticalActivity', 'criticalQuiet', 'accountSaturation', 'deficit',
	]);
	expectExact(harness.engagement.heldRequiresPendingWork, engagementLocation + '.heldRequiresPendingWork', true);
	expectExactStringSet(harness.engagement.refutingClasses, engagementLocation + '.refutingClasses', [
		'empty', 'below-limit-no-reason', 'unknown-hold', 'fallback-basis', 'stale-observation',
		'missing-observation', 'unreachable-observation', 'malformed-observation', 'reason-counter-contradiction',
	]);
	expectExact(harness.engagement.admissionImplementation, engagementLocation + '.admissionImplementation', 'production-module-imports');
	expectExactStringSet(harness.engagement.productionModules, engagementLocation + '.productionModules', [
		'mailserver/webmail/src/lib/offline/scheduler.ts',
		'mailserver/webmail/src/lib/offline/work-contract.ts',
	]);
	expectExactStringSet(harness.engagement.backoffRules, engagementLocation + '.backoffRules', [
		'retryableFailure-arms-backoff',
		'networkFlap-observation-only',
		'committed-progress-or-newer-authenticated-trigger-resets',
		'run-seeded-randomness',
	]);

	const quiescenceLocation = location + '.quiescence';
	exactKeys(harness.quiescence, quiescenceLocation, ['drainSettleDeadlineMs', 'settledIntervalMs']);
	expectExact(harness.quiescence.drainSettleDeadlineMs, quiescenceLocation + '.drainSettleDeadlineMs', 2000);
	expectExact(harness.quiescence.settledIntervalMs, quiescenceLocation + '.settledIntervalMs', 5000);

	const barrierLocation = location + '.phaseBarrier';
	exactKeys(harness.phaseBarrier, barrierLocation, [
		'rosters', 'transports', 'acknowledgedPhases', 'candidateRouteRules', 'preActivationAttempts',
		'preActivationRules', 'pauseDrainRules', 'requestHeaders', 'attemptIdentityFields',
		'attemptIdentityRules', 'corsAllowedHeaders', 'corsRules', 'phaseTime', 'pairState',
		'reservationRules', 'handshakeStatuses', 'handshakeRules', 'operationalFailures',
		'accountingRules', 'haltRecord', 'teardownOutcome', 'pairTerminalCombinations',
		'pairTerminalRules', 'unenteredMember', 'statistics',
	]);
	exactKeys(harness.phaseBarrier.rosters, barrierLocation + '.rosters', ['candidate', 'comparator']);
	expectExactStringSet(harness.phaseBarrier.rosters.candidate, barrierLocation + '.rosters.candidate', ['proxy', 'driver', 'sampler', 'coordinator']);
	expectExactStringSet(harness.phaseBarrier.rosters.comparator, barrierLocation + '.rosters.comparator', ['proxy', 'driver', 'sampler', 'instrument']);
	exactKeys(harness.phaseBarrier.transports, barrierLocation + '.transports', ['proxy', 'sampler', 'driver', 'instrument', 'coordinator']);
	for (const [key, expected] of Object.entries({
		proxy: 'in-process',
		sampler: 'in-process',
		driver: 'stdio-control-fd-through-wrapper',
		instrument: 'stdio-control-fd-direct',
		coordinator: 'pair-state-loopback-main-renderer',
	})) expectExact(harness.phaseBarrier.transports[key], barrierLocation + '.transports.' + key, expected);
	expectExactOrderedStrings(harness.phaseBarrier.acknowledgedPhases, barrierLocation + '.acknowledgedPhases', ['warmup', 'measurement']);
	expectExactStringSet(harness.phaseBarrier.candidateRouteRules, barrierLocation + '.candidateRouteRules', [
		'candidate-only', 'loopback-endpoint', 'run-scoped-nonce-handshake', 'main-renderer-push-and-ack',
		'boot-dispatch-queued-until-common-start', 'trigger-ingestion-remains-active',
		'absent-without-harness-seam', 'absent-in-off-comparator',
	]);
	expectExact(harness.phaseBarrier.preActivationAttempts, barrierLocation + '.preActivationAttempts', 0);
	expectExactStringSet(harness.phaseBarrier.preActivationRules, barrierLocation + '.preActivationRules', [
		'warmup-starts-at-window-start',
		'later-phase-starts-at-observed-pause-ack-after-closure',
		'ends-at-common-start-minus-participant-rtt-half',
		'dedicated-counter-outside-workload-and-control-ledgers',
		'fail-fast-without-upstream-draw-or-bandwidth',
	]);
	expectExactStringSet(harness.phaseBarrier.pauseDrainRules, barrierLocation + '.pauseDrainRules', [
		'pause-before-measurement-handshake', 'warmup-pause-vacuous', 'per-request-admission',
		'synchronous-generation-read-at-dispatch-and-await-resumption', 'settle-existing-work',
		'await-launched-executions-in-finally', 'defensive-zero-ack-guard',
		'ack-gated-rearm-after-ledger-closure', 'reopen-at-common-executable-start',
	]);
	expectExactStringSet(harness.phaseBarrier.requestHeaders, barrierLocation + '.requestHeaders', [
		'x-e6-dispatch-phase-epoch', 'x-e6-attempt-id', 'x-e6-request-seq',
	]);
	expectExactOrderedStrings(harness.phaseBarrier.attemptIdentityFields, barrierLocation + '.attemptIdentityFields', [
		'dispatchPhaseEpoch', 'attemptId', 'requestSeq',
	]);
	expectExactStringSet(harness.phaseBarrier.attemptIdentityRules, barrierLocation + '.attemptIdentityRules', [
		'stamps-read-in-authorizing-synchronous-segment', 'request-sequence-starts-at-one',
		'closed-epoch-terminal-identity-is-duplicate', 'unseen-closed-epoch-identity-is-halting-drain-breach',
		'unstamped-forbidden-arrival-is-preactivation-failure',
	]);
	expectExactStringSet(harness.phaseBarrier.corsAllowedHeaders, barrierLocation + '.corsAllowedHeaders', [
		'content-type', 'x-e6-proxy-source', 'x-e6-dispatch-phase-epoch', 'x-e6-attempt-id', 'x-e6-request-seq',
	]);
	expectExactStringSet(harness.phaseBarrier.corsRules, barrierLocation + '.corsRules', [
		'declared-loopback-origin-only', 'credentials-enabled', 'preflight-and-actual-responses',
		'config-digest-bound', 'options-only-control-exclusion', 'post-fully-accounted-and-body-readable',
	]);

	const phaseTimeLocation = barrierLocation + '.phaseTime';
	exactKeys(harness.phaseBarrier.phaseTime, phaseTimeLocation, [
		'steps', 'clock', 'alignmentExchangesPerParticipantPerPhase',
		'phaseAnchorRoundTripDeadlineMs', 'workReleaseDeliveryDeadlineMs', 'rules',
	]);
	expectExactOrderedStrings(harness.phaseBarrier.phaseTime.steps, phaseTimeLocation + '.steps', [
		'delivery-acknowledgment', 'epoch-establishment-and-alignment', 'work-release',
	]);
	expectExact(harness.phaseBarrier.phaseTime.clock, phaseTimeLocation + '.clock', 'harness-local-monotonic');
	expectExact(harness.phaseBarrier.phaseTime.alignmentExchangesPerParticipantPerPhase, phaseTimeLocation + '.alignmentExchangesPerParticipantPerPhase', 1);
	expectExact(harness.phaseBarrier.phaseTime.phaseAnchorRoundTripDeadlineMs, phaseTimeLocation + '.phaseAnchorRoundTripDeadlineMs', 250);
	expectExact(harness.phaseBarrier.phaseTime.workReleaseDeliveryDeadlineMs, phaseTimeLocation + '.workReleaseDeliveryDeadlineMs', 250);
	expectExactStringSet(harness.phaseBarrier.phaseTime.rules, phaseTimeLocation + '.rules', [
		'delivery-ack-clock-free', 'epoch-after-all-delivery-acks', 'release-after-all-alignment-acks',
		'start-equals-broadcast-plus-delivery-lead', 'local-start-equals-local-origin-plus-carried-start',
		'permission-delivered-strictly-before-start', 'early-recipients-hold-until-start',
		'all-grids-stages-and-timers-share-start', 'participant-tolerance-rtt-half',
		'broadcast-bound-independent-of-delivery-bound', 'alignment-bound-independent-of-drain-bound',
		'alignment-reply-precedes-broadcast', 'slot-stage-mapping-and-equal-stage-exposure',
	]);

	const pairStateLocation = barrierLocation + '.pairState';
	exactKeys(harness.phaseBarrier.pairState, pairStateLocation, [
		'schemaVersion', 'states', 'stagedStateDeadlineMs', 'armedAckDeadlineMs',
		'haltReferenceFields', 'rules',
	]);
	expectExact(harness.phaseBarrier.pairState.schemaVersion, pairStateLocation + '.schemaVersion', 2);
	expectExactOrderedStrings(harness.phaseBarrier.pairState.states, pairStateLocation + '.states', [
		'declared', 'launching', 'ready', 'complete', 'released',
	]);
	expectSafeInteger(harness.phaseBarrier.pairState.stagedStateDeadlineMs, pairStateLocation + '.stagedStateDeadlineMs', 1);
	expectSafeInteger(harness.phaseBarrier.pairState.armedAckDeadlineMs, pairStateLocation + '.armedAckDeadlineMs', 1);
	expectExactStringSet(harness.phaseBarrier.pairState.haltReferenceFields, pairStateLocation + '.haltReferenceFields', [
		'failureClass', 'haltedAtUtc', 'haltRecordRef',
	]);
	expectExactStringSet(harness.phaseBarrier.pairState.rules, pairStateLocation + '.rules', [
		'both-shells-at-creation', 'listeners-bound-before-launch', 'declared-null-readiness',
		'launching-valid-main-pid-other-readiness-pending', 'ready-complete-distinct-identity',
		'complete-preserves-ready-identity', 'halted-handshake-requires-window-halt-reference',
		'complete-handshake-halt-reference-only-for-own-transition-failed-result',
		'halt-reference-binds-sealed-window-record-never-pair-aggregate',
		'released-preserves-halt-reference',
		'released-attachment-variants-require-teardown-outcome-reference',
		'released-transition-failed-forbids-teardown-outcome-reference-uses-inline-receipt',
		'complete-after-measurement-or-sealed-window-halt', 'released-preserves-identity-adds-absence-evidence',
		'next-launch-after-prior-release', 'comparator-has-no-candidate-seam',
	]);

	expectExactStringSet(harness.phaseBarrier.reservationRules, barrierLocation + '.reservationRules', [
		'reference-identity-ownership', 'selection-install-same-synchronous-segment',
		'expired-writes-after-install-inside-wrapper', 'single-transfer-at-execution-push',
		'every-exit-releases-only-owned-untransferred', 'all-releases-by-reference',
		'preserve-other-cycles-and-global-per-account-limits', 'backoff-pre-await-reference-release',
		'post-await-backoff-queue-only', 'live-readmission-suppresses-mirror',
		'fresh-same-segment-terminal-read-suppresses-enqueue', 'preserve-backoff-envelope-and-queue-age',
	]);
	expectExactStringSet(harness.phaseBarrier.handshakeStatuses, barrierLocation + '.handshakeStatuses', ['complete', 'halted']);
	expectExactStringSet(harness.phaseBarrier.handshakeRules, barrierLocation + '.handshakeRules', [
		'complete-has-all-phase-acks-and-clock-evidence', 'halted-has-failure-observation-and-completed-prefix',
		'unexecuted-steps-marked-halted-before-step', 'prefix-and-remainder-crosschecked-with-ledger-and-acks',
		'missing-or-contradicting-evidence-refuses-publication', 'well-formed-operational-failure-publishes-fail',
	]);
	expectExactStringSet(harness.phaseBarrier.operationalFailures, barrierLocation + '.operationalFailures', [
		'late-broadcast', 'late-delivery', 'alignment-overrun', 'drain-breach', 'slot-stage-mismatch',
	]);
	expectExactStringSet(harness.phaseBarrier.accountingRules, barrierLocation + '.accountingRules', [
		'scheduled-from-built-plan', 'attempted-from-terminal-ledger', 'unexecuted-enumerated-schedule-complement',
		'complete-attempted-equals-scheduled-and-unexecuted-zero',
		'halted-attempted-plus-unexecuted-equals-scheduled', 'sampler-lifecycle-independent-counts',
		'never-admitted-participant-zero', 'post-admission-legitimate-attempts-retained',
		'closure-zero-scoped-to-closedAdmissionEpoch', 'current-epoch-before-halt-remains-legitimate',
		'nonclosing-partition-refuses-publication',
	]);

	const haltLocation = barrierLocation + '.haltRecord';
	exactKeys(harness.phaseBarrier.haltRecord, haltLocation, ['kind', 'schemaVersion', 'variants', 'haltPhases', 'measurementPhases', 'rules']);
	expectExact(harness.phaseBarrier.haltRecord.kind, haltLocation + '.kind', 'e6-window-halt');
	expectExact(harness.phaseBarrier.haltRecord.schemaVersion, haltLocation + '.schemaVersion', 1);
	expectExactStringSet(harness.phaseBarrier.haltRecord.variants, haltLocation + '.variants', ['before-start', 'after-partial-start', 'transition-failed']);
	expectExactStringSet(harness.phaseBarrier.haltRecord.haltPhases, haltLocation + '.haltPhases', ['warmup', 'measurement', 'teardown']);
	expectExactStringSet(harness.phaseBarrier.haltRecord.measurementPhases, haltLocation + '.measurementPhases', ['entered', 'unentered']);
	expectExactStringSet(harness.phaseBarrier.haltRecord.rules, haltLocation + '.rules', [
		'phase-draining-entry-before-step-zero', 'phase-aware-machinery-and-halt-latch',
		'unentered-measurement-unarmed-no-measurement-evidence',
		'entered-unarmed-has-breach-entry-no-armed-evidence',
		'armed-before-start-honest-zero-sample-lifecycle',
		'partial-start-retains-timestamped-samples-and-recomputed-peaks',
		'warmup-halt-preserves-own-lifecycle-measurement-unentered',
		'transition-failed-binds-valid-completed-result', 'transition-failed-teardown-entered-and-armed',
		'h2-seals-window-record-before-teardown-ack', 'parent-record-immutable',
		'capture-inadequacy-recorded-false-when-honest', 'observation-floor-computed-never-waived',
		'seals-bindings-ledger-and-statistics-still-validated', 'fabricated-evidence-refuses-publication',
	]);

	const teardownLocation = barrierLocation + '.teardownOutcome';
	exactKeys(harness.phaseBarrier.teardownOutcome, teardownLocation, [
		'kind', 'schemaVersion', 'attachmentVariants', 'inlineOnlyVariants', 'outcomeClasses',
		'parentBindingFields', 'releaseReferenceFields', 'rules',
	]);
	expectExact(harness.phaseBarrier.teardownOutcome.kind, teardownLocation + '.kind', 'e6-teardown-outcome');
	expectExact(harness.phaseBarrier.teardownOutcome.schemaVersion, teardownLocation + '.schemaVersion', 1);
	expectExactStringSet(harness.phaseBarrier.teardownOutcome.attachmentVariants, teardownLocation + '.attachmentVariants', ['before-start', 'after-partial-start']);
	expectExactStringSet(harness.phaseBarrier.teardownOutcome.inlineOnlyVariants, teardownLocation + '.inlineOnlyVariants', ['transition-failed']);
	expectExactStringSet(harness.phaseBarrier.teardownOutcome.outcomeClasses, teardownLocation + '.outcomeClasses', ['passed', 'failed']);
	expectExactStringSet(harness.phaseBarrier.teardownOutcome.parentBindingFields, teardownLocation + '.parentBindingFields', ['haltRecordRef', 'haltRecordDigest']);
	expectExactStringSet(harness.phaseBarrier.teardownOutcome.releaseReferenceFields, teardownLocation + '.releaseReferenceFields', ['outcomeClass', 'teardownOutcomeRef', 'teardownOutcomeDigest']);
	const attachmentVariants = harness.phaseBarrier.teardownOutcome.attachmentVariants;
	const inlineOnlyVariants = harness.phaseBarrier.teardownOutcome.inlineOnlyVariants;
	if (attachmentVariants.some((variant) => inlineOnlyVariants.includes(variant)) ||
		new Set([...attachmentVariants, ...inlineOnlyVariants]).size !== harness.phaseBarrier.haltRecord.variants.length ||
		harness.phaseBarrier.haltRecord.variants.some((variant) => !attachmentVariants.includes(variant) && !inlineOnlyVariants.includes(variant))) {
		fail(teardownLocation + ': attachment and inline-only variants must be disjoint and cover every halt variant');
	}
	expectExactStringSet(harness.phaseBarrier.teardownOutcome.rules, teardownLocation + '.rules', [
		'same-generation-window-binding-as-parent', 'exactly-one-attachment-for-attachment-variant',
		'inline-complete-receipt-for-transition-failed', 'transition-failed-attachment-is-double-binding-refusal',
		'complete-receipt-all-applicable-assertions', 'passed-all-assertions-ok',
		'failed-at-least-one-evidence-consistent-not-ok', 'no-measurement-evidence-in-attachment',
		'parent-seal-before-outcome-seal-before-release', 'parent-never-rewritten-or-resealed',
		'pair-binds-parent-and-outcome-digests', 'failed-outcome-adds-quiescence-false-other-parent-evidence-preserved',
	]);
	expectExactStringSet(harness.phaseBarrier.pairTerminalCombinations, barrierLocation + '.pairTerminalCombinations', [
		'full/full', 'halt/full', 'full/halt', 'halt/halt',
		'failed-transition-terminal/unentered', 'unentered/failed-transition-terminal',
		'full/failed-transition-terminal', 'failed-transition-terminal/full',
		'halt/failed-transition-terminal', 'failed-transition-terminal/halt',
	]);
	expectExactStringSet(harness.phaseBarrier.pairTerminalRules, barrierLocation + '.pairTerminalRules', [
		'first-boundary-failure-preempts-next-launch', 'final-boundary-failure-preserves-existing-peer',
		'failed-slot-accepts-inline-transition-failure-or-halt-with-failed-outcome',
		'unentered-only-with-failed-transition-terminal', 'never-two-failed-transition-terminals',
		'unentered-declared-only-null-pids-zero-traffic-attempts-samples',
		'aggregate-after-both-member-terminals-and-teardowns',
		'eligibility-conjoins-own-member-evidence-both-gates-fail-on-ineligible-pair',
	]);

	const unenteredLocation = barrierLocation + '.unenteredMember';
	exactKeys(harness.phaseBarrier.unenteredMember, unenteredLocation, [
		'kind', 'schemaVersion', 'bindingFields', 'requiredMarkerFields', 'declaredEntryState',
		'forbiddenStateFlips', 'launchingFlipAtUtc', 'neverLaunched', 'nullIdentityFields',
		'attemptedPerClass', 'scheduleEnumeration', 'samplerEvidence', 'issueOrdering', 'rules',
	]);
	expectExact(harness.phaseBarrier.unenteredMember.kind, unenteredLocation + '.kind', 'e6-member-unentered');
	expectExact(harness.phaseBarrier.unenteredMember.schemaVersion, unenteredLocation + '.schemaVersion', 1);
	expectExactStringSet(harness.phaseBarrier.unenteredMember.bindingFields, unenteredLocation + '.bindingFields', [
		'runId', 'pairIndex', 'windowId', 'member', 'profileDigest', 'scheduleDigest',
]);
	expectExactStringSet(harness.phaseBarrier.unenteredMember.requiredMarkerFields, unenteredLocation + '.requiredMarkerFields', [
		'declaredEntryRef', 'launchingFlipAtUtc', 'neverLaunched',
]);
	expectExact(harness.phaseBarrier.unenteredMember.declaredEntryState, unenteredLocation + '.declaredEntryState', 'declared');
	expectExactStringSet(harness.phaseBarrier.unenteredMember.forbiddenStateFlips, unenteredLocation + '.forbiddenStateFlips', [
		'launching', 'ready', 'complete', 'released',
]);
	expectExact(harness.phaseBarrier.unenteredMember.launchingFlipAtUtc, unenteredLocation + '.launchingFlipAtUtc', null);
	expectExact(harness.phaseBarrier.unenteredMember.neverLaunched, unenteredLocation + '.neverLaunched', true);
	expectExactStringSet(harness.phaseBarrier.unenteredMember.nullIdentityFields, unenteredLocation + '.nullIdentityFields', [
		'mainPid', 'rendererPid', 'saturationUrl',
]);
	expectExact(harness.phaseBarrier.unenteredMember.attemptedPerClass, unenteredLocation + '.attemptedPerClass', 0);
	expectExact(harness.phaseBarrier.unenteredMember.scheduleEnumeration, unenteredLocation + '.scheduleEnumeration', 'all-built-schedule-identities');
	expectExact(harness.phaseBarrier.unenteredMember.samplerEvidence, unenteredLocation + '.samplerEvidence', 'explicit-absence-no-machinery-ever-registered');
	expectExact(harness.phaseBarrier.unenteredMember.issueOrdering, unenteredLocation + '.issueOrdering', 'failed-window-halt-seal-before-unentered-issue');
	expectExactStringSet(harness.phaseBarrier.unenteredMember.rules, unenteredLocation + '.rules', [
		'only-never-launched-successor-of-failed-transition-terminal',
		'same-generation-member-profile-and-schedule-binding', 'declared-entry-reference-resolves',
		'no-forbidden-flip-anywhere-in-pair-document', 'null-pids-and-saturation-url',
		'no-spawn-launch-or-consumed-ready-record', 'zero-attributed-requests-bytes-and-attempts',
		'attempted-zero-plus-exact-schedule-complement-closes',
		'sampler-absence-record-never-fabricated-zeros', 'no-fault-clock-handshake-evidence',
		'own-content-digest-and-seal-required', 'projection-preserves-evidence-and-empty-retained-sets',
		'engagement-and-saturation-unavailable-never-passing',
		'any-machine-check-failure-refuses-publication',
	]);

	const statisticsLocation = barrierLocation + '.statistics';
	exactKeys(harness.phaseBarrier.statistics, statisticsLocation, [
		'functions', 'nullDifferenceAndBoundFields', 'availabilityField', 'unavailableReasonField',
		'emptyPopulationReason', 'rules',
	]);
	expectExactStringSet(harness.phaseBarrier.statistics.functions, statisticsLocation + '.functions', ['pooledQuantilePair', 'peakBootstrapBound']);
	expectExactStringSet(harness.phaseBarrier.statistics.nullDifferenceAndBoundFields, statisticsLocation + '.nullDifferenceAndBoundFields', [
		'pointAbsMs', 'pointRelPercent', 'upper95AbsMs', 'upper95RelPercent',
]);
	expectExact(harness.phaseBarrier.statistics.availabilityField, statisticsLocation + '.availabilityField', 'statisticAvailable');
	expectExact(harness.phaseBarrier.statistics.unavailableReasonField, statisticsLocation + '.unavailableReasonField', 'statisticUnavailableReason');
	expectExact(harness.phaseBarrier.statistics.emptyPopulationReason, statisticsLocation + '.emptyPopulationReason', 'emptyPopulation');
	expectExactStringSet(harness.phaseBarrier.statistics.rules, statisticsLocation + '.rules', [
		'either-empty-side-short-circuits-before-arithmetic-and-resampling',
		'empty-differences-and-bounds-null', 'empty-side-percentiles-remain-null',
		'unavailable-marker-false-and-empty-side-disclosed', 'singleton-recomputes-exactly',
		'unavailable-never-passes-ceiling', 'validator-recomputes-null-aware-shape',
		'aggregate-and-both-receipts-propagate-verbatim', 'retained-generations-unchanged',
	]);

	const comparabilityLocation = location + '.comparability';
	exactKeys(harness.comparability, comparabilityLocation, [
		'optionalRequestTolerancePercent', 'optionalByteTolerancePercent', 'disclosure',
	]);
	expectExact(harness.comparability.optionalRequestTolerancePercent, comparabilityLocation + '.optionalRequestTolerancePercent', 5);
	expectExact(harness.comparability.optionalByteTolerancePercent, comparabilityLocation + '.optionalByteTolerancePercent', 10);
	expectExactStringSet(harness.comparability.disclosure, comparabilityLocation + '.disclosure', [
		'pair-documents-per-window-per-population', 'paired-regression-gate', 'crossprocess-critical-saturation-gate',
	]);
}

function validateFrozenProfileEntry(profile, location) {
	exactKeys(profile, location, [
		'profileId', 'profileVersion', 'status', 'frozenAtUtc', 'platform', 'host', 'shell', 'toolchain',
		'corpus', 'clients', 'criticalRequestClasses', 'optionalSaturation', 'networkFaults',
		'processMetricBoundaries', 'clockAndSeeds',
	], ['attemptsPerCriticalClassPerRun', 'harnessInstrument']);
	expectString(profile.profileId, `${location}.profileId`);
	if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(profile.profileId)) fail(`${location}.profileId: expected a lowercase hyphenated identifier`);
	expectPositiveInt(profile.profileVersion, `${location}.profileVersion`);
	if (profile.profileVersion === 1) {
		if (own(profile, 'attemptsPerCriticalClassPerRun')) fail(`${location}: changing the v1 attempt budget requires a new profileVersion`);
	} else {
		expectPositiveInt(profile.attemptsPerCriticalClassPerRun, `${location}.attemptsPerCriticalClassPerRun`, { minimum: 1001 });
		const interval = 300000 / (profile.attemptsPerCriticalClassPerRun * 5);
		if (!Number.isInteger(interval) || interval < 10) fail(`${location}.attemptsPerCriticalClassPerRun: schedule requires an integer interval >= 10ms`);
	}

	if (profile.profileVersion >= 3 && !own(profile, 'harnessInstrument')) {
		fail(`${location}: missing field \"harnessInstrument\" for profileVersion >= 3`);
	}
	if (own(profile, 'harnessInstrument')) validateHarnessInstrument(profile.harnessInstrument, profile, `${location}.harnessInstrument`);

	// Everything inside profiles[] is frozen by construction; selections that
	// are not frozen yet belong in unselectedPlatforms, never here.
	expectExact(profile.status, `${location}.status`, 'frozen');
	validateUtc(profile.frozenAtUtc, `${location}.frozenAtUtc`);
	expectEnum(profile.platform, `${location}.platform`, E6_PLATFORMS);

	exactKeys(profile.host, `${location}.host`, ['os', 'arch', 'selection']);
	expectString(profile.host.os, `${location}.host.os`);
	expectString(profile.host.arch, `${location}.host.arch`);
	expectExact(profile.host.selection, `${location}.host.selection`, 'explicit');

	exactKeys(profile.shell, `${location}.shell`, ['name', 'build', 'contractVersion']);
	expectString(profile.shell.name, `${location}.shell.name`);
	expectString(profile.shell.build, `${location}.shell.build`);
	expectExact(profile.shell.contractVersion, `${location}.shell.contractVersion`, 1);

	exactKeys(profile.toolchain, `${location}.toolchain`, ['node', 'go', 'rust']);
	for (const tool of ['node', 'go', 'rust']) expectString(profile.toolchain[tool], `${location}.toolchain.${tool}`);

	exactKeys(profile.corpus, `${location}.corpus`, ['accounts', 'messagesPerAccount', 'attachmentsPerAccount', 'cacheState']);
	expectPositiveInt(profile.corpus.accounts, `${location}.corpus.accounts`);
	expectPositiveInt(profile.corpus.messagesPerAccount, `${location}.corpus.messagesPerAccount`);
	expectPositiveInt(profile.corpus.attachmentsPerAccount, `${location}.corpus.attachmentsPerAccount`);
	expectEnum(profile.corpus.cacheState, `${location}.corpus.cacheState`, new Set(['cold-per-pair', 'warm-persistent']));

	exactKeys(profile.clients, `${location}.clients`, ['pairRoles', 'buildBinding']);
	expectStringArray(profile.clients.pairRoles, `${location}.clients.pairRoles`);
	if (profile.clients.pairRoles.length !== 2) fail(`${location}.clients.pairRoles: a comparison pair has exactly two roles`);
	expectExact(profile.clients.pairRoles[0], `${location}.clients.pairRoles[0]`, 'flag-off-comparator');
	expectExact(profile.clients.pairRoles[1], `${location}.clients.pairRoles[1]`, 'execute-candidate');
	expectString(profile.clients.buildBinding, `${location}.clients.buildBinding`);

	// Critical request classes/mix: the five plan Critical classes, all bound,
	// with a mix that sums to exactly 100 percent.
	expectArray(profile.criticalRequestClasses, `${location}.criticalRequestClasses`);
	if (profile.criticalRequestClasses.length === 0) fail(`${location}.criticalRequestClasses: must not be empty`);
	const seenClasses = new Set();
	let mixTotal = 0;
	for (const [index, entry] of profile.criticalRequestClasses.entries()) {
		exactKeys(entry, `${location}.criticalRequestClasses[${index}]`, ['class', 'mixPercent']);
		expectString(entry.class, `${location}.criticalRequestClasses[${index}].class`);
		if (!CRITICAL_REQUEST_CLASSES.has(entry.class)) fail(`${location}.criticalRequestClasses[${index}].class: unknown Critical class "${entry.class}"`);
		if (seenClasses.has(entry.class)) fail(`${location}.criticalRequestClasses[${index}].class: duplicate Critical class "${entry.class}"`);
		seenClasses.add(entry.class);
		expectPositiveInt(entry.mixPercent, `${location}.criticalRequestClasses[${index}].mixPercent`);
		mixTotal += entry.mixPercent;
	}
	for (const required of CRITICAL_REQUEST_CLASSES) {
		if (!seenClasses.has(required)) fail(`${location}.criticalRequestClasses: missing Critical class "${required}"`);
	}
	if (mixTotal !== 100) fail(`${location}.criticalRequestClasses: mix must total exactly 100 percent, got ${mixTotal}`);

	exactKeys(profile.optionalSaturation, `${location}.optionalSaturation`, ['admitted', 'description']);
	if (profile.optionalSaturation.admitted !== true) fail(`${location}.optionalSaturation.admitted: the comparison saturates optional load`);
	expectString(profile.optionalSaturation.description, `${location}.optionalSaturation.description`);

	exactKeys(profile.networkFaults, `${location}.networkFaults`, ['stages', 'outage']);
	expectArray(profile.networkFaults.stages, `${location}.networkFaults.stages`);
	if (profile.networkFaults.stages.length === 0) fail(`${location}.networkFaults.stages: must not be empty`);
	const seenStages = new Set();
	for (const [index, stage] of profile.networkFaults.stages.entries()) {
		exactKeys(stage, `${location}.networkFaults.stages[${index}]`, ['name', 'bandwidthKbit', 'latencyMs', 'lossPercent']);
		expectString(stage.name, `${location}.networkFaults.stages[${index}].name`);
		if (seenStages.has(stage.name)) fail(`${location}.networkFaults.stages[${index}].name: duplicate stage "${stage.name}"`);
		seenStages.add(stage.name);
		expectPositiveInt(stage.bandwidthKbit, `${location}.networkFaults.stages[${index}].bandwidthKbit`);
		expectPositiveInt(stage.latencyMs, `${location}.networkFaults.stages[${index}].latencyMs`);
		if (!Number.isFinite(stage.lossPercent) || stage.lossPercent < 0 || stage.lossPercent > 100) {
			fail(`${location}.networkFaults.stages[${index}].lossPercent: expected a percentage in [0, 100]`);
		}
	}
	exactKeys(profile.networkFaults.outage, `${location}.networkFaults.outage`, ['countPerMeasurement', 'durationSeconds', 'reconnectWithinSeconds', 'schedule']);
	expectPositiveInt(profile.networkFaults.outage.countPerMeasurement, `${location}.networkFaults.outage.countPerMeasurement`);
	expectPositiveInt(profile.networkFaults.outage.durationSeconds, `${location}.networkFaults.outage.durationSeconds`);
	expectPositiveInt(profile.networkFaults.outage.reconnectWithinSeconds, `${location}.networkFaults.outage.reconnectWithinSeconds`);
	expectEnum(profile.networkFaults.outage.schedule, `${location}.networkFaults.outage.schedule`, new Set(['fixed-mid-measurement']));

	exactKeys(profile.processMetricBoundaries, `${location}.processMetricBoundaries`, ['measuredProcesses', 'sampleIntervalMs']);
	expectStringArray(profile.processMetricBoundaries.measuredProcesses, `${location}.processMetricBoundaries.measuredProcesses`);
	expectPositiveInt(profile.processMetricBoundaries.sampleIntervalMs, `${location}.processMetricBoundaries.sampleIntervalMs`);

	exactKeys(profile.clockAndSeeds, `${location}.clockAndSeeds`, ['clock', 'runSeed', 'orderSeed', 'bootstrapSeed']);
	for (const field of ['clock', 'runSeed', 'orderSeed', 'bootstrapSeed']) {
		expectString(profile.clockAndSeeds[field], `${location}.clockAndSeeds.${field}`);
	}
}

export function validateE6ProfileDocument(profile) {
	const location = 'profile';
	exactKeys(profile, location, ['schemaVersion', 'freezeSemantics', 'protocol', 'regressionCeilings', 'profiles', 'unselectedPlatforms']);
	if (profile.schemaVersion !== 1) fail(`${location}.schemaVersion: expected 1`);

	exactKeys(profile.freezeSemantics, `${location}.freezeSemantics`, ['statement', 'resultsQualifyOnlyThisProfile', 'postResultChangesProhibited']);
	expectString(profile.freezeSemantics.statement, `${location}.freezeSemantics.statement`);
	if (profile.freezeSemantics.resultsQualifyOnlyThisProfile !== true) {
		fail(`${location}.freezeSemantics.resultsQualifyOnlyThisProfile: results must qualify only their exact profile`);
	}
	if (profile.freezeSemantics.postResultChangesProhibited !== true) {
		fail(`${location}.freezeSemantics.postResultChangesProhibited: post-result workload/metric/seed/stopping changes are prohibited`);
	}

	// Measurement protocol, pinned to the plan's comparison gate numbers.
	exactKeys(profile.protocol, `${location}.protocol`, [
		'minimumPairs', 'randomizedPairOrder', 'identicalWorkloadPairs', 'warmupSeconds', 'measurementSeconds',
		'minimumObservationsPerCriticalClassPerRun', 'percentileMethod', 'bootstrap', 'failureAccounting',
	]);
	expectPositiveInt(profile.protocol.minimumPairs, `${location}.protocol.minimumPairs`, { minimum: 20 });
	if (profile.protocol.randomizedPairOrder !== true) fail(`${location}.protocol.randomizedPairOrder: pair order is randomized`);
	if (profile.protocol.identicalWorkloadPairs !== true) fail(`${location}.protocol.identicalWorkloadPairs: pair members share an identical workload`);
	expectExact(profile.protocol.warmupSeconds, `${location}.protocol.warmupSeconds`, 120);
	expectExact(profile.protocol.measurementSeconds, `${location}.protocol.measurementSeconds`, 300);
	expectPositiveInt(profile.protocol.minimumObservationsPerCriticalClassPerRun, `${location}.protocol.minimumObservationsPerCriticalClassPerRun`, { minimum: 1000 });
	expectExact(profile.protocol.percentileMethod, `${location}.protocol.percentileMethod`, 'nearest-rank');
	exactKeys(profile.protocol.bootstrap, `${location}.protocol.bootstrap`, ['resamples', 'method', 'bound']);
	expectExact(profile.protocol.bootstrap.resamples, `${location}.protocol.bootstrap.resamples`, 10000);
	expectExact(profile.protocol.bootstrap.method, `${location}.protocol.bootstrap.method`, 'paired');
	expectExact(profile.protocol.bootstrap.bound, `${location}.protocol.bootstrap.bound`, 'upper-one-sided-95');
	expectExact(profile.protocol.failureAccounting, `${location}.protocol.failureAccounting`, 'separate-attempts-retained');

	// Regression ceilings, pinned to the section 8 gate numbers.
	exactKeys(profile.regressionCeilings, `${location}.regressionCeilings`, [
		'criticalP95MaxPercent', 'criticalP95MaxMilliseconds', 'criticalP99MaxPercent', 'criticalP99MaxMilliseconds', 'peakCpuRssMaxPercent',
	]);
	expectExact(profile.regressionCeilings.criticalP95MaxPercent, `${location}.regressionCeilings.criticalP95MaxPercent`, 5);
	expectExact(profile.regressionCeilings.criticalP95MaxMilliseconds, `${location}.regressionCeilings.criticalP95MaxMilliseconds`, 50);
	expectExact(profile.regressionCeilings.criticalP99MaxPercent, `${location}.regressionCeilings.criticalP99MaxPercent`, 10);
	expectExact(profile.regressionCeilings.criticalP99MaxMilliseconds, `${location}.regressionCeilings.criticalP99MaxMilliseconds`, 100);
	expectExact(profile.regressionCeilings.peakCpuRssMaxPercent, `${location}.regressionCeilings.peakCpuRssMaxPercent`, 10);

	expectArray(profile.profiles, `${location}.profiles`);
	if (profile.profiles.length === 0) fail(`${location}.profiles: at least one frozen selected profile is required`);
	const seenProfileIds = new Set();
	for (const [index, entry] of profile.profiles.entries()) {
		validateFrozenProfileEntry(entry, `${location}.profiles[${index}]`);
		if (seenProfileIds.has(entry.profileId)) fail(`${location}.profiles[${index}]: duplicate profileId "${entry.profileId}"`);
		seenProfileIds.add(entry.profileId);
	}

	// Selection is explicit: every platform is exactly once either a frozen
	// selected profile or an unselected entry, never both and never inferred.
	const selectedPlatforms = new Set(profile.profiles.map((entry) => entry.platform));
	expectArray(profile.unselectedPlatforms, `${location}.unselectedPlatforms`);
	const seenUnselected = new Set();
	for (const [index, entry] of profile.unselectedPlatforms.entries()) {
		const entryLocation = `${location}.unselectedPlatforms[${index}]`;
		exactKeys(entry, entryLocation, ['platform', 'status', 'rule']);
		expectEnum(entry.platform, `${entryLocation}.platform`, E6_PLATFORMS);
		if (selectedPlatforms.has(entry.platform)) fail(`${entryLocation}.platform: "${entry.platform}" is already a selected profile`);
		if (seenUnselected.has(entry.platform)) fail(`${entryLocation}.platform: duplicate unselected platform "${entry.platform}"`);
		seenUnselected.add(entry.platform);
		expectExact(entry.status, `${entryLocation}.status`, 'unselected');
		expectExact(entry.rule, `${entryLocation}.rule`, 'freeze-before-any-results-qualify');
	}
	for (const platform of E6_PLATFORMS) {
		if (!selectedPlatforms.has(platform) && !seenUnselected.has(platform)) {
			fail(`${location}.unselectedPlatforms: platform "${platform}" is neither selected nor explicitly unselected`);
		}
	}
	return profile;
}

// --- E7 useful-outcome contract (plan: "E7 useful-outcome contract") ---

function validateE7Threshold(threshold, location) {
	expectObject(threshold, location);
	if (!own(threshold, 'status')) fail(`${location}: missing field "status"`);
	// A threshold is either honestly pending its Q0/E6 baseline or recorded
	// with the baseline-justified number itself; a claimed number without the
	// number, or a "justified" status carrying only prose, fails closed.
	expectEnum(threshold.status, `${location}.status`, new Set(['pending-q0-baseline', 'baseline-justified']));
	if (threshold.status === 'pending-q0-baseline') {
		exactKeys(threshold, location, ['status', 'note']);
		expectString(threshold.note, `${location}.note`);
		return;
	}
	exactKeys(threshold, location, ['status', 'value', 'basis']);
	if (typeof threshold.value !== 'number' || !Number.isFinite(threshold.value)) {
		fail(`${location}.value: a baseline-justified threshold carries its finite numeric value`);
	}
	expectString(threshold.basis, `${location}.basis`);
}

function validateE7OutcomeBinding(binding, location, knownCapabilities) {
	exactKeys(binding, location, ['name', 'role', 'capabilities', 'threshold', 'sampleRule', 'missingDataRule']);
	expectString(binding.name, `${location}.name`);
	if (!E7_PLAN_OUTCOME_NAMES.has(binding.name)) {
		fail(`${location}.name: "${binding.name}" is not in the plan's "Metrics and initial success criteria" list`);
	}
	expectEnum(binding.role, `${location}.role`, E7_OUTCOME_ROLES);
	expectStringArray(binding.capabilities, `${location}.capabilities`);
	if (binding.capabilities.length === 0) fail(`${location}.capabilities: an outcome is always capability-scoped`);
	expectUnique(binding.capabilities, `${location}.capabilities entry`);
	for (const [index, capability] of binding.capabilities.entries()) {
		if (!knownCapabilities.has(capability)) {
			fail(`${location}.capabilities[${index}]: unknown capability "${capability}"`);
		}
	}
	validateE7Threshold(binding.threshold, `${location}.threshold`);
	expectString(binding.sampleRule, `${location}.sampleRule`);
	expectString(binding.missingDataRule, `${location}.missingDataRule`);
}

function validateE7CapabilityScoping(contract) {
	exactKeys(contract.capabilityScoping, 'contract.capabilityScoping', ['statement', 'unscopedOutcomeProhibited', 'capabilities']);
	expectString(contract.capabilityScoping.statement, 'contract.capabilityScoping.statement');
	if (contract.capabilityScoping.unscopedOutcomeProhibited !== true) {
		fail('contract.capabilityScoping.unscopedOutcomeProhibited: outcomes are always capability-scoped');
	}
	expectArray(contract.capabilityScoping.capabilities, 'contract.capabilityScoping.capabilities');
	if (contract.capabilityScoping.capabilities.length === 0) fail('contract.capabilityScoping.capabilities: must not be empty');
	const seen = new Set();
	for (const [index, capability] of contract.capabilityScoping.capabilities.entries()) {
		const location = `contract.capabilityScoping.capabilities[${index}]`;
		exactKeys(capability, location, ['capability', 'owner', 'pilotAdmitted', 'rule']);
		expectString(capability.capability, `${location}.capability`);
		if (seen.has(capability.capability)) fail(`${location}: duplicate capability "${capability.capability}"`);
		seen.add(capability.capability);
		expectEnum(capability.owner, `${location}.owner`, E7_CAPABILITY_OWNERS);
		if (capability.pilotAdmitted !== true && capability.pilotAdmitted !== false) {
			fail(`${location}.pilotAdmitted: expected true or false`);
		}
		expectString(capability.rule, `${location}.rule`);
	}
	return contract.capabilityScoping;
}

function validateE7IncompleteOutcomeRule(contract) {
	exactKeys(contract.incompleteOutcomeRule, 'contract.incompleteOutcomeRule', ['statement', 'pilotMayNotBeginWithUnspecifiedFields', 'requiredOutcomeFields']);
	expectString(contract.incompleteOutcomeRule.statement, 'contract.incompleteOutcomeRule.statement');
	if (contract.incompleteOutcomeRule.pilotMayNotBeginWithUnspecifiedFields !== true) {
		fail('contract.incompleteOutcomeRule.pilotMayNotBeginWithUnspecifiedFields: a pilot with unspecified required fields cannot begin');
	}
	expectStringArray(contract.incompleteOutcomeRule.requiredOutcomeFields, 'contract.incompleteOutcomeRule.requiredOutcomeFields');
	if (contract.incompleteOutcomeRule.requiredOutcomeFields.length === 0) {
		fail('contract.incompleteOutcomeRule.requiredOutcomeFields: must not be empty');
	}
	expectUnique(contract.incompleteOutcomeRule.requiredOutcomeFields, 'contract.incompleteOutcomeRule.requiredOutcomeFields entry');
	for (const [index, field] of contract.incompleteOutcomeRule.requiredOutcomeFields.entries()) {
		if (!E7_REQUIRED_OUTCOME_FIELDS.has(field)) {
			fail(`contract.incompleteOutcomeRule.requiredOutcomeFields[${index}]: unknown required outcome field "${field}"`);
		}
	}
	return contract.incompleteOutcomeRule;
}

function validateE7UsefulnessNotSafetyOnly(contract) {
	exactKeys(contract.usefulnessNotSafetyOnly, 'contract.usefulnessNotSafetyOnly', ['statement', 'usefulnessOutcomesSubstituteForSafetyGates', 'e6SafetyGatesRemainNonwaivable']);
	expectString(contract.usefulnessNotSafetyOnly.statement, 'contract.usefulnessNotSafetyOnly.statement');
	if (contract.usefulnessNotSafetyOnly.usefulnessOutcomesSubstituteForSafetyGates !== false) {
		fail('contract.usefulnessNotSafetyOnly.usefulnessOutcomesSubstituteForSafetyGates: must stay false — usefulness never substitutes for the E6 safety/SLO gates');
	}
	if (contract.usefulnessNotSafetyOnly.e6SafetyGatesRemainNonwaivable !== true) {
		fail('contract.usefulnessNotSafetyOnly.e6SafetyGatesRemainNonwaivable: the E6 safety gates are nonwaivable');
	}
	return contract.usefulnessNotSafetyOnly;
}

function validateE7OutcomeContract(contract) {
	const location = 'contract';
	exactKeys(contract, location, [
		'schemaVersion', 'contractId', 'frozenAtUtc', 'authority', 'outcomeNameSource', 'freezeSemantics',
		'capabilityScoping', 'outcomeBindings', 'incompleteOutcomeRule', 'usefulnessNotSafetyOnly', 'expansionRule', 'pilotScope',
	]);
	if (contract.schemaVersion !== 1) fail(`${location}.schemaVersion: expected 1`);
	expectString(contract.contractId, `${location}.contractId`);
	if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(contract.contractId)) fail(`${location}.contractId: expected a lowercase hyphenated identifier`);
	validateUtc(contract.frozenAtUtc, `${location}.frozenAtUtc`);
	expectSafeRelativePath(contract.authority, `${location}.authority`);
	expectExact(contract.outcomeNameSource, `${location}.outcomeNameSource`, 'Metrics and initial success criteria');

	exactKeys(contract.freezeSemantics, `${location}.freezeSemantics`, ['statement', 'allOutcomeEvidencePlanned', 'postResultChangesProhibited']);
	expectString(contract.freezeSemantics.statement, `${location}.freezeSemantics.statement`);
	if (contract.freezeSemantics.allOutcomeEvidencePlanned !== true) {
		fail(`${location}.freezeSemantics.allOutcomeEvidencePlanned: the pilot is a later, separately gated run; outcome evidence is planned`);
	}
	if (contract.freezeSemantics.postResultChangesProhibited !== true) {
		fail(`${location}.freezeSemantics.postResultChangesProhibited: post-result outcome/threshold/scope changes are prohibited`);
	}

	validateE7CapabilityScoping(contract);
	const knownCapabilities = new Set(contract.capabilityScoping.capabilities.map((entry) => entry.capability));

	expectArray(contract.outcomeBindings, `${location}.outcomeBindings`);
	if (contract.outcomeBindings.length === 0) fail(`${location}.outcomeBindings: at least one bound outcome is required`);
	const seenNames = new Set();
	let primaryUsefulnessOutcomes = 0;
	for (const [index, binding] of contract.outcomeBindings.entries()) {
		validateE7OutcomeBinding(binding, `${location}.outcomeBindings[${index}]`, knownCapabilities);
		if (seenNames.has(binding.name)) fail(`${location}.outcomeBindings[${index}]: duplicate outcome name "${binding.name}"`);
		seenNames.add(binding.name);
		if (binding.role === 'primary-usefulness') primaryUsefulnessOutcomes += 1;
	}
	if (primaryUsefulnessOutcomes === 0) {
		fail(`${location}.outcomeBindings: at least one primary foreground/reconnect usefulness outcome is required`);
	}
	// Capability evidence binding direction: a capability that is not admitted
	// to the pilot cannot inherit a usefulness claim, so every primary-usefulness
	// outcome must bind at least one pilot-admitted capability from the registry.
	for (const [index, binding] of contract.outcomeBindings.entries()) {
		if (binding.role !== 'primary-usefulness') continue;
		const admitted = contract.capabilityScoping.capabilities.find((capability) =>
			capability.pilotAdmitted === true && binding.capabilities.includes(capability.capability));
		if (!admitted) {
			fail(`${location}.outcomeBindings[${index}]: a primary-usefulness outcome must bind at least one pilot-admitted capability from the registry; a capability that is not admitted cannot inherit a usefulness claim`);
		}
	}

	validateE7IncompleteOutcomeRule(contract);
	validateE7UsefulnessNotSafetyOnly(contract);

	exactKeys(contract.expansionRule, `${location}.expansionRule`, ['statement', 'retainedPilotDecisionPrecedesExpansion', 'allowedDecisions', 'accountableOwnerRequired']);
	expectString(contract.expansionRule.statement, `${location}.expansionRule.statement`);
	if (contract.expansionRule.retainedPilotDecisionPrecedesExpansion !== true) {
		fail(`${location}.expansionRule.retainedPilotDecisionPrecedesExpansion: the retained pilot decision precedes expansion`);
	}
	expectStringArray(contract.expansionRule.allowedDecisions, `${location}.expansionRule.allowedDecisions`);
	expectUnique(contract.expansionRule.allowedDecisions, `${location}.expansionRule.allowedDecisions entry`);
	const allowedDecisions = new Set(['approved-expansion', 'remain-at-current-cohort', 'rollback', 'insufficient-evidence']);
	for (const [index, decision] of contract.expansionRule.allowedDecisions.entries()) {
		if (!allowedDecisions.has(decision)) fail(`${location}.expansionRule.allowedDecisions[${index}]: unknown expansion decision "${decision}"`);
	}
	if (contract.expansionRule.accountableOwnerRequired !== true) fail(`${location}.expansionRule.accountableOwnerRequired: an accountable owner and reason are required`);

	// The pilot binds frozen profiles from the one canonical E6 profile
	// document; a contract referencing an unfrozen or unknown profile fails.
	exactKeys(contract.pilotScope, `${location}.pilotScope`, [
		'status', 'capabilityProfileBinding', 'eligibleMailWorkflows', 'excludedWorkflows',
		'cohort', 'observationWindow', 'denominator', 'offComparator',
	]);
	expectExact(contract.pilotScope.status, `${location}.pilotScope.status`, 'planned');
	exactKeys(contract.pilotScope.capabilityProfileBinding, `${location}.pilotScope.capabilityProfileBinding`, ['profileDocument', 'requiredProfileIds', 'rule']);
	expectExact(contract.pilotScope.capabilityProfileBinding.profileDocument, `${location}.pilotScope.capabilityProfileBinding.profileDocument`, E6_PROFILE_REL);
	expectStringArray(contract.pilotScope.capabilityProfileBinding.requiredProfileIds, `${location}.pilotScope.capabilityProfileBinding.requiredProfileIds`);
	expectUnique(contract.pilotScope.capabilityProfileBinding.requiredProfileIds, `${location}.pilotScope.capabilityProfileBinding.requiredProfileIds entry`);
	expectString(contract.pilotScope.capabilityProfileBinding.rule, `${location}.pilotScope.capabilityProfileBinding.rule`);
	const profilePath = path.join(repositoryRoot, E6_PROFILE_REL);
	if (!fs.existsSync(profilePath)) {
		fail(`${location}.pilotScope.capabilityProfileBinding: the frozen profile document "${E6_PROFILE_REL}" must exist`);
	}
	const profile = validateE6ProfileDocument(readJson(profilePath, 'profile'));
	const frozenProfileIds = new Set(profile.profiles.map((entry) => entry.profileId));
	for (const [index, profileId] of contract.pilotScope.capabilityProfileBinding.requiredProfileIds.entries()) {
		if (!frozenProfileIds.has(profileId)) {
			fail(`${location}.pilotScope.capabilityProfileBinding.requiredProfileIds[${index}]: "${profileId}" is not a frozen selected profile in ${E6_PROFILE_REL}`);
		}
	}
	expectStringArray(contract.pilotScope.eligibleMailWorkflows, `${location}.pilotScope.eligibleMailWorkflows`);
	expectStringArray(contract.pilotScope.excludedWorkflows, `${location}.pilotScope.excludedWorkflows`);
	// Scope fields stay honest: 'specified' pins a value now, and everything
	// still 'planned-until-pilot-admission' keeps the incomplete-outcome
	// begin-gate (validated above) engaged — the pilot cannot begin.
	for (const field of ['cohort', 'observationWindow', 'denominator', 'offComparator']) {
		const fieldLocation = `${location}.pilotScope.${field}`;
		exactKeys(contract.pilotScope[field], fieldLocation, ['status', 'rule']);
		expectEnum(contract.pilotScope[field].status, `${fieldLocation}.status`, E7_SCOPE_FIELD_STATUSES);
		expectString(contract.pilotScope[field].rule, `${fieldLocation}.rule`);
	}
	return contract;
}

function validateManifestProfileBindings(manifestInfo) {
	const needsProfile = [...manifestInfo.casesById.values()].some((entry) =>
		entry.contract?.kind === 'e6-profile-frozen' || own(entry, 'requiredProfiles'));
	if (!needsProfile) return;
	const profilePath = path.join(repositoryRoot, E6_PROFILE_REL);
	if (!fs.existsSync(profilePath)) {
		fail(`manifest: E6 profile bindings require the frozen profile document "${E6_PROFILE_REL}" to exist`);
	}
	const profile = readJson(profilePath, 'profile');
	validateE6ProfileDocument(profile);
	const frozenById = new Map(profile.profiles.map((entry) => [entry.profileId, entry]));
	for (const entry of manifestInfo.casesById.values()) {
		for (const [index, profileId] of (entry.requiredProfiles ?? []).entries()) {
			// Plan DX/E7 row: "`all` is a local deterministic aggregate, not E7
			// release readiness." Selection is explicit per frozen profile ID;
			// the all aggregate is never a bindable profile.
			if (profileId === 'all') {
				fail(`manifest.cases: case ${entry.id} binds requiredProfiles[${index}] "all" — the "all" selection is a local deterministic aggregate, not a frozen profile; bind explicit frozen profile IDs`);
			}
			const bound = frozenById.get(profileId);
			if (!bound) {
				fail(`manifest.cases: case ${entry.id} binds requiredProfiles[${index}] "${profileId}" which is not a frozen selected profile in ${E6_PROFILE_REL}`);
			}
		}
	}
}

// E7 outcome-contract cases bind one canonical frozen document. OUTCOME-
// CONTRACT-FROZEN validates that the document exists, parses, and pins the
// schema plus plan-derived name membership; the other cases each bind their
// contract aspect fail-closed. Any of them present makes the whole document's
// structural freeze repo-wide, exactly like the E6 profile. Returns the
// validated contract so the capability-evidence cross-check can reuse it.
function validateManifestE7OutcomeBindings(manifestInfo) {
	const e7Cases = [...manifestInfo.casesById.values()].filter((entry) =>
		E7_OUTCOME_CONTRACT_KINDS.has(entry.contract?.kind));
	if (e7Cases.length === 0) return null;
	const contractPath = path.join(repositoryRoot, E7_CONTRACT_REL);
	if (!fs.existsSync(contractPath)) {
		fail(`manifest: E7 outcome-contract cases require the frozen contract document "${E7_CONTRACT_REL}" to exist`);
	}
	const contract = readJson(contractPath, 'e7 outcome contract');
	validateE7OutcomeContract(contract);
	for (const entry of e7Cases) {
		switch (entry.contract.kind) {
			case 'e7-outcome-contract-frozen':
				// Full document validation above: existence, schema, and outcome
				// name membership against the plan-derived list.
				break;
			case 'e7-incomplete-outcome-no-expansion':
				validateE7IncompleteOutcomeRule(contract);
				break;
			case 'e7-capability-scoped-outcome':
				validateE7CapabilityScoping(contract);
				break;
			case 'e7-usefulness-not-safety-only':
				validateE7UsefulnessNotSafetyOnly(contract);
				break;
			case 'e7-capability-evidence-binding':
				// The frozen registry half of the binding; the cross-check against
				// the manifest's actual evidence bindings runs in
				// validateManifestE7CapabilityEvidenceBindings below.
				validateE7CapabilityScoping(contract);
				break;
		}
	}
	return contract;
}

// Plan DX/E7 ownership row: "`all` is a local deterministic aggregate, not E7
// release readiness." CAS-E7-LOCAL-ALL-NOT-RELEASE binds that distinction
// fail-closed: the frozen profile document keeps selection explicit (results
// qualify only the exact frozen profile, never an inferred all), the sustained
// selected-profile runtime evidence cases stay required and profile-bound, and
// a profile-bound case can never carry the local manifest-checker command as
// its runtime evidence.
function validateManifestE7LocalAllNotRelease(manifestInfo) {
	const localAllCases = [...manifestInfo.casesById.values()].filter((entry) =>
		entry.contract?.kind === 'e7-local-all-not-release');
	if (localAllCases.length === 0) return;
	const profilePath = path.join(repositoryRoot, E6_PROFILE_REL);
	if (!fs.existsSync(profilePath)) {
		fail(`manifest: E7 local-all cases require the frozen profile document "${E6_PROFILE_REL}" to exist`);
	}
	validateE6ProfileDocument(readJson(profilePath, 'profile'));
	for (const entry of localAllCases) {
		if (entry.fixture !== E6_PROFILE_REL) {
			fail(`manifest.cases: case ${entry.id} (e7-local-all-not-release) must bind the frozen E6 profile document "${E6_PROFILE_REL}" as its fixture`);
		}
	}
	for (const caseId of E7_RELEASE_RUNTIME_CASE_IDS) {
		const entry = manifestInfo.casesById.get(caseId);
		if (!entry || entry.requiredState !== 'required' || !Array.isArray(entry.requiredProfiles) || entry.requiredProfiles.length === 0) {
			fail(`manifest: E7 release readiness requires the selected-profile runtime evidence case "${caseId}" to stay present, requiredState "required", and bound to non-empty frozen requiredProfiles — the local deterministic aggregate cannot substitute`);
		}
	}
	for (const entry of manifestInfo.casesById.values()) {
		if (!Array.isArray(entry.requiredProfiles) || entry.requiredProfiles.length === 0) continue;
		if (typeof entry.command === 'string' && entry.command.startsWith(LOCAL_MANIFEST_CHECKER_COMMAND)) {
			fail(`manifest.cases: case ${entry.id} binds requiredProfiles but its command is the local manifest checker — a local deterministic aggregate is not selected-profile runtime evidence`);
		}
	}
}

// Plan DX/E7 ownership row: capability-scoped outcomes bind only to capability
// evidence that exists. CAS-E7-CAPABILITY-EVIDENCE-BINDING cross-checks the
// frozen contract's capability registry against the manifest's actual evidence
// bindings: every pilot-admitted capability's owning unit must hold at least
// one retained requirement binding — admitted-without-evidence fails closed.
// Unscoped outcomes and unknown capabilities already fail closed through the
// contract validation above; this closes the evidence side of the binding.
function validateManifestE7CapabilityEvidenceBindings(manifestInfo, contract) {
	const evidenceCases = [...manifestInfo.casesById.values()].filter((entry) =>
		entry.contract?.kind === 'e7-capability-evidence-binding');
	if (evidenceCases.length === 0 || !contract) return;
	for (const entry of evidenceCases) {
		if (entry.fixture !== E7_CONTRACT_REL) {
			fail(`manifest.cases: case ${entry.id} (e7-capability-evidence-binding) must bind the frozen E7 outcome contract "${E7_CONTRACT_REL}" as its fixture`);
		}
	}
	const requirementIds = [...manifestInfo.registryByCase.values()].map((binding) => binding.requirementId);
	for (const capability of contract.capabilityScoping.capabilities) {
		if (capability.pilotAdmitted !== true) continue;
		const segment = E7_OWNER_EVIDENCE_SEGMENTS.get(capability.owner);
		if (!segment) {
			fail(`manifest: capability "${capability.capability}" owner "${capability.owner}" has no evidence-binding segment`);
		}
		const hasEvidence = requirementIds.some((requirementId) => requirementId.includes(`/${segment}/`));
		if (!hasEvidence) {
			fail(`manifest: capability "${capability.capability}" is pilotAdmitted=true but no ${capability.owner} capability evidence binding exists in the manifest evidence registry — admitted-without-evidence bindings fail closed`);
		}
	}
}

function validateManifest(manifest) {
	const location = 'manifest';
	exactKeys(manifest, location, ['schemaVersion', 'program', 'authority', 'cases', 'evidenceRegistry']);
	if (manifest.schemaVersion !== 1) fail(`${location}.schemaVersion: expected 1`);
	expectString(manifest.program, `${location}.program`);
	expectSafeRelativePath(manifest.authority, `${location}.authority`);
	expectArray(manifest.cases, `${location}.cases`);
	if (manifest.cases.length === 0) fail(`${location}.cases: must not be empty`);

	const casesById = new Map();
	// fixtureDigest presence is conditional (required whenever the fixture
	// file exists — see the binding check below), so it is structurally
	// optional here and enforced by the binding rule.
	const caseKeys = ['id', 'introducedBy', 'owner', 'fixture', 'lane', 'requiredState', 'timeoutSeconds', 'expectedDisposition', 'retainedArtifacts'];
	const caseOptionalKeys = ['contract', 'fixtureDigest', 'seed', 'command', 'requiredProfiles', 'generationReceipt'];
	for (const [index, entry] of manifest.cases.entries()) {
		const caseLocation = `${location}.cases[${index}]`;
		exactKeys(entry, caseLocation, caseKeys, caseOptionalKeys);
		expectString(entry.id, `${caseLocation}.id`);
		if (!CASE_ID_RE.test(entry.id)) fail(`${caseLocation}.id: invalid case ID "${entry.id}"`);
		if (casesById.has(entry.id)) fail(`duplicate case ID "${entry.id}"`);
		casesById.set(entry.id, entry);
		expectString(entry.introducedBy, `${caseLocation}.introducedBy`);
		if (!INTRODUCED_BY_RE.test(entry.introducedBy)) fail(`${caseLocation}.introducedBy: invalid state "${entry.introducedBy}"`);
		expectString(entry.owner, `${caseLocation}.owner`);
		expectSafeRelativePath(entry.fixture, `${caseLocation}.fixture`);
		// B62 bindings fail closed: a binding that exists must bind REALITY.
		// When the fixture file exists, the digest is REQUIRED and must equal
		// the sha-256 of the actual content — a syntax-valid digest over stale
		// content is a failure, so a fixture edited without rebinding its
		// evidence can never pass. A case whose fixture does not exist yet is
		// an honestly planned fixture: it stays admission-planned and can
		// never carry enforced evidence (validated below and in validateResults).
		const fixturePath = path.join(repositoryRoot, entry.fixture);
		if (fs.existsSync(fixturePath)) {
			expectString(entry.fixtureDigest, `${caseLocation}.fixtureDigest`);
			if (!SHA256_RE.test(entry.fixtureDigest)) fail(`${caseLocation}.fixtureDigest: expected a lowercase sha-256 hex digest`);
			const actualDigest = createHash('sha256').update(fs.readFileSync(fixturePath)).digest('hex');
			if (actualDigest !== entry.fixtureDigest) {
				fail(`${caseLocation}.fixtureDigest: stale binding — expected ${actualDigest} for fixture "${entry.fixture}", got ${entry.fixtureDigest}`);
			}
		} else if (entry.expectedDisposition !== 'planned') {
			fail(`${caseLocation}.fixture: enforced disposition requires the fixture file "${entry.fixture}" to exist and be digest-bound`);
		}
		expectEnum(entry.lane, `${caseLocation}.lane`, LANES);
		expectEnum(entry.requiredState, `${caseLocation}.requiredState`, REQUIRED_STATES);
		expectInteger(entry.timeoutSeconds, `${caseLocation}.timeoutSeconds`, { positive: true, maximum: 86400 });
		expectEnum(entry.expectedDisposition, `${caseLocation}.expectedDisposition`, EXPECTED_DISPOSITIONS);
		expectArray(entry.retainedArtifacts, `${caseLocation}.retainedArtifacts`);
		if (entry.retainedArtifacts.length === 0) fail(`${caseLocation}.retainedArtifacts: must not be empty`);
		for (const [artifactIndex, artifact] of entry.retainedArtifacts.entries()) {
			expectSafeRelativePath(artifact, `${caseLocation}.retainedArtifacts[${artifactIndex}]`);
		}
		expectUnique(entry.retainedArtifacts, `${entry.id} retained artifact`);
		if (own(entry, 'seed')) expectString(entry.seed, `${caseLocation}.seed`);
		if (own(entry, 'command')) {
			// The ownership table binds every case to one exact rerun command; it
			// must be a single bounded line that names the case it owns.
			expectString(entry.command, `${caseLocation}.command`);
			if (/[\u0000-\u001f]/.test(entry.command) || /^[\s]|[\s]$/.test(entry.command) || entry.command.length > 512) {
				fail(`${caseLocation}.command: must be one exact non-empty command line of at most 512 characters`);
			}
			if (!entry.command.includes(entry.id)) {
				fail(`${caseLocation}.command: must contain the exact case ID "${entry.id}" so the rerun command is unambiguous`);
			}
		}
		if (own(entry, 'requiredProfiles')) {
			expectStringArray(entry.requiredProfiles, `${caseLocation}.requiredProfiles`);
			expectUnique(entry.requiredProfiles, `${caseLocation}.requiredProfiles entry`);
		}
		// Executed E6 consumption binding: a generation receipt is valid only on
		// the sustained-run runtime gate cases, only with an enforced
		// disposition, and only with the exact receipt shape.
		if (own(entry, 'generationReceipt')) {
			if (!E7_RELEASE_RUNTIME_CASE_IDS.has(entry.id)) {
				fail(`${caseLocation}.generationReceipt: only the sustained-run runtime gate cases (${[...E7_RELEASE_RUNTIME_CASE_IDS].sort().join(', ')}) may bind a generation receipt`);
			}
			if (entry.expectedDisposition !== 'enforced') {
				fail(`${caseLocation}.generationReceipt: a generation receipt binds executed evidence, so expectedDisposition must be "enforced"`);
			}
			exactKeys(entry.generationReceipt, `${caseLocation}.generationReceipt`, GENERATION_RECEIPT_KEYS);
			if (!RUN_ID_RE.test(entry.generationReceipt.runId)) fail(`${caseLocation}.generationReceipt.runId: invalid run ID`);
			if (!SHA256_RE.test(entry.generationReceipt.aggregateSha256)) fail(`${caseLocation}.generationReceipt.aggregateSha256: expected a lowercase sha-256 hex digest`);
			if (entry.generationReceipt.gate !== E6_RUNTIME_CASE_GATES.get(entry.id)) {
				fail(`${caseLocation}.generationReceipt.gate: expected exactly ${JSON.stringify(E6_RUNTIME_CASE_GATES.get(entry.id))}, got ${JSON.stringify(entry.generationReceipt.gate)}`);
			}
			if (typeof entry.generationReceipt.gatePass !== 'boolean') fail(`${caseLocation}.generationReceipt.gatePass: expected a boolean`);
			if (typeof entry.generationReceipt.overallPass !== 'boolean') fail(`${caseLocation}.generationReceipt.overallPass: expected a boolean`);
		}
		if (own(entry, 'contract')) validateContract(entry.contract, `${caseLocation}.contract`);
		// E4-I Astra correction (finding 20): an E4-I binding case is only
		// identity-bound with its deterministic seed AND its contract symbols —
		// removing either used to still validate, so the binding could be
		// silently weakened after the fact. They are REQUIRED here.
		if (entry.introducedBy === 'E4-I') {
			if (!own(entry, 'seed')) fail(`${caseLocation}.seed: E4-I cases must bind their deterministic seed`);
			if (!own(entry, 'contract')) fail(`${caseLocation}.contract: E4-I cases must bind their contract`);
			if (!Array.isArray(entry.contract.symbols) || entry.contract.symbols.length === 0) {
				fail(`${caseLocation}.contract.symbols: E4-I cases must bind their contract symbols`);
			}
		}
		// E6 comparison runs are bound to the frozen profile's clocks and seeds;
		// an E6 case that silently loses its seed loses its reproducibility
		// binding (contract symbols stay optional: sustained-run cases bind the
		// profile document, not source symbols).
		if (entry.introducedBy === 'E6' && !own(entry, 'seed')) {
			fail(`${caseLocation}.seed: E6 cases must bind their deterministic seed`);
		}
		// E7 cases are bound by the ownership table's mapping rule (owner,
		// fixture, command, timeout, result binding) and the DX/E7 row; a
		// missing identity field or an unknown contract kind is a silently
		// weakened binding and fails closed.
		if (entry.introducedBy === 'E7') {
			if (!own(entry, 'seed')) fail(`${caseLocation}.seed: E7 cases must bind their deterministic seed`);
			if (!own(entry, 'command')) fail(`${caseLocation}.command: E7 cases must bind their exact rerun command`);
			if (!own(entry, 'contract')) fail(`${caseLocation}.contract: E7 cases must bind their contract`);
			if (!E7_CASE_KINDS.has(entry.contract?.kind)) {
				fail(`${caseLocation}.contract.kind: unknown E7 contract kind ${JSON.stringify(entry.contract?.kind)}`);
			}
		}
	}

	validateEvidenceRegistry(manifest.evidenceRegistry, casesById);
	const registryByCase = buildRegistryByCase(manifest.evidenceRegistry);
	validateManifestProfileBindings({ casesById });
	const e7Contract = validateManifestE7OutcomeBindings({ casesById });
	validateManifestE7LocalAllNotRelease({ casesById });
	validateManifestE7CapabilityEvidenceBindings({ casesById, registryByCase }, e7Contract);
	return { casesById, registryByCase };
}

function buildRegistryByCase(registry) {
	const registryByCase = new Map();
	for (const binding of registry) {
		registryByCase.set(binding.caseId, binding);
	}
	return registryByCase;
}

function validateEvidenceRegistry(registry, casesById) {
	expectArray(registry, 'manifest.evidenceRegistry');
	if (registry.length === 0) fail('manifest.evidenceRegistry: must not be empty');
	const seenCaseIds = new Set();
	const seenRequirementIds = new Set();
	const seenTestIds = new Set();
	const seenResultIds = new Set();
	for (const [index, binding] of registry.entries()) {
		const location = `manifest.evidenceRegistry[${index}]`;
		exactKeys(binding, location, ['caseId', 'requirementId', 'testId', 'resultId', 'gate', 'lane', 'retainedArtifact']);
		for (const field of ['caseId', 'requirementId', 'testId', 'resultId']) expectString(binding[field], `${location}.${field}`);
		if (!casesById.has(binding.caseId)) fail(`${location}.caseId: unknown case ID "${binding.caseId}"`);
		if (seenCaseIds.has(binding.caseId)) fail(`duplicate evidence binding for case ID "${binding.caseId}"`);
		if (seenRequirementIds.has(binding.requirementId)) fail(`duplicate evidence requirement ID "${binding.requirementId}"`);
		if (seenTestIds.has(binding.testId)) fail(`duplicate evidence test ID "${binding.testId}"`);
		if (seenResultIds.has(binding.resultId)) fail(`duplicate evidence result ID "${binding.resultId}"`);
		seenCaseIds.add(binding.caseId);
		seenRequirementIds.add(binding.requirementId);
		seenTestIds.add(binding.testId);
		seenResultIds.add(binding.resultId);
		expectEnum(binding.gate, `${location}.gate`, GATES);
		expectEnum(binding.lane, `${location}.lane`, LANES);
		const caseEntry = casesById.get(binding.caseId);
		if (binding.lane !== caseEntry.lane) fail(`${location}.lane: does not match case ${binding.caseId}`);
		if (!caseEntry.retainedArtifacts.includes(binding.retainedArtifact)) fail(`${location}.retainedArtifact: not declared by case ${binding.caseId}`);
		expectSafeRelativePath(binding.retainedArtifact, `${location}.retainedArtifact`);
	}
	for (const caseId of casesById.keys()) {
		if (!seenCaseIds.has(caseId)) fail(`missing evidence binding for case ID "${caseId}"`);
	}
}

function validateUtcTime(value, location) {
	expectString(value, location);
	if (!UTC_RE.test(value) || !Number.isFinite(Date.parse(value))) fail(`${location}: expected a valid UTC timestamp ending in Z`);
	const normalized = new Date(value).toISOString();
	if (value !== normalized && value !== normalized.replace('.000Z', 'Z')) fail(`${location}: expected canonical UTC timestamp`);
}

function validateNormalizedValues(value, location) {
	exactKeys(value, location, ['mode', 'networkCost', 'power', 'thermal', 'storagePressure', 'maxBytes']);
	expectEnum(value.mode, `${location}.mode`, new Set(['off', 'observe', 'execute']));
	expectEnum(value.networkCost, `${location}.networkCost`, new Set(['offline', 'unmetered', 'metered', 'unknown']));
	expectEnum(value.power, `${location}.power`, new Set(['normal', 'charging', 'saver', 'unknown']));
	expectEnum(value.thermal, `${location}.thermal`, new Set(['nominal', 'serious', 'critical', 'unknown']));
	expectEnum(value.storagePressure, `${location}.storagePressure`, new Set(['normal', 'low', 'critical', 'unknown']));
	expectInteger(value.maxBytes, `${location}.maxBytes`, { minimum: 0, maximum: 8589934592 });
}

function validateDecisionRecord(record) {
	exactKeys(record, 'decision', ['schemaVersion', 'requested', 'effective', 'policySource', 'capabilitySource', 'eligibility', 'queue', 'pauseReason']);
	if (record.schemaVersion !== 1) fail('decision.schemaVersion: expected 1');
	validateNormalizedValues(record.requested, 'decision.requested');
	validateNormalizedValues(record.effective, 'decision.effective');

	exactKeys(record.policySource, 'decision.policySource', ['kind', 'rule', 'revision']);
	expectEnum(record.policySource.kind, 'decision.policySource.kind', new Set(['default', 'global', 'group', 'account-policy']));
	expectEnum(record.policySource.rule, 'decision.policySource.rule', new Set(['default', 'allow', 'observe', 'deny']));
	expectInteger(record.policySource.revision, 'decision.policySource.revision', { minimum: 0, maximum: Number.MAX_SAFE_INTEGER });

	exactKeys(record.capabilitySource, 'decision.capabilitySource', ['kind', 'contractVersion']);
	expectEnum(record.capabilitySource.kind, 'decision.capabilitySource.kind', new Set(['default', 'compiled-manifest', 'native-snapshot']));
	if (record.capabilitySource.contractVersion !== 1) fail('decision.capabilitySource.contractVersion: expected 1');

	expectEnum(record.eligibility, 'decision.eligibility', new Set(['eligible', 'ineligible', 'blocked', 'unknown']));
	exactKeys(record.queue, 'decision.queue', ['class', 'ageSeconds']);
	expectEnum(record.queue.class, 'decision.queue.class', new Set(['interactive', 'background', 'opportunistic']));
	expectInteger(record.queue.ageSeconds, 'decision.queue.ageSeconds', { minimum: 0, maximum: 604800 });
	expectEnum(record.pauseReason, 'decision.pauseReason', new Set(['none', 'critical-activity', 'feature-disabled', 'policy', 'capability', 'network', 'power-saver', 'thermal', 'storage-pressure', 'deadline', 'revoked', 'unknown']));
	return record;
}

function validateObservation(value, location) {
	exactKeys(value, location, ['state'], ['count']);
	expectEnum(value.state, `${location}.state`, new Set(['present', 'absent', 'unknown']));
	if (own(value, 'count')) expectInteger(value.count, `${location}.count`, { minimum: 0 });
}

function validateCleanupAction(value, location) {
	exactKeys(value, location, ['before', 'after', 'status'], ['manualRecoveryCommand']);
	validateObservation(value.before, `${location}.before`);
	validateObservation(value.after, `${location}.after`);
	expectEnum(value.status, `${location}.status`, new Set(['cleaned', 'already_clean', 'failed']));
	if (value.status === 'failed') {
		if (!own(value, 'manualRecoveryCommand')) fail(`${location}.manualRecoveryCommand: required when status is failed`);
		expectString(value.manualRecoveryCommand, `${location}.manualRecoveryCommand`);
		if (/^[\s]|[\s]$/.test(value.manualRecoveryCommand) || /[\u0000-\u001f]/.test(value.manualRecoveryCommand) || value.manualRecoveryCommand.length > 512) fail(`${location}.manualRecoveryCommand: must be one exact non-empty command`);
	} else if (own(value, 'manualRecoveryCommand')) {
		fail(`${location}.manualRecoveryCommand: only allowed when status is failed`);
	}
}

function validateCleanupReceipt(receipt) {
	exactKeys(receipt, 'cleanup', ['schemaVersion', 'runId', 'utcTime', 'actions']);
	if (receipt.schemaVersion !== 1) fail('cleanup.schemaVersion: expected 1');
	expectString(receipt.runId, 'cleanup.runId');
	if (!RUN_ID_RE.test(receipt.runId)) fail('cleanup.runId: invalid run ID');
	validateUtcTime(receipt.utcTime, 'cleanup.utcTime');
	exactKeys(receipt.actions, 'cleanup.actions', ['qdisc', 'isolatedDatabase', 'portsProcesses', 'tempFiles', 'firewall']);
	for (const action of ['qdisc', 'isolatedDatabase', 'portsProcesses', 'tempFiles', 'firewall']) validateCleanupAction(receipt.actions[action], `cleanup.actions.${action}`);
	return receipt;
}

function validateResultEntry(value, location) {
	// B62 bindings fail closed: a result entry is an identity-bound record,
	// never a bare {caseId,status} pair. resultId binds it to the evidence
	// registry and the retained artifacts bind it to this run's outputs.
	exactKeys(value, location, ['caseId', 'status', 'resultId', 'lane', 'retainedArtifacts'], ['detail']);
	expectString(value.caseId, `${location}.caseId`);
	expectEnum(value.status, `${location}.status`, RESULT_STATUSES);
	expectString(value.resultId, `${location}.resultId`);
	expectEnum(value.lane, `${location}.lane`, LANES);
	expectArray(value.retainedArtifacts, `${location}.retainedArtifacts`);
	if (value.retainedArtifacts.length === 0) fail(`${location}.retainedArtifacts: must not be empty`);
	for (const [index, artifact] of value.retainedArtifacts.entries()) expectSafeRelativePath(artifact, `${location}.retainedArtifacts[${index}]`);
	if (own(value, 'detail')) expectString(value.detail, `${location}.detail`);
}

function validateRetainedEvidence(artifact, result, resultsDocument, caseEntry, location, evidenceRoot) {
	// E4-I Astra correction (finding 20): a retained artifact must EXIST and its
	// contents must PROVE this run's pass — a fabricated PASS citing a
	// nonexistent artifact, an artifact from another run, or a receipt that
	// does not record the pass itself, is a failure. Names were checked before;
	// from here on the evidence itself is bound.
	const artifactPath = path.join(evidenceRoot, artifact);
	if (!fs.existsSync(artifactPath)) {
		fail(`${location}: "${artifact}" does not exist for run "${resultsDocument.runId}" — a pass cannot cite evidence that was never written`);
	}
	const receipt = readJson(artifactPath, `${location}[receipt]`);
	exactKeys(receipt, `${location}.receipt`, ['schemaVersion', 'caseId', 'status', 'lane', 'runId', 'utcTime', 'fixture', 'fixtureDigest', 'observations'], ['seed', 'fail', 'cause']);
	if (receipt.schemaVersion !== 1) fail(`${location}.receipt.schemaVersion: expected 1`);
	if (receipt.caseId !== result.caseId) fail(`${location}.receipt.caseId: "${receipt.caseId}" does not match the result's case "${result.caseId}"`);
	if (receipt.runId !== resultsDocument.runId) fail(`${location}.receipt.runId: "${receipt.runId}" is not this run ("${resultsDocument.runId}")`);
	if (E7_RELEASE_RUNTIME_CASE_IDS.has(result.caseId)) {
		// Executed E6 consumption records reality: the receipt must record the
		// result's own outcome, pass or honest executed FAIL.
		if (receipt.status !== result.status) {
			fail(`${location}.receipt.status: "${receipt.status}" — an executed E6 receipt must record the result's own outcome "${result.status}"`);
		}
	} else if (receipt.status !== 'passed') {
		fail(`${location}.receipt.status: "${receipt.status}" — a required pass cannot be evidenced by a receipt that did not itself pass`);
	}
	if (receipt.lane !== result.lane) fail(`${location}.receipt.lane: "${receipt.lane}" does not match the result lane "${result.lane}"`);
	validateUtcTime(receipt.utcTime, `${location}.receipt.utcTime`);
	expectSafeRelativePath(receipt.fixture, `${location}.receipt.fixture`);
	if (receipt.fixture !== caseEntry.fixture) fail(`${location}.receipt.fixture: "${receipt.fixture}" does not match the case fixture "${caseEntry.fixture}"`);
	// The receipt's fixture digest binds it to the ACTUAL fixture content, the
	// same rule the manifest binding uses — a receipt over stale content fails.
	if (typeof receipt.fixtureDigest !== 'string' || !SHA256_RE.test(receipt.fixtureDigest)) {
		fail(`${location}.receipt.fixtureDigest: expected a lowercase sha-256 hex digest`);
	}
	const actualFixtureDigest = createHash('sha256').update(fs.readFileSync(path.join(evidenceRoot, caseEntry.fixture))).digest('hex');
	if (receipt.fixtureDigest !== actualFixtureDigest) {
		fail(`${location}.receipt.fixtureDigest: stale binding — expected ${actualFixtureDigest} for fixture "${caseEntry.fixture}", got ${receipt.fixtureDigest}`);
	}
	if (own(receipt, 'seed') && own(caseEntry, 'seed') && receipt.seed !== caseEntry.seed) {
		fail(`${location}.receipt.seed: "${receipt.seed}" does not match the case seed "${caseEntry.seed}"`);
	}
	if (E7_RELEASE_RUNTIME_CASE_IDS.has(result.caseId)) {
		const observations = receipt.observations;
		const aggregatePath = `test-results/connectivity-aware-sync/${receipt.runId}/e6/generation/aggregate.json`;
		assert.equal(observations?.aggregatePath, aggregatePath, `${location}: E6 aggregate must belong to this run`);
		const retained = readRetainedE6Generation(path.dirname(path.join(evidenceRoot, aggregatePath)), observations.aggregateSha256);
		const { aggregate, profile, checks, profileQualified } = retained;
		assert.equal(aggregate.runId, receipt.runId, 'E6 aggregate run identity differs');
		assert.equal(profile.digest, receipt.fixtureDigest, 'E6 aggregate fixture differs');
		assert.ok(caseEntry.requiredProfiles.includes(profile.selected.profileId), 'E6 aggregate profile is not selected');
		validateE6ProfileDocument(profile.document);
		const expected = {
			aggregatePath, aggregateSha256: observations.aggregateSha256,
			source: aggregate.seal.git, harness: aggregate.seal.harness, profile: aggregate.profile,
			profileQualified, schemaAssertions: checks, gate: aggregate.verdict[E6_RUNTIME_CASE_GATES.get(result.caseId)],
			overallPass: aggregate.verdict.overallPass, claimsUnavailableClasses: aggregate.verdict.claimsUnavailableClasses,
			pairDocDigests: aggregate.seal.pairDocDigests,
		};
		assert.deepEqual(observations, expected, 'E6 receipt observations differ from validated retained generation');
		// The manifest's generation receipt must bind exactly this generation
		// and its verdict fields; a swapped aggregate or an altered verdict
		// without a new sealed generation fails closed.
		const bound = caseEntry.generationReceipt;
		if (!bound) fail(`${location}: executed E6 case ${result.caseId} must bind a manifest generationReceipt`);
		if (bound.runId !== receipt.runId || bound.aggregateSha256 !== observations.aggregateSha256) {
			fail(`${location}: generation receipt does not bind this retained generation (${bound.runId} / ${bound.aggregateSha256})`);
		}
		if (bound.gate !== E6_RUNTIME_CASE_GATES.get(result.caseId) || bound.gatePass !== expected.gate.pass || bound.overallPass !== expected.overallPass) {
			fail(`${location}: generation receipt verdict fields differ from the retained aggregate — a verdict altered without a new generation fails closed`);
		}
		// The recorded status must equal the retained gate verdict: a floor
		// claim flipped from fail to pass without a new generation is exactly
		// such a mismatch, as is a fabricated FAIL over a passing gate.
		if ((result.status === 'passed') !== (expected.gate.pass === true)) {
			fail(`${location}: recorded status "${result.status}" does not match the retained ${E6_RUNTIME_CASE_GATES.get(result.caseId)} verdict (${expected.gate.pass ? 'pass' : 'fail'})`);
		}
		if (!profileQualified && result.status === 'passed' && E6_PROFILE_CLAIM_GATES.has(E6_RUNTIME_CASE_GATES.get(result.caseId))) {
			fail(`${location}: E6 exact host/profile qualification is unavailable; a gate observation is not profile admission`);
		}
	}
}

function validateResults(resultsDocument, manifestInfo, selectedCaseId, evidenceRoot = repositoryRoot) {
	// The results document carries run identity: an unbound run cannot pass.
	exactKeys(resultsDocument, 'results', ['schemaVersion', 'results', 'runId', 'utcTime']);
	if (resultsDocument.schemaVersion !== 1) fail('results.schemaVersion: expected 1');
	expectString(resultsDocument.runId, 'results.runId');
	if (!RUN_ID_RE.test(resultsDocument.runId)) fail('results.runId: invalid run ID');
	validateUtcTime(resultsDocument.utcTime, 'results.utcTime');
	expectArray(resultsDocument.results, 'results.results');
	if (resultsDocument.results.length === 0) fail('results.results: must not be empty');

	const expected = selectedCaseId ? new Set([selectedCaseId]) : new Set([...manifestInfo.casesById.values()].filter((entry) => entry.requiredState === 'required').map((entry) => entry.id));
	const seen = new Set();
	for (const [index, result] of resultsDocument.results.entries()) {
		const location = `results.results[${index}]`;
		validateResultEntry(result, location);
		if (!manifestInfo.casesById.has(result.caseId)) fail(`${location}.caseId: unknown case ID "${result.caseId}"`);
		if (selectedCaseId && result.caseId !== selectedCaseId) fail(`${location}.caseId: outside exact --case ${selectedCaseId} selection`);
		if (seen.has(result.caseId)) fail(`duplicate result case ID "${result.caseId}"`);
		seen.add(result.caseId);
		const binding = manifestInfo.registryByCase.get(result.caseId);
		if (!binding) fail(`${location}.resultId: no evidence registry binding for case "${result.caseId}"`);
		if (result.resultId !== binding.resultId) fail(`${location}.resultId: does not match the evidence registry binding "${binding.resultId}" for case ${result.caseId}`);
		if (result.lane !== binding.lane) fail(`${location}.lane: does not match the evidence registry binding lane "${binding.lane}" for case ${result.caseId}`);
		const caseEntry = manifestInfo.casesById.get(result.caseId);
		// A result cannot exist for a fixture that does not exist: planned
		// fixtures are unbindable, so any reported evidence for them fails.
		if (!fs.existsSync(path.join(evidenceRoot, caseEntry.fixture))) {
			fail(`${location}.caseId: case ${result.caseId} reports evidence but its fixture "${caseEntry.fixture}" does not exist`);
		}
		const declared = new Set(caseEntry.retainedArtifacts.map((artifact) => artifact.replace(RUN_ID_PLACEHOLDER, resultsDocument.runId)));
		for (const artifact of result.retainedArtifacts) {
			if (!declared.has(artifact)) {
				fail(`${location}.retainedArtifacts: "${artifact}" is not a retained artifact declared by case ${result.caseId} for run "${resultsDocument.runId}"`);
			}
		}
		if (result.status !== 'passed') {
			// Honest executed consumption: only the sustained-run E6 runtime
			// gate cases may record an executed FAIL, and the retained
			// generation must itself prove it (validated below).
			if (!(result.status === 'failed' && E7_RELEASE_RUNTIME_CASE_IDS.has(result.caseId))) {
				fail(`case ${result.caseId}: required evidence reported ${result.status}; only passed is accepted`);
			}
		}
		// The pass must be PROVEN by the retained evidence itself.
		for (const [artifactIndex, artifact] of result.retainedArtifacts.entries()) {
			validateRetainedEvidence(artifact, result, resultsDocument, caseEntry, `${location}.retainedArtifacts[${artifactIndex}]`, evidenceRoot);
		}
	}
	for (const caseId of expected) {
		if (!seen.has(caseId)) fail(`missing result case ID "${caseId}"`);
	}
	return resultsDocument;
}

function validateSelection(manifestInfo, selectedCaseId) {
	if (!selectedCaseId) return;
	if (!CASE_ID_RE.test(selectedCaseId)) fail(`--case: invalid case ID "${selectedCaseId}"`);
	if (!manifestInfo.casesById.has(selectedCaseId)) fail(`--case: unknown case ID "${selectedCaseId}"`);
}

function validateManifestGenerationReceipt(manifestInfo, entry) {
	const resultsPath = path.join(repositoryRoot, 'test-results', 'connectivity-aware-sync', entry.generationReceipt.runId, 'e6', `results-${entry.id}.json`);
	if (!fs.existsSync(resultsPath)) {
		fail(`case ${entry.id}.generationReceipt: retained results document "test-results/connectivity-aware-sync/${entry.generationReceipt.runId}/e6/results-${entry.id}.json" does not exist on this checkout — a manifest receipt must bind a generation retained here`);
	}
	// The published per-case results document IS the aggregate's derived
	// results document: validating it runs the full retained-generation chain
	// (receipt existence, digest binding, accounting partition, verdict
	// consistency) plus the manifest receipt cross-check.
	validateResults(readJson(resultsPath, `case ${entry.id} generation receipt`), manifestInfo, entry.id);
}

function validateManifestDisposition(manifestInfo, selectedCaseId, hasResults) {
	const entries = selectedCaseId ? [manifestInfo.casesById.get(selectedCaseId)] : [...manifestInfo.casesById.values()];
	// The retained receipts tree is gitignored: on a fresh checkout (CI) it is
	// absent entirely and a manifest-only run cannot cross-check citations.
	// The signal is a REAL retained generation (a run directory carrying the
	// canonical e6/generation/aggregate.json layout), not the tree root: lane
	// runs create scratch run directories here before invoking this checker.
	// Where a real generation exists, every cited receipt must resolve to a
	// retained results document and pass the full retained-generation chain —
	// a fabricated run ID cannot hide behind a missing file.
	const retainedGenerationPresent = hasRetainedE6Generation(path.join(repositoryRoot, 'test-results', 'connectivity-aware-sync'));
	for (const entry of entries) {
		if (entry.expectedDisposition !== 'enforced') continue;
		if (own(entry, 'generationReceipt')) {
			// Executed-with-receipt binding: the schema-level validation runs
			// during the manifest walk above (field types, format, gate name),
			// and the retained-generation existence and content cross-check runs
			// whenever a real retained generation exists on this checkout. With
			// an explicit results document the caller's document is validated
			// instead and the receipt cross-check runs inside
			// validateRetainedEvidence.
			if (!hasResults && retainedGenerationPresent) {
				validateManifestGenerationReceipt(manifestInfo, entry);
			}
			continue;
		}
		if (!hasResults) fail(`case ${entry.id}.expectedDisposition: enforced evidence requires a results file`);
	}
}

function parseJsonText(text, location) {
	assertNoDuplicateJsonKeys(text, location);
	try {
		return JSON.parse(text);
	} catch (error) {
		fail(`${location}: invalid JSON (${error.message})`);
	}
}

function readJson(filename, location) {
	let text;
	try {
		text = fs.readFileSync(filename, 'utf8');
	} catch (error) {
		fail(`${location}: cannot read ${filename} (${error.message})`);
	}
	return parseJsonText(text, location);
}

function assertNoDuplicateJsonKeys(text, location) {
	let index = 0;

	function parseError(message) {
		fail(`${location}: invalid JSON near character ${index + 1} (${message})`);
	}

	function skipWhitespace() {
		while (index < text.length && /\s/.test(text[index])) index += 1;
	}

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
				if (own(simple, escaped)) value += simple[escaped];
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
		if (character === '"') {
			parseString();
			return;
		}
		if (character === 't' && text.slice(index, index + 4) === 'true') {
			index += 4;
			return;
		}
		if (character === 'f' && text.slice(index, index + 5) === 'false') {
			index += 5;
			return;
		}
		if (character === 'n' && text.slice(index, index + 4) === 'null') {
			index += 4;
			return;
		}
		const number = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
		if (number) {
			index += number[0].length;
			return;
		}
		parseError('expected value');
	}

	function parseObject() {
		index += 1;
		skipWhitespace();
		const keys = new Set();
		if (text[index] === '}') {
			index += 1;
			return;
		}
		while (index < text.length) {
			skipWhitespace();
			const key = parseString();
			if (keys.has(key)) fail(`${location}: duplicate JSON field "${key}"`);
			keys.add(key);
			skipWhitespace();
			if (text[index++] !== ':') parseError('expected colon');
			parseValue();
			skipWhitespace();
			if (text[index] === '}') {
				index += 1;
				return;
			}
			if (text[index++] !== ',') parseError('expected comma');
		}
		parseError('unterminated object');
	}

	function parseArray() {
		index += 1;
		skipWhitespace();
		if (text[index] === ']') {
			index += 1;
			return;
		}
		while (index < text.length) {
			parseValue();
			skipWhitespace();
			if (text[index] === ']') {
				index += 1;
				return;
			}
			if (text[index++] !== ',') parseError('expected comma');
		}
		parseError('unterminated array');
	}

	skipWhitespace();
	parseValue();
	skipWhitespace();
	if (index !== text.length) parseError('trailing data');
}

function parseArgs(argv) {
	const options = { manifest: '', results: '', caseId: '', decision: '', cleanup: '', profile: '', outcomeContract: '' };
	const positional = [];
	for (let index = 0; index < argv.length; index += 1) {
		const argument = argv[index];
		if (argument === '--case' || argument === '--results' || argument === '--decision' || argument === '--cleanup' || argument === '--profile' || argument === '--outcome-contract') {
			const value = argv[++index];
			if (!value || value.startsWith('--')) fail(`${argument}: requires a value`);
			const key = argument === '--case' ? 'caseId' : argument === '--outcome-contract' ? 'outcomeContract' : argument.slice(2);
			if (options[key]) fail(`${argument}: provided more than once`);
			options[key] = value;
		} else if (argument.startsWith('--')) {
			fail(`unknown option "${argument}"`);
		} else {
			positional.push(argument);
		}
	}

	if (options.decision || options.cleanup || options.profile || options.outcomeContract) {
		if (positional.length || options.manifest || options.results) fail('decision/cleanup/profile/outcome-contract validation cannot be combined with a manifest');
		const selected = [options.decision, options.cleanup, options.profile, options.outcomeContract].filter(Boolean);
		if (selected.length > 1) fail('pass only one of --decision, --cleanup, --profile, or --outcome-contract');
		return options;
	}
	if (positional.length > 2) fail('usage: check-connectivity-aware-sync-cases.mjs MANIFEST [RESULTS] [--results FILE] [--case ID] | --decision FILE | --cleanup FILE | --profile FILE | --outcome-contract FILE');
	if (positional[0]) options.manifest = positional[0];
	if (positional[1]) {
		if (options.results) fail('results file provided both positionally and with --results');
		options.results = positional[1];
	}
	if (!options.manifest) fail('usage: check-connectivity-aware-sync-cases.mjs MANIFEST [RESULTS] [--results FILE] [--case ID] | --decision FILE | --cleanup FILE | --profile FILE | --outcome-contract FILE');
	return options;
}

function run(options) {
	if (options.decision || options.cleanup || options.profile || options.outcomeContract) {
		if (options.decision) {
			validateDecisionRecord(readJson(options.decision, 'decision'));
			console.log(`connectivity-aware-sync: PASS decision ${options.decision}`);
		}
		if (options.cleanup) {
			validateCleanupReceipt(readJson(options.cleanup, 'cleanup'));
			console.log(`connectivity-aware-sync: PASS cleanup ${options.cleanup}`);
		}
		if (options.profile) {
			validateE6ProfileDocument(readJson(options.profile, 'profile'));
			console.log(`connectivity-aware-sync: PASS profile ${options.profile}`);
		}
		if (options.outcomeContract) {
			validateE7OutcomeContract(readJson(options.outcomeContract, 'e7 outcome contract'));
			console.log(`connectivity-aware-sync: PASS outcome-contract ${options.outcomeContract}`);
		}
		return;
	}

	const manifest = readJson(options.manifest, 'manifest');
	const manifestInfo = validateManifest(manifest);
	validateSelection(manifestInfo, options.caseId);
	validateManifestDisposition(manifestInfo, options.caseId, Boolean(options.results));
	if (options.results) validateResults(readJson(options.results, 'results'), manifestInfo, options.caseId);
	const scope = options.caseId ? ` case ${options.caseId}` : '';
	const resultScope = options.results ? ' with results' : ' manifest-only';
	console.log(`connectivity-aware-sync: PASS${scope}${resultScope} (${manifest.cases.length} manifest case(s))`);
}

export {
	assertNoDuplicateJsonKeys,
	parseJsonText,
	validateCleanupReceipt,
	validateDecisionRecord,
	validateE7CapabilityScoping,
	validateE7IncompleteOutcomeRule,
	validateE7OutcomeContract,
	validateE7UsefulnessNotSafetyOnly,
	validateManifest,
	validateResults,
};

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
	try {
		run(parseArgs(process.argv.slice(2)));
	} catch (error) {
		console.error(`connectivity-aware-sync: FAIL — ${error.message}`);
		process.exitCode = error.message.startsWith('usage:') || error.message.includes('requires a value') || error.message.startsWith('unknown option') ? 2 : 1;
	}
}
