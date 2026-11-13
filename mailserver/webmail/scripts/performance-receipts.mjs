import { createHash } from 'node:crypto';
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
	statSync,
	writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

/**
 * Receipt writer and guard seam for `scripts/verify-webmail-performance.sh`.
 *
 * Two evidence kinds share one run root and must never be mistaken for each
 * other (plan: retired-docs:superpowers/plans/2026-08-09-webmail-loading-performance.md,
 * release closure section):
 *
 * - `timing` receipts (`run.json`) are written only by the diagnostic/ci/release
 *   measurement lanes and are the only writers allowed to advance
 *   `test-results/webmail-performance/latest.json`.
 * - `rehearsal` receipts (`rehearsal-receipt.v1.json`) are written only by the
 *   retained-prior-artifact update rehearsal. They never touch `latest.json`
 *   and are never written into a timing run directory.
 *
 * Every refusal below is a fail-closed policy violation, not a fallback.
 */

export const TIMING_RECEIPT_NAME = 'run.json';
export const REHEARSAL_RECEIPT_NAME = 'rehearsal-receipt.v1.json';
export const TIMING_KIND = 'timing';
export const REHEARSAL_KIND = 'rehearsal';
export const REHEARSAL_REPORT_VERSION = 'webmail-performance-rehearsal-receipt-v1';
export const LEDGER_REPORT_VERSION = 'webmail-performance-asset-ledger-v1';
export const LATEST_RELATIVE_PATH = 'mailserver/webmail/test-results/webmail-performance/latest.json';
export const PRIOR_ARTIFACT_LEDGER_NAME = 'asset-ledger.v1.json';
export const PRIOR_ARTIFACT_WEB_DIR_NAME = 'web';

const WEBMAIL_ROOT_RELATIVE = 'mailserver/webmail';

export class PerfEvidenceError extends Error {
	constructor({ code, problem, cause, value, artifact, fix, rerun }) {
		super(`E_WEBMAIL_PERF_${code} problem=${problem} cause=${cause} value=${value ?? '-'} artifact=${artifact}`);
		this.name = 'PerfEvidenceError';
		this.code = code;
		this.problem = problem;
		this.causeText = cause;
		this.value = value;
		this.artifact = artifact;
		this.fix = fix;
		this.rerun = rerun;
	}

	grammarLine() {
		return `E_WEBMAIL_PERF_${this.code} problem=${this.problem} cause=${this.causeText} value=${this.value ?? '-'} artifact=${this.artifact} fix='${this.fix}' rerun='${this.rerun ?? 'bash scripts/verify-webmail-performance.sh --help'}'`;
	}
}

function sha256(bytes) {
	return createHash('sha256').update(bytes).digest('hex');
}

function writeJsonAtomic(filePath, value) {
	mkdirSync(dirname(filePath), { recursive: true });
	const temp = `${filePath}.tmp-${process.pid}`;
	writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`);
	renameSync(temp, filePath);
}

function requireString(value, name) {
	if (typeof value !== 'string' || value.length === 0) {
		throw new Error(`${name} must be a non-empty string`);
	}
	return value;
}

function resultsRoot(root) {
	return join(root, WEBMAIL_ROOT_RELATIVE, 'test-results', 'webmail-performance');
}

export function buildTimingReceipt({
	runId,
	mode,
	samples,
	warmup,
	buildId,
	commit,
	fixtureSha256,
	hostClass,
	nodeVersion,
	hostSupported,
	startedAt,
	finishedAt,
	evidence,
}) {
	const started = Date.parse(requireString(startedAt, 'startedAt'));
	const finishedMs = Date.parse(requireString(finishedAt, 'finishedAt'));
	if (!Number.isFinite(started) || !Number.isFinite(finishedMs) || finishedMs < started) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'timing_duration_unrecordable',
			cause: 'started_at_or_finished_at_is_not_a_valid_timestamp',
			value: `${startedAt}..${finishedAt}`,
			artifact: TIMING_RECEIPT_NAME,
			fix: 'rerun the timing lane without clock tampering',
			rerun: `bash scripts/verify-webmail-performance.sh ${mode}`,
		});
	}
	return {
		schemaVersion: 1,
		kind: TIMING_KIND,
		verdict: 'pass',
		runId: requireString(runId, 'runId'),
		mode: requireString(mode, 'mode'),
		samples: Number(samples),
		warmup: Number(warmup),
		buildId: requireString(buildId, 'buildId'),
		commit: requireString(commit, 'commit'),
		fixtureSha256: requireString(fixtureSha256, 'fixtureSha256'),
		hostClass: requireString(hostClass, 'hostClass'),
		hostSupported: hostSupported === true || hostSupported === '1',
		nodeVersion: requireString(nodeVersion, 'nodeVersion'),
		startedAt,
		finishedAt,
		durationSeconds: Math.round((finishedMs - started) / 1000),
		evidence: requireString(evidence, 'evidence'),
		summary: `${requireString(evidence, 'evidence')}/performance-summary.v1.json`,
	};
}

export function buildRehearsalReceipt({
	runId,
	commit,
	candidateBuildId,
	priorBuildId,
	priorArtifact,
	candidateLedger,
	phases,
	hostClass,
	nodeVersion,
	hostSupported,
	fixtureSha256,
	startedAt,
	finishedAt,
	evidence,
}) {
	if (!Array.isArray(phases) || phases.length === 0) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'rehearsal_phases_missing',
			cause: 'a_rehearsal_receipt_requires_prior_and_candidate_phase_records',
			value: String(phases?.length ?? 0),
			artifact: REHEARSAL_RECEIPT_NAME,
			fix: 'rerun the rehearsal lane; it always records a prior and a candidate phase',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal',
		});
	}
	const started = Date.parse(requireString(startedAt, 'startedAt'));
	const finishedMs = Date.parse(requireString(finishedAt, 'finishedAt'));
	if (!Number.isFinite(started) || !Number.isFinite(finishedMs) || finishedMs < started) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'rehearsal_duration_unrecordable',
			cause: 'started_at_or_finished_at_is_not_a_valid_timestamp',
			value: `${startedAt}..${finishedAt}`,
			artifact: REHEARSAL_RECEIPT_NAME,
			fix: 'rerun the rehearsal lane without clock tampering',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal',
		});
	}
	return {
		reportVersion: REHEARSAL_REPORT_VERSION,
		schemaVersion: 1,
		kind: REHEARSAL_KIND,
		verdict: 'pass',
		runId: requireString(runId, 'runId'),
		mode: 'rehearsal',
		commit: requireString(commit, 'commit'),
		candidateBuildId: requireString(candidateBuildId, 'candidateBuildId'),
		priorBuildId: requireString(priorBuildId, 'priorBuildId'),
		priorArtifact: {
			artifactSetSha256: requireString(priorArtifact.artifactSetSha256, 'priorArtifact.artifactSetSha256'),
			ledgerSha256: requireString(priorArtifact.ledgerSha256, 'priorArtifact.ledgerSha256'),
			assetCount: priorArtifact.assetCount,
		},
		candidateArtifactSetSha256: requireString(candidateLedger.artifactSetSha256, 'candidateLedger.artifactSetSha256'),
		fixtureSha256: requireString(fixtureSha256, 'fixtureSha256'),
		hostClass: requireString(hostClass, 'hostClass'),
		hostSupported: hostSupported === true || hostSupported === '1',
		nodeVersion: requireString(nodeVersion, 'nodeVersion'),
		startedAt,
		finishedAt,
		durationSeconds: Math.round((finishedMs - started) / 1000),
		phases,
		evidence: requireString(evidence, 'evidence'),
	};
}

export function writeTimingReceipt({ root, runDir, receipt }) {
	root = resolve(root);
	runDir = resolve(runDir);
	if (receipt?.kind !== TIMING_KIND) {
		throw new PerfEvidenceError({
			code: 'POLICY_VIOLATION',
			problem: 'timing_writer_refused_non_timing_receipt',
			cause: 'the_timing_writer_only_writes_kind_timing_receipts',
			value: String(receipt?.kind ?? '<absent>'),
			artifact: TIMING_RECEIPT_NAME,
			fix: 'use the rehearsal writer for kind rehearsal receipts',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	if (existsSync(join(runDir, REHEARSAL_RECEIPT_NAME))) {
		throw new PerfEvidenceError({
			code: 'POLICY_VIOLATION',
			problem: 'timing_receipt_refused_for_rehearsal_run',
			cause: 'the_run_directory_already_holds_a_rehearsal_receipt',
			value: REHEARSAL_RECEIPT_NAME,
			artifact: runDir,
			fix: 'keep timing and rehearsal runs in their own run directories',
			rerun: 'bash scripts/verify-webmail-performance.sh --help',
		});
	}
	writeJsonAtomic(join(runDir, TIMING_RECEIPT_NAME), receipt);
	const latest = join(resultsRoot(root), 'latest.json');
	writeJsonAtomic(latest, receipt);
	return { receiptPath: join(runDir, TIMING_RECEIPT_NAME), latestPath: latest };
}

export function writeRehearsalReceipt({ runDir, receipt }) {
	// Deliberately takes no `root`: the rehearsal writer has no latest.json code
	// path at all; only a timing receipt may advance the promoted pointer.
	runDir = resolve(runDir);
	if (receipt?.kind !== REHEARSAL_KIND || receipt?.reportVersion !== REHEARSAL_REPORT_VERSION) {
		throw new PerfEvidenceError({
			code: 'POLICY_VIOLATION',
			problem: 'rehearsal_writer_refused_non_rehearsal_receipt',
			cause: 'the_rehearsal_writer_only_writes_kind_rehearsal_receipts',
			value: String(receipt?.kind ?? '<absent>'),
			artifact: REHEARSAL_RECEIPT_NAME,
			fix: 'use the timing writer for kind timing receipts',
			rerun: 'bash scripts/verify-webmail-performance.sh --help',
		});
	}
	if (existsSync(join(runDir, TIMING_RECEIPT_NAME))) {
		throw new PerfEvidenceError({
			code: 'POLICY_VIOLATION',
			problem: 'rehearsal_receipt_refused_for_timing_run',
			cause: 'the_run_directory_already_holds_a_timing_receipt',
			value: TIMING_RECEIPT_NAME,
			artifact: runDir,
			fix: 'keep timing and rehearsal runs in their own run directories',
			rerun: 'bash scripts/verify-webmail-performance.sh --help',
		});
	}
	const receiptPath = join(runDir, REHEARSAL_RECEIPT_NAME);
	writeJsonAtomic(receiptPath, receipt);
	// Deliberate: the rehearsal has no latest.json code path at all. Only a
	// timing receipt may advance the promoted pointer.
	return { receiptPath };
}

/**
 * Validate a retained prior artifact bundle.
 *
 * Bundle layout (the only accepted shape):
 *   <artifactDir>/asset-ledger.v1.json   the signed asset ledger
 *   <artifactDir>/web/                   full retained web root (index.html,
 *                                        service-worker.js, _app/version.json,
 *                                        critical shell, hashed assets, sidecars)
 *
 * Every ledger row is re-hashed against the retained bytes, so a tampered or
 * partial retention fails closed. A bundle whose build id equals the candidate
 * is refused: an update rehearsal needs an actually-different prior artifact.
 */
export function validatePriorArtifact({ artifactDir, candidateBuildId }) {
	artifactDir = resolve(artifactDir);
	const ledgerPath = join(artifactDir, PRIOR_ARTIFACT_LEDGER_NAME);
	const webDir = join(artifactDir, PRIOR_ARTIFACT_WEB_DIR_NAME);
	if (!isFile(ledgerPath) || !isDirectory(webDir)) {
		throw new PerfEvidenceError({
			code: 'INPUTS_ABSENT',
			problem: 'retained_prior_artifact_incomplete',
			cause: 'bundle_requires_asset_ledger_and_web_directory',
			value: artifactDir,
			artifact: PRIOR_ARTIFACT_LEDGER_NAME,
			fix: `retain the prior release as ${PRIOR_ARTIFACT_LEDGER_NAME} plus a ${PRIOR_ARTIFACT_WEB_DIR_NAME}/ copy of its web root`,
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	const ledgerBytes = readFileSync(ledgerPath);
	let ledger;
	try {
		ledger = JSON.parse(ledgerBytes.toString('utf8'));
	} catch {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'retained_prior_ledger_unparseable',
			cause: 'ledger_is_not_valid_json',
			value: PRIOR_ARTIFACT_LEDGER_NAME,
			artifact: ledgerPath,
			fix: 'retain an intact asset ledger with the prior artifact',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	if (ledger?.reportVersion !== LEDGER_REPORT_VERSION || ledger?.schemaVersion !== 1) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'retained_prior_ledger_unsupported',
			cause: 'report_version_or_schema_version_is_not_ledger_v1',
			value: String(ledger?.reportVersion ?? '<absent>'),
			artifact: PRIOR_ARTIFACT_LEDGER_NAME,
			fix: 'retain the ledger produced by scripts/performance-report.mjs v1',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	if (typeof ledger.buildId !== 'string' || ledger.buildId.length === 0 || !Array.isArray(ledger.assets) || ledger.assets.length === 0) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'retained_prior_ledger_malformed',
			cause: 'build_id_or_assets_are_missing',
			value: String(ledger.buildId ?? '<absent>'),
			artifact: PRIOR_ARTIFACT_LEDGER_NAME,
			fix: 'retain a complete signed ledger (buildId plus assets)',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	for (const requiredFile of ['index.html', 'service-worker.js', '_app/version.json']) {
		if (!isFile(join(webDir, requiredFile))) {
			throw new PerfEvidenceError({
				code: 'INPUTS_ABSENT',
				problem: 'retained_prior_web_root_incomplete',
				cause: `${requiredFile}_is_missing_from_the_retained_web_root`,
				value: requiredFile,
				artifact: `${PRIOR_ARTIFACT_WEB_DIR_NAME}/${requiredFile}`,
				fix: `copy the complete prior web root including ${requiredFile}`,
				rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
			});
		}
	}
	const versionRecord = JSON.parse(readFileSync(join(webDir, '_app/version.json'), 'utf8'));
	if (versionRecord?.version !== ledger.buildId) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'retained_prior_build_id_mismatch',
			cause: 'retained_version_json_disagrees_with_the_ledger_build_id',
			value: `${versionRecord?.version ?? '<absent>'}!=${ledger.buildId}`,
			artifact: `${PRIOR_ARTIFACT_WEB_DIR_NAME}/_app/version.json`,
			fix: 'retain the web root and the ledger from the same prior build',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	if (candidateBuildId && ledger.buildId === candidateBuildId) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'prior_artifact_matches_candidate',
			cause: 'an_update_rehearsal_requires_a_different_retained_prior_build',
			value: ledger.buildId,
			artifact: PRIOR_ARTIFACT_LEDGER_NAME,
			fix: 'point --prior-artifact at the actually retained prior release artifact',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	for (const asset of ledger.assets) {
		verifyAssetRow(webDir, asset);
	}
	return {
		buildId: ledger.buildId,
		artifactSetSha256: typeof ledger.artifactSetSha256 === 'string' ? ledger.artifactSetSha256 : null,
		ledgerSha256: sha256(ledgerBytes),
		assetCount: ledger.assets.length,
		webDir,
	};
}

function isFile(path) {
	try {
		return statSync(path).isFile();
	} catch {
		return false;
	}
}

function isDirectory(path) {
	try {
		return statSync(path).isDirectory();
	} catch {
		return false;
	}
}

function verifyAssetRow(webDir, asset) {
	const path = typeof asset?.path === 'string' ? asset.path : '';
	if (
		path.length === 0 ||
		isAbsolute(path) ||
		path.split('/').includes('..') ||
		path.split('/').includes('.') === true
	) {
		throw pathRefused(path);
	}
	const filePath = join(webDir, path);
	if (!isFile(filePath)) {
		throw new PerfEvidenceError({
			code: 'INPUTS_ABSENT',
			problem: 'retained_prior_asset_missing',
			cause: 'the_ledger_row_has_no_retained_file',
			value: path,
			artifact: `${PRIOR_ARTIFACT_WEB_DIR_NAME}/${path}`,
			fix: 'retain the complete prior web root; every ledger row must be present',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	const bytes = readFileSync(filePath);
	if (bytes.byteLength !== asset.identityBytes || sha256(bytes) !== asset.identitySha256) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'retained_prior_asset_tampered',
			cause: 'retained_bytes_do_not_match_the_signed_ledger_row',
			value: path,
			artifact: `${PRIOR_ARTIFACT_WEB_DIR_NAME}/${path}`,
			fix: 're-retain the prior artifact; the retained copy is not byte-identical to the signed ledger',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
		});
	}
	for (const representation of Object.values(asset.representations ?? {})) {
		const sidecarPath = typeof representation?.path === 'string' ? representation.path : '';
		if (sidecarPath.length === 0) continue;
		const sidecarFile = join(webDir, sidecarPath);
		if (!isFile(sidecarFile)) {
			throw new PerfEvidenceError({
				code: 'INPUTS_ABSENT',
				problem: 'retained_prior_sidecar_missing',
				cause: 'a_signed_representation_sidecar_has_no_retained_file',
				value: sidecarPath,
				artifact: `${PRIOR_ARTIFACT_WEB_DIR_NAME}/${sidecarPath}`,
				fix: 'retain the compressed sidecars together with the prior web root',
				rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
			});
		}
		const sidecarBytes = readFileSync(sidecarFile);
		if (sidecarBytes.byteLength !== representation.bytes || sha256(sidecarBytes) !== representation.sha256) {
			throw new PerfEvidenceError({
				code: 'INVALID_EVIDENCE',
				problem: 'retained_prior_sidecar_tampered',
				cause: 'retained_sidecar_bytes_do_not_match_the_signed_ledger_row',
				value: sidecarPath,
				artifact: `${PRIOR_ARTIFACT_WEB_DIR_NAME}/${sidecarPath}`,
				fix: 're-retain the prior artifact; the retained sidecar is not byte-identical',
				rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
			});
		}
	}
}

function pathRefused(path) {
	return new PerfEvidenceError({
		code: 'INVALID_EVIDENCE',
		problem: 'retained_prior_ledger_unsafe_path',
		cause: 'ledger_rows_must_stay_inside_the_retained_web_root',
		value: path,
		artifact: PRIOR_ARTIFACT_LEDGER_NAME,
		fix: 'retain the ledger produced by scripts/performance-report.mjs; hand-built ledgers are refused',
		rerun: 'bash scripts/verify-webmail-performance.sh rehearsal --help',
	});
}

function fixtureSha256(root) {
	return sha256(readFileSync(join(root, WEBMAIL_ROOT_RELATIVE, 'e2e/fixtures/seed.sql')));
}

function hostClass() {
	return `${process.platform}-${process.arch}`;
}

export function parsePhases(raw, { priorBuildId, candidateBuildId }) {
	let phases;
	try {
		phases = JSON.parse(raw);
	} catch {
		phases = null;
	}
	if (
		!Array.isArray(phases) ||
		phases.length !== 2 ||
		phases.some((phase) => !phase || typeof phase !== 'object' || typeof phase.name !== 'string' || typeof phase.servedBuildId !== 'string')
	) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'rehearsal_phase_records_invalid',
			cause: 'exactly_one_prior_and_one_candidate_phase_record_is_required',
			value: String(Array.isArray(phases) ? phases.length : '<unparseable>'),
			artifact: REHEARSAL_RECEIPT_NAME,
			fix: 'rerun the rehearsal lane',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal',
		});
	}
	const byName = Object.fromEntries(phases.map((phase) => [phase.name, phase]));
	if (byName['phase-prior']?.servedBuildId !== priorBuildId || byName['phase-candidate']?.servedBuildId !== candidateBuildId) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'rehearsal_served_build_mismatch',
			cause: 'a_phase_did_not_serve_its_expected_artifact',
			value: `${byName['phase-prior']?.servedBuildId ?? '<absent>'}->${byName['phase-candidate']?.servedBuildId ?? '<absent>'}`,
			artifact: REHEARSAL_RECEIPT_NAME,
			fix: 'rerun the rehearsal; the prior phase must serve the prior build and the candidate phase the candidate build',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal',
		});
	}
	return phases;
}

export function selfTest() {
	const checks = [];
	const assert = (name, condition) => {
		if (!condition) throw new Error(`self-test failed: ${name}`);
		checks.push(name);
	};
	const root = mkdtempSync(join(tmpdir(), 'setjoin-receipts-selftest-'));
	try {
		const runRoot = join(root, 'repo');
		const timingRunDir = join(runRoot, 'runs', 't1');
		const startedAt = new Date().toISOString();
		const finishedAt = new Date(Date.now() + 1000).toISOString();
		const baseTiming = {
			runId: 't1',
			mode: 'ci',
			samples: 5,
			warmup: 1,
			buildId: 'b1',
			commit: 'commit12345678',
			hostClass: hostClass(),
			nodeVersion: process.version,
			hostSupported: true,
			startedAt,
			finishedAt,
			evidence: 'runs/t1',
		};

		// 1. A timing receipt writes run.json plus latest.json and nothing else.
		const timing = buildTimingReceipt({ ...baseTiming, fixtureSha256: 'f'.repeat(64) });
		const written = writeTimingReceipt({ root: runRoot, runDir: timingRunDir, receipt: timing });
		assert('timing receipt written', isFile(written.receiptPath));
		assert('timing advances latest', isFile(written.latestPath));
		assert('timing kind recorded', JSON.parse(readFileSync(written.receiptPath, 'utf8')).kind === TIMING_KIND);
		assert('no rehearsal artifact in timing run', !existsSync(join(timingRunDir, REHEARSAL_RECEIPT_NAME)));
		assert('timing duration recorded', timing.durationSeconds >= 1);

		// 2. The timing writer refuses a run directory holding a rehearsal receipt.
		mkdirSync(join(runRoot, 'runs', 't2'), { recursive: true });
		writeFileSync(join(runRoot, 'runs', 't2', REHEARSAL_RECEIPT_NAME), '{}\n');
		let refused = null;
		try {
			writeTimingReceipt({ root: runRoot, runDir: join(runRoot, 'runs', 't2'), receipt: timing });
		} catch (error) {
			refused = error;
		}
		assert('timing refuses rehearsal run dir', refused?.code === 'POLICY_VIOLATION');

		// 3. The rehearsal writer writes only its own named receipt and never
		//    touches latest.json or run.json.
		const rehearsalRunDir = join(runRoot, 'runs', 't3-rehearsal');
		const latestBefore = readFileSync(join(runRoot, LATEST_RELATIVE_PATH), 'utf8');
		const rehearsal = buildRehearsalReceipt({
			runId: 't3-rehearsal',
			commit: 'commit12345678',
			candidateBuildId: 'b2',
			priorBuildId: 'b1',
			priorArtifact: { artifactSetSha256: 'a'.repeat(64), ledgerSha256: 'b'.repeat(64), assetCount: 2 },
			candidateLedger: { artifactSetSha256: 'c'.repeat(64) },
			phases: [
				{ name: 'phase-prior', servedBuildId: 'b1', summary: 'runs/t3-rehearsal/phase-prior/performance-summary.v1.json' },
				{ name: 'phase-candidate', servedBuildId: 'b2', summary: 'runs/t3-rehearsal/phase-candidate/performance-summary.v1.json' },
			],
			hostClass: hostClass(),
			nodeVersion: process.version,
			hostSupported: true,
			fixtureSha256: 'f'.repeat(64),
			startedAt,
			finishedAt,
			evidence: 'runs/t3-rehearsal',
		});
		const rehearsalWritten = writeRehearsalReceipt({ runDir: rehearsalRunDir, receipt: rehearsal });
		assert('rehearsal receipt written', isFile(rehearsalWritten.receiptPath));
		assert('rehearsal receipt name distinct', REHEARSAL_RECEIPT_NAME !== TIMING_RECEIPT_NAME);
		assert('rehearsal kind recorded', JSON.parse(readFileSync(rehearsalWritten.receiptPath, 'utf8')).kind === REHEARSAL_KIND);
		assert('rehearsal never advances latest', readFileSync(join(runRoot, LATEST_RELATIVE_PATH), 'utf8') === latestBefore);
		assert('rehearsal never writes run.json', !existsSync(join(rehearsalRunDir, TIMING_RECEIPT_NAME)));
		assert('rehearsal temp files cleaned', readdirSync(rehearsalRunDir).every((name) => !name.includes('.tmp-')));

		// 4. The rehearsal writer refuses a run directory holding a timing receipt.
		refused = null;
		try {
			writeRehearsalReceipt({ runDir: timingRunDir, receipt: rehearsal });
		} catch (error) {
			refused = error;
		}
		assert('rehearsal refuses timing run dir', refused?.code === 'POLICY_VIOLATION');

		// 5. Kind substitution is refused in both directions.
		refused = null;
		try {
			writeTimingReceipt({ root: runRoot, runDir: join(runRoot, 'runs', 't5'), receipt: rehearsal });
		} catch (error) {
			refused = error;
		}
		assert('timing writer refuses rehearsal receipt', refused?.code === 'POLICY_VIOLATION');
		refused = null;
		try {
			writeRehearsalReceipt({ runDir: join(runRoot, 'runs', 't5'), receipt: timing });
		} catch (error) {
			refused = error;
		}
		assert('rehearsal writer refuses timing receipt', refused?.code === 'POLICY_VIOLATION');

		// 6. Phase records must bind each phase to its expected served build.
		refused = null;
		try {
			parsePhases(JSON.stringify(rehearsal.phases), { priorBuildId: 'b1', candidateBuildId: 'bX' });
		} catch (error) {
			refused = error;
		}
		assert('phase served-build mismatch refused', refused?.code === 'INVALID_EVIDENCE');
		assert('phase records accepted when bound', parsePhases(JSON.stringify(rehearsal.phases), { priorBuildId: 'b1', candidateBuildId: 'b2' }).length === 2);

		// 7. Retained prior artifact validation: happy path plus every refusal.
		const artifactDir = join(root, 'prior-artifact');
		const webDir = join(artifactDir, 'web');
		mkdirSync(join(webDir, '_app'), { recursive: true });
		const indexBytes = Buffer.from('<html>prior</html>\n');
		const workerBytes = Buffer.from('self.addEventListener("install", () => {});\n');
		writeFileSync(join(webDir, 'index.html'), indexBytes);
		writeFileSync(join(webDir, 'service-worker.js'), workerBytes);
		writeFileSync(join(webDir, '_app', 'version.json'), `${JSON.stringify({ version: 'b1' })}\n`);
		const ledger = {
			reportVersion: LEDGER_REPORT_VERSION,
			schemaVersion: 1,
			buildId: 'b1',
			artifactSetSha256: 'a'.repeat(64),
			assets: [
				{ path: 'index.html', identityBytes: indexBytes.byteLength, identitySha256: sha256(indexBytes) },
				{
					path: 'service-worker.js',
					identityBytes: workerBytes.byteLength,
					identitySha256: sha256(workerBytes),
					representations: {
						br: { path: 'service-worker.js.br', bytes: 5, sha256: sha256(Buffer.from('brbed')) },
					},
				},
			],
		};
		writeFileSync(join(artifactDir, PRIOR_ARTIFACT_LEDGER_NAME), `${JSON.stringify(ledger, null, 2)}\n`);
		writeFileSync(join(webDir, 'service-worker.js.br'), 'brbed');
		const validated = validatePriorArtifact({ artifactDir, candidateBuildId: 'b2' });
		assert('prior artifact validated', validated.buildId === 'b1' && validated.assetCount === 2);
		assert('prior ledger hash recorded', /^[a-f0-9]{64}$/.test(validated.ledgerSha256));

		refused = null;
		try {
			validatePriorArtifact({ artifactDir: join(root, 'absent'), candidateBuildId: 'b2' });
		} catch (error) {
			refused = error;
		}
		assert('absent prior artifact refused', refused?.code === 'INPUTS_ABSENT');

		writeFileSync(join(webDir, 'index.html'), '<html>tampered</html>\n');
		refused = null;
		try {
			validatePriorArtifact({ artifactDir, candidateBuildId: 'b2' });
		} catch (error) {
			refused = error;
		}
		assert('tampered prior asset refused', refused?.code === 'INVALID_EVIDENCE');
		writeFileSync(join(webDir, 'index.html'), indexBytes);

		refused = null;
		try {
			validatePriorArtifact({ artifactDir, candidateBuildId: 'b1' });
		} catch (error) {
			refused = error;
		}
		assert('prior equal to candidate refused', refused?.code === 'INVALID_EVIDENCE');

		writeFileSync(join(webDir, '_app', 'version.json'), `${JSON.stringify({ version: 'b9' })}\n`);
		refused = null;
		try {
			validatePriorArtifact({ artifactDir, candidateBuildId: 'b2' });
		} catch (error) {
			refused = error;
		}
		assert('stale version record refused', refused?.code === 'INVALID_EVIDENCE');
		writeFileSync(join(webDir, '_app', 'version.json'), `${JSON.stringify({ version: 'b1' })}\n`);

		writeFileSync(join(webDir, 'service-worker.js.br'), 'tampered');
		refused = null;
		try {
			validatePriorArtifact({ artifactDir, candidateBuildId: 'b2' });
		} catch (error) {
			refused = error;
		}
		assert('tampered sidecar refused', refused?.code === 'INVALID_EVIDENCE');
		writeFileSync(join(webDir, 'service-worker.js.br'), 'brbed');

		const traversalLedger = JSON.parse(JSON.stringify(ledger));
		traversalLedger.assets[0].path = '../escape.html';
		writeFileSync(join(artifactDir, PRIOR_ARTIFACT_LEDGER_NAME), `${JSON.stringify(traversalLedger, null, 2)}\n`);
		refused = null;
		try {
			validatePriorArtifact({ artifactDir, candidateBuildId: 'b2' });
		} catch (error) {
			refused = error;
		}
		assert('ledger path traversal refused', refused?.code === 'INVALID_EVIDENCE');
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
	return checks;
}

function cliWriteTiming() {
	const root = process.env.ROOT;
	const runDir = process.env.RUN_DIR;
	if (!root || !runDir) throw new Error('write-timing requires ROOT and RUN_DIR env');
	const receipt = buildTimingReceipt({
		runId: process.env.RUN_ID,
		mode: process.env.MODE,
		samples: process.env.SAMPLES,
		warmup: process.env.WARMUP,
		buildId: process.env.BUILD_ID,
		commit: process.env.COMMIT,
		fixtureSha256: fixtureSha256(root),
		hostClass: hostClass(),
		nodeVersion: process.version,
		hostSupported: process.env.HOST_SUPPORTED === '1',
		startedAt: process.env.STARTED_AT ?? new Date().toISOString(),
		finishedAt: new Date().toISOString(),
		evidence: relative(resolve(root), resolve(runDir)).replaceAll('\\', '/'),
	});
	const written = writeTimingReceipt({ root, runDir, receipt });
	process.stdout.write(`timing receipt ${written.receiptPath}\nlatest ${written.latestPath}\n`);
}

function cliWriteRehearsal() {
	const root = process.env.ROOT;
	const runDir = process.env.RUN_DIR;
	const priorArtifactDir = process.env.PRIOR_ARTIFACT_DIR;
	const candidateLedgerPath = process.env.CANDIDATE_LEDGER;
	if (!root || !runDir || !priorArtifactDir || !candidateLedgerPath) {
		throw new Error('write-rehearsal requires ROOT, RUN_DIR, PRIOR_ARTIFACT_DIR and CANDIDATE_LEDGER env');
	}
	const priorBuildId = requireString(process.env.PRIOR_BUILD_ID, 'PRIOR_BUILD_ID');
	const candidateBuildId = requireString(process.env.CANDIDATE_BUILD_ID, 'CANDIDATE_BUILD_ID');
	const phases = parsePhases(process.env.PHASES_JSON ?? 'null', { priorBuildId, candidateBuildId });
	const priorArtifact = validatePriorArtifact({ artifactDir: priorArtifactDir, candidateBuildId });
	const candidateLedger = JSON.parse(readFileSync(candidateLedgerPath, 'utf8'));
	if (candidateLedger.buildId !== candidateBuildId) {
		throw new PerfEvidenceError({
			code: 'INVALID_EVIDENCE',
			problem: 'candidate_ledger_mismatch',
			cause: 'candidate_ledger_build_id_is_not_the_served_candidate',
			value: `${candidateLedger.buildId}!=${candidateBuildId}`,
			artifact: 'asset-ledger.v1.json',
			fix: 'rerun the rehearsal from a freshly built and ledger-verified candidate',
			rerun: 'bash scripts/verify-webmail-performance.sh rehearsal',
		});
	}
	const receipt = buildRehearsalReceipt({
		runId: requireString(process.env.RUN_ID, 'RUN_ID'),
		commit: requireString(process.env.COMMIT, 'COMMIT'),
		candidateBuildId,
		priorBuildId,
		priorArtifact,
		candidateLedger,
		phases,
		hostClass: hostClass(),
		nodeVersion: process.version,
		hostSupported: process.env.HOST_SUPPORTED === '1',
		fixtureSha256: fixtureSha256(root),
		startedAt: process.env.STARTED_AT ?? new Date().toISOString(),
		finishedAt: new Date().toISOString(),
		evidence: relative(resolve(root), resolve(runDir)).replaceAll('\\', '/'),
	});
	const written = writeRehearsalReceipt({ runDir, receipt });
	process.stdout.write(`rehearsal receipt ${written.receiptPath}\n`);
}

function cliValidatePriorArtifact(argv) {
	let artifactDir;
	let candidateBuildId;
	for (let index = 0; index < argv.length; index += 2) {
		const flag = argv[index];
		const value = argv[index + 1];
		if (flag === '--artifact') artifactDir = value;
		else if (flag === '--candidate-build-id') candidateBuildId = value;
		else throw new Error(`validate-prior-artifact: unknown flag ${flag}`);
	}
	if (!artifactDir) throw new Error('validate-prior-artifact requires --artifact DIR');
	const validated = validatePriorArtifact({ artifactDir, candidateBuildId });
	process.stdout.write(`${JSON.stringify(validated, null, 2)}\n`);
}

async function main() {
	const [subcommand, ...rest] = process.argv.slice(2);
	switch (subcommand) {
		case 'write-timing': cliWriteTiming(); break;
		case 'write-rehearsal': cliWriteRehearsal(); break;
		case 'validate-prior-artifact': cliValidatePriorArtifact(rest); break;
		case 'self-test': {
			const checks = selfTest();
			process.stdout.write(`performance-receipts self-test PASS (${checks.length} assertions)\n`);
			break;
		}
		default:
			process.stderr.write('usage: node scripts/performance-receipts.mjs <write-timing|write-rehearsal|validate-prior-artifact|self-test>\n');
			process.exitCode = 2;
	}
}

if (process.argv[1]?.endsWith('performance-receipts.mjs')) {
	main().catch((error) => {
		process.stderr.write(`${error instanceof PerfEvidenceError ? error.grammarLine() : String(error)}\n`);
		process.exit(1);
	});
}
