/**
 * E4-I test-build-only background-work harness.
 *
 * Named integration target of the E4-I verification bindings
 * (retired-docs:verification/2026-09-08-connectivity-e4i-verification-bindings.md).
 * Provides the deterministic drivers and case auditors for the four
 * `CAS-E4I-*` manifest cases:
 *
 * - a manual clock and a N66-contract fake bridge (crash-injectable, engine-
 *   authorization semantics) — `createHarnessClock`, `createContractBridge`;
 * - a fully wired harness coordinator and transfer executor;
 * - one auditor per case that checks real run observations and emits the
 *   pinned `FAIL <case ID>: ...` text plus a finite `subOracleId` cause line
 *   when a planted fault violates its oracle.
 *
 * TEST-BUILD-ONLY: production code must never import this module. The guard
 * below fails closed outside test runs; the module is additionally kept out
 * of the production graph because only `*.test.ts` files import it.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const isTestBuild =
	process.env.VITEST === 'true' || process.env.NODE_ENV === 'test';
if (!isTestBuild) {
	throw new Error(
		'backgroundWorkHarness is test-build-only; production code must never import it',
	);
}

import type {
	NativeBatchBudget,
	NativeBatchStatement,
	NativeDbAppKey,
	OfflineDbBridge,
} from '$lib/native/types';
import { tokenizeStatement } from '$lib/offline/nativeBatch';
import {
	BUNDLED_MANIFEST_DIGEST,
	MAIL_MIGRATION_MANIFEST,
	MAIL_SCHEMA_VERSION,
} from '$lib/offline/migrations';
import type { CoordinatorEvent, CoordinatorTrigger } from '$lib/offline/coordinator';
import { fieldValueEqual } from '$lib/offline/stagedPage';
import type { JobResult } from '$lib/offline/work-contract';
import type { SchedulerState } from '$lib/offline/work-contract';
import type { RangeObservation, TransferExecutorOutcome } from '$lib/offline/transferExecutor';

// ── pinned case contract ─────────────────────────────────────────────────────

export const E4I_CASE_IDS = [
	'CAS-E4I-TRIGGER-STEP-BOUNDS',
	'CAS-E4I-PERSISTENCE-RECOVERY',
	'CAS-E4I-TRANSFER-LIFECYCLE',
	'CAS-E4I-CONSUMER-PARITY',
] as const;
export type E4ICaseId = (typeof E4I_CASE_IDS)[number];

/**
 * E5 UI/accessibility cases (R4 "E5 webmail" + "E5 settings/admin" rows),
 * implemented by this owning change. Each has a pinned FAIL text composed in
 * the same shape as the E4-I bindings and a distinct finite subOracleId cause.
 */
export const E5_CASE_IDS = [
	'CAS-E5-NEVER-UNKNOWN',
	'CAS-E5-TRANSFER-TERMINALS',
	'CAS-E5-SAVE-ALL-PARTIAL',
	'CAS-E5-SAVE-ALL-CANCEL-RETRY',
	'CAS-E5-GROUP-ANNOUNCER',
	'CAS-E5-PREFERENCE-SAVE-FAILURE',
	'CAS-E5-PREFERENCE-DOUBLE-SUBMIT',
	'CAS-E5-PREFERENCE-ACCOUNT-RACE',
	'CAS-E5-PREVIEW-TARGET-RACE',
	'CAS-E5-PREVIEW-UNAVAILABLE',
	'CAS-E5-CROSSED-NETWORK-ATTACHMENT',
] as const;
export type E5CaseId = (typeof E5_CASE_IDS)[number];

/** Every case whose receipts this harness can write. */
export const PROGRAM_CASE_IDS = [...E4I_CASE_IDS, ...E5_CASE_IDS] as const;
export type ProgramCaseId = E4ICaseId | E5CaseId;

/** Exact failure text pinned by the bindings doc, keyed by case ID. */
export const E4I_FAIL_TEXTS: Readonly<Record<E4ICaseId, string>> = {
	'CAS-E4I-TRIGGER-STEP-BOUNDS':
		'scheduled step exceeded its bound or advanced an uncommitted cursor',
	'CAS-E4I-PERSISTENCE-RECOVERY':
		'page/checkpoint atomicity or bridge admission contract failed',
	'CAS-E4I-TRANSFER-LIFECYCLE':
		'transfer lifecycle escaped current authorization or retained a prohibited bearer',
	'CAS-E4I-CONSUMER-PARITY':
		'consumer projection disagreed with the committed execution result',
};

/** Exact failure text pinned by the E5 owning change (R4 case rows). */
export const E5_FAIL_TEXTS: Readonly<Record<E5CaseId, string>> = {
	'CAS-E5-NEVER-UNKNOWN':
		'E5 status invented a completion or mislabeled unknown freshness',
	'CAS-E5-TRANSFER-TERMINALS':
		'transfer terminal display offered a prohibited action',
	'CAS-E5-SAVE-ALL-PARTIAL':
		'save-all group misreported partial progress as success',
	'CAS-E5-SAVE-ALL-CANCEL-RETRY':
		'save-all cancel/retry escaped the eligible-child contract',
	'CAS-E5-GROUP-ANNOUNCER':
		'group announcer burst or announced per-chunk noise',
	'CAS-E5-PREFERENCE-SAVE-FAILURE':
		'preference save failure reported success or lost drafts',
	'CAS-E5-PREFERENCE-DOUBLE-SUBMIT':
		'a second preference submission escaped the pending guard',
	'CAS-E5-PREFERENCE-ACCOUNT-RACE':
		'a pending preference response survived an account change',
	'CAS-E5-PREVIEW-TARGET-RACE':
		'a stale preview response replaced a newer selection',
	'CAS-E5-PREVIEW-UNAVAILABLE':
		'preview failure was displayed as success or current facts',
	'CAS-E5-CROSSED-NETWORK-ATTACHMENT':
		'crossed settings explanation promised more than actual admission',
};

export interface E4IFailure {
	fail: string;
	cause: string;
}

/** Compose the pinned FAIL line plus the finite cause line (never raw input). */
export function e4iFailure(caseId: E4ICaseId, subOracleId: string, lane = 'core'): E4IFailure {
	return {
		fail: `FAIL ${caseId}: ${E4I_FAIL_TEXTS[caseId]}`,
		cause: `subOracleId=${subOracleId} lane=${lane}`,
	};
}

/** Same shape for the E5 cases. */
export function e5Failure(caseId: E5CaseId, subOracleId: string, lane = 'core'): E4IFailure {
	return {
		fail: `FAIL ${caseId}: ${E5_FAIL_TEXTS[caseId]}`,
		cause: `subOracleId=${subOracleId} lane=${lane}`,
	};
}

/** Dispatch the pinned FAIL composer for any program case. */
export function pinnedCaseFailure(caseId: ProgramCaseId, subOracleId: string, lane = 'core'): E4IFailure {
	return (E5_CASE_IDS as readonly string[]).includes(caseId)
		? e5Failure(caseId as E5CaseId, subOracleId, lane)
		: e4iFailure(caseId as E4ICaseId, subOracleId, lane);
}

export interface CaseVerdict {
	caseId: ProgramCaseId;
	ok: boolean;
	fail?: string;
	cause?: string;
	/** Privacy-safe observations only (counts, states, digests — never content). */
	observations: Record<string, unknown>;
}

/**
 * E4-I Astra correction (finding 14): a receipt can never report PASS while a
 * required scenario of its own suite failed. The lane runners collect the
 * per-scenario verdicts through an `afterEach` hook (`getCurrentTest()`), and
 * the retained verdict is gated on BOTH the auditor result AND the observed
 * scenario failures — a test that does not update the auditor's observations
 * can no longer hide behind an earlier PASS. A failed gate emits the pinned
 * FAIL text with a distinct finite `scenario-failures` cause.
 */
export function gateVerdictOnScenarios(verdict: CaseVerdict, scenarioFailures: readonly string[]): CaseVerdict {
	if (verdict.ok && scenarioFailures.length === 0) return verdict;
	if (!verdict.ok) return verdict;
	const failure = pinnedCaseFailure(verdict.caseId, 'scenario-failures');
	return {
		...verdict,
		ok: false,
		fail: failure.fail,
		cause: `${failure.cause} count=${scenarioFailures.length}`,
		observations: { ...verdict.observations, scenarioFailures: [...scenarioFailures] },
	};
}

/** Count one scenario result: anything that is not a pass is a receipt failure. */
export function scenarioFailed(task: { result?: { state?: string } } | null | undefined, name: string): string | null {
	const state = task?.result?.state;
	return state === 'pass' ? null : `${name || 'unnamed-scenario'}:${state ?? 'no-result'}`;
}

function ok(caseId: ProgramCaseId, observations: Record<string, unknown>): CaseVerdict {
	return { caseId, ok: true, observations };
}

function violated(caseId: ProgramCaseId, subOracleId: string, observations: Record<string, unknown>, lane = 'core'): CaseVerdict {
	const failure = pinnedCaseFailure(caseId, subOracleId, lane);
	return { caseId, ok: false, fail: failure.fail, cause: failure.cause, observations };
}

// ── deterministic clock ──────────────────────────────────────────────────────

export interface HarnessClock {
	nowMonoMs(): number;
	nowUtcMs(): number;
	advanceMonoMs(ms: number): void;
	advanceUtcMs(ms: number): void;
	setUtcMs(ms: number): void;
}

export function createHarnessClock(startUtcMs = Date.parse('2026-09-17T00:00:00Z')): HarnessClock {
	let mono = 0;
	let utc = startUtcMs;
	return {
		nowMonoMs: () => mono,
		nowUtcMs: () => utc,
		advanceMonoMs: (ms) => {
			mono += ms;
		},
		advanceUtcMs: (ms) => {
			utc += ms;
		},
		setUtcMs: (ms) => {
			utc = ms;
		},
	};
}

// ── N66 contract fake bridge ─────────────────────────────────────────────────

export interface ContractBridgeFault {
	/**
	 * When set, the batch/migration crashes at the named statement index —
	 * BEFORE applying it, modeling a native rollback where neither the page
	 * nor the checkpoint becomes visible.
	 */
	crashBatchAtStatement?: number;
	/** Crash after a migration step commits (version visible, next step lost). */
	crashAfterMigrationVersion?: number;
}

export interface ContractBridgeLog {
	entry: 'exec' | 'query' | 'transactionBatch' | 'migrateStore' | 'execSchemaInit';
	appKey: NativeDbAppKey;
	disposition: 'admitted' | 'refused' | 'crashed';
	/** Finite refusal identity — never raw SQL content. */
	reason?: string;
	statementCount?: number;
}

export interface ContractBridge extends OfflineDbBridge {
	readonly log: readonly ContractBridgeLog[];
	/** Rows visible after reopen (post-commit state). */
	table(appKey: NativeDbAppKey, name: string): Array<Record<string, unknown>>;
}

/**
 * A fake encrypted-store bridge that honors the native transaction freeze:
 * transaction control is refused on every entry by parsed-keyword engine
 * semantics, batches validate and then commit or apply nothing atomically,
 * migrations load only the bundled manifest (no runtime registration), and
 * cross-app handles are refused. Crash injection models native rollback.
 */
export function createContractBridge(options: {
	authorizedAppKeys?: readonly NativeDbAppKey[];
	fault?: ContractBridgeFault;
} = {}): ContractBridge {
	const authorized = new Set(options.authorizedAppKeys ?? ['mail']);
	const fault = options.fault ?? {};
	const log: ContractBridgeLog[] = [];
	const stores = new Map<NativeDbAppKey, Map<string, Array<Record<string, unknown>>>>();
	const schemaInitConsumed = new Set<NativeDbAppKey>();
	const storeVersions = new Map<NativeDbAppKey, number>();

	function tableOf(appKey: NativeDbAppKey, name: string): Array<Record<string, unknown>> {
		if (!authorized.has(appKey)) throw new Error(`cross-app store access refused: appKey=${appKey}`);
		const store = stores.get(appKey) ?? new Map<string, Array<Record<string, unknown>>>();
		stores.set(appKey, store);
		let table = store.get(name);
		if (!table) {
			table = [];
			store.set(name, table);
		}
		return table;
	}

	function engineRefusal(sql: string): string | null {
		const tokenized = tokenizeStatement(sql);
		if (tokenized.unterminated) return 'unterminated-literal';
		if (tokenized.hasStatementSeparator) return 'multi-statement';
		const keyword = tokenized.leadingKeyword;
		if (keyword === null) return 'empty-statement';
		if (['begin', 'commit', 'end', 'rollback', 'savepoint', 'release', 'start', 'abort'].includes(keyword)) {
			return 'transaction-control';
		}
		if (['pragma', 'attach', 'detach', 'vacuum'].includes(keyword)) return 'forbidden-keyword';
		return null;
	}

	function applyStatement(appKey: NativeDbAppKey, statement: NativeBatchStatement): void {
		const keyword = (tokenizeStatement(statement.sql).leadingKeyword ?? '').toLowerCase();
		const params = statement.params ?? [];
		if (keyword === 'insert' || keyword === 'replace') {
			const into = /into\s+([a-z_]+)/i.exec(statement.sql)?.[1]?.toLowerCase();
			if (into) {
				tableOf(appKey, into).push(Object.fromEntries(
					into === 'meta_mail'
						? [['key', params[0]], ['value', params[1]]]
						: params.map((value, index) => [`col${index}`, value]),
				));
			}
			return;
		}
		if (keyword === 'update') {
			const table = /update\s+([a-z_]+)/i.exec(statement.sql)?.[1]?.toLowerCase();
			if (table === 'meta_mail' || table === 'optional_jobs' || table === 'attachment_transfers') {
				// The fake applies a coarse generation/version effect: rows gain a
				// marker column so reopen can observe that a commit happened.
				for (const row of tableOf(appKey, table)) {
					(row as Record<string, unknown>).__updated = true;
				}
			}
			return;
		}
		if (keyword === 'delete') {
			const table = /delete\s+from\s+([a-z_]+)/i.exec(statement.sql)?.[1]?.toLowerCase();
			if (table) tableOf(appKey, table).length = 0;
			return;
		}
		if (keyword === 'create' || keyword === 'alter') {
			const name = /(?:table|index)[^(]*?\bif not exists\s+([a-z_]+)/i.exec(statement.sql)?.[1]
				?? /alter\s+table\s+([a-z_]+)/i.exec(statement.sql)?.[1];
			if (name && !/idx_/.test(name)) {
				tableOf(appKey, name);
				// Record the DDL so sqlite_master detection sees the real shape.
				tableOf(appKey, '__ddl').push({ name, sql: statement.sql });
			}
		}
	}

	function commitBatch(appKey: NativeDbAppKey, statements: readonly NativeBatchStatement[]): number {
		for (const statement of statements) {
			const refusal = engineRefusal(statement.sql);
			if (refusal !== null) throw new Error(`native batch refused: ${refusal}`);
		}
		// Crash injection models a native rollback: the whole batch applies
		// nothing. A crash before commit exposes neither page nor checkpoint.
		if (fault.crashBatchAtStatement !== undefined && statements.length > fault.crashBatchAtStatement) {
			throw new Error('native batch crashed before commit; nothing applied');
		}
		for (const statement of statements) {
			applyStatement(appKey, statement);
		}
		return statements.length;
	}

	function refuse(entry: ContractBridgeLog['entry'], appKey: NativeDbAppKey, reason: string): never {
		log.push({ entry, appKey, disposition: 'refused', reason });
		throw new Error(`${entry} refused: ${reason}`);
	}

	return {
		log,
		table(appKey, name) {
			return tableOf(appKey, name).map((row) => ({ ...row }));
		},
		async open(appKey) {
			if (!authorized.has(appKey)) throw new Error(`cross-app store access refused: appKey=${appKey}`);
			tableOf(appKey, '__open');
		},
		async isOpen(appKey) {
			return authorized.has(appKey) && (stores.get(appKey)?.has('__open') ?? false);
		},
		async exec(appKey, sql) {
			if (!authorized.has(appKey)) refuse('exec', appKey, 'foreign-app-handle');
			const refusal = engineRefusal(sql);
			if (refusal !== null) refuse('exec', appKey, refusal);
			log.push({ entry: 'exec', appKey, disposition: 'admitted', statementCount: 1 });
			applyStatement(appKey, { sql });
			return 1;
		},
		async query<T = Record<string, unknown>>(appKey: NativeDbAppKey, sql: string, params: unknown[] = []): Promise<T[]> {
			if (!authorized.has(appKey)) refuse('query', appKey, 'foreign-app-handle');
			const refusal = engineRefusal(sql);
			if (refusal !== null) refuse('query', appKey, refusal);
			log.push({ entry: 'query', appKey, disposition: 'admitted', statementCount: 1 });
			const lower = sql.toLowerCase();
			if (lower.includes('sqlite_master')) {
				const ddl = stores.get(appKey)?.get('__ddl') ?? [];
				return ddl.map((row) => ({ ...row })) as T[];
			}
			if (lower.includes('meta_mail')) {
				const rows = tableOf(appKey, 'meta_mail');
				const key = params[0];
				return rows.filter((row) => row.key === key || key === undefined) as T[];
			}
			return [] as T[];
		},
		async transactionBatch(appKey, statements, budget: NativeBatchBudget) {
			if (!authorized.has(appKey)) refuse('transactionBatch', appKey, 'foreign-app-handle');
			if (statements.length === 0) refuse('transactionBatch', appKey, 'empty-batch');
			if (statements.length > budget.maxStatements) refuse('transactionBatch', appKey, 'too-many-statements');
			log.push({
				entry: 'transactionBatch',
				appKey,
				disposition: 'admitted',
				statementCount: statements.length,
			});
			return commitBatch(appKey, statements);
		},
		async migrateStore(appKey, targetVersion) {
			if (!authorized.has(appKey)) refuse('migrateStore', appKey, 'foreign-app-handle');
			if (!Number.isSafeInteger(targetVersion)) refuse('migrateStore', appKey, 'unknown-version');
			if (targetVersion > MAIL_SCHEMA_VERSION) refuse('migrateStore', appKey, 'ahead-version');
			const current = storeVersions.get(appKey) ?? 0;
			if (targetVersion < current) refuse('migrateStore', appKey, 'downgrade');
			// The bundled manifest is the only trusted source; a runtime caller
			// cannot register or replace it (no register entry exists at all).
			if (BUNDLED_MANIFEST_DIGEST !== BUNDLED_MANIFEST_DIGEST) refuse('migrateStore', appKey, 'digest-mismatch');
			for (const step of MAIL_MIGRATION_MANIFEST.steps) {
				if (step.targetVersion <= current) continue;
				if (step.targetVersion > targetVersion) break;
				if (fault.crashAfterMigrationVersion !== undefined
					&& current < fault.crashAfterMigrationVersion
					&& step.targetVersion > fault.crashAfterMigrationVersion) {
					log.push({ entry: 'migrateStore', appKey, disposition: 'crashed', reason: `after-version=${fault.crashAfterMigrationVersion}` });
					throw new Error('native migration crashed between steps; committed versions persist');
				}
				commitBatch(appKey, step.statements.map((sql) => ({ sql })));
				commitBatch(appKey, [{
					sql: 'INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?, ?)',
					params: ['schema_version', String(step.targetVersion)],
				}]);
				storeVersions.set(appKey, step.targetVersion);
			}
			log.push({ entry: 'migrateStore', appKey, disposition: 'admitted', reason: `version=${storeVersions.get(appKey) ?? targetVersion}` });
			return { version: storeVersions.get(appKey) ?? targetVersion };
		},
		async execSchemaInit(appKey, sql) {
			if (!authorized.has(appKey)) refuse('execSchemaInit', appKey, 'foreign-app-handle');
			if (schemaInitConsumed.has(appKey)) refuse('execSchemaInit', appKey, 'one-shot-consumed');
			// The authorized init seam validates statement-by-statement: DDL is
			// batch-valid here, transaction control never is.
			const statements = sql.split(';').map((part) => part.trim()).filter(Boolean);
			for (const statement of statements) {
				const keyword = tokenizeStatement(statement).leadingKeyword;
				if (keyword !== null && ['begin', 'commit', 'end', 'rollback', 'savepoint', 'release'].includes(keyword)) {
					refuse('execSchemaInit', appKey, 'transaction-control');
				}
			}
			schemaInitConsumed.add(appKey);
			log.push({ entry: 'execSchemaInit', appKey, disposition: 'admitted' });
			for (const statement of statements) {
				applyStatement(appKey, { sql: statement });
			}
			return 0;
		},
		async wipe(appKey) {
			if (!authorized.has(appKey)) refuse('exec', appKey, 'foreign-app-handle');
			stores.delete(appKey);
			storeVersions.delete(appKey);
		},
	};
}

// ── case auditors ────────────────────────────────────────────────────────────

export interface StepBoundsAudit {
	events: readonly CoordinatorEvent[];
	/** Per-scheduled-step record counts as observed by the lane runner. */
	stepRecordCounts: readonly number[];
	/** True when a checkpoint advance was observed without a local commit. */
	cursorAdvancedWithoutCommit: boolean;
	/** True when the coordinator refused an unbounded wrapper at construction. */
	unboundedWrapperRefused: boolean;
	/** Distinct coalescing outcomes observed for duplicate trigger keys. */
	coalescedGenerations: readonly number[];
	queuedJobCountAfterDuplicateTriggers: number;
	/** True when Critical activity aborted running work before the next page. */
	criticalAbortedBeforeCursorAdvance: boolean;
}

/**
 * CAS-E4I-TRIGGER-STEP-BOUNDS oracle: positive bounds hold, and each planted
 * violation maps to a distinct subOracleId under the pinned FAIL text.
 */
export function auditTriggerStepBounds(audit: StepBoundsObservationsLike): CaseVerdict {
	const caseId: E4ICaseId = 'CAS-E4I-TRIGGER-STEP-BOUNDS';
	const observations: Record<string, unknown> = {
		stepCount: audit.stepRecordCounts.length,
		coalescedJobCount: audit.queuedJobCountAfterDuplicateTriggers,
		unboundedWrapperRefused: audit.unboundedWrapperRefused,
	};
	if (audit.stepRecordCounts.some((count) => count > 64)) {
		return violated(caseId, 'step-record-overrun', observations);
	}
	if (audit.cursorAdvancedWithoutCommit) {
		return violated(caseId, 'cursor-advanced-before-commit', observations);
	}
	if (!audit.unboundedWrapperRefused) {
		return violated(caseId, 'unbounded-wrapper-accepted', observations);
	}
	if (audit.queuedJobCountAfterDuplicateTriggers !== 1) {
		return violated(caseId, 'duplicate-trigger-not-coalesced', observations);
	}
	if (!audit.criticalAbortedBeforeCursorAdvance) {
		return violated(caseId, 'critical-interruption-missing', observations);
	}
	return ok(caseId, observations);
}
type StepBoundsObservationsLike = StepBoundsAudit;

export interface PersistenceRecoveryAudit {
	/** Denials observed on the bridge log, as finite reason identities. */
	denials: ReadonlyArray<{ entry: string; reason: string }>;
	/** Reopen observation after a crash before commit: neither page nor checkpoint visible. */
	crashBeforeCommitExposedNothing: boolean;
	/** Reopen observation after a successful commit: both visible. */
	commitExposedBoth: boolean;
	/** Reclaim after lease expiry succeeded exactly once (no duplicate effect). */
	leaseReclaimedOnce: boolean;
	/** Duplicate result application at the same generation was rejected. */
	duplicateEffectRejected: boolean;
	/** A valid batch and a bundled-migration success were demonstrated too. */
	positiveOracleDemonstrated: boolean;
}

/** CAS-E4I-PERSISTENCE-RECOVERY oracle. */
export function auditPersistenceRecovery(audit: PersistenceRecoveryAudit): CaseVerdict {
	const caseId: E4ICaseId = 'CAS-E4I-PERSISTENCE-RECOVERY';
	const observations: Record<string, unknown> = {
		denialCount: audit.denials.length,
		denialReasons: audit.denials.map((denial) => `${denial.entry}:${denial.reason}`),
	};
	if (!audit.crashBeforeCommitExposedNothing) {
		return violated(caseId, 'crash-before-commit-exposed-state', observations);
	}
	if (!audit.commitExposedBoth) {
		return violated(caseId, 'commit-missing-page-or-checkpoint', observations);
	}
	if (!audit.leaseReclaimedOnce) {
		return violated(caseId, 'lease-reclaim-not-single', observations);
	}
	if (!audit.duplicateEffectRejected) {
		return violated(caseId, 'duplicate-effect-accepted', observations);
	}
	if (!audit.positiveOracleDemonstrated) {
		return violated(caseId, 'positive-oracle-missing', observations);
	}
	// Every planted denial must be distinct and finite.
	const causes = new Set(audit.denials.map((denial) => `${denial.entry}:${denial.reason}`));
	if (causes.size !== audit.denials.length || audit.denials.length === 0) {
		return violated(caseId, 'denial-cause-not-distinct', observations);
	}
	return ok(caseId, observations);
}

export interface TransferLifecycleAudit {
	/** Full effect trace observed by the recording ports. */
	outcomes: ReadonlyArray<{ kind: TransferExecutorOutcome['kind'] }>;
	/** Every persisted row and metadata blob captured by the lane runner. */
	persistedTexts: readonly string[];
	/** True when a redirect was rejected and the redirect target never fetched. */
	redirectRejectedWithoutFollow: boolean;
	/** True when restart reminted under current authorization (fresh mint). */
	restartRemintedUnderCurrentAuthorization: boolean;
	/** True when account change cancelled and purged with zero cross-account reuse. */
	accountChangePurgedWithoutReuse: boolean;
	/** True when revocation cleanup dropped the bearer and paused admission. */
	revocationCleanupPausedAdmission: boolean;
	/** Confirmed content-unavailable purged; hidden preserved; stale ignored. */
	confirmedPurgedHiddenPreservedStaleIgnored: boolean;
	/** Balanced critical begin/end around effects, including failure paths. */
	criticalScopesBalanced: boolean;
}

/** CAS-E4I-TRANSFER-LIFECYCLE oracle. */
export function auditTransferLifecycle(audit: TransferLifecycleAudit): CaseVerdict {
	const caseId: E4ICaseId = 'CAS-E4I-TRANSFER-LIFECYCLE';
	const observations: Record<string, unknown> = {
		outcomeKinds: audit.outcomes.map((outcome) => outcome.kind),
		persistedRowCount: audit.persistedTexts.length,
	};
	const prohibited = audit.persistedTexts.filter((text) =>
		/bearer|authorization:/i.test(text) || /https?:\/\//.test(text));
	if (prohibited.length > 0) {
		return violated(caseId, 'prohibited-bearer-or-url-retained', observations);
	}
	if (!audit.redirectRejectedWithoutFollow) {
		return violated(caseId, 'redirect-followed', observations);
	}
	if (!audit.restartRemintedUnderCurrentAuthorization) {
		return violated(caseId, 'restart-did-not-remint', observations);
	}
	if (!audit.accountChangePurgedWithoutReuse) {
		return violated(caseId, 'account-change-reused-state', observations);
	}
	if (!audit.revocationCleanupPausedAdmission) {
		return violated(caseId, 'revocation-did-not-pause', observations);
	}
	if (!audit.confirmedPurgedHiddenPreservedStaleIgnored) {
		return violated(caseId, 'unavailable-classification-wrong', observations);
	}
	if (!audit.criticalScopesBalanced) {
		return violated(caseId, 'critical-scope-unbalanced', observations);
	}
	return ok(caseId, observations);
}

export interface ConsumerParityPair {
	/** What the E4 execution consumer read back for the job. */
	readKind: 'committed' | 'unknown';
	/** The committed result state when readKind is committed. */
	resultState?: JobResult['state'];
	/** The reason carried by a committed paused result. */
	pauseReason?: import('$lib/offline/work-contract').PauseReason;
	/** What the E5 projection derived through the shared mapping. */
	projected: SchedulerState;
}

function expectedProjection(pair: ConsumerParityPair): SchedulerState {
	if (pair.readKind === 'unknown' || !pair.resultState) return { kind: 'idle' };
	switch (pair.resultState) {
		case 'complete':
			return { kind: 'idle' };
		case 'paused':
			return { kind: 'paused', reason: pair.pauseReason ?? 'policyDenied' };
		default:
			return { kind: 'idle' };
	}
}

function projectionEquals(a: SchedulerState, b: SchedulerState): boolean {
	if (a.kind !== b.kind) return false;
	if (a.kind === 'paused' && b.kind === 'paused') return a.reason === b.reason;
	return true;
}

/**
 * CAS-E4I-CONSUMER-PARITY oracle: E4 execution results and the E5 projection
 * must agree for every committed/unknown/paused entry, and an unknown entry
 * must never surface as an invented completion.
 */
export function auditConsumerParity(pairs: readonly ConsumerParityPair[]): CaseVerdict {
	const caseId: E4ICaseId = 'CAS-E4I-CONSUMER-PARITY';
	const observations: Record<string, unknown> = { pairCount: pairs.length };
	for (const [index, pair] of pairs.entries()) {
		// An unknown read must never surface as an invented state.
		if (pair.readKind === 'unknown' && pair.projected.kind !== 'idle') {
			return violated(caseId, `unknown-invented-state-${index}`, observations);
		}
		if (!projectionEquals(pair.projected, expectedProjection(pair))) {
			observations.disagreeAtIndex = index;
			return violated(caseId, `projection-disagreement-${index}`, observations);
		}
	}
	if (pairs.length === 0) {
		return violated(caseId, 'positive-oracle-missing', observations);
	}
	return ok(caseId, observations);
}

// ── E5 case auditors (UI/accessibility; R4 E5 rows) ─────────────────────────

export interface E5NeverUnknownAudit {
	/** Freshness label keys observed from the projection (honest phrasing). */
	neverSyncedKey: string;
	unknownKey: string;
	/** The unknown read mapped through the shared seam. */
	unknownProjectedIdle: boolean;
	/** A committed result (complete/paused) drove the SAME mapping. */
	committedPairsAgree: boolean;
}

/** CAS-E5-NEVER-UNKNOWN oracle. */
export function auditE5NeverUnknown(audit: E5NeverUnknownAudit): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-NEVER-UNKNOWN';
	const observations: Record<string, unknown> = {
		neverSyncedKey: audit.neverSyncedKey,
		unknownKey: audit.unknownKey,
	};
	if (!audit.unknownProjectedIdle) return violated(caseId, 'unknown-not-idle', observations);
	if (!audit.committedPairsAgree) return violated(caseId, 'committed-mapping-disagreement', observations);
	if (audit.unknownKey === audit.neverSyncedKey) {
		return violated(caseId, 'freshness-keys-collapsed', observations);
	}
	return ok(caseId, observations);
}

export interface E5TransferTerminalsAudit {
	/** Row-state → displayed i18n key (verbatim mapping, no collapsing). */
	expiredKey: string;
	unavailableKey: string;
	verificationFailedKey: string;
	/** R4 action contracts. */
	expiredOffersAuthorizedRestart: boolean;
	unavailableOffersNoRetry: boolean;
	verificationFailedOffersNoOpenSave: boolean;
	/** Paused reasons preserved verbatim: one distinct key per reason. */
	pauseReasonKeyCount: number;
	pauseReasonKeyDistinct: boolean;
}

/** CAS-E5-TRANSFER-TERMINALS oracle. */
export function auditE5TransferTerminals(audit: E5TransferTerminalsAudit): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-TRANSFER-TERMINALS';
	const observations: Record<string, unknown> = {
		expiredKey: audit.expiredKey,
		unavailableKey: audit.unavailableKey,
		verificationFailedKey: audit.verificationFailedKey,
		pauseReasonKeyCount: audit.pauseReasonKeyCount,
	};
	if (!audit.expiredOffersAuthorizedRestart) return violated(caseId, 'expired-restart-missing', observations);
	if (!audit.unavailableOffersNoRetry) return violated(caseId, 'unavailable-offered-retry', observations);
	if (!audit.verificationFailedOffersNoOpenSave) return violated(caseId, 'verification-offered-open-save', observations);
	if (!audit.pauseReasonKeyDistinct || audit.pauseReasonKeyCount === 0) {
		return violated(caseId, 'pause-reasons-collapsed', observations);
	}
	return ok(caseId, observations);
}

export interface E5SaveAllPartialAudit {
	summary: { total: number; completed: number; failed: number; cancelled: number; expired: number; allComplete: boolean; indeterminate: boolean };
	/** Partial completion must never read as success. */
	partialNotSuccess: boolean;
	unknownSizesIndeterminate: boolean;
}

/** CAS-E5-SAVE-ALL-PARTIAL oracle. */
export function auditE5SaveAllPartial(audit: E5SaveAllPartialAudit): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-SAVE-ALL-PARTIAL';
	const observations: Record<string, unknown> = { summary: { ...audit.summary } };
	if (!audit.partialNotSuccess) return violated(caseId, 'partial-reported-success', observations);
	if (!audit.unknownSizesIndeterminate) return violated(caseId, 'unknown-size-determinate', observations);
	return ok(caseId, observations);
}

export interface E5SaveAllCancelRetryAudit {
	cancelPlan: { toCancel: string[]; preserved: string[] };
	retryIds: string[];
	/** Retry must select only eligible failed children (no unavailable/cancelled). */
	retryOnlyEligible: boolean;
	cancelPreservesCompleted: boolean;
}

/** CAS-E5-SAVE-ALL-CANCEL-RETRY oracle. */
export function auditE5SaveAllCancelRetry(audit: E5SaveAllCancelRetryAudit): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-SAVE-ALL-CANCEL-RETRY';
	const observations: Record<string, unknown> = {
		toCancel: audit.cancelPlan.toCancel.length,
		preserved: audit.cancelPlan.preserved.length,
		retryCount: audit.retryIds.length,
	};
	if (!audit.cancelPreservesCompleted) return violated(caseId, 'cancel-deleted-completed', observations);
	if (!audit.retryOnlyEligible) return violated(caseId, 'retry-selected-ineligible', observations);
	return ok(caseId, observations);
}

export interface E5GroupAnnouncerAudit {
	/** One announcement per settled change — never one per child. */
	announcementCount: number;
	changedChildren: number;
	/** 10% threshold policy: intra-band movement never announces. */
	intraBandChunkAnnounced: boolean;
	phaseChangeAnnounced: boolean;
}

/** CAS-E5-GROUP-ANNOUNCER oracle. */
export function auditE5GroupAnnouncer(audit: E5GroupAnnouncerAudit): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-GROUP-ANNOUNCER';
	const observations: Record<string, unknown> = {
		announcementCount: audit.announcementCount,
		changedChildren: audit.changedChildren,
	};
	if (audit.announcementCount > 1 && audit.changedChildren > 1) {
		return violated(caseId, 'burst-announcements', observations);
	}
	if (audit.intraBandChunkAnnounced) return violated(caseId, 'per-chunk-announced', observations);
	if (!audit.phaseChangeAnnounced) return violated(caseId, 'phase-change-silent', observations);
	return ok(caseId, observations);
}

export interface E5PreferenceAuditShape {
	/** After a failed save: drafts kept, acknowledged untouched, remedy surfaced. */
	draftsPreserved: boolean;
	acknowledgedUntouched: boolean;
	remedySurfaced: boolean;
	neverSuccess: boolean;
}

/** CAS-E5-PREFERENCE-SAVE-FAILURE oracle. */
export function auditE5PreferenceSaveFailure(audit: E5PreferenceAuditShape): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-PREFERENCE-SAVE-FAILURE';
	const observations: Record<string, unknown> = {};
	if (!audit.draftsPreserved) return violated(caseId, 'drafts-lost', observations);
	if (!audit.acknowledgedUntouched) return violated(caseId, 'acknowledged-mutated', observations);
	if (!audit.remedySurfaced) return violated(caseId, 'remedy-missing', observations);
	if (!audit.neverSuccess) return violated(caseId, 'failure-reported-success', observations);
	return ok(caseId, observations);
}

/** CAS-E5-PREFERENCE-DOUBLE-SUBMIT oracle. */
export function auditE5PreferenceDoubleSubmit(audit: { duplicateRefused: boolean; firstSaveIntact: boolean }): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-PREFERENCE-DOUBLE-SUBMIT';
	const observations: Record<string, unknown> = {};
	if (!audit.duplicateRefused) return violated(caseId, 'duplicate-accepted', observations);
	if (!audit.firstSaveIntact) return violated(caseId, 'first-save-disturbed', observations);
	return ok(caseId, observations);
}

/** CAS-E5-PREFERENCE-ACCOUNT-RACE oracle. */
export function auditE5PreferenceAccountRace(audit: { staleResponseRejected: boolean; draftsNotCarriedAcross: boolean }): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-PREFERENCE-ACCOUNT-RACE';
	const observations: Record<string, unknown> = {};
	if (!audit.staleResponseRejected) return violated(caseId, 'stale-response-applied', observations);
	if (!audit.draftsNotCarriedAcross) return violated(caseId, 'drafts-carried-across', observations);
	return ok(caseId, observations);
}

export interface E5PreviewRaceAudit {
	/** Old-generation and mismatched-target responses were both refused. */
	oldGenerationRejected: boolean;
	mismatchedTargetRejected: boolean;
}

/** CAS-E5-PREVIEW-TARGET-RACE oracle. */
export function auditE5PreviewTargetRace(audit: E5PreviewRaceAudit): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-PREVIEW-TARGET-RACE';
	const observations: Record<string, unknown> = {};
	if (!audit.oldGenerationRejected) return violated(caseId, 'old-generation-applied', observations);
	if (!audit.mismatchedTargetRejected) return violated(caseId, 'foreign-target-applied', observations);
	return ok(caseId, observations);
}

/** CAS-E5-PREVIEW-UNAVAILABLE oracle. */
export function auditE5PreviewUnavailable(audit: {
	unavailableLabeled: boolean;
	unauthorizedLabeled: boolean;
	retainedLabeledStale: boolean;
	malformedRefused: boolean;
}): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-PREVIEW-UNAVAILABLE';
	const observations: Record<string, unknown> = {};
	if (!audit.unavailableLabeled) return violated(caseId, 'unavailable-shown-current', observations);
	if (!audit.unauthorizedLabeled) return violated(caseId, 'unauthorized-shown-current', observations);
	if (!audit.retainedLabeledStale) return violated(caseId, 'retained-shown-fresh', observations);
	if (!audit.malformedRefused) return violated(caseId, 'malformed-applied', observations);
	return ok(caseId, observations);
}

export interface E5CrossedAudit {
	/** Every crossed combination explained actual admission, per control. */
	combinationsExplained: number;
	/** The explanation never promised "all network disabled". */
	promisedTotalDisablement: boolean;
	/** Refresh-never kept attachment admission explained independently. */
	scopedControlsKeptSeparate: boolean;
}

/** CAS-E5-CROSSED-NETWORK-ATTACHMENT oracle. */
export function auditE5CrossedNetworkAttachment(audit: E5CrossedAudit): CaseVerdict {
	const caseId: E5CaseId = 'CAS-E5-CROSSED-NETWORK-ATTACHMENT';
	const observations: Record<string, unknown> = { combinationsExplained: audit.combinationsExplained };
	if (audit.promisedTotalDisablement) return violated(caseId, 'total-disablement-promise', observations);
	if (!audit.scopedControlsKeptSeparate) return violated(caseId, 'controls-merged', observations);
	if (audit.combinationsExplained < 4) return violated(caseId, 'positive-oracle-missing', observations);
	return ok(caseId, observations);
}

// ── retained artifacts ───────────────────────────────────────────────────────

/**
 * E4-I r5 Astra correction (finding 6): the receipt producer and the case
 * validator must AGREE. The validator
 * (`scripts/check-connectivity-aware-sync-cases.mjs`) resolves retained
 * artifacts and fixtures from the REPOSITORY root — retained artifacts are
 * run-scoped (`test-results/connectivity-aware-sync/<run-id>/e4i/<slug>.json`)
 * and the receipt's fixture identity must equal the manifest case's
 * repo-root-relative fixture exactly. The harness therefore emits exactly
 * those shapes: every helper below speaks repo-root-relative, run-scoped
 * paths.
 */

/** Retained evidence path TEMPLATE per the manifest's artifact contract. */
export function e4iArtifactPath(caseId: E4ICaseId): string {
	const slug = caseId.replace(/^CAS-E4I-/, '').toLowerCase().replaceAll('_', '-');
	return path.posix.join('test-results', 'connectivity-aware-sync', '<run-id>', 'e4i', `${slug}.json`);
}

/** Same run-scoped template for the E5 cases (owning lane directory `e5/`). */
export function e5ArtifactPath(caseId: E5CaseId): string {
	const slug = caseId.replace(/^CAS-E5-/, '').toLowerCase().replaceAll('_', '-');
	return path.posix.join('test-results', 'connectivity-aware-sync', '<run-id>', 'e5', `${slug}.json`);
}

/** Dispatch the run-scoped artifact template for any program case. */
export function programArtifactPath(caseId: ProgramCaseId): string {
	return (E5_CASE_IDS as readonly string[]).includes(caseId)
		? e5ArtifactPath(caseId as E5CaseId)
		: e4iArtifactPath(caseId as E4ICaseId);
}

/**
 * Locate the webmail package root by walking up from the runner's working
 * directory until the harness's own source path is found. The lane contract
 * runs the suites from `mailserver/webmail`, so this is that package root.
 */
function webmailRootDir(): string {
	let dir = process.cwd();
	for (let depth = 0; depth < 8; depth += 1) {
		if (fs.existsSync(path.join(dir, 'src', 'lib', 'native', 'testing'))) return dir;
		const parent = path.dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	return process.cwd();
}

/**
 * The REPOSITORY root — the same root the case validator resolves from
 * (`scripts/` lives there). Walking up from the webmail package root keeps the
 * producer bound to the validator's resolution by construction instead of by
 * assumption.
 */
export function repositoryRootDir(): string {
	let dir = webmailRootDir();
	for (let depth = 0; depth < 8; depth += 1) {
		if (fs.existsSync(path.join(dir, 'scripts', 'check-connectivity-aware-sync-cases.mjs'))) return dir;
		const parent = path.dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	// The standard checkout keeps the webmail package at mailserver/webmail.
	return path.resolve(webmailRootDir(), '..', '..');
}

/** The webmail package's repo-root-relative POSIX path (e.g. mailserver/webmail). */
function webmailRootRelative(): string {
	return path.relative(repositoryRootDir(), webmailRootDir()).split(path.sep).join('/');
}

/** Fixture (binding test source) identity per manifest case, webmail-root-relative. */
const E4I_CASE_FIXTURES: Readonly<Record<E4ICaseId, { fixture: string; seed: string }>> = {
	'CAS-E4I-TRIGGER-STEP-BOUNDS': {
		fixture: 'src/lib/offline/e4i.triggerStepBounds.test.ts',
		seed: 'e4i-deterministic-clock-v1',
	},
	'CAS-E4I-PERSISTENCE-RECOVERY': {
		fixture: 'src/lib/offline/e4i.persistenceRecovery.test.ts',
		seed: 'e4i-contract-bridge-v1',
	},
	'CAS-E4I-TRANSFER-LIFECYCLE': {
		fixture: 'src/lib/offline/e4i.transferLifecycle.test.ts',
		seed: 'e4i-recording-ports-v1',
	},
	'CAS-E4I-CONSUMER-PARITY': {
		fixture: 'src/lib/offline/e4i.consumerParity.test.ts',
		seed: 'e4i-deterministic-clock-v1',
	},
};

/** E5 fixture identity: five binding suites carry the eleven E5 cases. */
const E5_CASE_FIXTURES: Readonly<Record<E5CaseId, { fixture: string; seed: string }>> = {
	'CAS-E5-NEVER-UNKNOWN': {
		fixture: 'src/lib/offline/e5.statusSemantics.test.ts',
		seed: 'e5-status-projection-v1',
	},
	'CAS-E5-TRANSFER-TERMINALS': {
		fixture: 'src/lib/offline/e5.transferTerminals.test.ts',
		seed: 'e5-transfer-display-v1',
	},
	'CAS-E5-SAVE-ALL-PARTIAL': {
		fixture: 'src/lib/offline/e5.saveAllGroup.test.ts',
		seed: 'e5-saveall-group-v1',
	},
	'CAS-E5-SAVE-ALL-CANCEL-RETRY': {
		fixture: 'src/lib/offline/e5.saveAllGroup.test.ts',
		seed: 'e5-saveall-group-v1',
	},
	'CAS-E5-GROUP-ANNOUNCER': {
		fixture: 'src/lib/offline/e5.saveAllGroup.test.ts',
		seed: 'e5-saveall-group-v1',
	},
	'CAS-E5-PREFERENCE-SAVE-FAILURE': {
		fixture: 'src/lib/offline/e5.settingsPreferences.test.ts',
		seed: 'e5-settings-controller-v1',
	},
	'CAS-E5-PREFERENCE-DOUBLE-SUBMIT': {
		fixture: 'src/lib/offline/e5.settingsPreferences.test.ts',
		seed: 'e5-settings-controller-v1',
	},
	'CAS-E5-PREFERENCE-ACCOUNT-RACE': {
		fixture: 'src/lib/offline/e5.settingsPreferences.test.ts',
		seed: 'e5-settings-controller-v1',
	},
	'CAS-E5-PREVIEW-TARGET-RACE': {
		fixture: 'src/lib/offline/e5.adminPreview.test.ts',
		seed: 'e5-admin-preview-v1',
	},
	'CAS-E5-PREVIEW-UNAVAILABLE': {
		fixture: 'src/lib/offline/e5.adminPreview.test.ts',
		seed: 'e5-admin-preview-v1',
	},
	'CAS-E5-CROSSED-NETWORK-ATTACHMENT': {
		fixture: 'src/lib/offline/e5.settingsPreferences.test.ts',
		seed: 'e5-settings-controller-v1',
	},
};

function caseFixtureIdentity(caseId: ProgramCaseId): { fixture: string; seed: string } {
	return (E5_CASE_IDS as readonly string[]).includes(caseId)
		? E5_CASE_FIXTURES[caseId as E5CaseId]
		: E4I_CASE_FIXTURES[caseId as E4ICaseId];
}

/**
 * The receipt's fixture identity: the manifest's repo-root-relative fixture
 * path for the case (what the validator compares against, exactly).
 */
export function caseFixturePath(caseId: E4ICaseId | E5CaseId): string {
	return path.posix.join(webmailRootRelative(), caseFixtureIdentity(caseId).fixture);
}

/** Sha-256 over the actual fixture file content — the binding's fixture identity. */
export function fixtureDigest(fixtureWebmailRelative: string): string {
	return createHash('sha256')
		.update(fs.readFileSync(path.join(webmailRootDir(), fixtureWebmailRelative)))
		.digest('hex');
}

/**
 * Default run identity (E4-I Astra correction: receipts must never overwrite
 * the default run). A lane-injected `SETJOIN_E4I_RUN_ID` names the run;
 * otherwise each run gets a distinct timestamped id so a fresh local run can
 * never overwrite a previous run's retained evidence.
 */
export function defaultRunId(): string {
	const injected = process.env.SETJOIN_E4I_RUN_ID;
	if (injected && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(injected)) return injected;
	return `local-${new Date().toISOString().replace(/[:.]/g, '-')}`;
}

/**
 * Write the privacy-safe case result artifact.
 *
 * E4-I Astra corrections: the receipt carries run/fixture/seed identity (the
 * sha-256 of the ACTUAL fixture file, the deterministic seed and the run id)
 * and writes into the run's own directory, so identity is verifiable and no
 * run overwrites another's evidence.
 *
 * E4-I r5 Astra correction (finding 6): the receipt is written where the
 * validator looks for it — under the REPOSITORY root's
 * `test-results/connectivity-aware-sync/<run-id>/e4i/` — and its fixture
 * identity is the repo-root-relative manifest path, so an honestly generated
 * receipt validates unchanged.
 */
export function writeCaseResult(verdict: CaseVerdict, runId: string = defaultRunId()): string {
	const repositoryRoot = repositoryRootDir();
	const laneDir = (E5_CASE_IDS as readonly string[]).includes(verdict.caseId) ? 'e5' : 'e4i';
	const target = path.join(repositoryRoot, 'test-results', 'connectivity-aware-sync', runId, laneDir);
	fs.mkdirSync(target, { recursive: true });
	const file = path.join(target, `${verdict.caseId.replace(/^CAS-E4I-/, '').replace(/^CAS-E5-/, '').toLowerCase().replaceAll('_', '-')}.json`);
	const fixtureIdentity = caseFixtureIdentity(verdict.caseId);
	const document = {
		schemaVersion: 1,
		caseId: verdict.caseId,
		status: verdict.ok ? 'passed' : 'failed',
		lane: 'core',
		runId,
		utcTime: new Date().toISOString(),
		fixture: caseFixturePath(verdict.caseId),
		fixtureDigest: fixtureDigest(fixtureIdentity.fixture),
		seed: fixtureIdentity.seed,
		fail: verdict.fail,
		cause: verdict.cause,
		observations: verdict.observations,
	};
	fs.writeFileSync(file, `${JSON.stringify(document, null, 2)}\n`);
	return file;
}

/** Observation helper: shape of one recorded native range request. */
export type RecordedRangeRequest = {
	url: string;
	requestStart: number;
	mintGeneration: number;
} & { bearerSeen: boolean };

export type RecordedMint = { generation: number; blobSha256PrefixFree: boolean };

export interface HarnessObservationSink {
	rangeRequests: RecordedRangeRequest[];
	mints: RecordedMint[];
	persistedTexts: string[];
	outcomes: Array<{ kind: TransferExecutorOutcome['kind'] }>;
	coordinatorEvents: CoordinatorEvent[];
	triggers: CoordinatorTrigger[];
}

// ── harness coordinator driver ───────────────────────────────────────────────

import { createCoordinator, type Coordinator, type CoordinatorPorts, type CoordinatorPolicy } from '$lib/offline/coordinator';
import { createMemoryJobPersistence } from '$lib/offline/jobStore';
import { createSyncDeltaStep, type DeltaChangesClient } from '$lib/offline/steps';
import type { OfflineStore, StoredMessage } from '$lib/offline/store';
import type { Email } from '$lib/types/jmap';

/** Nominal execute-mode policy: the only non-default a harness turns on. */
export const HARNESS_EXECUTE_POLICY = {
	flagEnabled: true,
	rolloutMode: 'execute' as const,
	requested: { backgroundSyncEnabled: true, automaticNetwork: 'any' as const },
	effective: { backgroundAllowed: true, automaticNetwork: 'any' as const, opportunisticRequiresCharging: false },
	workOffline: false,
};

/** Nominal bridge snapshot: foreground/reconnect execution, all constraints clear. */
export const HARNESS_NOMINAL_SNAPSHOT = {
	contractVersion: 1 as const,
	executionMode: 'foregroundReconnectOnly' as const,
	networkCost: 'unmetered' as const,
	power: 'charging' as const,
	powerSaver: false,
	charging: true,
	thermal: 'nominal' as const,
	storagePressure: 'normal' as const,
	foregroundExecution: true,
	backgroundExecution: false,
	schedule: false,
	cancel: true,
	durableTransfer: true,
};

export function createMemoryOfflineStore(): OfflineStore & { mutationCount(): number; failNextMerge(error: Error): void } {
	const messages = new Map<string, StoredMessage>();
	let mutations = 0;
	let failNextMerge: Error | null = null;
	return {
		async init() {},
		async isOpen() { return true; },
		async upsertMessage(m) { messages.set(m.id, { ...m }); mutations += 1; },
		async getMessage(id) { return messages.get(id) ?? null; },
		async listByReceivedDesc() { return [...messages.values()]; },
		async deleteOutOfWindow() { return 0; },
		async deleteMessage(id) { messages.delete(id); mutations += 1; },
		async mergeServerDelta(id, changed, serverVersion) {
			if (failNextMerge) {
				const error = failNextMerge;
				failNextMerge = null;
				throw error;
			}
			const existing = messages.get(id);
			mutations += 1;
			if (!existing) return 'absent';
			messages.set(id, { ...existing, ...changed, version: serverVersion });
			return 'merged';
		},
		// E4-I r11 Astra correction: the atomic per-field conditional restore.
		// The whole compare-and-restore loop is ONE synchronous mutation — no
		// await between the per-field comparison and the write — so no other
		// store operation can interleave inside it: a field still holding its
		// staged value (and not claimed by the row's current dirtyFields) is
		// restored, any field a concurrent edit rewrote is skipped.
		async restoreFieldsIfUnchanged(id, expectedState, fieldRestore) {
			const row = messages.get(id);
			if (!row) return false;
			const expected = expectedState as unknown as Record<string, unknown>;
			const restore = fieldRestore as unknown as Record<string, unknown>;
			const dirty = new Set(row.dirtyFields ?? []);
			for (const key of Object.keys(restore) as (keyof StoredMessage)[]) {
				if (key === 'id' || dirty.has(key)) continue;
				const current = (row as unknown as Record<string, unknown>)[key as string];
				if (fieldValueEqual(current, expected[key as string])) {
					(row as unknown as Record<string, unknown>)[key as string] = restore[key as string];
				}
			}
			mutations += 1;
			return true;
		},
		// E4-I r15 Astra correction: the in-memory restore is ONE synchronous
		// mutation (no await inside), so the rollback capability is always
		// present — flushAllOrNothing's capability gate never fires here.
		hasAtomicRestore: () => true,
		async getVersion(id) { return messages.get(id)?.version ?? 0; },
		async bumpLocalVersion(id) {
			const row = messages.get(id);
			const next = (row?.version ?? 0) + 1;
			if (row) row.version = next;
			return next;
		},
		async clearDirty(id) { const row = messages.get(id); if (row) row.dirtyFields = []; },
		async enqueueOptimisticEdit() {},
		async pendingMessageIds() { return new Set<string>(); },
		async listPendingOps() { return []; },
		async ackOp() {},
		async failOp() {},
		async searchBody() { return []; },
		async getMeta(key) { return key === 'emailState' ? '' : null; },
		async setMeta() {},
		async recordSyncIssue() {},
		async listSyncIssues() { return []; },
		async clearSyncIssue() {},
		async wipe() { messages.clear(); },
		mutationCount: () => mutations,
		failNextMerge(error) { failNextMerge = error; },
	};
}

export interface HarnessDeltaPage {
	newState: string;
	hasMoreChanges: boolean;
	created: string[];
	updated: string[];
	destroyed: string[];
	emails: Email[];
	/** Invoked before the page resolves (injection point for faults/interruptions). */
	onPage?: () => void;
}

export interface HarnessCoordinatorOptions {
	pages?: HarnessDeltaPage[];
	/** Defaults to the nominal execute policy; override to plant OFF/observe. */
	policy?: Partial<CoordinatorPolicy>;
	snapshot?: typeof HARNESS_NOMINAL_SNAPSHOT | null;
	/** Observation age in ms at admission time (plants staleness). */
	observationAgeMs?: number;
	events?: CoordinatorEvent[];
	clock?: HarnessClock;
	store?: ReturnType<typeof createMemoryOfflineStore>;
}

export interface HarnessCoordinator extends Coordinator {
	readonly clock: HarnessClock;
	readonly store: ReturnType<typeof createMemoryOfflineStore>;
	readonly jobs: ReturnType<typeof createMemoryJobPersistence>;
}

export function createHarnessCoordinator(options: HarnessCoordinatorOptions = {}): HarnessCoordinator {
	const clock = options.clock ?? createHarnessClock();
	const events = options.events ?? [];
	const store = options.store ?? createMemoryOfflineStore();
	const jobs = createMemoryJobPersistence();
	const policy = { ...HARNESS_EXECUTE_POLICY, ...(options.policy ?? {}) };
	const pages = [...(options.pages ?? [])];
	let currentPage: HarnessDeltaPage | null = null;
	const deltaClient: DeltaChangesClient = {
		emailChanges: async () => {
			currentPage = pages.shift() ?? null;
			currentPage?.onPage?.();
			return {
				newState: currentPage?.newState ?? '0',
				hasMoreChanges: currentPage?.hasMoreChanges ?? false,
				created: currentPage?.created ?? [],
				updated: currentPage?.updated ?? [],
				destroyed: currentPage?.destroyed ?? [],
			};
		},
		emailGet: async ({ ids }) => {
			const list = (currentPage?.emails ?? []).filter((email) => ids.includes(email.id));
			return { list, state: currentPage?.newState ?? '0' };
		},
	};
	const deltaStep = createSyncDeltaStep(deltaClient, { nowMonoMs: clock.nowMonoMs });
	// Window step reuses the delta client's emailGet and a trivial query.
	const windowStep = createSyncDeltaStep(deltaClient, { nowMonoMs: clock.nowMonoMs });
	const ports: CoordinatorPorts = {
		clock,
		random: () => 0.5,
		policy: { readPolicy: async () => policy as CoordinatorPolicy },
		capability: {
			readCapability: async () =>
				options.snapshot === null
					? null
					: {
						snapshot: options.snapshot ?? HARNESS_NOMINAL_SNAPSHOT,
						receivedMonoMs: clock.nowMonoMs() - (options.observationAgeMs ?? 0),
						epoch: 0,
					},
		},
		store,
		deltaStep,
		windowStep,
		jobs,
		onEvent: (event) => events.push(event),
	};
	const coordinator = createCoordinator(ports);
	return Object.assign(coordinator, { clock, store, jobs });
}

// ── harness transfer executor driver ─────────────────────────────────────────

import { createTransferExecutor, type TransferExecutor, type TransferExecutorPorts, type TransferAuthorizationContext } from '$lib/offline/transferExecutor';
import { createMemoryTransferPersistence } from '$lib/offline/jobStore';
import { createCriticalActivityCounter } from '$lib/offline/criticalScope';

export interface ScriptedResponse {
	respond: (args: { requestStart: number; mintGeneration: number }) => RangeObservation;
}

export interface HarnessExecutorOptions {
	authorization?: TransferAuthorizationContext | null;
	/** Scripted per-cycle range responses, consumed in order. */
	responses?: RangeObservation[];
	/** Computed digest returned by the fake sink on completion. */
	digest?: string;
	/** Fired before each fetch (injection point for mid-flight auth changes). */
	onFetch?: (args: { url: string; requestStart: number }) => void;
	/**
	 * Awaited inside the token mint before it resolves (injection point for a
	 * revoke/account-change racing a PENDING mint — the Astra resurrection
	 * trace).
	 */
	onMint?: () => Promise<void> | void;
	/**
	 * Awaited inside sink.openPartial (injection point for a revoke racing the
	 * sink WRITE effects — the r2 resurrection trace).
	 */
	onOpenPartial?: () => Promise<void> | void;
	/** Awaited inside sink.committedDigest (injection point for a revoke or a
	 * deadline crossing racing the verification await). */
	onDigest?: () => Promise<void> | void;
	/**
	 * Awaited inside sink.promote (injection point for a revoke racing the
	 * promotion await — the r5 resurrection trace: the revoke's purge lands
	 * while promote is in flight and the completion persist used to follow it).
	 */
	onPromote?: () => Promise<void> | void;
	/** Overrides the fixed receipt clock (injection point for deadline
	 * crossings between the executor's effect boundaries). */
	nowUtc?: () => string;
}

export interface HarnessExecutor extends TransferExecutor {
	readonly sink: {
		writes: Array<{ offset: number; length: number }>;
		purges: number;
		promotes: number;
	};
	readonly mints: Array<{ generation: number; jobId: string }>;
	readonly fetches: Array<{ url: string; requestStart: number; mintGeneration: number }>;
	readonly persisted: ReturnType<typeof createMemoryTransferPersistence>;
	readonly critical: ReturnType<typeof createCriticalActivityCounter>;
	setAuthorization(next: TransferAuthorizationContext | null): void;
}

export function createHarnessExecutor(options: HarnessExecutorOptions = {}): HarnessExecutor {
	let authorization: TransferAuthorizationContext | null =
		options.authorization === undefined
			? { accountId: 'acct-1', deviceId: 'dev-1', policyGeneration: 1 }
			: options.authorization;
	const authListeners: Array<() => void> = [];
	const responses = [...(options.responses ?? [])];
	const sinkState = { writes: [] as Array<{ offset: number; length: number }>, purges: 0, promotes: 0 };
	const mints: Array<{ generation: number; jobId: string }> = [];
	const fetches: Array<{ url: string; requestStart: number; mintGeneration: number }> = [];
	const persisted = createMemoryTransferPersistence();
	const critical = createCriticalActivityCounter();
	const ports: TransferExecutorPorts = {
		approvedOrigin: 'https://mail.example.net',
		authorization: async () => authorization,
		onAuthorizationChange(listener) {
			authListeners.push(listener);
			return () => {
				const index = authListeners.indexOf(listener);
				if (index >= 0) authListeners.splice(index, 1);
			};
		},
		mintTransferToken: async ({ accountId: _accountId, generation, jobId }) => {
			mints.push({ generation, jobId });
			await options.onMint?.();
			return `bearer-${generation}-${mints.length}`;
		},
		fetchRange: async (args) => {
			fetches.push({ url: args.url, requestStart: args.requestStart, mintGeneration: args.mintGeneration });
			options.onFetch?.(args);
			const response = responses.shift();
			if (!response) throw new Error('harness: no scripted response');
			return response;
		},
		sink: {
			openPartial: async () => {
				await options.onOpenPartial?.();
			},
			write: async (_transferId, offset, bytes) => {
				sinkState.writes.push({ offset, length: bytes.byteLength });
			},
			committedDigest: async () => {
				await options.onDigest?.();
				return options.digest ?? '';
			},
			promote: async () => {
				await options.onPromote?.();
				sinkState.promotes += 1;
			},
			purge: async () => {
				sinkState.purges += 1;
			},
		},
		persist: {
			upsertCheckpoint: (checkpoint) => persisted.upsertCheckpoint(checkpoint),
			loadCheckpoint: (jobId) => persisted.loadCheckpoint(jobId),
			purgeCheckpoint: (jobId) => persisted.purgeCheckpoint(jobId),
		},
		critical,
		nowUtc: options.nowUtc ?? (() => new Date(Date.parse('2026-09-17T01:00:00Z')).toISOString()),
	};
	const executor = createTransferExecutor(ports);
	return Object.assign(executor, {
		get sink() { return sinkState; },
		mints,
		fetches,
		persisted,
		critical,
		setAuthorization(next: TransferAuthorizationContext | null) {
			authorization = next;
			for (const listener of authListeners) listener();
		},
	});
}
