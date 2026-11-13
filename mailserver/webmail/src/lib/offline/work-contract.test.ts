import { describe, expect, it } from 'vitest';

import {
	BRIDGE_CAPABILITY_CONTRACT_VERSION,
	BRIDGE_EXECUTION_MODES,
	BRIDGE_NETWORK_COSTS,
	BRIDGE_POWER_STATES,
	BRIDGE_STORAGE_PRESSURES,
	BRIDGE_THERMAL_STATES,
	GLOBAL_OPTIONAL_CONCURRENCY,
	JOB_RESULT_STATES,
	JOB_STATES,
	MAX_QUEUE_AGE_DAYS,
	MAX_QUEUE_AGE_MS,
	MAX_RECORDS_PER_STEP,
	MAX_YIELD_BYTES,
	MAX_YIELD_TIME_MS,
	OPTIONAL_WORK_CLASSES,
	PAUSE_REASONS,
	PER_ACCOUNT_OPTIONAL_CONCURRENCY,
	PRIVACY_EXCLUDED_BRIDGE_FIELDS,
	PROTECTED_CRITICAL_SLOT_COUNT,
	ROLLOUT_MODES,
	ROLLOUT_MODE_RANK,
	SYNC_CHECKPOINT_VERSION,
	SYNC_STEP_OUTCOMES,
	WORK_CLASS_QUANTA,
	YIELD_MAX_BYTES,
	YIELD_MAX_MS,
	isBridgeCapabilitySnapshot,
	isJobResultState,
	isOptionalJobState,
	isOptionalWorkClass,
	isPauseReason,
	isRolloutMode,
	isSyncCheckpoint,
	isSyncStepOutcome,
	narrowRolloutMode,
	normalizeBridgeCapabilitySnapshot,
	validateSyncCheckpoint,
	validateSyncStepResult,
	validateWorkBudget,
	type BridgeCapabilitySnapshot,
	type SyncStepOptions,
	type SyncStepResult,
	type WorkBudget,
} from './work-contract';

const foregroundSnapshot: BridgeCapabilitySnapshot = {
	contractVersion: BRIDGE_CAPABILITY_CONTRACT_VERSION,
	executionMode: 'foregroundReconnectOnly',
	networkCost: 'unmetered',
	power: 'charging',
	powerSaver: false,
	charging: true,
	thermal: 'nominal',
	storagePressure: 'normal',
	foregroundExecution: true,
	backgroundExecution: false,
	schedule: false,
	cancel: true,
	durableTransfer: true,
};

const validCheckpoint = { version: SYNC_CHECKPOINT_VERSION, cursor: null } as const;

describe('E0 work contract enums and constants', () => {
	it('freezes optional work classes and their quanta', () => {
		expect(OPTIONAL_WORK_CLASSES).toEqual(['interactive', 'background', 'opportunistic']);
		expect(WORK_CLASS_QUANTA).toEqual({ interactive: 8, background: 4, opportunistic: 1 });
		for (const value of OPTIONAL_WORK_CLASSES) expect(isOptionalWorkClass(value)).toBe(true);
		expect(isOptionalWorkClass('critical')).toBe(false);
	});

	it('freezes scheduler resource bounds and protected capacity', () => {
		expect(MAX_RECORDS_PER_STEP).toBe(64);
		expect(MAX_QUEUE_AGE_DAYS).toBe(7);
		expect(MAX_QUEUE_AGE_MS).toBe(7 * 24 * 60 * 60 * 1000);
		expect(YIELD_MAX_BYTES).toBe(2 * 1024 * 1024);
		expect(MAX_YIELD_BYTES).toBe(YIELD_MAX_BYTES);
		expect(YIELD_MAX_MS).toBe(5_000);
		expect(MAX_YIELD_TIME_MS).toBe(YIELD_MAX_MS);
		expect(GLOBAL_OPTIONAL_CONCURRENCY).toBe(2);
		expect(PER_ACCOUNT_OPTIONAL_CONCURRENCY).toBe(1);
		expect(PROTECTED_CRITICAL_SLOT_COUNT).toBe(1);
	});

	it('covers every pause, job, result, and step outcome value', () => {
		for (const value of PAUSE_REASONS) expect(isPauseReason(value)).toBe(true);
		for (const value of JOB_STATES) expect(isOptionalJobState(value)).toBe(true);
		for (const value of JOB_RESULT_STATES) expect(isJobResultState(value)).toBe(true);
		for (const value of SYNC_STEP_OUTCOMES) expect(isSyncStepOutcome(value)).toBe(true);
		expect(isPauseReason('unknown-reason')).toBe(false);
		expect(isOptionalJobState('done')).toBe(false);
		expect(isJobResultState('blocked')).toBe(false);
		expect(isSyncStepOutcome('failed')).toBe(false);
	});

	it('uses the total rollout order off < observe < execute and only narrows', () => {
		expect(ROLLOUT_MODES).toEqual(['off', 'observe', 'execute']);
		expect(ROLLOUT_MODE_RANK).toEqual({ off: 0, observe: 1, execute: 2 });
		for (const value of ROLLOUT_MODES) expect(isRolloutMode(value)).toBe(true);
		expect(narrowRolloutMode('execute', 'observe')).toBe('observe');
		expect(narrowRolloutMode('execute', 'off', 'observe')).toBe('off');
		expect(narrowRolloutMode(['execute', 'observe'])).toBe('observe');
		expect(narrowRolloutMode()).toBe('off');
		expect(isRolloutMode('pilot')).toBe(false);
	});
});

describe('E0 sync step and checkpoint contract', () => {
	it('keeps the exact step shapes available to E2', () => {
		const budget: WorkBudget = {
			maxRecords: 64,
			maxBytes: MAX_YIELD_BYTES,
			deadlineMonoMs: 123.5,
		};
		const options: SyncStepOptions = {
			store: null as never,
			accountId: 'account-opaque',
			signal: new AbortController().signal,
			budget,
			checkpoint: null,
		};
		const result: SyncStepResult = {
			checkpoint: validCheckpoint,
			progress: { done: 4, total: 10, chargedUnits: 5 },
			outcome: 'partial',
		};
		expect(options.budget.maxRecords).toBe(64);
		expect(result.outcome).toBe('partial');
	});

	it('accepts bounded budgets and rejects a changed record ceiling or deadline', () => {
		expect(validateWorkBudget({ maxRecords: 64, maxBytes: 2_000, deadlineMonoMs: 10 })).toEqual({
			maxRecords: 64,
			maxBytes: 2_000,
			deadlineMonoMs: 10,
		});
		expect(validateWorkBudget({ maxRecords: 63, maxBytes: 2_000, deadlineMonoMs: 10 })).toBeNull();
		expect(validateWorkBudget({ maxRecords: 64, maxBytes: MAX_YIELD_BYTES + 1, deadlineMonoMs: 10 })).toBeNull();
		expect(validateWorkBudget({ maxRecords: 64, maxBytes: 2_000, deadlineMonoMs: Infinity })).toBeNull();
	});

	it('accepts the versioned content-minimal checkpoint and rejects version drift/content', () => {
		expect(validateSyncCheckpoint(validCheckpoint)).toEqual(validCheckpoint);
		expect(isSyncCheckpoint(validCheckpoint)).toBe(true);
		expect(validateSyncCheckpoint({ version: 2, cursor: null })).toBeNull();
		expect(validateSyncCheckpoint({ version: 1, cursor: '' })).toBeNull();
		expect(validateSyncCheckpoint({ version: 1, cursor: null, subject: 'secret' })).toBeNull();
	});

	it('validates the exact step result and keeps no cursor-before-commit escape hatch', () => {
		const result = {
			checkpoint: validCheckpoint,
			progress: { done: 0, chargedUnits: 0 },
			outcome: 'blocked',
		};
		expect(validateSyncStepResult(result)).toEqual(result);
		expect(validateSyncStepResult({ ...result, checkpoint: { version: 2, cursor: null } })).toBeNull();
		expect(validateSyncStepResult({ ...result, outcome: 'failed' })).toBeNull();
		expect(validateSyncStepResult({ ...result, progress: { done: 3, total: 2, chargedUnits: 1 } })).toBeNull();
	});
});

describe('E0 bridge capability snapshot', () => {
	it('accepts the normalized foreground snapshot', () => {
		const normalized = normalizeBridgeCapabilitySnapshot(foregroundSnapshot);
		expect(normalized).toEqual(foregroundSnapshot);
		expect(isBridgeCapabilitySnapshot(normalized)).toBe(true);
	});

	it('covers every normalized bridge enum', () => {
		for (const value of BRIDGE_EXECUTION_MODES) {
			const snapshot = {
				...foregroundSnapshot,
				executionMode: value,
				backgroundExecution: value === 'background',
			};
			expect(normalizeBridgeCapabilitySnapshot(snapshot)).not.toBeNull();
		}
		for (const value of BRIDGE_NETWORK_COSTS) expect(typeof value).toBe('string');
		for (const value of BRIDGE_POWER_STATES) expect(typeof value).toBe('string');
		for (const value of BRIDGE_THERMAL_STATES) expect(typeof value).toBe('string');
		for (const value of BRIDGE_STORAGE_PRESSURES) expect(typeof value).toBe('string');
	});

	it('fails closed for unknown versions and enum values', () => {
		expect(normalizeBridgeCapabilitySnapshot({ ...foregroundSnapshot, contractVersion: 2 })).toBeNull();
		expect(normalizeBridgeCapabilitySnapshot({ ...foregroundSnapshot, executionMode: 'background' })).toBeNull();
		expect(normalizeBridgeCapabilitySnapshot({ ...foregroundSnapshot, networkCost: 'wifi' })).toBeNull();
		expect(normalizeBridgeCapabilitySnapshot({ ...foregroundSnapshot, power: 'unknown' })).toBeNull();
		expect(normalizeBridgeCapabilitySnapshot({ ...foregroundSnapshot, storagePressure: 'full' })).toBeNull();
	});

	it('rejects unknown keys and privacy-excluded network/location fields', () => {
		for (const field of PRIVACY_EXCLUDED_BRIDGE_FIELDS) {
			expect(normalizeBridgeCapabilitySnapshot({ ...foregroundSnapshot, [field]: 'redacted' })).toBeNull();
		}
		expect(normalizeBridgeCapabilitySnapshot({ ...foregroundSnapshot, futureCapability: true })).toBeNull();
		expect(Object.keys(foregroundSnapshot)).not.toEqual(expect.arrayContaining([...PRIVACY_EXCLUDED_BRIDGE_FIELDS]));
	});

	it('does not widen a foreground-only execution mode', () => {
		expect(normalizeBridgeCapabilitySnapshot({
			...foregroundSnapshot,
			executionMode: 'foregroundReconnectOnly',
			backgroundExecution: true,
		})).toBeNull();
	});
});
