import type { OfflineStore } from './store';

/** Optional work is deliberately separate from the existing Critical lanes. */
export const OPTIONAL_WORK_CLASSES = [
	'interactive',
	'background',
	'opportunistic',
] as const;
export type OptionalWorkClass = (typeof OPTIONAL_WORK_CLASSES)[number];

/** Scheduler cost units per turn, in the fixed total priority order. */
export const WORK_CLASS_QUANTA = {
	interactive: 8,
	background: 4,
	opportunistic: 1,
} as const satisfies Record<OptionalWorkClass, number>;
export const OPTIONAL_WORK_QUANTA = WORK_CLASS_QUANTA;

export const MAX_RECORDS_PER_STEP = 64 as const;
export const MAX_STEP_RECORDS = MAX_RECORDS_PER_STEP;
export const MAX_QUEUE_AGE_DAYS = 7 as const;
export const MAX_QUEUE_AGE_MS = MAX_QUEUE_AGE_DAYS * 24 * 60 * 60 * 1000;
export const MAX_OPTIONAL_QUEUE_AGE_MS = MAX_QUEUE_AGE_MS;

export const YIELD_MAX_BYTES = 2 * 1024 * 1024;
export const YIELD_MAX_MS = 5_000 as const;
export const MAX_YIELD_BYTES = YIELD_MAX_BYTES;
export const MAX_YIELD_TIME_MS = YIELD_MAX_MS;

export const GLOBAL_OPTIONAL_CONCURRENCY = 2 as const;
export const PER_ACCOUNT_OPTIONAL_CONCURRENCY = 1 as const;
export const OPTIONAL_GLOBAL_CONCURRENCY = GLOBAL_OPTIONAL_CONCURRENCY;
export const OPTIONAL_PER_ACCOUNT_CONCURRENCY = PER_ACCOUNT_OPTIONAL_CONCURRENCY;

/** Capacity reserved for the existing Critical authority paths. */
export const PROTECTED_CRITICAL_SLOT_COUNT = 1 as const;
export const RESERVED_CRITICAL_SLOTS = PROTECTED_CRITICAL_SLOT_COUNT;
export const CRITICAL_QUIET_RESUME_MS = 5_000 as const;
export const CRITICAL_QUIET_PERIOD_MS = CRITICAL_QUIET_RESUME_MS;

export const RETRY_INITIAL_DELAY_MS = 1_000 as const;
export const RETRY_MAX_DELAY_MS = 5 * 60 * 1_000;

export const ROLLOUT_MODES = ['off', 'observe', 'execute'] as const;
export type RolloutMode = (typeof ROLLOUT_MODES)[number];

/** The only rollout order: off < observe < execute. Narrowing is the meet. */
export const ROLLOUT_MODE_ORDER = ROLLOUT_MODES;
export const ROLLOUT_MODE_RANK: Readonly<Record<RolloutMode, number>> = {
	off: 0,
	observe: 1,
	execute: 2,
};

export function isOptionalWorkClass(value: unknown): value is OptionalWorkClass {
	return typeof value === 'string' && (OPTIONAL_WORK_CLASSES as readonly string[]).includes(value);
}

export function isRolloutMode(value: unknown): value is RolloutMode {
	return typeof value === 'string' && (ROLLOUT_MODES as readonly string[]).includes(value);
}

/**
 * Return the narrowest mode. Invalid runtime values fail closed to `off`; the
 * typed signature keeps normal callers on the exact three-value contract.
 */
export function narrowRolloutMode(...modes: RolloutMode[]): RolloutMode;
export function narrowRolloutMode(modes: readonly RolloutMode[]): RolloutMode;
export function narrowRolloutMode(
	...input: [readonly RolloutMode[]] | RolloutMode[]
): RolloutMode {
	const modes = input.length === 1 && Array.isArray(input[0])
		? input[0]
		: input;
	if (modes.length === 0) return 'off';
	let narrowest: RolloutMode = 'execute';
	for (const mode of modes) {
		if (!isRolloutMode(mode)) return 'off';
		if (ROLLOUT_MODE_RANK[mode] < ROLLOUT_MODE_RANK[narrowest]) narrowest = mode;
	}
	return narrowest;
}

export const PAUSE_REASONS = [
	'networkUnavailable',
	'meteredNetwork',
	'backgroundGrantExpired',
	'lowPower',
	'notCharging',
	'thermal',
	'storagePressure',
	'criticalActivity',
	'capabilityUnavailable',
	'policyDenied',
	'backoff',
	'deadlineExceeded',
	'cancelled',
	'authExpired',
	'statePruned',
	'validatorChanged',
	'observeOnly',
] as const;
export type PauseReason = (typeof PAUSE_REASONS)[number];

export function isPauseReason(value: unknown): value is PauseReason {
	return typeof value === 'string' && (PAUSE_REASONS as readonly string[]).includes(value);
}

export const JOB_STATES = [
	'queued',
	'running',
	'paused',
	'backoff',
	'complete',
	'failed',
	'expired',
	'cancelled',
] as const;
export type OptionalJobState = (typeof JOB_STATES)[number];
export type JobState = OptionalJobState;

export const JOB_RESULT_STATES = [
	'complete',
	'paused',
	'failed',
	'expired',
	'cancelled',
] as const;
export type JobResultState = (typeof JOB_RESULT_STATES)[number];

export function isOptionalJobState(value: unknown): value is OptionalJobState {
	return typeof value === 'string' && (JOB_STATES as readonly string[]).includes(value);
}

export function isJobResultState(value: unknown): value is JobResultState {
	return typeof value === 'string' && (JOB_RESULT_STATES as readonly string[]).includes(value);
}

export const WORK_ERROR_CODES = [
	'aborted',
	'network',
	'authorization',
	'policy',
	'capability',
	'storage',
	'checkpoint',
	'validator',
	'deadline',
	'unknown',
] as const;
export type WorkErrorCode = (typeof WORK_ERROR_CODES)[number];

export interface WorkError {
	code: WorkErrorCode;
	retryable: boolean;
}

export interface WorkBudget {
	maxRecords: typeof MAX_RECORDS_PER_STEP;
	maxBytes: number;
	deadlineMonoMs: number;
}

/**
 * The checkpoint is intentionally content-minimal: only a version fence and
 * an opaque server/page cursor cross the local durable boundary. It contains
 * no message content, identity, bearer, filename, or network-location data.
 *
 * No cursor advance before commit: a step may return the prior cursor again,
 * but it must publish a newer cursor only after its local page has committed.
 */
export const SYNC_CHECKPOINT_VERSION = 1 as const;
export interface SyncCheckpoint {
	version: typeof SYNC_CHECKPOINT_VERSION;
	cursor: string | null;
}
export type Checkpoint = SyncCheckpoint;

export function makeInitialSyncCheckpoint(): SyncCheckpoint {
	return { version: SYNC_CHECKPOINT_VERSION, cursor: null };
}

export interface SyncStepProgress {
	done: number;
	total?: number;
	chargedUnits: number;
}

export type SyncStepOutcome = 'partial' | 'complete' | 'blocked';
export const SYNC_STEP_OUTCOMES = ['partial', 'complete', 'blocked'] as const;

export function isSyncStepOutcome(value: unknown): value is SyncStepOutcome {
	return typeof value === 'string' && (SYNC_STEP_OUTCOMES as readonly string[]).includes(value);
}

/** Exact E0 step result contract. */
export interface SyncStepResult {
	checkpoint: SyncCheckpoint;
	progress: {
		done: number;
		total?: number;
		chargedUnits: number;
		/**
		 * Approximate applied byte charge of this call (E4-I r5 Astra
		 * correction). Optional for compatibility; a bounded step always
		 * reports it so the coordinator can deduct the call's consumption from
		 * its dispatch's ONE byte budget — a partial step must never re-spend
		 * the full allowance.
		 */
		appliedBytes?: number;
	};
	outcome: SyncStepOutcome;
}

/** Exact E0 step options contract. */
export interface SyncStepOptions {
	store: OfflineStore;
	accountId: string;
	signal: AbortSignal;
	budget: {
		maxRecords: 64;
		maxBytes: number;
		deadlineMonoMs: number;
	};
	checkpoint: SyncCheckpoint | null;
}

export type SyncStep = (options: SyncStepOptions) => Promise<SyncStepResult>;
export type SyncWindowStep = SyncStep;
export type SyncDeltaStep = SyncStep;

export type SchedulerState =
	| { kind: 'idle' }
	| { kind: 'running'; progress?: Pick<SyncStepProgress, 'done' | 'total'> }
	| { kind: 'paused'; reason: PauseReason }
	| { kind: 'backoff'; retryAt: number; reason: PauseReason };

export type BlockingIssue = 'none' | 'recoverable' | 'actionRequired' | 'locked';

export interface OptionalWorkJob {
	jobId: string;
	accountId: string;
	workClass: OptionalWorkClass;
	state: OptionalJobState;
	triggerGeneration: number;
	coalescingKey: string;
	attempts: number;
	deadlineUtc: string;
	checkpoint: SyncCheckpoint | null;
}

export interface EligibilitySnapshot {
	workClass: OptionalWorkClass;
	rolloutMode: RolloutMode;
	capability: BridgeCapabilitySnapshot;
	criticalActivity: number;
	queueAgeMs: number;
	nowMonoMs: number;
}

export type EligibilityDecision =
	| {
		kind: 'eligible';
		mode: 'execute';
		workClass: OptionalWorkClass;
		budget: WorkBudget;
	}
	| {
		kind: 'observed';
		mode: 'observe';
		workClass: OptionalWorkClass;
		reason: 'observeOnly';
	}
	| {
		kind: 'blocked';
		mode: RolloutMode;
		workClass: OptionalWorkClass;
		reason: PauseReason;
	};

export type JobResult =
	| { state: 'complete'; checkpoint: SyncCheckpoint; progress: SyncStepProgress }
	| { state: 'paused'; checkpoint: SyncCheckpoint; progress: SyncStepProgress; reason: PauseReason }
	| { state: 'failed'; checkpoint: SyncCheckpoint; progress: SyncStepProgress; error: WorkError }
	| { state: 'expired'; checkpoint: SyncCheckpoint; progress: SyncStepProgress; expiredAtUtc: string }
	| { state: 'cancelled'; checkpoint: SyncCheckpoint; progress: SyncStepProgress; reason: 'cancelled' };

export const BRIDGE_CAPABILITY_CONTRACT_VERSION = 1 as const;
export const BRIDGE_CONTRACT_VERSION = BRIDGE_CAPABILITY_CONTRACT_VERSION;
export const BRIDGE_EXECUTION_MODES = ['foregroundReconnectOnly', 'background'] as const;
export type BridgeExecutionMode = (typeof BRIDGE_EXECUTION_MODES)[number];
export const BRIDGE_NETWORK_COSTS = ['offline', 'unmetered', 'metered'] as const;
export type BridgeNetworkCost = (typeof BRIDGE_NETWORK_COSTS)[number];
export type NetworkCost = BridgeNetworkCost;
export const BRIDGE_POWER_STATES = ['battery', 'charging', 'full'] as const;
export type BridgePowerState = (typeof BRIDGE_POWER_STATES)[number];
export type PowerState = BridgePowerState;
export const BRIDGE_THERMAL_STATES = ['nominal', 'fair', 'serious', 'critical'] as const;
export type BridgeThermalState = (typeof BRIDGE_THERMAL_STATES)[number];
export type ThermalState = BridgeThermalState;
export const BRIDGE_STORAGE_PRESSURES = ['normal', 'elevated', 'critical'] as const;
export type BridgeStoragePressure = (typeof BRIDGE_STORAGE_PRESSURES)[number];
export type StoragePressure = BridgeStoragePressure;

/**
 * The normalized, privacy-safe bridge snapshot. The shell may report
 * foreground/reconnect execution now; `background` is meaningful only after
 * a shell has independently proven that the existing TS coordinator runs.
 */
export interface BridgeCapabilitySnapshot {
	contractVersion: typeof BRIDGE_CAPABILITY_CONTRACT_VERSION;
	executionMode: BridgeExecutionMode;
	networkCost: BridgeNetworkCost;
	power: BridgePowerState;
	powerSaver: boolean;
	charging: boolean;
	thermal: BridgeThermalState;
	storagePressure: BridgeStoragePressure;
	foregroundExecution: boolean;
	backgroundExecution: boolean;
	schedule: boolean;
	cancel: boolean;
	durableTransfer: boolean;
}

const BRIDGE_SNAPSHOT_KEYS = [
	'contractVersion',
	'executionMode',
	'networkCost',
	'power',
	'powerSaver',
	'charging',
	'thermal',
	'storagePressure',
	'foregroundExecution',
	'backgroundExecution',
	'schedule',
	'cancel',
	'durableTransfer',
] as const;

/** These fields are intentionally absent from the bridge contract. */
export const PRIVACY_EXCLUDED_BRIDGE_FIELDS = [
	'ssid',
	'carrier',
	'ip',
	'ipAddress',
	'location',
	'latitude',
	'longitude',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	const actual = Object.keys(value).sort();
	const expected = [...keys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isStringEnum<T extends readonly string[]>(values: T, value: unknown): value is T[number] {
	return typeof value === 'string' && (values as readonly string[]).includes(value);
}

export function validateWorkBudget(value: unknown): WorkBudget | null {
	if (!isRecord(value) || !hasExactKeys(value, ['maxRecords', 'maxBytes', 'deadlineMonoMs'])) return null;
	const maxBytes = value.maxBytes;
	const deadlineMonoMs = value.deadlineMonoMs;
	if (
		value.maxRecords !== MAX_RECORDS_PER_STEP ||
		typeof maxBytes !== 'number' ||
		!Number.isSafeInteger(maxBytes) ||
		maxBytes < 0 ||
		maxBytes > YIELD_MAX_BYTES ||
		typeof deadlineMonoMs !== 'number' ||
		!Number.isFinite(deadlineMonoMs) ||
		deadlineMonoMs < 0
	) return null;
	return {
		maxRecords: MAX_RECORDS_PER_STEP,
		maxBytes,
		deadlineMonoMs,
	};
}

export function isWorkBudget(value: unknown): value is WorkBudget {
	return validateWorkBudget(value) !== null;
}

export function validateSyncCheckpoint(value: unknown): SyncCheckpoint | null {
	if (!isRecord(value) || !hasExactKeys(value, ['version', 'cursor'])) return null;
	if (value.version !== SYNC_CHECKPOINT_VERSION) return null;
	if (value.cursor !== null && (typeof value.cursor !== 'string' || value.cursor.length === 0)) return null;
	return {
		version: SYNC_CHECKPOINT_VERSION,
		cursor: value.cursor,
	};
}

export function isSyncCheckpoint(value: unknown): value is SyncCheckpoint {
	return validateSyncCheckpoint(value) !== null;
}

function validateProgress(value: unknown): SyncStepProgress | null {
	if (!isRecord(value)) return null;
	const keys = Object.keys(value);
	if (keys.some((key) => key !== 'done' && key !== 'total' && key !== 'chargedUnits' && key !== 'appliedBytes')) return null;
	const done = value.done;
	const total = value.total;
	const chargedUnits = value.chargedUnits;
	if (
		typeof done !== 'number' ||
		!Number.isSafeInteger(done) ||
		done < 0 ||
		typeof chargedUnits !== 'number' ||
		!Number.isSafeInteger(chargedUnits) ||
		chargedUnits < 0
	) return null;
	// Optional appliedBytes: absent is fine; a PRESENT value must be a valid
	// charge — an invalid one fails validation instead of being dropped.
	const hasAppliedBytes = Object.prototype.hasOwnProperty.call(value, 'appliedBytes');
	if (hasAppliedBytes && (typeof value.appliedBytes !== 'number' || !Number.isSafeInteger(value.appliedBytes) || value.appliedBytes < 0)) return null;
	const bytes = hasAppliedBytes ? { appliedBytes: value.appliedBytes as number } : {};
	if (Object.prototype.hasOwnProperty.call(value, 'total')) {
		if (typeof total !== 'number' || !Number.isSafeInteger(total) || total < done) return null;
		return { done, total, chargedUnits, ...bytes };
	}
	return { done, chargedUnits, ...bytes };
}

export function validateSyncStepResult(value: unknown): SyncStepResult | null {
	if (!isRecord(value) || !hasExactKeys(value, ['checkpoint', 'progress', 'outcome'])) return null;
	const checkpoint = validateSyncCheckpoint(value.checkpoint);
	const progress = validateProgress(value.progress);
	if (!checkpoint || !progress || !isSyncStepOutcome(value.outcome)) return null;
	return { checkpoint, progress, outcome: value.outcome };
}

export function isSyncStepResult(value: unknown): value is SyncStepResult {
	return validateSyncStepResult(value) !== null;
}

export function normalizeBridgeCapabilitySnapshot(value: unknown): BridgeCapabilitySnapshot | null {
	if (!isRecord(value) || !hasExactKeys(value, BRIDGE_SNAPSHOT_KEYS)) return null;
	const executionMode = value.executionMode;
	const networkCost = value.networkCost;
	const power = value.power;
	const thermal = value.thermal;
	const storagePressure = value.storagePressure;
	if (value.contractVersion !== BRIDGE_CAPABILITY_CONTRACT_VERSION) return null;
	if (!isStringEnum(BRIDGE_EXECUTION_MODES, executionMode)) return null;
	if (!isStringEnum(BRIDGE_NETWORK_COSTS, networkCost)) return null;
	if (!isStringEnum(BRIDGE_POWER_STATES, power)) return null;
	if (!isStringEnum(BRIDGE_THERMAL_STATES, thermal)) return null;
	if (!isStringEnum(BRIDGE_STORAGE_PRESSURES, storagePressure)) return null;
	const booleanKeys = [
		'powerSaver',
		'charging',
		'foregroundExecution',
		'backgroundExecution',
		'schedule',
		'cancel',
		'durableTransfer',
	] as const;
	if (booleanKeys.some((key) => typeof value[key] !== 'boolean')) return null;
	const powerSaver = value.powerSaver;
	const charging = value.charging;
	const foregroundExecution = value.foregroundExecution;
	const backgroundExecution = value.backgroundExecution;
	const schedule = value.schedule;
	const cancel = value.cancel;
	const durableTransfer = value.durableTransfer;
	if (
		typeof powerSaver !== 'boolean' ||
		typeof charging !== 'boolean' ||
		typeof foregroundExecution !== 'boolean' ||
		typeof backgroundExecution !== 'boolean' ||
		typeof schedule !== 'boolean' ||
		typeof cancel !== 'boolean' ||
		typeof durableTransfer !== 'boolean'
	) return null;
	if (executionMode === 'background' && backgroundExecution !== true) return null;
	if (executionMode === 'foregroundReconnectOnly' && backgroundExecution !== false) return null;
	return {
		contractVersion: BRIDGE_CAPABILITY_CONTRACT_VERSION,
		executionMode,
		networkCost,
		power,
		powerSaver,
		charging,
		thermal,
		storagePressure,
		foregroundExecution,
		backgroundExecution,
		schedule,
		cancel,
		durableTransfer,
	};
}

export const validateBridgeCapabilitySnapshot = normalizeBridgeCapabilitySnapshot;

export function isBridgeCapabilitySnapshot(value: unknown): value is BridgeCapabilitySnapshot {
	return normalizeBridgeCapabilitySnapshot(value) !== null;
}
