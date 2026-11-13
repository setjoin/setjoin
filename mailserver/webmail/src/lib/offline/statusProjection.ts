import {
	BRIDGE_EXECUTION_MODES,
	BRIDGE_NETWORK_COSTS,
	isPauseReason,
	isRolloutMode,
	type BlockingIssue,
	type BridgeExecutionMode,
	type BridgeNetworkCost,
	type PauseReason,
	type RolloutMode,
	type SchedulerState,
} from './work-contract';

/** The explicit Work Offline control is independent from freshness. */
export type ManualMode = 'online' | 'workOffline';

/** Freshness never implies that a cache is absent or that a sync is running. */
export type Freshness = 'neverSynced' | 'current' | 'stale' | 'unknown';

export const BLOCKING_ISSUES = ['none', 'recoverable', 'actionRequired', 'locked'] as const;

export const BLOCKING_REASONS = ['authRequired', 'storagePressure', 'unknown'] as const;
export type BlockingReason = (typeof BLOCKING_REASONS)[number];

/**
 * This is a reason category, not a user-facing string. The UI owns
 * localization and wording; keeping the hint stable makes the projection safe
 * to consume from browser and native surfaces alike.
 */
export type UserActionHint =
	| { kind: 'retry' }
	| { kind: 'goOnline' }
	| { kind: 'syncNow' }
	| { kind: 'signIn' }
	| { kind: 'freeStorage' }
	| { kind: 'unlock' }
	| { kind: 'viewSettings' }
	| { kind: 'resolve' };

export interface AutomaticWorkInput {
	rolloutMode: RolloutMode;
	executionMode: BridgeExecutionMode;
	backgroundExecution: boolean;
}

export interface StatusProjectionInput {
	connectivity: {
		networkCost: BridgeNetworkCost;
	};
	freshness: Freshness;
	cached: boolean;
	scheduler: SchedulerState;
	blockingIssue: BlockingIssue;
	blockingReason?: BlockingReason;
	manualMode: ManualMode;
	automaticWork: AutomaticWorkInput;
}

export type AutomaticWorkStatus =
	| 'disabled'
	| 'observeOnly'
	| 'foregroundReconnectOnly'
	| 'background';

export interface AutomaticWorkProjection {
	rolloutMode: RolloutMode;
	executionMode: BridgeExecutionMode;
	backgroundExecution: boolean;
	backgroundSupport: 'available' | 'unsupported';
	status: AutomaticWorkStatus;
}

export type PrimaryDisplay =
	| 'current'
	| 'notCurrent'
	| 'neverSynced'
	| 'unknown'
	| 'actionRequired'
	| 'locked';

export type SecondaryDisplay =
	| { kind: 'offline' }
	| { kind: 'metered' }
	| { kind: 'running'; progress?: { done: number; total?: number } }
	| { kind: 'paused'; reason: PauseReason }
	| { kind: 'backoff'; retryAt: number; reason: PauseReason };

export interface StatusDisplayProjection {
	primary: PrimaryDisplay;
	secondary?: SecondaryDisplay;
	action?: UserActionHint;
}

export interface StatusProjection {
	/** Connectivity is reported separately from freshness and scheduler state. */
	connectivity: {
		networkCost: BridgeNetworkCost;
		reachable: boolean;
	};
	manualMode: ManualMode;
	freshness: {
		kind: Freshness;
		cached: boolean;
	};
	scheduler: SchedulerState;
	blockingIssue: BlockingIssue;
	blockingReason?: BlockingReason;
	automaticWork: AutomaticWorkProjection;
	display: StatusDisplayProjection;
}

/** These fields must never cross this projection boundary. */
export const PRIVACY_EXCLUDED_STATUS_FIELDS = [
	'accountId',
	'attachmentName',
	'body',
	'carrier',
	'content',
	'filename',
	'ip',
	'ipAddress',
	'jobId',
	'location',
	'messageId',
	'networkHistory',
	'sender',
	'ssid',
	'subject',
	'token',
	'url',
] as const;

const FRESHNESS_VALUES = ['neverSynced', 'current', 'stale', 'unknown'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(
	value: Record<string, unknown>,
	required: readonly string[],
	optional: readonly string[] = [],
): boolean {
	const allowed = new Set([...required, ...optional]);
	const actual = Object.keys(value);
	return (
		required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
		actual.every((key) => allowed.has(key))
	);
}

function isStringEnum<T extends readonly string[]>(values: T, value: unknown): value is T[number] {
	return typeof value === 'string' && (values as readonly string[]).includes(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
	return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isNonNegativeFiniteNumber(value: unknown): value is number {
	return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function parseProgress(value: unknown): { done: number; total?: number } | null {
	if (!isRecord(value) || !hasExactKeys(value, ['done'], ['total'])) return null;
	if (!isNonNegativeSafeInteger(value.done)) return null;
	if (!Object.prototype.hasOwnProperty.call(value, 'total')) return { done: value.done };
	if (!isNonNegativeSafeInteger(value.total) || value.total < value.done) return null;
	return { done: value.done, total: value.total };
}

function parseScheduler(value: unknown): SchedulerState | null {
	if (!isRecord(value) || typeof value.kind !== 'string') return null;

	switch (value.kind) {
		case 'idle':
			return hasExactKeys(value, ['kind']) ? { kind: 'idle' } : null;
		case 'running': {
			if (!hasExactKeys(value, ['kind'], ['progress'])) return null;
			if (!Object.prototype.hasOwnProperty.call(value, 'progress')) return { kind: 'running' };
			const progress = parseProgress(value.progress);
			return progress ? { kind: 'running', progress } : null;
		}
		case 'paused':
			return hasExactKeys(value, ['kind', 'reason']) && isPauseReason(value.reason)
				? { kind: 'paused', reason: value.reason }
				: null;
		case 'backoff':
			return hasExactKeys(value, ['kind', 'retryAt', 'reason']) &&
				isNonNegativeFiniteNumber(value.retryAt) &&
				isPauseReason(value.reason)
				? { kind: 'backoff', retryAt: value.retryAt, reason: value.reason }
				: null;
		default:
			return null;
	}
}

function parseAutomaticWork(value: unknown): AutomaticWorkInput | null {
	if (
		!isRecord(value) ||
		!hasExactKeys(value, ['rolloutMode', 'executionMode', 'backgroundExecution']) ||
		!isRolloutMode(value.rolloutMode) ||
		!isStringEnum(BRIDGE_EXECUTION_MODES, value.executionMode) ||
		typeof value.backgroundExecution !== 'boolean'
	) return null;

	if (
		(value.executionMode === 'background' && value.backgroundExecution !== true) ||
		(value.executionMode === 'foregroundReconnectOnly' && value.backgroundExecution !== false)
	) return null;

	return {
		rolloutMode: value.rolloutMode,
		executionMode: value.executionMode,
		backgroundExecution: value.backgroundExecution,
	};
}

/**
 * Parse an untrusted boundary payload without allowing fields to silently
 * become part of the status contract. Exact keys also reject identity,
 * content, token, and network-location fields at every nested boundary.
 */
export function parseStatusProjectionInput(value: unknown): StatusProjectionInput | null {
	if (
		!isRecord(value) ||
		!hasExactKeys(value, [
			'connectivity',
			'freshness',
			'cached',
			'scheduler',
			'blockingIssue',
			'manualMode',
			'automaticWork',
		], ['blockingReason'])
	) return null;
	if (
		!isRecord(value.connectivity) ||
		!hasExactKeys(value.connectivity, ['networkCost']) ||
		!isStringEnum(BRIDGE_NETWORK_COSTS, value.connectivity.networkCost) ||
		!isStringEnum(FRESHNESS_VALUES, value.freshness) ||
		typeof value.cached !== 'boolean' ||
		!isStringEnum(BLOCKING_ISSUES, value.blockingIssue) ||
		!isStringEnum(['online', 'workOffline'] as const, value.manualMode)
	) return null;

	if (value.freshness === 'neverSynced' && value.cached) return null;

	let blockingReason: BlockingReason | undefined;
	if (Object.prototype.hasOwnProperty.call(value, 'blockingReason')) {
		if (!isStringEnum(BLOCKING_REASONS, value.blockingReason)) return null;
		blockingReason = value.blockingReason;
		if (value.blockingIssue !== 'actionRequired') return null;
	}

	const scheduler = parseScheduler(value.scheduler);
	const automaticWork = parseAutomaticWork(value.automaticWork);
	if (!scheduler || !automaticWork) return null;

	return {
		connectivity: { networkCost: value.connectivity.networkCost },
		freshness: value.freshness,
		cached: value.cached,
		scheduler,
		blockingIssue: value.blockingIssue,
		...(blockingReason === undefined ? {} : { blockingReason }),
		manualMode: value.manualMode,
		automaticWork,
	};
}

export function isStatusProjectionInput(value: unknown): value is StatusProjectionInput {
	return parseStatusProjectionInput(value) !== null;
}

export const normalizeStatusProjectionInput = parseStatusProjectionInput;

function automaticWorkProjection(input: AutomaticWorkInput): AutomaticWorkProjection {
	let status: AutomaticWorkStatus;
	if (input.rolloutMode === 'off') status = 'disabled';
	else if (input.rolloutMode === 'observe') status = 'observeOnly';
	else if (input.executionMode === 'background') status = 'background';
	else status = 'foregroundReconnectOnly';

	return {
		rolloutMode: input.rolloutMode,
		executionMode: input.executionMode,
		backgroundExecution: input.backgroundExecution,
		backgroundSupport: input.executionMode === 'background' ? 'available' : 'unsupported',
		status,
	};
}

function primaryFor(input: StatusProjectionInput): PrimaryDisplay {
	if (input.blockingIssue === 'locked') return 'locked';
	if (input.blockingIssue === 'actionRequired') return 'actionRequired';
	switch (input.freshness) {
		case 'current':
			return 'current';
		case 'stale':
			return 'notCurrent';
		case 'neverSynced':
			return 'neverSynced';
		case 'unknown':
			return 'unknown';
	}
}

function retryOrOnline(input: StatusProjectionInput): UserActionHint | undefined {
	if (input.manualMode === 'workOffline') return { kind: 'goOnline' };
	if (input.connectivity.networkCost === 'offline') return undefined;
	return { kind: 'retry' };
}

function actionFor(input: StatusProjectionInput): UserActionHint | undefined {
	if (input.blockingIssue === 'locked') return { kind: 'unlock' };
	if (input.blockingIssue === 'actionRequired') {
		switch (input.blockingReason) {
			case 'authRequired':
				return { kind: 'signIn' };
			case 'storagePressure':
				return { kind: 'freeStorage' };
			default:
				return { kind: 'resolve' };
		}
	}
	if (input.scheduler.kind === 'running' || input.scheduler.kind === 'backoff') return undefined;
	if (input.scheduler.kind === 'paused' && input.scheduler.reason === 'policyDenied') {
		return { kind: 'viewSettings' };
	}
	if (input.blockingIssue === 'recoverable') return retryOrOnline(input);
	if (input.freshness === 'stale') return retryOrOnline(input);
	if (input.freshness === 'neverSynced') {
		if (input.manualMode === 'workOffline') return { kind: 'goOnline' };
		if (input.connectivity.networkCost !== 'offline') return { kind: 'syncNow' };
	}
	return undefined;
}

function secondaryFor(input: StatusProjectionInput): SecondaryDisplay | undefined {
	switch (input.scheduler.kind) {
		case 'running':
			return input.scheduler.progress === undefined
				? { kind: 'running' }
				: { kind: 'running', progress: { ...input.scheduler.progress } };
		case 'paused':
			return { kind: 'paused', reason: input.scheduler.reason };
		case 'backoff':
			return {
				kind: 'backoff',
				retryAt: input.scheduler.retryAt,
				reason: input.scheduler.reason,
			};
		case 'idle':
			if (input.connectivity.networkCost === 'offline') return { kind: 'offline' };
			if (input.connectivity.networkCost === 'metered') return { kind: 'metered' };
			return undefined;
	}
}

/**
 * Project the independent status axes without deciding authorization,
 * scheduling, or policy. The display block is derived convenience data; the
 * top-level axes remain the source of truth for later browser/native UI.
 */
export function projectStatus(input: StatusProjectionInput): StatusProjection {
	const automaticWork = automaticWorkProjection(input.automaticWork);
	const secondary = secondaryFor(input);
	const action = actionFor(input);
	const display: StatusDisplayProjection = {
		primary: primaryFor(input),
		...(secondary === undefined ? {} : { secondary }),
		...(action === undefined ? {} : { action }),
	};

	return {
		connectivity: {
			networkCost: input.connectivity.networkCost,
			reachable: input.connectivity.networkCost !== 'offline',
		},
		manualMode: input.manualMode,
		freshness: { kind: input.freshness, cached: input.cached },
		scheduler: input.scheduler,
		blockingIssue: input.blockingIssue,
		...(input.blockingReason === undefined ? {} : { blockingReason: input.blockingReason }),
		automaticWork,
		display,
	};
}

export const projectStatusProjection = projectStatus;

/**
 * E4-I consumer-parity seam: map one coordinator job result — as committed by
 * the job store and read back through `readJobResult` — onto the E5 scheduler
 * view state. E4 execution consumers and E5 projections consume the SAME
 * committed/unknown/paused results through this single mapping, so no surface
 * can invent a completion the coordinator never committed.
 *
 * - unknown (null) maps to `idle`: "no committed result" is never read as a
 *   completion or as currentness.
 * - `complete` maps to `idle` ONLY from a committed record.
 * - `paused` keeps its exact pause reason.
 * - Terminal failures/expiry/cancellation surface through the existing
 *   blocking-issue and action-hint inputs, not as a running state.
 */
export function schedulerStateFromJobResult(result: import('./work-contract').JobResult | null): SchedulerState {
	if (result === null) return { kind: 'idle' };
	switch (result.state) {
		case 'complete':
			return { kind: 'idle' };
		case 'paused':
			return { kind: 'paused', reason: result.reason };
		case 'failed':
		case 'cancelled':
		case 'expired':
			return { kind: 'idle' };
	}
}
