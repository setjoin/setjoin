import {
	MAX_QUEUE_AGE_MS,
	MAX_RECORDS_PER_STEP,
	YIELD_MAX_BYTES,
	YIELD_MAX_MS,
	isOptionalWorkClass,
	isRolloutMode,
	narrowRolloutMode,
	normalizeBridgeCapabilitySnapshot,
	type BridgeCapabilitySnapshot,
	type EligibilityDecision,
	type EligibilitySnapshot,
	type OptionalWorkClass,
	type PauseReason,
	type RolloutMode,
} from './work-contract';

/** The server/user network ceiling used by the E2 policy projection. */
export const AUTOMATIC_NETWORK_POLICIES = ['never', 'unmetered', 'any'] as const;
export type AutomaticNetworkPolicy = (typeof AUTOMATIC_NETWORK_POLICIES)[number];

export interface RequestedEligibilityPolicy {
	backgroundSyncEnabled: boolean;
	automaticNetwork: AutomaticNetworkPolicy;
}

export interface EffectiveEligibilityPolicy {
	backgroundAllowed: boolean;
	automaticNetwork: AutomaticNetworkPolicy;
	opportunisticRequiresCharging: boolean;
}

/**
 * The small, server-derived admission input for one optional sync job.
 * `rolloutMode` is already the authoritative rollout mode; requested/effective
 * contain the user/device request and the reducer-derived policy projection.
 * `nowUtcMs` is injected because persisted deadlines are wall-clock values,
 * while `nowMonoMs` is the scheduler's monotonic budget origin.
 */
export interface EligibilityInput extends EligibilitySnapshot {
	flagEnabled: boolean;
	requested: RequestedEligibilityPolicy;
	effective: EffectiveEligibilityPolicy;
	workOffline: boolean;
	deadlineUtc: string;
	nowUtcMs: number;
}

const NETWORK_RANK: Readonly<Record<AutomaticNetworkPolicy, number>> = {
	never: 0,
	unmetered: 1,
	any: 2,
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	const actual = Object.keys(value).sort();
	const expected = [...keys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isNonNegativeFinite(value: unknown): value is number {
	return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isNonNegativeInteger(value: unknown): value is number {
	return isNonNegativeFinite(value) && Number.isSafeInteger(value);
}

function isAutomaticNetworkPolicy(value: unknown): value is AutomaticNetworkPolicy {
	return typeof value === 'string' && (AUTOMATIC_NETWORK_POLICIES as readonly string[]).includes(value);
}

function parseDeadlineUtc(value: unknown): number | null {
	if (typeof value !== 'string' || value.trim() === '') return null;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function fallbackWorkClass(value: unknown): OptionalWorkClass {
	return isOptionalWorkClass(value) ? value : 'opportunistic';
}

function blocked(
	workClass: OptionalWorkClass,
	mode: RolloutMode,
	reason: PauseReason,
): EligibilityDecision {
	return { kind: 'blocked', mode, workClass, reason } as EligibilityDecision;
}

function blockedOff(value: unknown, reason: 'capabilityUnavailable' | 'policyDenied' = 'capabilityUnavailable'): EligibilityDecision {
	return blocked(fallbackWorkClass(value), 'off', reason);
}

interface ValidatedInput {
	workClass: OptionalWorkClass;
	rolloutMode: RolloutMode;
	flagEnabled: boolean;
	requested: RequestedEligibilityPolicy;
	effective: EffectiveEligibilityPolicy;
	workOffline: boolean;
	capability: BridgeCapabilitySnapshot;
	criticalActivity: number;
	queueAgeMs: number;
	nowMonoMs: number;
	nowUtcMs: number;
	deadlineUtcMs: number;
}

function validateInput(value: unknown): ValidatedInput | null {
	if (!isRecord(value)) return null;
	if (!hasExactKeys(value, [
		'capability',
		'criticalActivity',
		'deadlineUtc',
		'effective',
		'flagEnabled',
		'nowMonoMs',
		'nowUtcMs',
		'queueAgeMs',
		'requested',
		'rolloutMode',
		'workClass',
		'workOffline',
	])) return null;

	const workClass = value.workClass;
	const rolloutMode = value.rolloutMode;
	const flagEnabled = value.flagEnabled;
	const requested = value.requested;
	const effective = value.effective;
	const workOffline = value.workOffline;
	const capability = normalizeBridgeCapabilitySnapshot(value.capability);
	const deadlineUtcMs = parseDeadlineUtc(value.deadlineUtc);

	if (
		!isOptionalWorkClass(workClass) ||
		!isRolloutMode(rolloutMode) ||
		typeof flagEnabled !== 'boolean' ||
		!isRecord(requested) ||
		!isRecord(effective) ||
		typeof workOffline !== 'boolean' ||
		!capability ||
		!isNonNegativeInteger(value.criticalActivity) ||
		!isNonNegativeFinite(value.queueAgeMs) ||
		!isNonNegativeFinite(value.nowMonoMs) ||
		!isNonNegativeFinite(value.nowUtcMs) ||
		deadlineUtcMs === null
	) return null;

	if (
		!hasExactKeys(requested, ['automaticNetwork', 'backgroundSyncEnabled']) ||
		typeof requested.backgroundSyncEnabled !== 'boolean' ||
		!isAutomaticNetworkPolicy(requested.automaticNetwork) ||
		!hasExactKeys(effective, ['automaticNetwork', 'backgroundAllowed', 'opportunisticRequiresCharging']) ||
		typeof effective.backgroundAllowed !== 'boolean' ||
		typeof effective.opportunisticRequiresCharging !== 'boolean' ||
		!isAutomaticNetworkPolicy(effective.automaticNetwork)
	) return null;

	const requestedPolicy: RequestedEligibilityPolicy = {
		backgroundSyncEnabled: requested.backgroundSyncEnabled,
		automaticNetwork: requested.automaticNetwork,
	};
	const effectivePolicy: EffectiveEligibilityPolicy = {
		backgroundAllowed: effective.backgroundAllowed,
		automaticNetwork: effective.automaticNetwork,
		opportunisticRequiresCharging: effective.opportunisticRequiresCharging,
	};

	// Do not let contradictory power fields widen admission. `full` may be
	// reported either while plugged in or after charging has completed.
	if (
		(capability.power === 'charging' && capability.charging !== true) ||
		(capability.power === 'battery' && capability.charging !== false)
	) return null;

	return {
		workClass,
		rolloutMode: narrowRolloutMode([rolloutMode]),
		flagEnabled,
		requested: requestedPolicy,
		effective: effectivePolicy,
		workOffline,
		capability,
		criticalActivity: value.criticalActivity,
		queueAgeMs: value.queueAgeMs,
		nowMonoMs: value.nowMonoMs,
		nowUtcMs: value.nowUtcMs,
		deadlineUtcMs,
	};
}

function narrowerNetwork(
	requested: AutomaticNetworkPolicy,
	effective: AutomaticNetworkPolicy,
): AutomaticNetworkPolicy {
	return NETWORK_RANK[requested] <= NETWORK_RANK[effective]
		? requested
		: effective;
}

function capabilityAllowsExecution(capability: BridgeCapabilitySnapshot): boolean {
	const executionAvailable = capability.executionMode === 'background'
		? capability.backgroundExecution
		: capability.foregroundExecution;
	if (!executionAvailable || !capability.cancel) return false;
	// A background-advertising shell must also prove that it can receive a
	// scheduled opportunity. Foreground/reconnect-only shells intentionally do
	// not need the schedule bit: the coordinator supplies those triggers.
	return capability.executionMode !== 'background' || capability.schedule;
}

/**
 * Resolve one optional-work admission without side effects.
 *
 * Every input is checked at runtime because this boundary consumes reducer and
 * native data. A malformed value returns mode `off`; it can never become an
 * `eligible` or `observed` decision. Observe is likewise only returned for a
 * valid job that would otherwise pass admission, and never carries a budget.
 */
export function resolveEligibility(value: unknown): EligibilityDecision {
	const input = validateInput(value);
	if (!input) return blockedOff(isRecord(value) ? value.workClass : undefined);

	if (!input.flagEnabled || input.rolloutMode === 'off') {
		return blocked(input.workClass, 'off', 'policyDenied');
	}

	if (!capabilityAllowsExecution(input.capability)) {
		return blocked(input.workClass, input.rolloutMode, 'capabilityUnavailable');
	}
	if (input.criticalActivity !== 0) {
		return blocked(input.workClass, input.rolloutMode, 'criticalActivity');
	}
	if (input.workOffline) {
		return blocked(input.workClass, input.rolloutMode, 'networkUnavailable');
	}

	const automaticWork = input.workClass !== 'interactive';
	if (automaticWork && (!input.requested.backgroundSyncEnabled || !input.effective.backgroundAllowed)) {
		return blocked(input.workClass, input.rolloutMode, 'policyDenied');
	}

	if (input.capability.networkCost === 'offline') {
		return blocked(input.workClass, input.rolloutMode, 'networkUnavailable');
	}
	if (automaticWork) {
		const networkPolicy = narrowerNetwork(
			input.requested.automaticNetwork,
			input.effective.automaticNetwork,
		);
		if (networkPolicy === 'never') {
			return blocked(input.workClass, input.rolloutMode, 'policyDenied');
		}
		if (networkPolicy === 'unmetered' && input.capability.networkCost === 'metered') {
			return blocked(input.workClass, input.rolloutMode, 'meteredNetwork');
		}
	} else if (input.effective.automaticNetwork === 'never') {
		// An explicit action may override an automatic user preference and a
		// metered ceiling, but never a hard server-side network prohibition.
		return blocked(input.workClass, input.rolloutMode, 'policyDenied');
	}

	if (input.capability.powerSaver) {
		return blocked(input.workClass, input.rolloutMode, 'lowPower');
	}
	if (
		input.workClass === 'opportunistic' &&
		input.effective.opportunisticRequiresCharging &&
		!input.capability.charging
	) {
		return blocked(input.workClass, input.rolloutMode, 'notCharging');
	}
	if (input.capability.thermal !== 'nominal') {
		return blocked(input.workClass, input.rolloutMode, 'thermal');
	}
	if (input.capability.storagePressure !== 'normal') {
		return blocked(input.workClass, input.rolloutMode, 'storagePressure');
	}

	if (input.nowUtcMs >= input.deadlineUtcMs || input.queueAgeMs >= MAX_QUEUE_AGE_MS) {
		return blocked(input.workClass, input.rolloutMode, 'deadlineExceeded');
	}

	if (input.rolloutMode === 'observe') {
		return {
			kind: 'observed',
			mode: 'observe',
			workClass: input.workClass,
			reason: 'observeOnly',
		};
	}

	return {
		kind: 'eligible',
		mode: 'execute',
		workClass: input.workClass,
		budget: {
			maxRecords: MAX_RECORDS_PER_STEP,
			maxBytes: YIELD_MAX_BYTES,
			deadlineMonoMs: input.nowMonoMs + YIELD_MAX_MS,
		},
	};
}
