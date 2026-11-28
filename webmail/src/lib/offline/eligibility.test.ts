import { describe, expect, it } from 'vitest';

import {
	AUTOMATIC_NETWORK_POLICIES,
	type EligibilityInput,
} from './eligibility';
import {
	BRIDGE_CAPABILITY_CONTRACT_VERSION,
	MAX_QUEUE_AGE_MS,
	MAX_RECORDS_PER_STEP,
	YIELD_MAX_BYTES,
	YIELD_MAX_MS,
	type BridgeCapabilitySnapshot,
	type EligibilityDecision,
} from './work-contract';
import { resolveEligibility } from './eligibility';

const NOW_UTC = Date.parse('2026-08-11T00:00:00Z');
const DEADLINE_NOW = '2026-08-11T00:00:00.000Z';

const capability: BridgeCapabilitySnapshot = {
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

const baseInput = (overrides: Partial<EligibilityInput> = {}): EligibilityInput => ({
	workClass: 'background',
	rolloutMode: 'execute',
	flagEnabled: true,
	requested: {
		backgroundSyncEnabled: true,
		automaticNetwork: 'any',
	},
	effective: {
		backgroundAllowed: true,
		automaticNetwork: 'any',
		opportunisticRequiresCharging: true,
	},
	capability,
	criticalActivity: 0,
	queueAgeMs: 0,
	nowMonoMs: 1_000,
	nowUtcMs: NOW_UTC,
	deadlineUtc: '2026-08-12T00:00:00Z',
	workOffline: false,
	...overrides,
});

function decision(overrides: Partial<EligibilityInput> = {}): EligibilityDecision {
	return resolveEligibility(baseInput(overrides));
}

function expectBlocked(result: EligibilityDecision, reason?: string): void {
	expect(result.kind).toBe('blocked');
	if (reason && result.kind === 'blocked') expect(result.reason).toBe(reason);
}

describe('optional-work eligibility', () => {
	it('admits a valid execute request with the frozen step budget', () => {
		expect(decision()).toEqual({
			kind: 'eligible',
			mode: 'execute',
			workClass: 'background',
			budget: {
				maxRecords: MAX_RECORDS_PER_STEP,
				maxBytes: YIELD_MAX_BYTES,
				deadlineMonoMs: 1_000 + YIELD_MAX_MS,
			},
		});
	});

	it('intersects requested and effective policy instead of widening it', () => {
		expectBlocked(decision({
			requested: { backgroundSyncEnabled: true, automaticNetwork: 'any' },
			effective: { backgroundAllowed: true, automaticNetwork: 'unmetered', opportunisticRequiresCharging: true },
			capability: { ...capability, networkCost: 'metered' },
		}), 'meteredNetwork');
		expect(decision({
			requested: { backgroundSyncEnabled: true, automaticNetwork: 'unmetered' },
			effective: { backgroundAllowed: true, automaticNetwork: 'any', opportunisticRequiresCharging: true },
			capability: { ...capability, networkCost: 'unmetered' },
		})).toMatchObject({ kind: 'eligible' });
	});

	it('keeps the exact zero-age and just-before-expiry boundaries eligible', () => {
		expect(decision({ queueAgeMs: 0 })).toMatchObject({ kind: 'eligible' });
		expect(decision({ queueAgeMs: MAX_QUEUE_AGE_MS - 1 })).toMatchObject({ kind: 'eligible' });
		expect(decision({ nowUtcMs: NOW_UTC - 1, deadlineUtc: DEADLINE_NOW })).toMatchObject({ kind: 'eligible' });
	});

	it('rejects the seven-day queue-age and deadline boundaries', () => {
		expectBlocked(decision({ queueAgeMs: MAX_QUEUE_AGE_MS }), 'deadlineExceeded');
		expectBlocked(decision({ nowUtcMs: NOW_UTC, deadlineUtc: DEADLINE_NOW }), 'deadlineExceeded');
		expectBlocked(decision({ queueAgeMs: MAX_QUEUE_AGE_MS + 1 }), 'deadlineExceeded');
	});

	it('observe classifies a would-be admission without returning a budget', () => {
		expect(decision({ rolloutMode: 'observe' })).toEqual({
			kind: 'observed',
			mode: 'observe',
			workClass: 'background',
			reason: 'observeOnly',
		});
	});

	it('flag-off and rollout-off are blocked with mode off', () => {
		expect(decision({ flagEnabled: false })).toMatchObject({ kind: 'blocked', mode: 'off', reason: 'policyDenied' });
		expect(decision({ rolloutMode: 'off' })).toMatchObject({ kind: 'blocked', mode: 'off', reason: 'policyDenied' });
	});

	it('blocks Work Offline and active Critical activity before optional work', () => {
		expectBlocked(decision({ workOffline: true }), 'networkUnavailable');
		expectBlocked(decision({ criticalActivity: 1 }), 'criticalActivity');
	});

	it('handles network cost and the never/unmetered/any policy boundaries', () => {
		expect(AUTOMATIC_NETWORK_POLICIES).toEqual(['never', 'unmetered', 'any']);
		expectBlocked(decision({ capability: { ...capability, networkCost: 'offline' } }), 'networkUnavailable');
		expectBlocked(decision({ capability: { ...capability, networkCost: 'metered' }, effective: { ...baseInput().effective, automaticNetwork: 'unmetered' } }), 'meteredNetwork');
		expect(decision({ capability: { ...capability, networkCost: 'metered' }, requested: { ...baseInput().requested, automaticNetwork: 'any' }, effective: { ...baseInput().effective, automaticNetwork: 'any' } })).toMatchObject({ kind: 'eligible' });
		expectBlocked(decision({ effective: { ...baseInput().effective, automaticNetwork: 'never' } }), 'policyDenied');
	});

	it('allows explicit interactive work when background sync is disabled', () => {
		expect(decision({
			workClass: 'interactive',
			requested: { ...baseInput().requested, backgroundSyncEnabled: false, automaticNetwork: 'never' },
			effective: { ...baseInput().effective, backgroundAllowed: false, automaticNetwork: 'unmetered' },
			capability: { ...capability, networkCost: 'metered' },
		})).toMatchObject({ kind: 'eligible' });
		expectBlocked(decision({
			workClass: 'interactive',
			effective: { ...baseInput().effective, automaticNetwork: 'never' },
		}), 'policyDenied');
	});

	it('blocks power-saver and uncharged opportunistic work', () => {
		expectBlocked(decision({ capability: { ...capability, powerSaver: true } }), 'lowPower');
		expectBlocked(decision({
		workClass: 'opportunistic',
		capability: { ...capability, power: 'battery', charging: false },
		}), 'notCharging');
		expect(decision({
		workClass: 'opportunistic',
		capability: { ...capability, power: 'battery', charging: false },
		effective: { ...baseInput().effective, opportunisticRequiresCharging: false },
	})).toMatchObject({ kind: 'eligible' });
	});

	it('blocks every non-nominal thermal and storage-pressure state', () => {
		expectBlocked(decision({ capability: { ...capability, thermal: 'fair' } }), 'thermal');
		expectBlocked(decision({ capability: { ...capability, thermal: 'serious' } }), 'thermal');
		expectBlocked(decision({ capability: { ...capability, storagePressure: 'elevated' } }), 'storagePressure');
		expectBlocked(decision({ capability: { ...capability, storagePressure: 'critical' } }), 'storagePressure');
	});

	it('requires a proven execution and cancellation capability', () => {
		expectBlocked(decision({ capability: { ...capability, foregroundExecution: false } }), 'capabilityUnavailable');
		expectBlocked(decision({ capability: { ...capability, cancel: false } }), 'capabilityUnavailable');
		expect(decision({
		capability: {
			...capability,
			executionMode: 'background',
			foregroundExecution: false,
			backgroundExecution: true,
			schedule: true,
		},
	})).toMatchObject({ kind: 'eligible' });
	});

	it('fails closed for unknown work, rollout, policy, capability, and time input', () => {
		for (const invalid of [
			{ workClass: 'critical' },
			{ rolloutMode: 'pilot' },
			{ requested: { ...baseInput().requested, automaticNetwork: 'wifi' } },
			{ effective: { ...baseInput().effective, automaticNetwork: 'wifi' } },
			{ capability: { ...capability, networkCost: 'wifi' } },
			{ capability: { ...capability, contractVersion: 2 } },
			{ deadlineUtc: 'not-a-date' },
			{ deadlineUtc: 123 },
			{ futureEligibilityField: true },
			{ queueAgeMs: -1 },
			{ criticalActivity: Number.NaN },
		]) {
			const result = resolveEligibility(baseInput(invalid as Partial<EligibilityInput>));
			expect(result.kind).toBe('blocked');
			expect(result.mode).toBe('off');
		}
	});

	it('rejects contradictory native power input rather than widening it', () => {
		const result = resolveEligibility(baseInput({ capability: { ...capability, power: 'charging', charging: false } }));
		expect(result).toMatchObject({ kind: 'blocked', mode: 'off' });
	});
});
