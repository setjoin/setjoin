import { describe, expect, it } from 'vitest';

import {
	PRIVACY_EXCLUDED_STATUS_FIELDS,
	parseStatusProjectionInput,
	projectStatus,
	type StatusProjectionInput,
} from './statusProjection';

const baseInput: StatusProjectionInput = {
	connectivity: { networkCost: 'unmetered' },
	freshness: 'current',
	cached: true,
	scheduler: { kind: 'idle' },
	blockingIssue: 'none',
	manualMode: 'online',
	automaticWork: {
		rolloutMode: 'execute',
		executionMode: 'foregroundReconnectOnly',
		backgroundExecution: false,
	},
};

function input(overrides: Partial<StatusProjectionInput> = {}): StatusProjectionInput {
	return { ...baseInput, ...overrides };
}

describe('status projection — required Phase 2 states', () => {
	it('keeps offline connectivity and cached freshness independent', () => {
		const projection = projectStatus(input({
			connectivity: { networkCost: 'offline' },
			freshness: 'stale',
			cached: true,
		}));

		expect(projection.connectivity).toEqual({ networkCost: 'offline', reachable: false });
		expect(projection.freshness).toEqual({ kind: 'stale', cached: true });
		expect(projection.scheduler).toEqual({ kind: 'idle' });
		expect(projection.display.primary).toBe('notCurrent');
		expect(projection.display.secondary).toEqual({ kind: 'offline' });
		expect('action' in projection.display).toBe(false);
	});

	it('does not turn a metered sync into a different freshness or one-state enum', () => {
		const projection = projectStatus(input({
			connectivity: { networkCost: 'metered' },
			freshness: 'stale',
			scheduler: { kind: 'running', progress: { done: 12, total: 40 } },
		}));

		expect(projection.connectivity.networkCost).toBe('metered');
		expect(projection.freshness.kind).toBe('stale');
		expect(projection.scheduler).toEqual({ kind: 'running', progress: { done: 12, total: 40 } });
		expect(projection.display.primary).toBe('notCurrent');
		expect(projection.display.secondary).toEqual({
			kind: 'running',
			progress: { done: 12, total: 40 },
		});
		expect('action' in projection.display).toBe(false);
	});

	it('keeps stale freshness primary while a policy pause supplies the action', () => {
		const projection = projectStatus(input({
			freshness: 'stale',
			scheduler: { kind: 'paused', reason: 'policyDenied' },
		}));

		expect(projection.display.primary).toBe('notCurrent');
		expect(projection.display.secondary).toEqual({ kind: 'paused', reason: 'policyDenied' });
		expect(projection.display.action).toEqual({ kind: 'viewSettings' });
	});

	it('gives authentication a blocking primary and a stable sign-in hint', () => {
		const projection = projectStatus(input({
			blockingIssue: 'actionRequired',
			blockingReason: 'authRequired',
		}));

		expect(projection.display.primary).toBe('actionRequired');
		expect(projection.display.action).toEqual({ kind: 'signIn' });
	});

	it('gives storage pressure a blocking primary and a stable storage hint', () => {
		const projection = projectStatus(input({
			blockingIssue: 'actionRequired',
			blockingReason: 'storagePressure',
			scheduler: { kind: 'paused', reason: 'storagePressure' },
		}));

		expect(projection.display.primary).toBe('actionRequired');
		expect(projection.display.secondary).toEqual({ kind: 'paused', reason: 'storagePressure' });
		expect(projection.display.action).toEqual({ kind: 'freeStorage' });
	});

	it('represents observe-only policy without claiming automatic execution or asking for action', () => {
		const projection = projectStatus(input({
			automaticWork: {
				rolloutMode: 'observe',
				executionMode: 'foregroundReconnectOnly',
				backgroundExecution: false,
			},
		}));

		expect(projection.automaticWork).toEqual({
			rolloutMode: 'observe',
			executionMode: 'foregroundReconnectOnly',
			backgroundExecution: false,
			backgroundSupport: 'unsupported',
			status: 'observeOnly',
		});
		expect('action' in projection.display).toBe(false);
	});

	it('reports foregroundReconnectOnly as truthful unsupported background capability', () => {
		const projection = projectStatus(input());

		expect(projection.automaticWork.executionMode).toBe('foregroundReconnectOnly');
		expect(projection.automaticWork.backgroundExecution).toBe(false);
		expect(projection.automaticWork.backgroundSupport).toBe('unsupported');
		expect(projection.automaticWork.status).toBe('foregroundReconnectOnly');
	});
});

describe('status projection — exhaustive axis tables and pairwise actions', () => {
	it.each([
		['none', 'current'] as const,
		['recoverable', 'current'] as const,
		['actionRequired', 'actionRequired'] as const,
		['locked', 'locked'] as const,
	])('blocking issue %s has primary %s without overwriting freshness axes', (blockingIssue, primary) => {
		const projection = projectStatus(input({
			freshness: 'current',
			blockingIssue,
			...(blockingIssue === 'actionRequired' ? { blockingReason: 'authRequired' as const } : {}),
		}));

		expect(projection.display.primary).toBe(primary);
		expect(projection.freshness.kind).toBe('current');
	});

	it.each([
		['neverSynced', 'neverSynced'] as const,
		['current', 'current'] as const,
		['stale', 'notCurrent'] as const,
		['unknown', 'unknown'] as const,
	])('freshness %s maps to primary %s when unblocked', (freshness, primary) => {
		const projection = projectStatus(input({
			freshness,
			cached: freshness !== 'neverSynced',
		}));
		expect(projection.display.primary).toBe(primary);
		expect(projection.freshness.kind).toBe(freshness);
	});

	it.each([
		['offline', 'online', undefined] as const,
		['offline', 'workOffline', 'goOnline'] as const,
		['unmetered', 'online', 'retry'] as const,
		['unmetered', 'workOffline', 'goOnline'] as const,
		['metered', 'online', 'retry'] as const,
		['metered', 'workOffline', 'goOnline'] as const,
	])('stale × %s × %s yields only the action %s when actionable', (networkCost, manualMode, action) => {
		const projection = projectStatus(input({
			connectivity: { networkCost },
			freshness: 'stale',
			manualMode,
		}));

		if (action === undefined) expect('action' in projection.display).toBe(false);
		else expect(projection.display.action).toEqual({ kind: action });
	});

	it.each([
		['idle', { kind: 'idle' }, undefined] as const,
		['running', { kind: 'running', progress: { done: 2, total: 5 } }, 'running'] as const,
		['paused', { kind: 'paused', reason: 'meteredNetwork' }, 'paused'] as const,
		['backoff', { kind: 'backoff', retryAt: 42, reason: 'networkUnavailable' }, 'backoff'] as const,
	])('scheduler %s remains an independent secondary axis', (name, scheduler, secondaryKind) => {
		const projection = projectStatus(input({ scheduler }));
		expect(projection.scheduler).toEqual(scheduler);
		if (secondaryKind === undefined) expect('secondary' in projection.display).toBe(false);
		else expect(projection.display.secondary?.kind).toBe(secondaryKind);
		// Scheduler state must not change a current mailbox into a false stale state.
		expect(projection.freshness).toEqual({ kind: 'current', cached: true });
	});

	it.each([
		['off', 'foregroundReconnectOnly', false, 'disabled', 'unsupported'] as const,
		['off', 'background', true, 'disabled', 'available'] as const,
		['observe', 'foregroundReconnectOnly', false, 'observeOnly', 'unsupported'] as const,
		['observe', 'background', true, 'observeOnly', 'available'] as const,
		['execute', 'foregroundReconnectOnly', false, 'foregroundReconnectOnly', 'unsupported'] as const,
		['execute', 'background', true, 'background', 'available'] as const,
	])('policy %s × execution %s stays explicit', (rolloutMode, executionMode, backgroundExecution, status, support) => {
		const parsed = parseStatusProjectionInput({
			...input(),
			automaticWork: { rolloutMode, executionMode, backgroundExecution },
		});
		expect(parsed).not.toBeNull();
		const projection = projectStatus(parsed as StatusProjectionInput);
		expect(projection.automaticWork.status).toBe(status);
		expect(projection.automaticWork.backgroundSupport).toBe(support);
		expect(projection.automaticWork.rolloutMode).toBe(rolloutMode);
		expect(projection.automaticWork.executionMode).toBe(executionMode);
	});
});

describe('status projection — exact runtime boundary and privacy', () => {
	it('accepts the exact normalized input and returns a fresh, content-free shape', () => {
		const raw = {
			...baseInput,
			scheduler: { kind: 'running', progress: { done: 1, total: 3 } },
		};
		const parsed = parseStatusProjectionInput(raw);

		expect(parsed).toEqual(raw);
		expect(parsed).not.toBe(raw);
		expect(parsed?.scheduler).not.toBe(raw.scheduler);
		const projection = projectStatus(parsed as StatusProjectionInput);
		const serialized = JSON.stringify(projection);
		for (const field of PRIVACY_EXCLUDED_STATUS_FIELDS) expect(serialized).not.toContain(field);
	});

	it.each(PRIVACY_EXCLUDED_STATUS_FIELDS)('rejects privacy field %s at the top boundary', (field) => {
		const raw = { ...baseInput, [field]: 'redacted' };
		expect(parseStatusProjectionInput(raw)).toBeNull();
	});

	it('rejects privacy and unknown fields at nested boundaries instead of silently ignoring them', () => {
		expect(parseStatusProjectionInput({
			...baseInput,
			connectivity: { networkCost: 'unmetered', ipAddress: 'redacted' },
		})).toBeNull();
		expect(parseStatusProjectionInput({
			...baseInput,
			automaticWork: { ...baseInput.automaticWork, accountId: 'redacted' },
		})).toBeNull();
		expect(parseStatusProjectionInput({
			...baseInput,
			scheduler: { kind: 'running', progress: { done: 1, total: 2, subject: 'redacted' } },
		})).toBeNull();
	});

	it('fails closed for contradictory freshness, enum, execution, and progress values', () => {
		expect(parseStatusProjectionInput({ ...baseInput, freshness: 'neverSynced', cached: true })).toBeNull();
		expect(parseStatusProjectionInput({ ...baseInput, connectivity: { networkCost: 'wifi' } })).toBeNull();
		expect(parseStatusProjectionInput({
			...baseInput,
			automaticWork: { ...baseInput.automaticWork, executionMode: 'background', backgroundExecution: false },
		})).toBeNull();
		expect(parseStatusProjectionInput({
			...baseInput,
			scheduler: { kind: 'running', progress: { done: 4, total: 3 } },
		})).toBeNull();
	});

	it('accepts a locked action without disclosing content or inventing a retry', () => {
		const projection = projectStatus(input({
			blockingIssue: 'locked',
			freshness: 'stale',
			connectivity: { networkCost: 'offline' },
		}));

		expect(projection.display.primary).toBe('locked');
		expect(projection.display.action).toEqual({ kind: 'unlock' });
		expect(projection.display.secondary).toEqual({ kind: 'offline' });
	});
});

describe('status projection — action hints are sparse and stable', () => {
	it('does not emit an action for current, observe-only, or unsupported background states', () => {
		for (const automaticWork of [
			{ rolloutMode: 'observe', executionMode: 'foregroundReconnectOnly', backgroundExecution: false },
			{ rolloutMode: 'execute', executionMode: 'foregroundReconnectOnly', backgroundExecution: false },
		] as const) {
			const projection = projectStatus(input({ automaticWork }));
			expect('action' in projection.display).toBe(false);
		}
	});

	it('uses one stable action hint for each actual blocking requirement', () => {
		const cases = [
			['authRequired', 'signIn'],
			['storagePressure', 'freeStorage'],
		] as const;
		for (const [blockingReason, kind] of cases) {
			const projection = projectStatus(input({ blockingIssue: 'actionRequired', blockingReason }));
			expect(projection.display.action).toEqual({ kind });
		}
	});

	it('keeps the source input unchanged', () => {
		const source = input({ scheduler: { kind: 'running', progress: { done: 1, total: 4 } } });
		const before = JSON.stringify(source);
		projectStatus(source);
		expect(JSON.stringify(source)).toBe(before);
	});
});
