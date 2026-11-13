/**
 * E5 UI display-projection edge branches (coverage round r2).
 *
 * Table-driven projection coverage for the status-text and transfer-row
 * branches the scenario suites leave cold: the current/actionRequired/locked
 * primaries, the offline/metered/indeterminate-running/backoff secondaries,
 * the null freshness labels, and the queued/verifying/recoverableError/
 * cancelled transfer-row action sets.
 */

import { describe, it, expect } from 'vitest';

import {
	E5_FRESHNESS_NEVER_SYNCED_KEY,
	E5_FRESHNESS_UNKNOWN_KEY,
	e5StatusText,
	e5TransferDisplay,
	freshnessLabelKey,
	pauseReasonKey,
	E5_PAUSE_REASON_KEYS,
	type E5TransferRowInput,
} from './e5.uiProjection';
import { projectStatus, type StatusProjection, type StatusProjectionInput } from './statusProjection';
import { PAUSE_REASONS } from './work-contract';

function base(overrides: Partial<StatusProjectionInput> = {}): StatusProjectionInput {
	return {
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
		...overrides,
	};
}

const project = (overrides: Partial<StatusProjectionInput> = {}): StatusProjection =>
	projectStatus(base(overrides));

describe('status text primaries and secondaries', () => {
	it('a CURRENT mailbox reads as current — never as an action or alert', () => {
		const text = e5StatusText(project());
		expect(text.primaryKey).toBe('offline.e5.status.current');
		expect(text.alert).toBe(false);
		expect(text.secondary).toBeUndefined();
		expect(text.action).toBeUndefined();
	});

	it('an action-required projection announces with role=alert and the reason-matched action', () => {
		const text = e5StatusText(project({
			blockingIssue: 'actionRequired',
			blockingReason: 'authRequired',
		}));
		expect(text.primaryKey).toBe('offline.e5.status.action_required');
		expect(text.alert).toBe(true);
		expect(text.action).toEqual({ hint: 'signIn', key: 'offline.e5.action.sign_in' });
		// The offline secondary rides along when the link is down.
		const offlineText = e5StatusText(project({
			blockingIssue: 'actionRequired',
			blockingReason: 'authRequired',
			connectivity: { networkCost: 'offline' },
		}));
		expect(offlineText.secondary).toEqual({ kind: 'offline', key: 'offline.e5.secondary.offline' });
	});

	it('a locked projection resolves the unlock action', () => {
		const text = e5StatusText(project({ blockingIssue: 'locked' }));
		expect(text.primaryKey).toBe('offline.e5.status.locked');
		expect(text.action).toEqual({ hint: 'unlock', key: 'offline.e5.action.unlock' });
	});

	it('a metered idle link explains the metered wait as the secondary', () => {
		const text = e5StatusText(project({
			freshness: 'stale',
			connectivity: { networkCost: 'metered' },
		}));
		expect(text.secondary).toEqual({ kind: 'metered', key: 'offline.e5.secondary.metered' });
	});

	it('a running scheduler without progress reports the indeterminate secondary', () => {
		const text = e5StatusText(project({
			freshness: 'stale',
			scheduler: { kind: 'running' },
		}));
		expect(text.secondary).toEqual({
			kind: 'runningIndeterminate',
			key: 'offline.e5.secondary.running_indeterminate',
		});
		// A running dispatch never offers an action.
		expect(text.action).toBeUndefined();
	});

	it('a backoff scheduler keeps its pause reason and retry timestamp', () => {
		const text = e5StatusText(project({
			freshness: 'stale',
			scheduler: { kind: 'backoff', retryAt: 1234, reason: 'networkUnavailable' },
		}));
		expect(text.secondary).toEqual({
			kind: 'backoff',
			key: 'offline.e5.pause.networkUnavailable',
			pauseReason: 'networkUnavailable',
			retryAt: 1234,
		});
	});
});

describe('freshness labels and pause keys', () => {
	it('current and stale have no honest freshness label', () => {
		expect(freshnessLabelKey('current')).toBeNull();
		expect(freshnessLabelKey('stale')).toBeNull();
		expect(freshnessLabelKey('neverSynced')).toBe(E5_FRESHNESS_NEVER_SYNCED_KEY);
		expect(freshnessLabelKey('unknown')).toBe(E5_FRESHNESS_UNKNOWN_KEY);
	});

	it('every contract pause reason maps to its own verbatim key', () => {
		for (const reason of PAUSE_REASONS) {
			expect(pauseReasonKey(reason)).toBe(`offline.e5.pause.${reason}`);
		}
		expect(E5_PAUSE_REASON_KEYS).toEqual(PAUSE_REASONS.map((reason) => `offline.e5.pause.${reason}`));
	});
});

describe('transfer row display action sets', () => {
	const display = (input: E5TransferRowInput) => e5TransferDisplay(input);

	it('a queued row may only be cancelled', () => {
		const row = display({ state: 'queued' });
		expect(row.key).toBe('offline.e5.transfer.queued');
		expect(row.actions).toEqual({ resume: false, cancel: true, retry: false, open: false, save: false });
		expect(row.alert).toBe(false);
	});

	it('a verifying row may only be cancelled (no resume/retry mid-verification)', () => {
		const row = display({ state: 'verifying', committedBytes: 10, totalBytes: 10 });
		expect(row.key).toBe('offline.e5.transfer.verifying');
		expect(row.actions).toEqual({ resume: false, cancel: true, retry: false, open: false, save: false });
	});

	it('a recoverable error offers retry + cancel', () => {
		const row = display({ state: 'recoverableError' });
		expect(row.key).toBe('offline.e5.transfer.recoverable_error');
		expect(row.actions).toEqual({ resume: false, cancel: true, retry: true, open: false, save: false });
	});

	it('a cancelled row offers retry only', () => {
		const row = display({ state: 'cancelled' });
		expect(row.key).toBe('offline.e5.transfer.cancelled');
		expect(row.actions).toEqual({ resume: false, cancel: false, retry: true, open: false, save: false });
	});
});
