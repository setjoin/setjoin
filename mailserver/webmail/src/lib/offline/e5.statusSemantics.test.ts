/**
 * CAS-E5-NEVER-UNKNOWN — E5 verification binding (core lane, UI level).
 *
 * R4 "E5 complete states": `neverSynced` means "Not synced on this device";
 * `unknown` means "Sync status unavailable" — never an empty server mailbox
 * and never currentness. The scheduler axis ALWAYS arrives through the E4-I
 * shared mapping (`schedulerStateFromJobResult` over `readJobResult`), so an
 * unknown read is idle and no surface can invent a completion.
 *
 * The bindings run at TWO levels: the pure projection seam below, and —
 * one level up — the RENDERED OfflineStatus component (bottom describe),
 * proving the honest labels survive the actual UI render path.
 */

import { describe, it, expect, afterAll, afterEach, beforeEach, vi } from 'vitest';
import { getCurrentTest } from 'vitest/suite';
import { render } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';

// Render-path mocks (same set as e5.defaultInert.test.ts / OfflineStatus.test.ts):
// the offline singleton needs a native-available gate, and OfflineStatus's
// import graph needs its side-effect modules stubbed.
vi.mock('$lib/offline/store', () => ({
	isOfflineAvailable: vi.fn().mockReturnValue(true),
	getStore: vi.fn().mockReturnValue(null),
	MAIL_APP_KEY: 'mail',
}));
vi.mock('$lib/offline/sync', () => ({ requestSync: vi.fn() }));
vi.mock('$lib/offline/reconcile', () => ({
	listSyncIssues: vi.fn().mockResolvedValue([]),
	resolveId: vi.fn(),
}));
vi.mock('$lib/offline/leader', () => ({ withSyncOwnership: vi.fn() }));
vi.mock('$lib/jmap/client', () => ({ emailQuery: vi.fn(), emailGet: vi.fn() }));
vi.mock('$lib/db/offline', () => ({ getPendingActions: vi.fn().mockResolvedValue([]) }));

import {
	auditE5NeverUnknown,
	e5Failure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
} from '$lib/native/testing/backgroundWorkHarness';
import {
	E5_FRESHNESS_NEVER_SYNCED_KEY,
	E5_FRESHNESS_UNKNOWN_KEY,
	e5SchedulerFromJobResult,
	e5StatusText,
	freshnessLabelKey,
} from './e5.uiProjection';
import { projectStatus } from './statusProjection';
import type { JobResult } from './work-contract';
import { makeInitialSyncCheckpoint } from './work-contract';
import OfflineStatus from '$lib/components/OfflineStatus.svelte';
import { offline } from '$lib/offline/state.svelte';
import { e5ui } from './e5ui.svelte';

const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

beforeEach(() => {
	offline.featureEnabled = false;
	offline.capsAllowed = false;
	offline.workOffline = false;
	offline.syncPhase = 'idle';
	offline.syncIssueCount = 0;
	offline.autoMergedCount = 0;
	offline.setLockState('unlocked');
	offline.liveMessage = '';
	offline.liveParams = undefined;
	e5ui.__resetForTests();
});

function activateE5(): void {
	e5ui.featureEnabled = true;
	e5ui.mode = 'execute';
}

function projectionFor(
	freshness: 'neverSynced' | 'unknown',
	scheduler: import('./work-contract').SchedulerState = { kind: 'idle' },
) {
	return projectStatus({
		connectivity: { networkCost: 'unmetered' },
		freshness,
		cached: freshness === 'neverSynced' ? false : true,
		scheduler,
		blockingIssue: 'none',
		manualMode: 'online',
		automaticWork: {
			rolloutMode: 'execute',
			executionMode: 'foregroundReconnectOnly',
			backgroundExecution: false,
		},
	});
}

describe('CAS-E5-NEVER-UNKNOWN', () => {
	it('positive oracle: unknown maps to idle through the shared seam and never reads as current', () => {
		// A job nobody committed anything for: the outcome is unknown.
		const mapped = e5SchedulerFromJobResult(null);
		expect(mapped).toEqual({ kind: 'idle' });

		const text = e5StatusText(projectionFor('unknown'));
		expect(text.primaryKey).toBe(E5_FRESHNESS_UNKNOWN_KEY);
		// Never currentness, never an invented completion or activity.
		expect(text.primaryKey).not.toBe('offline.e5.status.current');
		expect(text.secondary).toBeUndefined();
		expect(text.action).toBeUndefined();
		expect(text.alert).toBe(false);
	});

	it('neverSynced means "Not synced on this device" — a distinct honest key', () => {
		expect(freshnessLabelKey('neverSynced')).toBe(E5_FRESHNESS_NEVER_SYNCED_KEY);
		expect(freshnessLabelKey('unknown')).toBe(E5_FRESHNESS_UNKNOWN_KEY);
		const text = e5StatusText(projectionFor('neverSynced'));
		expect(text.primaryKey).toBe(E5_FRESHNESS_NEVER_SYNCED_KEY);
		expect(text.primaryKey).not.toBe(E5_FRESHNESS_UNKNOWN_KEY);
		// neverSynced + no cache is the honest empty state; it still may offer
		// a sync action, but the LABEL never promises an empty server mailbox.
		expect(text.primaryKey).not.toBe('offline.e5.status.current');
	});

	it('committed results drive the SAME mapping: complete is idle, paused keeps its reason', () => {
		const complete: JobResult = {
			state: 'complete',
			checkpoint: makeInitialSyncCheckpoint(),
			progress: { done: 5, total: 5, chargedUnits: 1 },
		};
		expect(e5SchedulerFromJobResult(complete)).toEqual({ kind: 'idle' });

		const paused: JobResult = {
			state: 'paused',
			reason: 'meteredNetwork',
			checkpoint: makeInitialSyncCheckpoint(),
			progress: { done: 2, total: 5, chargedUnits: 1 },
		};
		const pausedState = e5SchedulerFromJobResult(paused);
		expect(pausedState).toEqual({ kind: 'paused', reason: 'meteredNetwork' });
		// The display keeps the reason verbatim (its own key, no collapsing).
		const text = e5StatusText(projectionFor('unknown', pausedState));
		expect(text.secondary).toMatchObject({ kind: 'paused', key: 'offline.e5.pause.meteredNetwork', pauseReason: 'meteredNetwork' });
	});

	it('the E5 surface gate is inert by default and renders the E5 status only when active', async () => {
		// Component-level proof lives in e5.defaultInert.test.ts (OFF posture)
		// and OfflineStatus.test.ts (existing behavior). Here the GATE OBJECT is
		// pinned: shipped defaults are OFF/observe-inert.
		const { e5ui } = await import('./e5ui.svelte');
		expect(e5ui.featureEnabled).toBe(false);
		expect(e5ui.mode).toBe('off');
		expect(e5ui.active).toBe(false);
	});

	it('planted faults produce the pinned FAIL text with distinct finite causes', () => {
		const pinned = e5Failure('CAS-E5-NEVER-UNKNOWN', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E5-NEVER-UNKNOWN: E5 status invented a completion or mislabeled unknown freshness',
		);

		const invented = auditE5NeverUnknown({
			neverSyncedKey: E5_FRESHNESS_NEVER_SYNCED_KEY,
			unknownKey: E5_FRESHNESS_UNKNOWN_KEY,
			unknownProjectedIdle: false,
			committedPairsAgree: true,
		});
		expect(invented.ok).toBe(false);
		expect(invented.fail).toBe(pinned.fail);
		expect(invented.cause).toBe('subOracleId=unknown-not-idle lane=core');

		const disagreement = auditE5NeverUnknown({
			neverSyncedKey: E5_FRESHNESS_NEVER_SYNCED_KEY,
			unknownKey: E5_FRESHNESS_UNKNOWN_KEY,
			unknownProjectedIdle: true,
			committedPairsAgree: false,
		});
		expect(disagreement.ok).toBe(false);
		expect(disagreement.fail).toBe(pinned.fail);
		expect(disagreement.cause).toBe('subOracleId=committed-mapping-disagreement lane=core');
		expect(disagreement.cause).not.toBe(invented.cause);

		const collapsed = auditE5NeverUnknown({
			neverSyncedKey: E5_FRESHNESS_UNKNOWN_KEY,
			unknownKey: E5_FRESHNESS_UNKNOWN_KEY,
			unknownProjectedIdle: true,
			committedPairsAgree: true,
		});
		expect(collapsed.ok).toBe(false);
		expect(collapsed.cause).toBe('subOracleId=freshness-keys-collapsed lane=core');

		const positive = auditE5NeverUnknown({
			neverSyncedKey: E5_FRESHNESS_NEVER_SYNCED_KEY,
			unknownKey: E5_FRESHNESS_UNKNOWN_KEY,
			unknownProjectedIdle: true,
			committedPairsAgree: true,
		});
		expect(positive.ok).toBe(true);
	});

	// The receipt is written ONCE, after every required scenario, gated on the
	// accumulated positive oracle AND every scenario's actual verdict.
	afterAll(async () => {
		const positive = auditE5NeverUnknown({
			neverSyncedKey: E5_FRESHNESS_NEVER_SYNCED_KEY,
			unknownKey: E5_FRESHNESS_UNKNOWN_KEY,
			unknownProjectedIdle: e5SchedulerFromJobResult(null).kind === 'idle',
			committedPairsAgree: true,
		});
		const final = gateVerdictOnScenarios(positive, scenarioFailures);
		expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
		writeCaseResult(final);
	});
});

// ── Coverage one level up: the RENDERED component ───────────────────────────
// The pure bindings above prove the projection seam; these prove the honest
// labels survive the actual OfflineStatus render path (Coordinator axes →
// e5ui → rendered DOM), including the {ago} parameter supplied from
// lastCurrentAt.

describe('CAS-E5-NEVER-UNKNOWN — rendered OfflineStatus component', () => {
	it('unknown freshness renders "Sync status unavailable" — never currentness, activity, or an action', async () => {
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		e5ui.setStatusAxes({ freshness: 'unknown', cached: true, blockingIssue: 'none', networkCost: 'unmetered' });
		activateE5();
		const { getByTestId, queryByTestId } = render(OfflineStatus);
		await tick();
		const primary = getByTestId('e5-status-primary');
		expect(primary.textContent).toContain('Sync status unavailable');
		expect(primary.textContent).not.toMatch(/up to date/i);
		expect(primary.textContent).not.toMatch(/not synced/i);
		// No invented scheduler activity and no invented action for unknown.
		expect(queryByTestId('e5-status-secondary')).toBeNull();
		expect(queryByTestId('e5-status-action')).toBeNull();
	});

	it('neverSynced renders "Not synced on this device" — a distinct honest label', async () => {
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		e5ui.setStatusAxes({ freshness: 'neverSynced', cached: false, blockingIssue: 'none', networkCost: 'unmetered' });
		activateE5();
		const { getByTestId } = render(OfflineStatus);
		await tick();
		const primary = getByTestId('e5-status-primary');
		expect(primary.textContent).toContain('Not synced on this device');
		expect(primary.textContent).not.toMatch(/up to date/i);
		expect(primary.textContent).not.toContain('Sync status unavailable');
	});

	it('not-current status interpolates {ago} from the lastCurrentAt axis', async () => {
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		e5ui.setStatusAxes({ freshness: 'stale', cached: true, blockingIssue: 'none', networkCost: 'unmetered' });
		e5ui.lastCurrentAt = Date.now() - 90_000; // 90s ago → a "minutes" phrase
		activateE5();
		const { getByTestId } = render(OfflineStatus);
		await tick();
		const primary = getByTestId('e5-status-primary');
		expect(primary.textContent).toMatch(/not current/i);
		expect(primary.textContent).toMatch(/last synced/i);
		expect(primary.textContent).not.toContain('{ago}');
		expect(primary.textContent).toMatch(/minute/i);
	});

	it('a not-current status with no known last-current time stays honest (no invented time)', async () => {
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		e5ui.setStatusAxes({ freshness: 'stale', cached: true, blockingIssue: 'none', networkCost: 'unmetered' });
		expect(e5ui.lastCurrentAt).toBeNull();
		activateE5();
		const { getByTestId } = render(OfflineStatus);
		await tick();
		const primary = getByTestId('e5-status-primary');
		expect(primary.textContent).toMatch(/not current/i);
		expect(primary.textContent).toContain('at an unknown time');
		expect(primary.textContent).not.toContain('{ago}');
	});
});
