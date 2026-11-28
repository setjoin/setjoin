/**
 * E5 UI runtime-state edge branches (coverage round r2).
 *
 * Real behavior tests against the `e5ui` singleton for the edges the main
 * suites leave cold: the inert-until-wired transfer action dispatch, settings
 * draft editing and the race-safe saver's three outcomes (no saver / failure
 * announcement / silent success), the single scheduler-path into the UI,
 * per-transfer row bookkeeping, and the save-all group helper surface
 * (duplicate creation, unknown groups, retry/cancel plans, dispose).
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

import { e5ui } from './e5ui.svelte';
import { makeInitialSyncCheckpoint, type JobResult } from './work-contract';
import type { ReadJobOutcome } from './coordinator';

function pausedResult(reason: string = 'meteredNetwork'): JobResult {
	return {
		state: 'paused',
		reason,
		checkpoint: makeInitialSyncCheckpoint(),
		progress: { done: 2, chargedUnits: 1 },
	} as JobResult;
}

function snapshotFor(requested: {
	backgroundSyncEnabled: boolean;
	automaticNetwork: 'never' | 'unmetered' | 'any';
	attachmentPrefetch: 'never' | 'unmetered' | 'always';
}) {
	return {
		requested,
		effective: {
			backgroundAllowed: true,
			automaticNetwork: requested.automaticNetwork,
			attachmentPrefetch: requested.attachmentPrefetch,
			opportunisticRequiresCharging: false,
		},
		sources: {},
	};
}

beforeEach(() => {
	e5ui.__resetForTests();
});

describe('E5 transfer action dispatch', () => {
	it('stays inert without a handler and forwards key + action once one is wired', () => {
		// No handler wired: calling is a no-op, never a throw.
		expect(() => e5ui.transferAction('row-1', 'resume')).not.toThrow();
		const handler = vi.fn();
		e5ui.transferActionHandler = handler;
		e5ui.transferAction('row-1', 'cancel');
		expect(handler).toHaveBeenCalledWith('row-1', 'cancel');
		expect(handler).toHaveBeenCalledTimes(1);
	});

	it('setDurableTransferAvailable records the shell-proven capability truth', () => {
		expect(e5ui.durableTransferAvailable).toBe(false);
		e5ui.setDurableTransferAvailable(true);
		expect(e5ui.durableTransferAvailable).toBe(true);
		e5ui.setDurableTransferAvailable(false);
		expect(e5ui.durableTransferAvailable).toBe(false);
	});
});

describe('E5 settings edits and the race-safe saver', () => {
	it('editSettings mutates the draft and bumps the settings revision', () => {
		const before = e5ui.settingsRevision;
		const draftBefore = e5ui.settings.view().draft;
		e5ui.editSettings({ automaticNetwork: 'any' });
		expect(e5ui.settingsRevision).toBe(before + 1);
		expect(e5ui.settings.view().draft.automaticNetwork).toBe('any');
		expect(e5ui.settings.view().dirty).toBe(true);
		expect(draftBefore.automaticNetwork).toBe('unmetered');
	});

	it('submitSettings without a wired saver refuses honestly and stays silent', async () => {
		expect(e5ui.announcement).toBeNull();
		expect(await e5ui.submitSettings()).toBe(false);
		// No invented outcome announcement for a missing endpoint.
		expect(e5ui.announcement).toBeNull();
	});

	it('a FAILED save announces the remedy on this channel and preserves drafts', async () => {
		e5ui.bindSettingsAccount('acct-1', 'dev-1');
		e5ui.editSettings({ attachmentPrefetch: 'always' });
		const saver = vi.fn().mockRejectedValue(new Error('network down'));
		e5ui.settingsSaver = saver;
		expect(await e5ui.submitSettings()).toBe(false);
		// The failure keeps the channel (page-local alert remedies stay local).
		expect(e5ui.announcement?.key).toBe('offline.e5.settings.announce_failed');
		// The draft survived the failure for retry.
		expect(e5ui.settings.view().draft.attachmentPrefetch).toBe('always');
		expect(e5ui.settings.view().status.kind).toBe('failed');
	});

	it('a SUCCESSFUL save is silent here (the owning surface owns the announcement)', async () => {
		e5ui.bindSettingsAccount('acct-1', 'dev-1');
		const requested = {
			backgroundSyncEnabled: true,
			automaticNetwork: 'unmetered' as const,
			attachmentPrefetch: 'unmetered' as const,
		};
		const saver = vi.fn().mockResolvedValue(snapshotFor(requested));
		e5ui.settingsSaver = saver;
		e5ui.editSettings({ automaticNetwork: 'any' });
		expect(await e5ui.submitSettings()).toBe(true);
		// Single-announcer contract: no global re-announcement of a success.
		expect(e5ui.announcement).toBeNull();
		// The authoritative response became the acknowledged state.
		expect(e5ui.settings.view().acknowledged?.requested.automaticNetwork).toBe('unmetered');
		expect(e5ui.settings.view().dirty).toBe(false);
	});

	it('a duplicate submission while a save is in flight is refused without announcing', async () => {
		e5ui.bindSettingsAccount('acct-1', 'dev-1');
		let release: (() => void) | null = null;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		e5ui.settingsSaver = () => gate.then(() => snapshotFor({
			backgroundSyncEnabled: false,
			automaticNetwork: 'unmetered',
			attachmentPrefetch: 'never',
		}));
		const first = e5ui.submitSettings();
		const second = await e5ui.submitSettings();
		expect(second).toBe(false);
		release!();
		expect(await first).toBe(true);
		expect(e5ui.announcement).toBeNull();
	});
});

describe('E5 scheduler axis (the only path scheduler activity takes)', () => {
	it('applyJobOutcome maps a committed paused result through the shared mapping', () => {
		const state = e5ui.applyJobOutcome({ kind: 'committed', result: pausedResult() });
		expect(state).toEqual({ kind: 'paused', reason: 'meteredNetwork' });
		expect(e5ui.scheduler).toEqual({ kind: 'paused', reason: 'meteredNetwork' });
	});

	it('applyJobOutcome maps an unknown read to idle — never an invented completion', () => {
		const state = e5ui.applyJobOutcome({ kind: 'unknown' });
		expect(state).toEqual({ kind: 'idle' });
		expect(e5ui.scheduler).toEqual({ kind: 'idle' });
	});

	it('refreshFromCoordinator reads through the coordinator seam and projects the outcome', async () => {
		const outcome: ReadJobOutcome = { kind: 'committed', result: pausedResult('batteryThermal') } as ReadJobOutcome;
		const readJobResult = vi.fn().mockResolvedValue(outcome);
		const state = await e5ui.refreshFromCoordinator(readJobResult, 'opt-reconnect-acct-1');
		expect(readJobResult).toHaveBeenCalledWith('opt-reconnect-acct-1');
		expect(state).toEqual({ kind: 'paused', reason: 'batteryThermal' });
		expect(e5ui.scheduler).toEqual({ kind: 'paused', reason: 'batteryThermal' });
	});

	it('setStatusAxes keeps its axes independent and accepts an optional scheduler state', () => {
		e5ui.setStatusAxes({
			freshness: 'stale',
			cached: true,
			blockingIssue: 'recoverable',
			blockingReason: 'storagePressure',
			networkCost: 'metered',
		});
		expect(e5ui.freshness).toBe('stale');
		expect(e5ui.cached).toBe(true);
		expect(e5ui.blockingIssue).toBe('recoverable');
		expect(e5ui.blockingReason).toBe('storagePressure');
		expect(e5ui.networkCost).toBe('metered');
		expect(e5ui.scheduler).toEqual({ kind: 'idle' });
		// The projection carries the blocking reason it was given.
		const projection = e5ui.projection('workOffline', 'observe');
		expect(projection.blockingIssue).toBe('recoverable');
		// A later axes update with a scheduler state lands ONLY through here.
		e5ui.setStatusAxes({
			freshness: 'stale',
			cached: true,
			blockingIssue: 'none',
			networkCost: 'unmetered',
			scheduler: { kind: 'paused', reason: 'meteredNetwork' },
		});
		expect(e5ui.scheduler).toEqual({ kind: 'paused', reason: 'meteredNetwork' });
	});
});

describe('E5 per-transfer row bookkeeping', () => {
	it('set, count, read and clear rows independently by opaque key', () => {
		expect(e5ui.transferRowCount).toBe(0);
		e5ui.setTransferRow('a', { state: 'transferring', committedBytes: 10, totalBytes: 100 });
		e5ui.setTransferRow('b', { state: 'queued' });
		expect(e5ui.transferRowCount).toBe(2);
		expect(e5ui.transferRow('a')).toMatchObject({ state: 'transferring', committedBytes: 10 });
		// Rows are snapshots: mutating the input object afterwards does not leak.
		const input = { state: 'transferring' as const, committedBytes: 1, totalBytes: 9 };
		e5ui.setTransferRow('c', input);
		input.committedBytes = 999;
		expect(e5ui.transferRow('c')?.committedBytes).toBe(1);
		e5ui.clearTransferRow('b');
		expect(e5ui.transferRowCount).toBe(2);
		expect(e5ui.transferRow('b')).toBeNull();
		// Clearing an unknown key is a no-op.
		e5ui.clearTransferRow('nope');
		expect(e5ui.transferRowCount).toBe(2);
		expect(e5ui.transferRow('nope')).toBeNull();
	});
});

describe('E5 save-all group helpers', () => {
	it('refuses a duplicate group id', () => {
		e5ui.createSaveAllGroup('m1', ['c1']);
		expect(() => e5ui.createSaveAllGroup('m1', ['c2'])).toThrow(/already exists/);
	});

	it('applySaveAllChild returns null for an unknown group and ticks for a known one', () => {
		expect(e5ui.applySaveAllChild('missing', 'c1', { state: 'transferring' })).toBeNull();
		e5ui.createSaveAllGroup('m1', ['c1', 'c2']);
		const tick = e5ui.applySaveAllChild('m1', 'c1', { state: 'transferring', committedBytes: 50, totalBytes: 100 });
		expect(tick?.view.summary.total).toBe(2);
		expect(e5ui.saveAllGroup('m1')?.children.find((child) => child.id === 'c1')?.state).toBe('transferring');
	});

	it('retrySaveAll selects retry-eligible children and answers [] for an unknown group', () => {
		expect(e5ui.retrySaveAll('missing')).toEqual([]);
		e5ui.createSaveAllGroup('m1', ['c1', 'c2', 'c3']);
		e5ui.applySaveAllChild('m1', 'c1', { state: 'recoverableError' });
		e5ui.applySaveAllChild('m1', 'c2', { state: 'downloadExpired' });
		// Retry eligibility: recoverable errors and expired downloads — never a
		// completed child or a hard terminal one.
		expect(e5ui.retrySaveAll('m1')).toEqual(['c1', 'c2']);
	});

	it('cancelSaveAll plans per-child cancellation and answers null for an unknown group', () => {
		expect(e5ui.cancelSaveAll('missing')).toBeNull();
		e5ui.createSaveAllGroup('m1', ['c1', 'c2']);
		e5ui.applySaveAllChild('m1', 'c1', { state: 'complete' });
		const plan = e5ui.cancelSaveAll('m1');
		expect(plan?.toCancel).toEqual(['c2']);
		expect(plan?.preserved).toEqual(['c1']);
	});

	it('announceSaveAllGroup replaces the burst with one summary and ignores unknown groups', () => {
		// Unknown group: silent, no invented announcement.
		e5ui.announceSaveAllGroup('missing');
		expect(e5ui.announcement).toBeNull();
		e5ui.createSaveAllGroup('m1', ['c1', 'c2', 'c3']);
		e5ui.applySaveAllChild('m1', 'c1', { state: 'complete' });
		e5ui.applySaveAllChild('m1', 'c2', { state: 'recoverableError' });
		e5ui.applySaveAllChild('m1', 'c3', { state: 'cancelled' });
		e5ui.announceSaveAllGroup('m1');
		expect(e5ui.announcement?.key).toBe('offline.e5.saveall.announce');
		expect(e5ui.announcement?.params).toMatchObject({
			completed: '1',
			total: '3',
			failed: '1',
			cancelled: '1',
		});
	});

	it('disposeSaveAllGroup drops the group; later helpers answer their empty cases', () => {
		e5ui.createSaveAllGroup('m1', ['c1']);
		e5ui.disposeSaveAllGroup('m1');
		expect(e5ui.saveAllGroup('m1')).toBeNull();
		expect(e5ui.retrySaveAll('m1')).toEqual([]);
		expect(e5ui.cancelSaveAll('m1')).toBeNull();
	});
});
