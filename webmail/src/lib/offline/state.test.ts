import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('offline state', () => {
	let offline: typeof import('./state.svelte').offline;
	beforeEach(async () => {
		vi.resetModules();
		(window as never as { setjoinNative: { db: object } }).setjoinNative = { db: {} };
		offline = (await import('./state.svelte')).offline;
		offline.featureEnabled = false;
		offline.capsAllowed = false;
		offline.workOffline = false;
	});

	it('controls are inert until feature AND caps allow AND native present', () => {
		expect(offline.controlsActive).toBe(false);
		offline.featureEnabled = true;
		expect(offline.controlsActive).toBe(false); // caps still absent (#2a owns it)
		offline.capsAllowed = true;
		expect(offline.controlsActive).toBe(true); // native db bridge present
	});

	it('effectiveOffline is true when Work-Offline is forced', () => {
		offline.workOffline = true;
		expect(offline.effectiveOffline).toBe(true);
	});

	it('needsUnlock is true only when offline + active + still locked', () => {
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		offline.workOffline = true; // effectiveOffline
		offline.setLockState('locked');
		expect(offline.needsUnlock).toBe(true);
		offline.setLockState('unlocked');
		expect(offline.needsUnlock).toBe(false);
	});

	it('sync phase + progress flow from provisioning (first-time) to idle', () => {
		offline.setSyncPhase('provisioning');
		offline.setSyncProgress(0, 120);
		expect(offline.syncPhase).toBe('provisioning');
		expect(offline.syncProgress).toEqual({ done: 0, total: 120 });
		offline.setSyncPhase('idle');
		expect(offline.syncError).toBeNull();
	});

	it('sync error is captured and surfaced', () => {
		offline.setSyncError('network down');
		expect(offline.syncPhase).toBe('error');
		expect(offline.syncError).toBe('network down');
	});

	it('announces async outcomes to AT (live-region key set)', () => {
		offline.setSyncPhase('syncing');
		offline.setSyncPhase('idle'); // settled after a sync
		expect(offline.liveMessage).toBe('offline.live.synced');
		offline.setSyncError('boom');
		expect(offline.liveMessage).toBe('offline.live.sync_failed');
		offline.announce('offline.live.unlocked');
		expect(offline.liveMessage).toBe('offline.live.unlocked');
	});
});

describe('offline state (plain browser)', () => {
	it('controlsActive is false when no native db bridge', async () => {
		vi.resetModules();
		delete (window as never as { setjoinNative?: unknown }).setjoinNative;
		const { offline } = await import('./state.svelte');
		offline.featureEnabled = true;
		offline.capsAllowed = true;
		expect(offline.controlsActive).toBe(false);
	});
});
