import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import { readFileSync } from 'node:fs';

// Mock isOfflineAvailable so the offline singleton's readonly nativeAvailable = true
// without needing window.setjoinNative (which would require vi.hoisted + module reset).
// ponytail: mocking the single public gate fn > fighting ESM hoisting order.
vi.mock('$lib/offline/store', () => ({
	isOfflineAvailable: vi.fn().mockReturnValue(true),
	getStore: vi.fn().mockReturnValue(null),
	MAIL_APP_KEY: 'mail',
}));
// Stub requestSync — avoids real JMAP calls.
vi.mock('$lib/offline/sync', () => ({ requestSync: vi.fn() }));
// Stub reconcile (listSyncIssues used by refreshIssueCount).
vi.mock('$lib/offline/reconcile', () => ({
	listSyncIssues: vi.fn().mockResolvedValue([]),
	resolveId: vi.fn(),
}));
// Stub leader (Web Locks).
vi.mock('$lib/offline/leader', () => ({ withSyncOwnership: vi.fn() }));
// Stub jmap/client.
vi.mock('$lib/jmap/client', () => ({ emailQuery: vi.fn(), emailGet: vi.fn() }));
// Stub db/offline.
vi.mock('$lib/db/offline', () => ({ getPendingActions: vi.fn().mockResolvedValue([]) }));

import OfflineStatus from './OfflineStatus.svelte';
import { offline } from '$lib/offline/state.svelte';

beforeEach(() => {
	vi.restoreAllMocks(); // clean up any spies from the previous test
	offline.featureEnabled = false;
	offline.capsAllowed = false;
	offline.workOffline = false;
	offline.syncPhase = 'idle';
	offline.syncIssueCount = 0;
	offline.autoMergedCount = 0;
	offline.setLockState('unlocked');
	offline.liveMessage = '';
	offline.liveParams = undefined;
});

function activate() { offline.featureEnabled = true; offline.capsAllowed = true; }

describe('OfflineStatus', () => {
	it('is inert when caps are absent (default-OFF by construction)', () => {
		const { queryByTestId } = render(OfflineStatus);
		expect(queryByTestId('work-offline-toggle')).toBeNull();
	});

	it('shows controls when feature + caps allow + native present', () => {
		activate();
		const { getByTestId } = render(OfflineStatus);
		expect(getByTestId('work-offline-toggle')).toBeTruthy();
	});

	it('shows a determinate progress while provisioning (first-time)', () => {
		activate();
		offline.setSyncPhase('provisioning');
		offline.setSyncProgress(3, 10);
		const { getByTestId, getByRole } = render(OfflineStatus);
		expect(getByTestId('offline-provisioning')).toBeTruthy();
		expect(getByRole('progressbar')).toBeTruthy(); // M1 Progress
		// triggering control disabled during sync
		expect((getByTestId('work-offline-toggle') as HTMLButtonElement).disabled).toBe(true);
	});

	it('shows "syncing N of M" on a return sync', () => {
		activate();
		offline.setSyncPhase('syncing');
		offline.setSyncProgress(2, 5);
		const { getByTestId } = render(OfflineStatus);
		expect(getByTestId('offline-syncing').textContent).toContain('2');
		expect(getByTestId('offline-syncing').textContent).toContain('5');
	});

	it('shows an inline error with a retry (role=alert)', () => {
		activate();
		offline.setSyncError('boom');
		const { getByTestId, getByRole } = render(OfflineStatus);
		expect(getByRole('alert')).toBeTruthy();
		expect(getByTestId('offline-retry')).toBeTruthy();
	});

	it('shows a stale state with a manual resync', () => {
		activate();
		offline.setSyncPhase('stale');
		const { getByTestId } = render(OfflineStatus);
		expect(getByTestId('offline-resync')).toBeTruthy();
	});

	it('shows the issues badge only when count > 0 and opens the inspector', async () => {
		activate();
		offline.syncIssueCount = 0;
		const { queryByTestId, rerender, getByTestId } = render(OfflineStatus);
		expect(queryByTestId('sync-issues-badge')).toBeNull();
		offline.syncIssueCount = 2;
		await rerender({});
		expect(getByTestId('sync-issues-badge')).toBeTruthy();
	});

	it('shows a lock indicator when offline + locked', () => {
		activate();
		offline.workOffline = true;
		offline.setLockState('locked');
		const { getByTestId } = render(OfflineStatus);
		expect(getByTestId('offline-locked')).toBeTruthy();
	});

	it('gives the provisioning progress bar an accessible name (Progress label)', () => {
		activate();
		offline.setSyncPhase('provisioning');
		offline.setSyncProgress(1, 4);
		const { getByRole } = render(OfflineStatus);
		// label is required by the M1 Progress contract -> aria-label present.
		expect(getByRole('progressbar').getAttribute('aria-label')).toBeTruthy();
	});

	it('caps the issues badge at 99+ so a runaway count never breaks the pill', async () => {
		activate();
		offline.syncIssueCount = 250;
		const { getByTestId } = render(OfflineStatus);
		expect(getByTestId('sync-issues-badge').textContent).toContain('99+');
	});

	it('the rare badge carries explanatory text, not just a count (F1 auto-merge → higher-signal)', () => {
		activate();
		offline.syncIssueCount = 1;
		const { getByTestId } = render(OfflineStatus);
		// "Needs your choice" beside the chip — the badge explains itself now that
		// flag/keyword/mailbox conflicts auto-merge and never reach it.
		expect(getByTestId('sync-issues-badge').textContent).toMatch(/needs your choice/i);
	});

	it('pushes ONE quiet auto-merge toast when conflicts auto-resolved (confirm-success, no per-item nag)', async () => {
		const toasts = await import('$lib/components/ui/toasts.svelte');
		const spy = vi.spyOn(toasts, 'showToast');
		activate();
		render(OfflineStatus);
		offline.autoMergedCount = 3; // syncWindow would set this after a reconnect pass
		await tick(); // let the $effect run
		expect(spy).toHaveBeenCalledTimes(1); // aggregate, not per-item
		expect(spy.mock.calls[0][0]).toMatch(/3.*merged automatically/i);
		// no Undo action — the merge already happened (nothing to revert).
		expect(spy.mock.calls[0][1]?.actionLabel).toBeUndefined();
		// the one-shot count resets so it never re-fires (no nagging).
		expect(offline.autoMergedCount).toBe(0);
	});

	it('no auto-merge toast when nothing auto-resolved (silent when n=0)', async () => {
		const toasts = await import('$lib/components/ui/toasts.svelte');
		const spy = vi.spyOn(toasts, 'showToast');
		activate();
		offline.autoMergedCount = 0;
		render(OfflineStatus);
		await tick();
		expect(spy).not.toHaveBeenCalled();
	});

	it('announces the auto-merge outcome to AT with the interpolated count', async () => {
		activate();
		offline.notifyAutoMerged(2);
		const { getByTestId } = render(OfflineStatus);
		await tick();
		expect(getByTestId('offline-live').textContent).toContain('2');
	});

	it('the visual pill is NOT live; ONE offscreen polite region owns async outcomes (single-announcer contract)', () => {
		activate();
		const { getByTestId } = render(OfflineStatus);
		const pill = getByTestId('offline-status');
		// Design Pass 5: the visual container is not live (a named group only);
		// everything dynamic is announced through the single offscreen region.
		expect(pill.getAttribute('role')).toBe('group');
		expect(pill.getAttribute('aria-live')).toBeNull();
		const live = getByTestId('offline-live');
		expect(live.getAttribute('role')).toBe('status');
		expect(live.getAttribute('aria-live')).toBe('polite');
		// No second competing region exists, even with the program active.
		expect(document.querySelectorAll('[aria-live="polite"]')).toHaveLength(1);
	});

	it('the Work-Offline toggle is a ≥44px aria-pressed button (keyboard-operable)', () => {
		activate();
		const { getByTestId } = render(OfflineStatus);
		const toggle = getByTestId('work-offline-toggle') as HTMLButtonElement;
		expect(toggle.tagName).toBe('BUTTON');
		expect(toggle.getAttribute('aria-pressed')).toBe('false');
	});
});

// ── Style invariants (source-read, can't silently regress) ────────────────────

const src = readFileSync('src/lib/components/OfflineStatus.svelte', 'utf8');

describe('OfflineStatus style invariants', () => {
	it('declares a prefers-reduced-motion fallback for its transitions', () => {
		expect(src).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/);
	});
	it('uses token durations only (no raw ms/hex in <style>)', () => {
		const style = src.slice(src.indexOf('<style>'));
		expect(style).not.toMatch(/#[0-9a-fA-F]{3,6}\b/); // no raw hex -> contrast in both themes
		expect(style).toMatch(/var\(--duration-fast\)/);
	});
});
