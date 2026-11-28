/**
 * CAS-E5-PREFERENCE-ACCOUNT-RACE / CAS-E5-CROSSED-NETWORK-ATTACHMENT —
 * coverage one level up: the REAL identity seam and the RENDERED settings UI.
 *
 * The controller-level bindings live in e5.settingsPreferences.test.ts (and
 * own the case receipts). This suite proves the same contracts through the
 * actual wiring:
 * - the settings page binds the auth store's REAL account identity
 *   (`user:{id}` from the JWT claims, else the email — the same identity the
 *   auth store itself uses) and this device's canonical secure-store
 *   `device_id` — never an email + "this-device" literal;
 * - an identity change mid-flight re-binds and a pending response for the old
 *   binding can never land;
 * - a plain browser (no bridge, or a contract-invalid bridge that falls back
 *   to webFallbacks) binds a null device id — never a placeholder, and never
 *   the localStorage-persisted 'sjn:device_id' fallback value (r3: canonical
 *   identity comes ONLY from the native secure store);
 * - r2 regression: a device-ID lookup begun for one identity that resolves
 *   after the identity changed is DISCARDED — it can never re-bind the
 *   singleton back to the old account;
 * - r2 regression: a successful E5 save announces exactly once through the
 *   page's sr-only live region — no competing toast, and (r3) no e5ui global
 *   announcement that OfflineStatus would relay as a second announcer;
 * - the crossed-settings explanation reflects the EFFECTIVE background policy
 *   (not the draft switch) and the LIVE metering snapshot.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';

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
vi.mock('$lib/jmap/client', async (importOriginal) => {
	const actual = await importOriginal<Record<string, unknown>>();
	return { ...actual, emailQuery: vi.fn(), emailGet: vi.fn() };
});
vi.mock('$lib/db/offline', () => ({ getPendingActions: vi.fn().mockResolvedValue([]) }));

import SettingsPage from '../../routes/settings/+page.svelte';
import { user } from '$lib/stores/auth';
import { offline } from '$lib/offline/state.svelte';
import { e5ui } from '$lib/offline/e5ui.svelte';
import { clearToasts, toasts } from '$lib/components/ui/toasts.svelte';
import type { OfflineCaps } from '$lib/offline/caps';
import type { E5AcknowledgeSnapshot } from './e5Settings';

const flush = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

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
	vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
		ok: false, status: 404, json: async () => ({}), text: async () => '',
	}));
	vi.stubGlobal('localStorage', {
		getItem: vi.fn().mockReturnValue(null),
		setItem: vi.fn(),
		removeItem: vi.fn(),
	});
});

afterEach(() => {
	delete (window as unknown as { setjoinNative?: unknown }).setjoinNative;
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
	e5ui.__resetForTests();
	user.set(null);
});

const approvedCaps = (): OfflineCaps => ({
	allowed: true, approvalState: 'approved', maxOfflineDays: 7,
	wipeOnLogout: 'admin_default', requireApproval: false,
});

function activateE5(): void {
	e5ui.featureEnabled = true;
	e5ui.mode = 'execute';
}

/** Bridge whose secure store provisions device_id 4242 (the CA-2 identity). */
function bridgeWithDeviceId(deviceId: string | null): void {
	(window as unknown as { setjoinNative: unknown }).setjoinNative = {
		version: 1,
		capabilities: ['secureStore'],
		secureStore: {
			get: async (key: string) => (key === 'device_id' ? deviceId : null),
		},
	};
}

/**
 * Bridge whose device_id reads PARK on per-call gates: the test decides the
 * resolution ORDER, so a lookup begun for one identity can be forced to
 * resolve after a later identity's lookup (the r2 stale-landing trace).
 */
function bridgeWithDeferredDeviceReads(): Array<(deviceId: string | null) => void> {
	const resolvers: Array<(deviceId: string | null) => void> = [];
	(window as unknown as { setjoinNative: unknown }).setjoinNative = {
		version: 1,
		capabilities: ['secureStore'],
		secureStore: {
			get: (key: string) =>
				new Promise<string | null>((resolve) => {
					if (key === 'device_id') resolvers.push(resolve);
					else resolve(null);
				}),
		},
	};
	return resolvers;
}

const OTHER_ACCOUNT_SNAPSHOT: E5AcknowledgeSnapshot = {
	requested: { backgroundSyncEnabled: true, automaticNetwork: 'any', attachmentPrefetch: 'always' },
	effective: { backgroundAllowed: true, automaticNetwork: 'any', attachmentPrefetch: 'always', opportunisticRequiresCharging: false },
	sources: {},
};

function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
	let resolve!: (v: T) => void;
	const promise = new Promise<T>((res) => { resolve = res; });
	return { promise, resolve };
}

describe('CAS-E5-PREFERENCE-ACCOUNT-RACE — rendered settings page through the real identity seam', () => {
	it('binds the auth identity + the canonical device id from the secure store', async () => {
		bridgeWithDeviceId('4242');
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();
		render(SettingsPage, { __offlineCaps: approvedCaps(), __bridgePresent: true } as never);
		await tick();
		await flush();
		// REAL lifecycle identity: the JWT-claim user id — not the email, not a
		// "this-device" literal.
		expect(e5ui.settings.accountId).toBe('user:42');
		expect(e5ui.settings.deviceId).toBe('4242');
	});

	it('falls back to the email identity only when the gateway provides no user id', async () => {
		bridgeWithDeviceId('4242');
		user.set({ email: 'Carol@Example.COM', isAdmin: false, hasMailbox: true });
		activateE5();
		render(SettingsPage, { __offlineCaps: approvedCaps(), __bridgePresent: true } as never);
		await tick();
		await flush();
		// Same derivation the auth store uses (lowercased email identity).
		expect(e5ui.settings.accountId).toBe('email:carol@example.com');
	});

	it('a plain browser (no bridge) never binds the localStorage fallback id — device id is honestly absent (r3)', async () => {
		// The web fallback secure store persists an id under 'sjn:device_id' for
		// non-identity plumbing. The r3 trace: readOwnDeviceId routed through
		// getNative()'s webFallbacks, so a browser carrying that persisted value
		// bound it as the CANONICAL settings identity. Canonical identity comes
		// only from the native secure store, so the fallback id stays unbound.
		vi.stubGlobal('localStorage', {
			getItem: vi.fn((key: string) => (key === 'sjn:device_id' ? '7777' : null)),
			setItem: vi.fn(),
			removeItem: vi.fn(),
		});
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();
		render(SettingsPage, { __offlineCaps: approvedCaps(), __bridgePresent: true } as never);
		await tick();
		await flush();
		expect(e5ui.settings.accountId).toBe('user:42');
		expect(e5ui.settings.deviceId).toBeNull();
	});

	it('a contract-invalid bridge falls back to webFallbacks and still binds NO canonical device id (r3)', async () => {
		// getNative() fails closed to webFallbacks when the injected bridge
		// declares a foreign version — and webFallbacks' localStorage stand-in
		// is NOT the canonical secure store. Even with a persisted fallback id
		// present, the binding stays honestly absent.
		(window as unknown as { setjoinNative: unknown }).setjoinNative = {
			version: 999, // foreign bridge version → incompatible → webFallbacks
			capabilities: ['secureStore'],
			secureStore: { get: async () => '9999' },
		};
		vi.stubGlobal('localStorage', {
			getItem: vi.fn((key: string) => (key === 'sjn:device_id' ? '7777' : null)),
			setItem: vi.fn(),
			removeItem: vi.fn(),
		});
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();
		render(SettingsPage, { __offlineCaps: approvedCaps(), __bridgePresent: true } as never);
		await tick();
		await flush();
		expect(e5ui.settings.accountId).toBe('user:42');
		expect(e5ui.settings.deviceId).toBeNull();
	});

	it('an identity change mid-flight invalidates the pending response; it can never land', async () => {
		bridgeWithDeviceId('4242');
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();

		const gate = deferred<E5AcknowledgeSnapshot>();
		e5ui.settingsSaver = async () => gate.promise;

		const { getByTestId, queryByTestId } = render(
			SettingsPage,
			{ __offlineCaps: approvedCaps(), __bridgePresent: true } as never,
		);
		await tick();
		await flush();
		expect(e5ui.settings.accountId).toBe('user:42');

		// Save goes pending (acknowledged is null → dirty → button enabled).
		const save = getByTestId('e5-save-prefs') as HTMLButtonElement;
		expect(save.disabled).toBe(false);
		await fireEvent.click(save);
		await tick();
		expect(e5ui.settings.view().pending).toBe(true);

		// The account lifecycle moves mid-flight (sign-out / switch / impersonation).
		user.set({ email: 'alice@example.com', userId: 43, isAdmin: false, hasMailbox: true });
		await tick();
		await flush();
		expect(e5ui.settings.accountId).toBe('user:43');
		expect(e5ui.settings.view().pending).toBe(false);

		// The stale response for user 42 resolves afterwards — it must not land.
		gate.resolve(OTHER_ACCOUNT_SNAPSHOT);
		await tick();
		await flush();

		const view = e5ui.settings.view();
		expect(view.acknowledged).toBeNull();
		expect(view.pending).toBe(false);
		// The other account's effective values never render.
		expect(queryByTestId('e5-effective-prefs')).toBeNull();
	});

	it('a device-ID lookup begun for the old identity that resolves LAST never re-binds it (r2 stale landing)', async () => {
		// Each device read parks on its own gate: the test forces lookup #1
		// (user:42) to resolve AFTER lookup #2 (user:43) — Astra's trace, where
		// the delayed stale read re-bound the singleton back to the old account.
		const deviceReads = bridgeWithDeferredDeviceReads();
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();

		render(SettingsPage, { __offlineCaps: approvedCaps(), __bridgePresent: true } as never);
		await tick();
		await flush();
		// Lookup #1 (for user:42) is in flight.
		expect(deviceReads.length).toBe(1);

		// The account lifecycle moves to user:43 — lookup #2 begins.
		user.set({ email: 'alice@example.com', userId: 43, isAdmin: false, hasMailbox: true });
		await tick();
		await flush();
		expect(deviceReads.length).toBe(2);

		// Lookup #2 (user:43) resolves first: the new binding lands.
		deviceReads[1]('4242');
		await tick();
		await flush();
		expect(e5ui.settings.accountId).toBe('user:43');
		expect(e5ui.settings.deviceId).toBe('4242');

		// The STALE lookup #1 (begun for user:42) resolves LAST. Without the
		// generation guard it re-bound the singleton to user:42; with it, the
		// stale result is discarded and the current binding stands.
		deviceReads[0]('4242');
		await tick();
		await flush();
		expect(e5ui.settings.accountId).toBe('user:43');
		expect(e5ui.settings.deviceId).toBe('4242');
	});
});

describe('single-announcer contract — rendered settings page (r2 duplicate-emission regression)', () => {
	it('a successful E5 save announces exactly once: the page live region only — no toast, no e5ui global (r3)', async () => {
		bridgeWithDeviceId('4242');
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();
		e5ui.settingsSaver = async () => ({
			requested: { backgroundSyncEnabled: true, automaticNetwork: 'unmetered', attachmentPrefetch: 'never' },
			effective: {
				backgroundAllowed: true,
				automaticNetwork: 'unmetered',
				attachmentPrefetch: 'never',
				opportunisticRequiresCharging: false,
			},
			sources: {},
		});
		clearToasts();

		const { getByTestId, container } = render(
			SettingsPage,
			{ __offlineCaps: approvedCaps(), __bridgePresent: true } as never,
		);
		await tick();
		await flush();

		const save = getByTestId('e5-save-prefs') as HTMLButtonElement;
		expect(save.disabled).toBe(false);
		await fireEvent.click(save);
		await tick();
		await flush();

		// The save succeeded (authoritative snapshot acknowledged)…
		expect(e5ui.settings.view().status.kind).toBe('saved');

		// …and announced EXACTLY once: the page's sr-only polite live region
		// (the single-announcer owner) carries the saved announcement, while no
		// toast was pushed — a role=status toast would be a second announcer.
		const liveRegion = container.querySelector('.sj-settings-vh');
		expect(liveRegion?.textContent).toBe('Offline preferences saved.');
		expect(toasts.length).toBe(0);

		// r3: e5ui's GLOBAL announcement channel stayed silent for the success —
		// it used to re-announce the save, and OfflineStatus relays that retained
		// message into its own region on a later mount (a second announcer). The
		// page live region above is the sole announcer.
		expect(e5ui.announcement).toBeNull();
	});
});

describe('CAS-E5-CROSSED-NETWORK-ATTACHMENT — rendered settings page (effective policy + live metering)', () => {
	it('explains the EFFECTIVE background policy, not the draft switch', async () => {
		bridgeWithDeviceId('4242');
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();
		// Server-resolved: the user's REQUESTED background sync is ON, but the
		// EFFECTIVE policy forbids it, with both stored preferences permissive.
		e5ui.settings.acknowledge({
			requested: { backgroundSyncEnabled: true, automaticNetwork: 'any', attachmentPrefetch: 'always' },
			effective: { backgroundAllowed: false, automaticNetwork: 'any', attachmentPrefetch: 'always', opportunisticRequiresCharging: false },
			sources: {},
		});
		e5ui.networkCost = 'unmetered';
		const { getByTestId } = render(SettingsPage, { __offlineCaps: approvedCaps(), __bridgePresent: true } as never);
		await tick();
		const explanation = getByTestId('e5-crossed-explanation');
		// Effective background off — even though the DRAFT switch is on.
		expect(explanation.textContent).toMatch(/Background sync is off/i);
		expect(explanation.textContent).toMatch(/explicit actions still work/i);
		// Permissive effective prefs on an unmetered link: on, and no all-network promise.
		expect(explanation.textContent).toMatch(/within its network limit/i);
		expect(explanation.textContent).not.toMatch(/metered/i);
	});

	it('the copy tracks the LIVE metering snapshot', async () => {
		bridgeWithDeviceId('4242');
		user.set({ email: 'alice@example.com', userId: 42, isAdmin: false, hasMailbox: true });
		activateE5();
		e5ui.settings.acknowledge({
			requested: { backgroundSyncEnabled: true, automaticNetwork: 'unmetered', attachmentPrefetch: 'unmetered' },
			effective: { backgroundAllowed: true, automaticNetwork: 'unmetered', attachmentPrefetch: 'unmetered', opportunisticRequiresCharging: false },
			sources: {},
		});
		e5ui.networkCost = 'metered';
		const { getByTestId } = render(SettingsPage, { __offlineCaps: approvedCaps(), __bridgePresent: true } as never);
		await tick();
		let explanation = getByTestId('e5-crossed-explanation');
		expect(explanation.textContent).toMatch(/waits for an unmetered network/i);
		expect(explanation.textContent).toMatch(/metered network right now/i);

		// The link becomes unmetered: the metered-wait lines must go, live.
		e5ui.networkCost = 'unmetered';
		await tick();
		explanation = getByTestId('e5-crossed-explanation');
		expect(explanation.textContent).not.toMatch(/metered/i);
		expect(explanation.textContent).toMatch(/within its network limit/i);
	});
});
