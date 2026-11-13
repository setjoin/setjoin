import { get } from 'svelte/store';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
	jmapSession,
	effectiveCaps,
	firstEnabledApp,
	appsCapsStrict,
	setAppsCapsStrict,
	strictEntitlementsAdvertised,
	loadSessionStore,
	sessionResolved,
} from './session';

vi.mock('$lib/http', () => ({ httpRequest: vi.fn() }));
import { httpRequest } from '$lib/http';
import type { AppId } from '$lib/types/jmap';

const ALL_APPS = ['mail', 'calendar', 'contacts', 'tasks', 'approvals', 'drive', 'chat', 'meet'];

beforeEach(() => {
	jmapSession.set(null);
	// Reset the TYPES-002 B8 rollout gate — strict tests flip it ON and must not
	// leak the posture into the default-allow window tests below.
	setAppsCapsStrict(false);
});

describe('effectiveCaps', () => {
	it('returns FALLBACK_CAPS (all apps, assist=false, bundling=false) when jmapSession is null', () => {
		jmapSession.set(null);
		const caps = get(effectiveCaps);
		expect(caps.enabledApps).toEqual(ALL_APPS);
		expect(caps.assist).toBe(false);
		expect(caps.bundling).toBe(false);
		expect(caps.externalLabels).toBe(false);
	});

	it('derives external labels only from an explicit true capability', () => {
		jmapSession.set({
			effectiveCapabilities: {
				apps: {},
				features: { assist: false, bundles: false, external_labels: true },
			},
		} as never);
		expect(get(effectiveCaps).externalLabels).toBe(true);

		jmapSession.set({
			effectiveCapabilities: {
				apps: {},
				features: { assist: false, bundles: false },
			},
		} as never);
		expect(get(effectiveCaps).externalLabels).toBe(false);
	});

	it('returns FALLBACK_CAPS when session has no effectiveCapabilities key', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {}
			// no effectiveCapabilities
		});
		const caps = get(effectiveCaps);
		expect(caps.enabledApps).toEqual(ALL_APPS);
		expect(caps.assist).toBe(false);
		expect(caps.bundling).toBe(false);
	});

	it('guest invite capabilities fail closed when either server bit is absent', () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true } } } as never);
		let caps: import('$lib/types/jmap').EffectiveCapabilities | undefined;
		const unsubscribe = effectiveCaps.subscribe((value) => { caps = value; });
		expect(caps?.guestAccounts).toBe(true);
		expect(caps?.guestInvite).toBe(false);
		unsubscribe();
	});

	it('derives optional guest runtime policy fail closed', () => {
		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: {
				apps: { meet: true },
				features: { assist: false, bundles: false },
				guest: { allowMeetCreate: true, allowDownload: true },
			},
		} as never);
		let caps = get(effectiveCaps);
		expect(caps.allowMeetCreate).toBe(true);
		expect(caps.allowMeetHost).toBe(false);
		expect(caps.allowDownload).toBe(true);

		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: {
				apps: { meet: true },
				features: { assist: false, bundles: false },
				guest: { allowMeetHost: true },
			},
		} as never);
		caps = get(effectiveCaps);
		expect(caps.allowMeetCreate).toBe(false);
		expect(caps.allowMeetHost).toBe(true);
		expect(caps.allowDownload).toBe(false);
	});

	it('filters enabledApps from apps payload (mail+tasks only)', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: true, calendar: false, contacts: false, tasks: true, approvals: false, drive: false, chat: false, meet: false },
				features: { assist: false, bundles: false }
			}
		});
		const caps = get(effectiveCaps);
		expect(caps.enabledApps).toEqual(['mail', 'tasks']);
	});

	it('reflects features.assist in assist field', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: true, calendar: true, contacts: true, tasks: true, approvals: true, drive: false, chat: false },
				features: { assist: true, bundles: false }
			}
		});
		const caps = get(effectiveCaps);
		expect(caps.assist).toBe(true);
		expect(caps.bundling).toBe(false);
	});

	it('reflects features.bundles in bundling field', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: true, calendar: true, contacts: true, tasks: true, approvals: true, drive: false, chat: false },
				features: { assist: false, bundles: true }
			}
		});
		const caps = get(effectiveCaps);
		expect(caps.assist).toBe(false);
		expect(caps.bundling).toBe(true);
	});

	it('treats absent app key as enabled while the B8 window toggle is OFF (default-allow)', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {},
			effectiveCapabilities: {
				// calendar key absent — should be treated as enabled
				apps: { mail: true, contacts: false, tasks: true } as Record<string, boolean> as Record<AppId, boolean>,
				features: { assist: false, bundles: false }
			}
		});
		const caps = get(effectiveCaps);
		// mail, calendar (absent → enabled), tasks; contacts=false excluded
		expect(caps.enabledApps).toContain('mail');
		expect(caps.enabledApps).toContain('calendar');
		expect(caps.enabledApps).toContain('tasks');
		expect(caps.enabledApps).not.toContain('contacts');
	});
});

describe('effectiveCaps strict entitlements (TYPES-002, B8 rollout flipped ON)', () => {
	// Session payload with only mail + tasks asserted; every other app key absent.
	const partialSession = {
		apiUrl: '/jmap',
		downloadUrl: '/blobs/{blobId}',
		uploadUrl: '/upload',
		eventSourceUrl: '/events',
		state: 'abc',
		accounts: {},
		primaryAccounts: {},
		username: 'user@example.com',
		capabilities: {},
		effectiveCapabilities: {
			apps: { mail: true, contacts: false, tasks: true } as Record<string, boolean> as Record<AppId, boolean>,
			features: { assist: false, bundles: false }
		}
	};

	it('fails closed: an absent app key disables the app (explicit true only)', () => {
		setAppsCapsStrict(true);
		jmapSession.set(partialSession);
		const caps = get(effectiveCaps);
		// mail + tasks asserted true; calendar is ABSENT ⇒ disabled, contacts=false excluded
		expect(caps.enabledApps).toEqual(['mail', 'tasks']);
		expect(caps.enabledApps).not.toContain('calendar');
	});

	it('fails closed: a payload with no apps map at all enables nothing', () => {
		setAppsCapsStrict(true);
		jmapSession.set({
			effectiveCapabilities: { features: { assist: false, bundles: false } }
		} as never);
		// The wire is an unvalidated cast — the derivation must deny, not throw.
		expect(get(effectiveCaps).enabledApps).toEqual([]);
		expect(get(firstEnabledApp)).toBe('/apps');
	});

	it('toggles back OFF restoring the default-allow window posture', () => {
		setAppsCapsStrict(true);
		jmapSession.set(partialSession);
		expect(get(effectiveCaps).enabledApps).toEqual(['mail', 'tasks']);

		setAppsCapsStrict(false);
		const caps = get(effectiveCaps);
		expect(caps.enabledApps).toContain('calendar'); // absent ⇒ enabled again
		expect(caps.enabledApps).not.toContain('contacts'); // explicit false still excluded
	});

	it('fails closed when a strict-ON session carries no effectiveCapabilities key (r2 Finding 1)', () => {
		setAppsCapsStrict(true);
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {}
			// no effectiveCapabilities — strict mode asserts no entitlements from it
		});
		expect(get(effectiveCaps).enabledApps).toEqual([]);
		expect(get(firstEnabledApp)).toBe('/apps');

		// The compatibility fallback is strict-OFF only: toggling back restores it.
		setAppsCapsStrict(false);
		expect(get(effectiveCaps).enabledApps).toEqual(ALL_APPS);
	});

	it('fails closed on a null session under strict mode (r2 Finding 1)', () => {
		setAppsCapsStrict(true);
		jmapSession.set(null);
		expect(get(effectiveCaps).enabledApps).toEqual([]);
		expect(get(effectiveCaps).assist).toBe(false);
	});
});

describe('strictEntitlementsAdvertised (TYPES-002 rollout wire signal)', () => {
	it('is true only on an explicit vendor-block appsStrictEntitlements: true', () => {
		expect(
			strictEntitlementsAdvertised({
				capabilities: { 'urn:setjoin:params:jmap:mail': { appsStrictEntitlements: true } },
			})
		).toBe(true);
	});

	it('is false for absent/false field, absent vendor block, or a malformed document — never throws', () => {
		expect(
			strictEntitlementsAdvertised({ capabilities: { 'urn:setjoin:params:jmap:mail': { appsStrictEntitlements: false } } })
		).toBe(false);
		expect(strictEntitlementsAdvertised({ capabilities: { 'urn:setjoin:params:jmap:mail': {} } })).toBe(false);
		expect(strictEntitlementsAdvertised({ capabilities: {} })).toBe(false);
		expect(strictEntitlementsAdvertised({})).toBe(false);
		expect(strictEntitlementsAdvertised(null)).toBe(false);
		expect(strictEntitlementsAdvertised(undefined)).toBe(false);
		expect(strictEntitlementsAdvertised('garbage')).toBe(false);
	});
});

describe('loadSessionStore binds the rollout posture to its wire source (r2 Finding 2)', () => {
	const advertisedSession = {
		capabilities: { 'urn:setjoin:params:jmap:mail': { appsStrictEntitlements: true } },
		effectiveCapabilities: { apps: { mail: true }, features: { assist: false, bundles: false } },
	};

	it('flips strict ON when the session document advertises the posture', async () => {
		vi.mocked(httpRequest).mockResolvedValue({ json: async () => advertisedSession } as unknown as Response);
		await loadSessionStore();
		expect(get(appsCapsStrict)).toBe(true);
		// strict derivation is live: only the explicitly-true app is enabled
		expect(get(effectiveCaps).enabledApps).toEqual(['mail']);
	});

	it('stays OFF when the signal is absent (legacy server / rollout not admitted)', async () => {
		vi.mocked(httpRequest).mockResolvedValue({
			json: async () => ({ effectiveCapabilities: { apps: { mail: true }, features: {} } }),
		} as unknown as Response);
		await loadSessionStore();
		expect(get(appsCapsStrict)).toBe(false);
		// default-allow window preserved: absent app keys still enabled
		expect(get(effectiveCaps).enabledApps).toEqual(ALL_APPS);
	});

	it('does not widen access on a failed load after a strict session (posture untouched)', async () => {
		setAppsCapsStrict(true);
		vi.mocked(httpRequest).mockRejectedValue(new Error('network down'));
		await loadSessionStore();
		// an unknown state never re-widens to default-allow
		expect(get(appsCapsStrict)).toBe(true);
		expect(get(jmapSession)).toBe(null);
		expect(get(sessionResolved)).toBe(true);
	});
});

describe('firstEnabledApp', () => {
	it('returns /inbox when enabledApps starts with mail', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: true, calendar: true, contacts: false, tasks: false, approvals: false, drive: false, chat: false },
				features: { assist: false, bundles: false }
			}
		});
		expect(get(firstEnabledApp)).toBe('/inbox');
	});

	it('returns /tasks when only tasks is enabled', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: false, calendar: false, contacts: false, tasks: true, approvals: false, drive: false, chat: false },
				features: { assist: false, bundles: false }
			}
		});
		expect(get(firstEnabledApp)).toBe('/tasks');
	});

	it('returns /apps (not a guarded app route) when enabledApps is empty', () => {
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'user@example.com',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: false, calendar: false, contacts: false, tasks: false, approvals: false, drive: false, chat: false, meet: false },
				features: { assist: false, bundles: false }
			}
		});
		// Must NOT fall back to '/inbox': that is itself a route-guarded app path, so
		// the layout route guard would redirect /inbox → firstEnabledApp=/inbox forever.
		expect(get(firstEnabledApp)).toBe('/apps');
	});
});
