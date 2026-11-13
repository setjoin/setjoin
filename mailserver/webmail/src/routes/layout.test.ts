/**
 * layout.test.ts — Task 7: Post-login redirect + SPA route guards
 *
 * Tests the $effect blocks in +layout.svelte:
 * 1. Post-login redirect from '/' → firstEnabledApp
 * 2. Auth guard: unauthenticated → redirect to '/'
 * 3. Auth guard: public routes (/setup, /recover) bypass the guard
 * 4. App route guard: blocked app → redirect to firstEnabledApp
 *
 * Strategy: render the Layout component with controlled store state and
 * a mocked `goto`, then assert it fires with the right arguments.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fireEvent, render, waitFor, within } from '@testing-library/svelte/svelte5';
import { get } from 'svelte/store';
import { authenticated, user, authInitializing, authResolution } from '$lib/stores/auth';
import { jmapSession, effectiveCaps, firstEnabledApp } from '$lib/stores/session';
import { touRemediation } from '$lib/stores/touRemediation';
import { goto } from '$app/navigation';
import { page } from '$app/state';
import { bootstrapLocale, locale, setLocale } from '$lib/i18n';

// Import the layout under test
import Layout from './+layout.svelte';

// Mutable page ref provided by the mock in vitest.setup.ts
const mockPage = page as { url: { pathname: string; searchParams: URLSearchParams; hash: string } };
const mockGoto = goto as ReturnType<typeof vi.fn>;

function setPathname(pathname: string) {
	mockPage.url.pathname = pathname;
}

function setSearch(search = '') {
	mockPage.url.searchParams = new URLSearchParams(search);
}

function setHash(hash = '') {
	mockPage.url.hash = hash;
}

function resetStores() {
	authenticated.set(false);
	user.set(null);
	authInitializing.set(true);
	authResolution.set({ state: 'probing', attempt: 0 });
	jmapSession.set(null);
	setLocale('en');
	localStorage.removeItem('locale');
}

function setAuthenticated(isAdmin = false) {
	authenticated.set(true);
	const nextUser = { email: 'alice@test.local', isAdmin, hasMailbox: true };
	user.set(nextUser);
	authInitializing.set(false);
	authResolution.set({ state: 'authenticated', attempt: 1, user: nextUser });
}

function setUnauthenticated() {
	authenticated.set(false);
	user.set(null);
	authInitializing.set(false);
	authResolution.set({ state: 'anonymous', attempt: 1, status: 401 });
}

// P14/P11c (C-6): a guest session — accountType drives the fail-closed route
// allowlist below, independent of $jmapSession/$effectiveCaps entirely.
function setGuestAuthenticated() {
	authenticated.set(true);
	const nextUser = { email: 'pat@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' as const };
	user.set(nextUser);
	authInitializing.set(false);
	authResolution.set({ state: 'authenticated', attempt: 1, user: nextUser });
}

beforeEach(() => {
	resetStores();
	localStorage.removeItem('locale');
	mockGoto.mockClear();
	// Default: unauthenticated, on inbox
	setPathname('/inbox');
	setSearch();
	setHash();
});

afterEach(() => {
	vi.unstubAllGlobals();
	// Restore pathname to default
	setPathname('/inbox');
	setSearch();
	setHash();
});

// ── Post-login redirect ──────────────────────────────────────────────────────

describe('Post-login redirect', () => {
	it('restores the persisted locale on a hard-refresh mount', async () => {
		localStorage.setItem('locale', 'zh');
		setPathname('/');
		setUnauthenticated();

		await bootstrapLocale();
		render(Layout);

		await waitFor(() => expect(get(locale)).toBe('zh'));
		expect(document.documentElement.lang).toBe('zh');
	});

	it('redirects to /inbox when authenticated and pathname is "/" with mail as first enabled app', async () => {
		setPathname('/');
		// Default fallback caps have mail first
		expect(get(firstEnabledApp)).toBe('/inbox');

		setAuthenticated();
		render(Layout);

		// Allow effects to flush
		await vi.runAllTimersAsync().catch(() => {});
		// Effect fires synchronously in Svelte 5 runes on first render
		expect(mockGoto).toHaveBeenCalledWith('/inbox', { replaceState: true });
	});

	it('redirects to /tasks when authenticated and pathname is "/" and only tasks is enabled', async () => {
		setPathname('/');
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'alice@test.local',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: false, calendar: false, contacts: false, tasks: true, approvals: false, drive: false, chat: false },
				features: { assist: false, bundles: false }
			}
		});

		expect(get(firstEnabledApp)).toBe('/tasks');
		setAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/tasks', { replaceState: true });
	});

	it('resumes the exact OIDC OP completion route after login', async () => {
		setPathname('/');
		setSearch('continue=%2Fauth%2Foidc%2Fop%2Fcomplete%3Fid%3Drequest-1');
		const assign = vi.fn();
		Object.defineProperty(window, 'location', {
			value: { ...window.location, assign },
			writable: true,
		});
		setAuthenticated();

		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(assign).toHaveBeenCalledWith(
			'/auth/oidc/op/complete?id=request-1',
		);
		expect(mockGoto).not.toHaveBeenCalled();
	});

	it('rejects an unrelated post-login continuation', async () => {
		setPathname('/');
		setSearch('continue=https%3A%2F%2Fevil.example%2F');
		setAuthenticated();

		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/inbox', { replaceState: true });
	});
});

// ── Auth guard ───────────────────────────────────────────────────────────────

describe('Auth guard', () => {
	it('renders a public route while the auth probe is still pending', () => {
		setPathname('/');
		authenticated.set(false);
		authInitializing.set(true);
		authResolution.set({ state: 'probing', attempt: 1 });

		const { container } = render(Layout);

		expect(container.querySelector('.sj-unauthenticated-content')).not.toBeNull();
		expect(container.querySelector('.sj-shell-loading')).toBeNull();
	});

	it('shows an actionable retry state without redirecting when auth is unavailable', async () => {
		setPathname('/inbox');
		authenticated.set(false);
		authInitializing.set(false);
		authResolution.set({ state: 'unavailable', attempt: 2, cause: 'server' });

		render(Layout);

		expect(document.querySelector('.sj-auth-unavailable')).not.toBeNull();
		expect(document.querySelector('.sj-unauthenticated-content')).toBeNull();
		expect(document.querySelector('.sj-auth-unavailable button')).not.toBeNull();
		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).not.toHaveBeenCalled();
	});

	it('redirects to "/" when unauthenticated and on /inbox', async () => {
		setPathname('/inbox');
		setUnauthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/');
	});

	it('does NOT redirect when unauthenticated and pathname is "/setup"', async () => {
		setPathname('/setup');
		setUnauthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		// goto('/') must not have been called for the setup route
		const callsToRoot = mockGoto.mock.calls.filter(
			(args: unknown[]) => args[0] === '/' && (args[1] == null || (args[1] as { replaceState?: boolean }).replaceState !== true)
		);
		expect(callsToRoot).toHaveLength(0);
	});

	it('does NOT redirect when unauthenticated and pathname is "/recover"', async () => {
		setPathname('/recover');
		setUnauthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		// goto('/') must not have been called for the recover route
		const callsToRoot = mockGoto.mock.calls.filter(
			(args: unknown[]) => args[0] === '/' && (args[1] == null || (args[1] as { replaceState?: boolean }).replaceState !== true)
		);
		expect(callsToRoot).toHaveLength(0);
	});

	it('does NOT redirect when unauthenticated and pathname is "/security-event" (post-wipe landing)', async () => {
		setPathname('/security-event');
		setUnauthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		const callsToRoot = mockGoto.mock.calls.filter(
			(args: unknown[]) => args[0] === '/' && (args[1] == null || (args[1] as { replaceState?: boolean }).replaceState !== true)
		);
		expect(callsToRoot).toHaveLength(0);
	});

	it('does NOT redirect the unauthenticated guest invitation acceptance route', async () => {
		setPathname('/guest-invite/accept');
		setUnauthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		const callsToRoot = mockGoto.mock.calls.filter(
			(args: unknown[]) => args[0] === '/' && (args[1] == null || (args[1] as { replaceState?: boolean }).replaceState !== true)
		);
		expect(callsToRoot).toHaveLength(0);
	});
});

// ── App route guard ──────────────────────────────────────────────────────────

describe('App route guard', () => {
	it('redirects to firstEnabledApp when navigating to a blocked app route', async () => {
		// Disable calendar — user is on /calendar
		setPathname('/calendar');
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'alice@test.local',
			capabilities: {},
			effectiveCapabilities: {
				apps: { mail: true, calendar: false, contacts: false, tasks: false, approvals: false, drive: false, chat: false, meet: false },
				features: { assist: false, bundles: false }
			}
		});

		expect(get(effectiveCaps).enabledApps).toEqual(['mail']);
		expect(get(firstEnabledApp)).toBe('/inbox');

		setAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		// Guard should redirect to /inbox (first enabled app) since calendar is disabled
		expect(mockGoto).toHaveBeenCalledWith('/inbox', { replaceState: true });
	});

	it('does NOT redirect when B8 effectiveCapabilities is absent (fallback mode)', async () => {
		// No effectiveCapabilities on session — guard should be skipped
		setPathname('/calendar');
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'abc',
			accounts: {},
			primaryAccounts: {},
			username: 'alice@test.local',
			capabilities: {}
			// no effectiveCapabilities key
		});

		setAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		// Route guard must not fire when the capabilities key is absent:
		// goto('/inbox', {replaceState:true}) must not be called due to the guard
		// (the post-login redirect won't fire either, since pathname !== '/').
		expect(mockGoto).not.toHaveBeenCalledWith('/inbox', { replaceState: true });
	});

	it('guards Approvals from the same catalog as every other capability app', async () => {
		setPathname('/approvals/request-1');
		jmapSession.set({
			apiUrl: '/jmap', downloadUrl: '/blobs/{blobId}', uploadUrl: '/upload', eventSourceUrl: '/events',
			state: 'abc', accounts: {}, primaryAccounts: {}, username: 'alice@test.local', capabilities: {},
			effectiveCapabilities: {
				apps: { mail: true, approvals: false },
				features: { assist: false, bundles: false },
			},
		});
		setAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/inbox', { replaceState: true });
	});

	it('does not classify a near-prefix route as a capability app', async () => {
		setPathname('/chatty');
		jmapSession.set({
			apiUrl: '/jmap', downloadUrl: '/blobs/{blobId}', uploadUrl: '/upload', eventSourceUrl: '/events',
			state: 'abc', accounts: {}, primaryAccounts: {}, username: 'alice@test.local', capabilities: {},
			effectiveCapabilities: {
				apps: { mail: true, chat: false },
				features: { assist: false, bundles: false },
			},
		});
		setAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).not.toHaveBeenCalledWith('/inbox', { replaceState: true });
	});

	it('redirects to /apps with replacement and discards source query/hash when no app is enabled', async () => {
		setPathname('/calendar');
		setSearch('from=stale');
		setHash('#stale');
		jmapSession.set({
			apiUrl: '/jmap', downloadUrl: '/blobs/{blobId}', uploadUrl: '/upload', eventSourceUrl: '/events',
			state: 'abc', accounts: {}, primaryAccounts: {}, username: 'alice@test.local', capabilities: {},
			effectiveCapabilities: {
				apps: Object.fromEntries(
					['mail', 'calendar', 'contacts', 'tasks', 'approvals', 'drive', 'chat', 'meet'].map((app) => [app, false]),
				) as never,
				features: { assist: false, bundles: false },
			},
		});
		expect(get(firstEnabledApp)).toBe('/apps');
		setAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/apps', { replaceState: true });
		expect(mockGoto).not.toHaveBeenCalledWith(expect.stringContaining('?'));
		expect(mockGoto).not.toHaveBeenCalledWith(expect.stringContaining('#'));
	});
});

// ── Guest route allowlist (P14/P11c, codex C-6) ─────────────────────────────
// The guard's guest branch is a ROUTE ALLOWLIST ('/chat' + subroutes) with a
// FIXED '/chat' fallback — it must never consult $jmapSession/$effectiveCaps/
// $firstEnabledApp, so every case here leaves jmapSession at its default null
// (the FALLBACK_CAPS trap the member branch would otherwise fall into).

describe('Guest route allowlist (P11c / C-6)', () => {
	it('a G3 guest with successful capabilities sees entitled Chat and Meet rail apps', async () => {
		setPathname('/chat');
		jmapSession.set({
			apiUrl: '/jmap',
			downloadUrl: '/blobs/{blobId}',
			uploadUrl: '/upload',
			eventSourceUrl: '/events',
			state: 'guest',
			accounts: {},
			primaryAccounts: {},
			username: 'pat@partner.example',
			capabilities: {},
			isGuest: true,
			effectiveCapabilities: {
				apps: { mail: false, calendar: false, contacts: false, tasks: false, approvals: false, drive: false, chat: true, meet: true },
				features: { assist: false, bundles: false },
			},
		} as never);
		setGuestAuthenticated();
		const { queryByLabelText, getByLabelText } = render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(getByLabelText('Chat')).toBeTruthy();
		expect(queryByLabelText('Drive')).toBeNull();
		expect(getByLabelText('Meet')).toBeTruthy();
	});

	it('allows an entitled guest to remain on /meet', async () => {
		setPathname('/meet');
		jmapSession.set({
			apiUrl: '/jmap', downloadUrl: '/blobs/{blobId}', uploadUrl: '/upload', eventSourceUrl: '/events',
			state: 'guest', accounts: {}, primaryAccounts: {}, username: 'pat@partner.example', capabilities: {}, isGuest: true,
			effectiveCapabilities: {
				apps: { mail: false, calendar: false, contacts: false, tasks: false, approvals: false, drive: false, chat: true, meet: true },
				features: { assist: false, bundles: false },
			},
		} as never);
		setGuestAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).not.toHaveBeenCalledWith('/chat', { replaceState: true });
	});

	it('redirects a guest from disabled /meet to the first entitled guest app', async () => {
		setPathname('/meet');
		jmapSession.set({
			apiUrl: '/jmap', downloadUrl: '/blobs/{blobId}', uploadUrl: '/upload', eventSourceUrl: '/events',
			state: 'guest', accounts: {}, primaryAccounts: {}, username: 'pat@partner.example', capabilities: {}, isGuest: true,
			effectiveCapabilities: {
				apps: { mail: false, calendar: false, contacts: false, tasks: false, approvals: false, drive: false, chat: true, meet: false },
				features: { assist: false, bundles: false },
			},
		} as never);
		setGuestAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/chat', { replaceState: true });
	});

	it('a guest at /inbox with caps ABSENT is redirected to /chat, never re-redirected to /inbox (the FALLBACK_CAPS loop)', async () => {
		setPathname('/inbox');
		setGuestAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/chat', { replaceState: true });
		expect(mockGoto).not.toHaveBeenCalledWith('/inbox', { replaceState: true });
	});

	it('a guest at /chat with caps absent sees no member shell or command-palette actions', async () => {
		setPathname('/chat');
		setGuestAuthenticated();
		const { getByLabelText, queryByLabelText, findByRole } = render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(getByLabelText('Chat')).toBeTruthy();
		expect(queryByLabelText('Mail')).toBeNull();
		expect(queryByLabelText('Settings')).toBeNull();
		await fireEvent.keyDown(document, { key: 'k', metaKey: true });
		const palette = await findByRole('dialog', { name: 'Command palette' });
		expect(within(palette).getByText('Chat')).toBeTruthy();
		expect(within(palette).queryByText('Compose')).toBeNull();
		expect(within(palette).queryByText('Settings')).toBeNull();
		expect(within(palette).queryByText('Show welcome tour')).toBeNull();
	});

	it('a guest at /approvals (a route the member prefix map omits entirely) is still redirected to /chat', async () => {
		setPathname('/approvals');
		setGuestAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).toHaveBeenCalledWith('/chat', { replaceState: true });
	});

	it('a guest at /chat/5 is left alone (allowlisted, no bounce loop)', async () => {
		setPathname('/chat/5');
		setGuestAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).not.toHaveBeenCalledWith('/chat', { replaceState: true });
	});

	it('a member at /inbox with caps absent is unaffected (member branch byte-identical)', async () => {
		setPathname('/inbox');
		setAuthenticated();
		render(Layout);

		await vi.runAllTimersAsync().catch(() => {});
		expect(mockGoto).not.toHaveBeenCalledWith('/inbox', { replaceState: true });
		expect(mockGoto).not.toHaveBeenCalledWith('/chat', { replaceState: true });
	});
});

// ── ToU remediation mount ────────────────────────────────────────────────────

describe('ToU remediation', () => {
	beforeEach(() => {
		touRemediation.set({ pending: false });
	});

	afterEach(() => {
		touRemediation.set({ pending: false });
	});

	it('mounts TermsAcceptance when touRemediation becomes pending', async () => {
		// Stub fetch: /terms/pending returns one ToU; other calls return the default stub.
		vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
			if (typeof url === 'string' && url.includes('/terms/pending')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: async () => [{ id: 1, name: 'AUP', version: 1, body_md: '# AUP', require_scroll: true }],
					text: async () => '',
					clone: function() { return this; },
				});
			}
			return Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => '', clone: function() { return this; } });
		}));

		setPathname('/inbox');
		setAuthenticated();
		touRemediation.set({ pending: true, touId: 1 });

		const { findByTestId } = render(Layout);

		// findByTestId waits (async) for the element to appear after effects + fetch settle.
		const body = await findByTestId('tou-body');
		expect(body).toBeTruthy();
	});
});

// ── Topbar title (UX #5 — meet/drive mislabels) ──────────────────────────────

describe('appTitle / activeApp topbar label', () => {
	it('shows "Meet" on /meet routes', async () => {
		setPathname('/meet');
		setAuthenticated();
		const { container } = render(Layout);
		await waitFor(() => {
			expect(container.querySelector('.sj-topbar-title')?.textContent).toBe('Meet');
		});
	});

	it('shows "Drive" on /drive routes', async () => {
		setPathname('/drive');
		setAuthenticated();
		const { container } = render(Layout);
		await waitFor(() => {
			expect(container.querySelector('.sj-topbar-title')?.textContent).toBe('Drive');
		});
	});
});
