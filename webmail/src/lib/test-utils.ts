import { render, type RenderOptions } from '@testing-library/svelte/svelte5';
import { vi } from 'vitest';
import {
	authenticated,
	user,
	authInitializing,
	type AuthUser
} from '$lib/stores/auth';
import { jmapSession } from '$lib/stores/session';
import { composeStore } from '$lib/stores/compose';

/**
 * Set auth stores to an authenticated user state before rendering a component.
 * Use this for any test that renders a component inside the authenticated layout.
 */
export async function renderAsUser<Props extends Record<string, any>>(
	Component: any,
	props?: Props,
	userOverrides?: Partial<AuthUser>
) {
	const authUser: AuthUser = {
		email: 'alice@test.local',
		isAdmin: false,
		hasMailbox: true,
		...userOverrides
	};
	authenticated.set(true);
	user.set(authUser);
	authInitializing.set(false);

	// Populate the JMAP session store so derived stores (effectiveCaps,
	// adminConsoles) resolve correctly during render.
	if (authUser.isAdmin) {
		jmapSession.set({
			accounts: { a1: { name: authUser.email, isPrimary: true } },
			primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
			capabilities: {
				'urn:ietf:params:jmap:core': {},
				'urn:setjoin:params:jmap:mail': {
					admin: { consoles: ['mail', 'system', 'logs', 'auth'] }
				}
			}
		} as any);
	} else {
		jmapSession.set({
			accounts: { a1: { name: authUser.email, isPrimary: true } },
			primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
			capabilities: { 'urn:ietf:params:jmap:core': {} }
		} as any);
	}

	const result = render(Component, props as any);

	return { ...result, authUser };
}

/**
 * Reset all shared stores to initial state.  Call in `beforeEach` so tests
 * start from a clean slate.
 */
export function resetStores() {
	// Auth
	authenticated.set(false);
	user.set(null);
	authInitializing.set(true);

	// Compose — close every session (multi-compose, QoL #18).
	composeStore.reset();

	// JMAP session
	jmapSession.set(null);
}

/**
 * Opt-in fetch stub: stubs only the named routes; any other fetch throws
 * (naming method + URL), so phantom calls fail loudly.
 *
 * `routes` is an ordered list of [pattern, value] pairs. A string pattern
 * matches by substring, a RegExp by test(). The value is either the JSON
 * body to return (wrapped in an ok:200 response), a function
 * `(url, init) => body | responseLike`, or a full response-like object
 * (detected by an `ok` property).
 */
export function stubFetchRoutes(
	routes: Array<[string | RegExp, unknown]>
) {
	const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = input instanceof Request ? input.url : String(input);
		const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
		for (const [pattern, value] of routes) {
			const hit = typeof pattern === 'string' ? url.includes(pattern) : pattern.test(url);
			if (!hit) continue;
			const body = typeof value === 'function' ? await value(url, init) : value;
			if (body !== null && typeof body === 'object' && 'ok' in body) return body;
			return {
				ok: true,
				status: 200,
				json: async () => body,
				text: async () => JSON.stringify(body)
			};
		}
		throw new Error(`Unstubbed fetch: ${method} ${url} — add it to stubFetchRoutes()`);
	});
	vi.stubGlobal('fetch', fn);
	return fn;
}

/**
 * Stub `fetch` to return a minimal JMAP session response, used by pages
 * that call `loadSession()` in `onMount`.
 */
export function mockSessionLoad() {
	vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
		const url = typeof _input === 'string' ? _input : _input.toString();
		if (url.includes('/jmap') && !url.includes('/jmap/ws')) {
			return {
				ok: true,
				status: 200,
				json: async () => ({
					methodResponses: [[
						'Session',
						{
							accounts: { a1: { name: 'alice@test.local', isPrimary: true } },
							primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
							capabilities: { 'urn:ietf:params:jmap:core': {} }
						},
						'a1'
					]]
				}),
				text: async () => ''
			};
		}
		// Admin API fallback
		if (url.includes('/admin/')) {
			// Some endpoints return arrays directly
			if (url.includes('/admin/departments/tree') || url.includes('/admin/features') || url.includes('/admin/alerts') || url.includes('/admin/migration')) {
				return { ok: true, status: 200, json: async () => [], text: async () => '' };
			}
			// Endpoints that return objects with array properties
			if (url.includes('/admin/outbound-tls-policy')) {
				return { ok: true, status: 200, json: async () => ({ enforce_domains: [], skip_domains: [], global_mode: 'off' }), text: async () => '' };
			}
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}
		return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
	}));
}

/**
 * Stub `fetch` to return a successful JMAP email query response with
 * mock email data.  Use for inbox/email tests.
 */
export function mockEmailLoad(emails: any[] = mockEmails()) {
	vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
		const url = typeof _input === 'string' ? _input : _input.toString();
		const body = _init?.body ? JSON.parse(_init.body as string) : {};
		const methodCalls = body.methodCalls || [];

		const responses: any[] = [];
		for (const mc of methodCalls) {
			const [name, args, callId] = mc;
			switch (name) {
				case 'Mailbox/get':
					responses.push([name, { list: [{ id: 'mb1', name: 'Inbox' }], state: 's1' }, callId]);
					break;
				case 'Email/query':
					responses.push([name, { ids: emails.map((e: any) => e.id), total: emails.length }, callId]);
					break;
				case 'Email/get':
					responses.push([name, { list: emails, state: 's1' }, callId]);
					break;
				default:
					responses.push([name, { list: [], state: 's1' }, callId]);
			}
		}
		return { ok: true, status: 200, json: async () => ({ methodResponses: responses }) };
	}));
}

/**
 * Stub fetch for JMAP Task/query + Task/get responses.
 * Use for tasks page tests that call taskQuery/taskGet.
 */
export function mockTaskLoad(tasks: any[] = []) {
	vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
		const url = typeof _input === 'string' ? _input : _input.toString();
		const body = _init?.body ? JSON.parse(_init.body as string) : {};
		const methodCalls = body.methodCalls || [];

		const responses: any[] = [];
		for (const mc of methodCalls) {
			const [name, args, callId] = mc;
			switch (name) {
				case 'Session':
					responses.push([name, { accounts: { a1: { name: 'alice@test.local' } }, primaryAccounts: {}, capabilities: {} }, callId]);
					break;
				case 'Task/query':
					responses.push([name, { ids: tasks.map((t: any) => t.id), total: tasks.length }, callId]);
					break;
				case 'Task/get':
					responses.push([name, { list: tasks, state: 's1' }, callId]);
					break;
				default:
					responses.push([name, {}, callId]);
			}
		}
		return { ok: true, status: 200, json: async () => ({ methodResponses: responses }) };
	}));
}

/**
 * Stub fetch for JMAP EmailDeleted/query responses.
 * Use for recover page tests that call emailDeletedQuery.
 */
export function mockDeletedEmailLoad(deletedEmails: any[] = []) {
	vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
		const url = typeof _input === 'string' ? _input : _input.toString();
		const body = _init?.body ? JSON.parse(_init.body as string) : {};
		const methodCalls = body.methodCalls || [];

		const responses: any[] = [];
		for (const mc of methodCalls) {
			const [name, args, callId] = mc;
			switch (name) {
				case 'Session':
					responses.push([name, { accounts: { a1: { name: 'alice@test.local' } }, primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' }, capabilities: { 'urn:ietf:params:jmap:core': {} } }, callId]);
					break;
				case 'EmailDeleted/query':
					responses.push([name, { ids: deletedEmails.map((e: any) => e.id), total: deletedEmails.length }, callId]);
					break;
				default:
					responses.push([name, {}, callId]);
			}
		}
		return { ok: true, status: 200, json: async () => ({ methodResponses: responses }) };
	}));
}

export function mockEmails() {
	return [
		{
			id: 'e1',
			subject: 'Welcome to the team',
			from: [{ email: 'sender@example.com', name: 'Sender' }],
			receivedAt: '2026-01-01T09:00:00Z',
			mailboxIds: { mb1: true },
			hasAttachment: false
		},
		{
			id: 'e2', 
			subject: 'Meeting tomorrow',
			from: [{ email: 'bob@example.com', name: 'Bob' }],
			receivedAt: '2026-01-01T10:00:00Z',
			mailboxIds: { mb1: true },
			hasAttachment: false
		}
	];
}
