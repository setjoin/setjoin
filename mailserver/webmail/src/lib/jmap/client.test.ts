import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { get } from 'svelte/store';
import { deviceBlock } from '$lib/stores/deviceBlock';
import {
	jmapCall,
	loadSession,
	getAccountId,
	mailboxGet,
	emailQuery,
	emailGet,
	calendarGet,
	addressBookGet,
	taskGet,
	contactQuery,
	contactGet,
	galSearch,
	contactGroupGet,
	contactGroupQuery,
	contactGroupSet,
	contactGroupExpand,
	emailSet,
	taskSet,
	emailSubmissionCancel,
	emailRecover,
	emailPurge,
	emailNudgeDismiss,
	reminderDismiss,
	reminderSnooze,
	calendarEventRsvp,
	calendarEventRsvpOnBehalf,
	calendarEventCounter,
	calendarEventSendUpdate,
	calendarShareSet,
	calendarEventSetOccurrence,
	emailBundles,
	emailSubmissionQuery,
	reminderGet,
	identityGet,
	usingFor,
	resetJmapAuthContext,
	JmapMethodError
} from './client';

describe('jmap client', () => {
	beforeEach(() => {
		resetJmapAuthContext();
		vi.stubGlobal('fetch', vi.fn());
		vi.stubGlobal('window', { location: { href: '' } });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	describe('jmapCall', () => {
		it('posts correct structure', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					sessionState: 's1',
					methodResponses: [['Mailbox/get', { list: [] }, '0']]
				})
			});
			vi.stubGlobal('fetch', mockFetch);

			await jmapCall([['Mailbox/get', { accountId: 'a1' }, '0']]);
			const opts = mockFetch.mock.calls[0][1];
			expect(opts.method).toBe('POST');
			expect(opts.credentials).toBe('include');
			const body = JSON.parse(opts.body);
			expect(body.using).toContain('urn:ietf:params:jmap:core');
			expect(body.using).toContain('urn:ietf:params:jmap:mail');
			expect(body.methodCalls).toHaveLength(1);
		});

		it('uses custom capabilities when provided', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					sessionState: 's1',
					methodResponses: []
				})
			});
			vi.stubGlobal('fetch', mockFetch);

			await jmapCall([], ['urn:ietf:params:jmap:calendars']);
			const body = JSON.parse(mockFetch.mock.calls[0][1].body);
			expect(body.using).toEqual(['urn:ietf:params:jmap:calendars']);
		});

		it('redirects on 401', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 401
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(jmapCall([])).rejects.toThrow('Session expired');
			expect(window.location.href).toBe('/');
		});

		it('throws on non-ok status', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 500
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(jmapCall([])).rejects.toThrow('JMAP error: 500');
		});

		// HARD WIRE CONTRACT (c6): a 403 whose body carries code 'BZ095' is the
		// SYNTHETIC device-lockdown block from middleware/device_trust_gate.go —
		// the client must set the deviceBlock store (routing to /blocked) and
		// throw 'device_blocked', NOT surface a generic JMAP error. Pinned on
		// the Go side by TestDeviceLockdownGate_SyntheticBZ095Body.
		it('403 + body code BZ095 sets deviceBlock and throws device_blocked', async () => {
			const body = { title: 'Forbidden', status: 403, code: 'BZ095' };
			const res = {
				ok: false,
				status: 403,
				headers: { get: (k: string) => (k === 'X-CA-Correlation-Id' ? 'ref-123' : null) },
				clone: () => ({ json: async () => body }),
				json: async () => body
			};
			vi.stubGlobal('fetch', vi.fn().mockResolvedValue(res));

			deviceBlock.set({ blocked: false });
			await expect(jmapCall([])).rejects.toThrow('device_blocked');
			expect(get(deviceBlock)).toEqual({ blocked: true, ref: 'ref-123' });
			deviceBlock.set({ blocked: false });
		});

		it('403 without BZ095 body stays a generic JMAP error (no device block)', async () => {
			const res = {
				ok: false,
				status: 403,
				headers: { get: () => null },
				clone: () => ({ json: async () => ({ detail: 'some other 403' }) }),
				json: async () => ({ detail: 'some other 403' })
			};
			vi.stubGlobal('fetch', vi.fn().mockResolvedValue(res));

			deviceBlock.set({ blocked: false });
			await expect(jmapCall([])).rejects.toThrow('JMAP error: 403');
			expect(get(deviceBlock)).toEqual({ blocked: false });
		});

		it('passes AbortSignal', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ sessionState: 's1', methodResponses: [] })
			});
			vi.stubGlobal('fetch', mockFetch);

			await jmapCall([]);
			const opts = mockFetch.mock.calls[0][1];
			expect(opts.signal).toBeInstanceOf(AbortSignal);
		});
	});

	describe('loadSession', () => {
		it('throws on failure when no session has ever loaded', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 500
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(loadSession()).rejects.toThrow('Session load failed');
		});

		it('loads session and extracts accountId', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					apiUrl: '/jmap',
					accounts: { u1: { name: 'Alice' } },
					primaryAccounts: {}
				})
			});
			vi.stubGlobal('fetch', mockFetch);

			const session = await loadSession();
			expect(session.apiUrl).toBe('/jmap');
			expect(await getAccountId()).toBe('u1');
		});

		it('returns the cached session when a REFRESH fails (SW-claim abort resilience)', async () => {
			const initialFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} })
			});
			vi.stubGlobal('fetch', initialFetch);
			await loadSession();

			// A session is cached by the explicit load above; a failing refresh must fall
			// back to it instead of failing the action that triggered the refresh
			// (e.g. the service worker's first-install clients.claim() aborting
			// in-flight fetches with net::ERR_ABORTED).
			const mockFetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
			vi.stubGlobal('fetch', mockFetch);

			const session = await loadSession();
			expect(session.apiUrl).toBe('/jmap'); // stale-but-usable cached session
		});

		it('auth generation fences delayed user-A discovery after teardown and user-B discovery', async () => {
			let resolveUserA!: (value: unknown) => void;
			const userABody = new Promise((resolve) => { resolveUserA = resolve; });
			const fetchMock = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: () => userABody })
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						apiUrl: '/jmap',
						accounts: { 'user-b': { name: 'User B' } },
						primaryAccounts: { 'urn:ietf:params:jmap:mail': 'user-b' }
					})
				});
			vi.stubGlobal('fetch', fetchMock);

			const delayedUserA = loadSession();
			resetJmapAuthContext();
			await expect(loadSession()).resolves.toMatchObject({ accounts: { 'user-b': expect.anything() } });

			resolveUserA({
				apiUrl: '/jmap',
				accounts: { 'user-a': { name: 'User A' } },
				primaryAccounts: { 'urn:ietf:params:jmap:mail': 'user-a' }
			});
			await expect(delayedUserA).rejects.toThrow('auth context changed');
			expect(await getAccountId()).toBe('user-b');
			expect(fetchMock).toHaveBeenCalledTimes(2);
		});
	});

	describe('mail account call options', () => {
		async function seedPersonalAccount(): Promise<void> {
			vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					apiUrl: '/jmap',
					accounts: { personal: { name: 'Personal' } },
					primaryAccounts: { 'urn:ietf:params:jmap:mail': 'personal' }
				})
			}));
			await loadSession();
		}

		function jmapResponse(payload: unknown) {
			return {
				ok: true,
				status: 200,
				json: async () => ({ methodResponses: [['Mailbox/get', payload, '0']] })
			};
		}

		it('routes personal → shared A → shared B → personal with one request per operation', async () => {
			await seedPersonalAccount();
			const fetchMock = vi.fn().mockResolvedValue(jmapResponse({ list: [] }));
			vi.stubGlobal('fetch', fetchMock);

			await mailboxGet(undefined, { errorPolicy: 'throw' });
			await mailboxGet(undefined, { accountId: 'shared-a', errorPolicy: 'throw' });
			await mailboxGet(undefined, { accountId: 'shared-b', errorPolicy: 'throw' });
			await mailboxGet(undefined, { errorPolicy: 'throw' });

			const accountIds = fetchMock.mock.calls.map((call) =>
				JSON.parse(call[1].body).methodCalls[0][1].accountId
			);
			expect(accountIds).toEqual(['personal', 'shared-a', 'shared-b', 'personal']);
			expect(fetchMock).toHaveBeenCalledTimes(4);
		});

		it('keeps explicit empty accountId and error policy independent', async () => {
			await seedPersonalAccount();
			const fetchMock = vi.fn().mockResolvedValue(jmapResponse({
				type: 'accountNotFound',
				description: 'account missing'
			}));
			vi.stubGlobal('fetch', fetchMock);

			await expect(mailboxGet(undefined, {
				accountId: 'shared-a',
				errorPolicy: 'return-empty'
			})).resolves.toEqual([]);
			await expect(mailboxGet(undefined, {
				accountId: '',
				errorPolicy: 'throw'
			})).rejects.toThrow('account missing');
			await expect(mailboxGet(undefined, {
				errorPolicy: 'throw'
			})).rejects.toThrow('account missing');

			const accountIds = fetchMock.mock.calls.map((call) =>
				JSON.parse(call[1].body).methodCalls[0][1].accountId
			);
			expect(accountIds).toEqual(['shared-a', '', 'personal']);
			expect(fetchMock).toHaveBeenCalledTimes(3);
		});

		it('keeps forbidden/account-not-found distinct from transport failure', async () => {
			await seedPersonalAccount();
			const fetchMock = vi.fn()
				.mockResolvedValueOnce(jmapResponse({ type: 'forbidden', description: 'forbidden' }))
				.mockResolvedValueOnce(jmapResponse({ type: 'accountNotFound', description: 'missing' }))
				.mockRejectedValueOnce(new TypeError('Failed to fetch'));
			vi.stubGlobal('fetch', fetchMock);

			await expect(mailboxGet(undefined, { accountId: 'shared-a', errorPolicy: 'throw' }))
				.rejects.toThrow('forbidden');
			await expect(mailboxGet(undefined, { accountId: 'shared-b', errorPolicy: 'throw' }))
				.rejects.toThrow('missing');
			await expect(mailboxGet(undefined, { accountId: 'shared-b', errorPolicy: 'return-empty' }))
				.rejects.toThrow('Network error');
			expect(fetchMock).toHaveBeenCalledTimes(3);
		});

		// b1r2-011 r3: assertOk throws JmapMethodError — the structured type rides
		// on the thrown Error (offline replay classification reads it instead of
		// description prose), while the message stays `description || type` so
		// every existing .message consumer is unaffected (assertOk semantics
		// unchanged: same throw condition, same message).
		it('a method-level error carries the structured type + description on JmapMethodError', async () => {
			await seedPersonalAccount();
			const fetchMock = vi.fn().mockResolvedValue(jmapResponse({
				type: 'notFound',
				description: 'Message was deleted'
			}));
			vi.stubGlobal('fetch', fetchMock);

			const err: unknown = await mailboxGet(undefined, { accountId: 'shared-a', errorPolicy: 'throw' }).then(
				() => {
					throw new Error('expected a method-level rejection');
				},
				(e) => e
			);
			expect(err).toBeInstanceOf(JmapMethodError);
			expect(err).toMatchObject({
				name: 'JmapMethodError',
				jmapType: 'notFound',
				jmapDescription: 'Message was deleted',
				message: 'Message was deleted'
			});
		});

		it('a method-level error with no description keeps the type as its message (unchanged message shape)', async () => {
			await seedPersonalAccount();
			const fetchMock = vi.fn().mockResolvedValue(jmapResponse({ type: 'serverFail' }));
			vi.stubGlobal('fetch', fetchMock);

			await expect(mailboxGet(undefined, { accountId: 'shared-a', errorPolicy: 'throw' }))
				.rejects.toMatchObject({
					name: 'JmapMethodError',
					jmapType: 'serverFail',
					jmapDescription: undefined,
					message: 'serverFail'
				});
		});

		it('mutation helpers surface the error envelope as JmapMethodError too (emailSet assertOk path)', async () => {
			await seedPersonalAccount();
			const fetchMock = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					methodResponses: [['Email/set', { type: 'overQuota', description: 'mailbox is full' }, '0']]
				})
			});
			vi.stubGlobal('fetch', fetchMock);

			await expect(emailSet(null, { e1: { keywords: { $seen: true } } }, null))
				.rejects.toMatchObject({ jmapType: 'overQuota', jmapDescription: 'mailbox is full', message: 'mailbox is full' });
		});
	});

	describe('mailboxGet', () => {
		it('returns mailboxes', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							[
								'Mailbox/get',
								{ accountId: 'u1', list: [{ id: 'm1', name: 'Inbox' }] },
								'0'
							]
						]
					})
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			const mailboxes = await mailboxGet();
			expect(mailboxes).toHaveLength(1);
			expect(mailboxes[0].name).toBe('Inbox');
		});
	});

	describe('emailQuery', () => {
		it('returns email ids', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							[
								'Email/query',
								{ accountId: 'u1', ids: ['e1', 'e2'] },
								'0'
							]
						]
					})
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			const result = await emailQuery({ inMailbox: 'inbox' }, null, 20);
			expect(result.ids).toEqual(['e1', 'e2']);
		});
	});

	describe('calendarGet', () => {
		it('uses calendar capabilities', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							['Calendar/get', { accountId: 'u1', list: [] }, '0']
						]
					})
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			await calendarGet();
			const body = JSON.parse(mockFetch.mock.calls[1][1].body);
			expect(body.using).toContain('urn:ietf:params:jmap:calendars');
		});
	});

	describe('addressBookGet', () => {
		it('returns address books', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							[
								'AddressBook/get',
								{ accountId: 'u1', list: [{ id: 'ab1', name: 'Personal' }] },
								'0'
							]
						]
					})
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			const books = await addressBookGet();
			expect(books).toHaveLength(1);
			expect(books[0].name).toBe('Personal');
		});
	});

	describe('taskGet', () => {
		it('returns tasks', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							[
								'Task/get',
								{ accountId: 'u1', list: [{ id: 't1', title: 'Buy milk' }] },
								'0'
							]
						]
					})
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			const tasks = await taskGet(['t1']);
			expect(tasks).toHaveLength(1);
			expect(tasks[0].title).toBe('Buy milk');
		});
	});

	describe('getAccountId TTL cache', () => {
		beforeEach(() => {
			vi.useFakeTimers({ toFake: ['Date'] });
			// Expire any previously cached accountId from other tests in this file
			vi.advanceTimersByTime(120_000);
		});

		afterEach(() => {
			vi.useRealTimers();
		});

		it('returns cached accountId within 60s TTL and re-fetches after expiry', async () => {
			let callCount = 0;
			const mockFetch = vi.fn().mockImplementation(() => {
				callCount++;
				return Promise.resolve({
					ok: true,
					status: 200,
					json: async () => ({
						apiUrl: '/jmap',
						accounts: { [`u${callCount}`]: { name: `User ${callCount}` } },
						primaryAccounts: {}
					})
				});
			});
			vi.stubGlobal('fetch', mockFetch);

			// First call: should fetch session via /.well-known/jmap
			const id1 = await getAccountId();
			expect(id1).toBe('u1');
			expect(callCount).toBe(1);

			// Advance 30s (within 60s TTL): should return cached value, no new fetch
			vi.advanceTimersByTime(30_000);
			const id2 = await getAccountId();
			expect(id2).toBe('u1');
			expect(callCount).toBe(1);

			// Advance another 31s (total 61s, past 60s TTL): should re-fetch
			vi.advanceTimersByTime(31_000);
			const id3 = await getAccountId();
			expect(id3).toBe('u2');
			expect(callCount).toBe(2);

			// Advance 30s again (within TTL from last fetch): cached, no new fetch
			vi.advanceTimersByTime(30_000);
			const id4 = await getAccountId();
			expect(id4).toBe('u2');
			expect(callCount).toBe(2);
			});

		it('rejects delayed user-A getAccountId after reset and user-B discovery without a follow-on mutation', async () => {
			let resolveUserA!: (value: unknown) => void;
			const userABody = new Promise((resolve) => { resolveUserA = resolve; });
			const fetchMock = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: () => userABody })
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						apiUrl: '/jmap',
						accounts: { 'user-b': {} },
						primaryAccounts: { 'urn:ietf:params:jmap:mail': 'user-b' }
					})
				});
			vi.stubGlobal('fetch', fetchMock);

			const staleMutation = getAccountId().then(() =>
				emailSet(null, { message: { keywords: { $seen: true } } }, null)
			);
			await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
			resetJmapAuthContext();
			await expect(getAccountId()).resolves.toBe('user-b');

			resolveUserA({
				apiUrl: '/jmap',
				accounts: { 'user-a': {} },
				primaryAccounts: { 'urn:ietf:params:jmap:mail': 'user-a' }
			});
			await expect(staleMutation).rejects.toMatchObject({ name: 'JmapAuthGenerationError' });
			expect(fetchMock).toHaveBeenCalledTimes(2);
			expect(fetchMock.mock.calls.some(([url]) => url === '/jmap')).toBe(false);
		});

		it('keeps the stale account fallback for a same-generation refresh failure', async () => {
			const initialFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					apiUrl: '/jmap',
					accounts: { personal: {} },
					primaryAccounts: { 'urn:ietf:params:jmap:mail': 'personal' }
				})
			});
			vi.stubGlobal('fetch', initialFetch);
			await expect(getAccountId()).resolves.toBe('personal');
			vi.advanceTimersByTime(61_000);
			const failedRefresh = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
			vi.stubGlobal('fetch', failedRefresh);

			await expect(getAccountId()).resolves.toBe('personal');
			expect(failedRefresh).toHaveBeenCalledOnce();
		});
		});

	describe('AbortSignal propagation', () => {
		// Helper: create a mock that rejects if the passed signal is aborted
		function mockRejectingOnAbortedSignal(response: unknown) {
			return vi.fn().mockImplementation((_url: string, opts: RequestInit) => {
				if (opts.signal?.aborted) {
					return Promise.reject(new DOMException('The operation was aborted', 'AbortError'));
				}
				return Promise.resolve({
					ok: true,
					status: 200,
					json: async () => response
				});
			});
		}

		beforeEach(async () => {
			// Set up a valid session so accountId is non-null for
			// contactQuery / contactGet tests which don't auto-refresh.
			const sessionFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} })
			});
			vi.stubGlobal('fetch', sessionFetch);
			await loadSession();
		});

		it('jmapCall rejects with AbortError when passed a pre-aborted signal', async () => {
			const controller = new AbortController();
			controller.abort();

			// Mock fetch to immediately reject if signal is aborted.
			// When signal forwarding works, fetch receives an aborted signal
			// and the mock rejects — the test passes.
			const fetchMock = mockRejectingOnAbortedSignal({
				sessionState: 's1',
				methodResponses: []
			});
			vi.stubGlobal('fetch', fetchMock);

			await expect(jmapCall([], undefined, controller.signal)).rejects.toThrow('cancelled');
		});

		it('emailQuery rejects with AbortError when passed a pre-aborted signal', async () => {
			const controller = new AbortController();
			controller.abort();

			const fetchMock = mockRejectingOnAbortedSignal({
				sessionState: 's1',
				methodResponses: [['Email/query', { ids: [], total: 0, position: 0 }, '0']]
			});
			vi.stubGlobal('fetch', fetchMock);

			await expect(emailQuery({}, null, 20, undefined, controller.signal)).rejects.toThrow('cancelled');
		});

		it('emailGet rejects with AbortError when passed a pre-aborted signal', async () => {
			const controller = new AbortController();
			controller.abort();

			const fetchMock = mockRejectingOnAbortedSignal({
				sessionState: 's1',
				methodResponses: [['Email/get', { list: [] }, '0']]
			});
			vi.stubGlobal('fetch', fetchMock);

			await expect(emailGet(['e1'], undefined, controller.signal)).rejects.toThrow('cancelled');
		});

		it('contactQuery rejects with AbortError when passed a pre-aborted signal', async () => {
			const controller = new AbortController();
			controller.abort();

			const fetchMock = mockRejectingOnAbortedSignal({
				sessionState: 's1',
				methodResponses: [['ContactCard/query', { ids: [], total: 0, position: 0 }, '0']]
			});
			vi.stubGlobal('fetch', fetchMock);

			await expect(contactQuery({}, null, 0, 100, controller.signal)).rejects.toThrow('cancelled');
		});

		it('contactGet rejects with AbortError when passed a pre-aborted signal', async () => {
			const controller = new AbortController();
			controller.abort();

			const fetchMock = mockRejectingOnAbortedSignal({
				sessionState: 's1',
				methodResponses: [['ContactCard/get', { list: [] }, '0']]
			});
			vi.stubGlobal('fetch', fetchMock);

			await expect(contactGet(['c1'], undefined, controller.signal)).rejects.toThrow('cancelled');
		});

		it('galSearch rejects with AbortError when passed a pre-aborted signal', async () => {
			const controller = new AbortController();
			controller.abort();

			const fetchMock = mockRejectingOnAbortedSignal({
				sessionState: 's1',
				methodResponses: [['ContactCard/galSearch', { list: [] }, '0']]
			});
			vi.stubGlobal('fetch', fetchMock);

			await expect(galSearch('test', 50, controller.signal)).rejects.toThrow('cancelled');
		});

		it('active signal — function resolves normally when signal is not aborted', async () => {
			const fetchMock = mockRejectingOnAbortedSignal({
				sessionState: 's1',
				methodResponses: [['Email/query', { ids: ['e1'], total: 1, position: 0 }, '0']]
			});
			vi.stubGlobal('fetch', fetchMock);

			const controller = new AbortController();
			const result = await emailQuery({}, null, 20, undefined, controller.signal);

			expect(result.ids).toEqual(['e1']);
			expect(controller.signal.aborted).toBe(false);
		});
	});

	describe('contact groups (A4)', () => {
		function mock(response: unknown, method: string) {
			const fetchMock = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					sessionState: 's1',
					methodResponses: [[method, response, '0']]
				})
			});
			vi.stubGlobal('fetch', fetchMock);
			return fetchMock;
		}

		it('contactGroupQuery returns ids', async () => {
			mock({ ids: ['1', '2'], total: 2 }, 'ContactGroup/query');
			const out = await contactGroupQuery();
			expect(out.ids).toEqual(['1', '2']);
		});

		it('contactGroupGet returns the group list', async () => {
			mock({ list: [{ id: '1', name: 'Team', memberCount: 2 }] }, 'ContactGroup/get');
			const out = await contactGroupGet(['1']);
			expect(out[0].name).toBe('Team');
		});

		it('contactGroupSet sends the contacts capability and returns the response', async () => {
			const fetchMock = mock({ created: { k1: { id: '9' } } }, 'ContactGroup/set');
			const out = await contactGroupSet({ k1: { name: 'New' } }, null, null);
			expect(out.created?.k1?.id).toBe('9');
			const body = JSON.parse(fetchMock.mock.calls[0][1].body);
			expect(body.using).toContain('urn:ietf:params:jmap:contacts');
		});

		it('contactGroupExpand returns recipient list', async () => {
			const fetchMock = mock({ list: [{ name: 'Alice', email: 'alice@x.test' }] }, 'ContactGroup/expand');
			const out = await contactGroupExpand('42');
			expect(out[0].email).toBe('alice@x.test');
			const body = JSON.parse(fetchMock.mock.calls[0][1].body);
			expect(body.methodCalls[0][0]).toBe('ContactGroup/expand');
			expect(body.methodCalls[0][1].groupId).toBe('42');
		});
	});

	describe('mutation error envelopes (assertOk)', () => {
		// The gateway returns a method-level error envelope (name "error" + type/
		// description) on reducer exceptions (RLS/quota/invalid-state). Mutation
		// helpers must throw, not cast the error body to a success shape.
		function envelopeMock(method: string, args: unknown) {
			const fetchMock = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ sessionState: 's1', methodResponses: [[method, args, '0']] })
			});
			vi.stubGlobal('fetch', fetchMock);
			return fetchMock;
		}

		it('emailSet throws on a method-level error envelope', async () => {
			envelopeMock('error', { type: 'serverFail', description: 'quota exceeded' });
			await expect(emailSet(null, { e1: { keywords: {} } }, null)).rejects.toThrow('quota exceeded');
		});

		it('emailSet resolves on success', async () => {
			envelopeMock('Email/set', { updated: { e1: null } });
			const out = await emailSet(null, { e1: { keywords: {} } }, null);
			expect(out.updated?.e1).toBeNull();
		});

		it('taskSet throws on a method-level error envelope', async () => {
			envelopeMock('error', { type: 'invalidState' });
			await expect(taskSet({ k1: { title: 'x' } }, null, null)).rejects.toThrow('invalidState');
		});

		// ── Destructive/undo helpers (b1r2-010): their callers discard return
		// values, so an unguarded HTTP-200 error envelope read as silent success —
		// canceled mail still sent and purged mail stayed retrievable. Every
		// mutating helper must surface the envelope as a rejection to its caller.
		// Some calendar reducers (rsvp/sendUpdate/setOccurrence) also pass through
		// error-SHAPED bodies ({type, description}) under their own method name
		// instead of raising, so assertOk's envelope check is the only guard.

		it('emailSubmissionCancel throws on an undo-window rejection envelope', async () => {
			const fetchMock = envelopeMock('error', { type: 'invalidState', description: 'undo window elapsed' });
			await expect(emailSubmissionCancel('e1')).rejects.toThrow('undo window elapsed');
			const body = JSON.parse(fetchMock.mock.calls[0][1].body);
			expect(body.methodCalls[0][0]).toBe('EmailSubmission/cancel');
		});

		it('emailSubmissionCancel surfaces shared-mailbox rejections with the account override', async () => {
			const fetchMock = envelopeMock('error', { type: 'forbidden', description: 'send grant revoked' });
			await expect(emailSubmissionCancel('7', 'mbx-9')).rejects.toThrow('send grant revoked');
			const body = JSON.parse(fetchMock.mock.calls[0][1].body);
			expect(body.methodCalls[0][1].accountId).toBe('mbx-9');
		});

		it('emailSubmissionCancel resolves on success', async () => {
			envelopeMock('EmailSubmission/cancel', { message_id: '7', received_at: '2026-01-01T00:00:00Z', undo: true });
			const out = await emailSubmissionCancel('7');
			expect(out).toMatchObject({ message_id: '7', undo: true });
		});

		it('emailRecover throws on a method-level error envelope', async () => {
			envelopeMock('error', { type: 'serverFail', description: 'database error' });
			await expect(emailRecover(['1'])).rejects.toThrow('database error');
		});

		it('emailRecover resolves with the recovered buckets', async () => {
			envelopeMock('Email/recover', { recovered: { '1': null }, notRecovered: {} });
			const out = await emailRecover(['1']);
			expect(out).toMatchObject({ recovered: { '1': null } });
		});

		it('emailPurge throws on a quota rejection envelope', async () => {
			envelopeMock('error', { type: 'quotaRequest', description: 'storage quota exceeded' });
			await expect(emailPurge(['1'])).rejects.toThrow('storage quota exceeded');
		});

		it('emailPurge resolves with the purged buckets', async () => {
			envelopeMock('Email/purge', { purged: ['1'], notPurged: {} });
			const out = await emailPurge(['1']);
			expect(out).toMatchObject({ purged: ['1'] });
		});

		it('emailNudgeDismiss throws on a method-level error envelope', async () => {
			envelopeMock('error', { type: 'serverFail', description: 'dismiss failed' });
			await expect(emailNudgeDismiss('t1')).rejects.toThrow('dismiss failed');
		});

		// Reminder/* helpers resolve the account via getAccountId → loadSession,
		// so the mock serves the discovery response before the method envelope.
		function sessionThenEnvelope(method: string, args: unknown) {
			const fetchMock = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						apiUrl: '/jmap',
						accounts: { u1: { name: 'Alice' } },
						primaryAccounts: { 'urn:ietf:params:jmap:mail': 'u1' }
					})
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ sessionState: 's1', methodResponses: [[method, args, '0']] })
				});
			vi.stubGlobal('fetch', fetchMock);
			return fetchMock;
		}

		it('reminderDismiss throws on a foreign-reminder rejection envelope', async () => {
			sessionThenEnvelope('error', { type: 'forbidden', description: 'reminder not found in this account' });
			await expect(reminderDismiss('3')).rejects.toThrow('reminder not found');
		});

		it('reminderDismiss resolves on success', async () => {
			sessionThenEnvelope('Reminder/dismiss', { dismissed: true, reminderId: '3' });
			await expect(reminderDismiss('3')).resolves.toBeUndefined();
		});

		it('reminderSnooze throws on a past-time rejection envelope', async () => {
			sessionThenEnvelope('error', { type: 'invalidArguments', description: 'snooze time must be in the future' });
			await expect(reminderSnooze('3', '2020-01-01T00:00:00Z')).rejects.toThrow('must be in the future');
		});

		it('calendarEventRsvp throws on an error-shaped pass-through body', async () => {
			envelopeMock('CalendarEvent/rsvp', { type: 'notFound', description: 'Attendee not found for this event' });
			await expect(calendarEventRsvp('1', 'accepted')).rejects.toThrow('Attendee not found');
		});

		it('calendarEventRsvp resolves on success', async () => {
			envelopeMock('CalendarEvent/rsvp', { accountId: '1', oldState: '4', newState: '5', updated: 1 });
			const out = await calendarEventRsvp('1', 'accepted');
			expect(out).toMatchObject({ updated: 1 });
		});

		it('calendarEventRsvpOnBehalf throws on a delegate-grant rejection', async () => {
			envelopeMock('CalendarEvent/rsvp', { type: 'forbidden', description: 'Not authorized to respond on behalf of this mailbox' });
			await expect(calendarEventRsvpOnBehalf('1', 'declined', 'mgr@x.test')).rejects.toThrow('on behalf of');
		});

		it('calendarEventCounter throws on an attendee-membership rejection', async () => {
			envelopeMock('error', { type: 'forbidden', description: 'Not an attendee of this event' });
			await expect(calendarEventCounter('1', '2026-09-11T10:00:00Z', '2026-09-11T11:00:00Z')).rejects.toThrow('Not an attendee');
		});

		it('calendarEventSendUpdate throws on a notMeeting pass-through body', async () => {
			envelopeMock('CalendarEvent/sendUpdate', { type: 'notMeeting', description: 'Event is not a meeting' });
			await expect(calendarEventSendUpdate('1')).rejects.toThrow('not a meeting');
		});

		it('calendarShareSet throws on an ACL rejection envelope', async () => {
			envelopeMock('error', { type: 'forbidden', description: 'not the calendar owner' });
			await expect(calendarShareSet('1', [{ userEmail: 'a@x.test', level: 'manage' }], [])).rejects.toThrow('not the calendar owner');
		});

		it('calendarEventSetOccurrence throws on an invalid-scope pass-through body', async () => {
			envelopeMock('CalendarEvent/setOccurrence', { type: 'invalidArguments', description: 'scope must be this, following, or series' });
			const bogusScope = 'bogus' as unknown as 'this' | 'following' | 'series';
			await expect(calendarEventSetOccurrence('1', '2026-09-11T10:00:00Z', bogusScope, {})).rejects.toThrow('scope must be');
		});
	});
});

// The gateway's method registry golden artifact (c4): every registered method
// with its required capability and app gate. Reading the SAME file the Go
// golden test pins means the client capability table (client.ts usingFor)
// cannot drift from the server registry — a method the server moves to a new
// capability fails this suite until usingFor is updated.
// A helper whose `using` array omits the method's required capability is rejected
// with 400 unknownCapability — this shipped TWICE (EmailSubmission/* and
// Email/bundles both 400'd in production). This guard catches the whole class.
// vitest cwd is mailserver/webmail — the golden file lives in the Go package.
const GOLDEN_PATH = resolve(process.cwd(), '../internal/jmap/testdata/methods.golden');

function goldenRegistry(): Map<string, string> {
	const rows = new Map<string, string>();
	for (const line of readFileSync(GOLDEN_PATH, 'utf8').trim().split('\n')) {
		const [method, capability] = line.split('\t');
		rows.set(method, capability);
	}
	return rows;
}

function requiredCap(method: string): string {
	const cap = goldenRegistry().get(method);
	if (!cap) throw new Error(`${method} is not in the server registry golden file`);
	return cap;
}

describe('jmap client — usingFor mirrors the server method registry', () => {
	it('declares every golden-file method with its server-required capability', () => {
		const registry = goldenRegistry();
		expect(registry.size).toBeGreaterThan(70);
		for (const [method, capability] of registry) {
			expect(usingFor([method]), `usingFor(${method})`).toContain(capability);
		}
	});
});

describe('jmap client — every helper declares the gateway-required capability', () => {
	beforeEach(() => {
		vi.stubGlobal('window', { location: { href: '' } });
	});
	afterEach(() => vi.unstubAllGlobals());

	// One representative call per capability family (each family shares a *_CAPS
	// const, so one rep guards the whole family).
	const cases: Array<[string, () => Promise<unknown>]> = [
		['Mailbox/get', () => mailboxGet()],
		['Email/query', () => emailQuery({}, null)],
		['Email/bundles', () => emailBundles()],
		['EmailSubmission/query', () => emailSubmissionQuery()],
		['Calendar/get', () => calendarGet()],
		['ContactCard/query', () => contactQuery({}, null, undefined, undefined)],
		['Task/get', () => taskGet([])],
		['Reminder/get', () => reminderGet()],
		['Identity/get', () => identityGet()]
	];

	for (const [method, invoke] of cases) {
		it(`${method} → using ⊇ ${requiredCap(method)}`, async () => {
			const mockFetch = vi.fn(async (_url: string, _opts: { body: string }) => ({
				ok: true,
				status: 200,
				json: async () => ({
					apiUrl: '/jmap',
					accounts: { '1': {} },
					primaryAccounts: {},
					sessionState: 's',
					methodResponses: [[method, { list: [], ids: [], bundles: [], created: {}, accountId: '1' }, '0']]
				})
			}));
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			await invoke().catch(() => { /* only the request shape matters */ });

			const call = mockFetch.mock.calls.find((c) => {
				try {
					return JSON.parse(c[1].body).methodCalls?.[0]?.[0] === method;
				} catch {
					return false;
				}
			});
			expect(call, `no /jmap request carried ${method}`).toBeTruthy();
			const using = JSON.parse(call![1].body).using as string[];
			expect(using, `${method} using=${JSON.stringify(using)}`).toContain(requiredCap(method));
		});
	}
});
