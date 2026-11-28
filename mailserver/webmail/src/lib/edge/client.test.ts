import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const dpopMock = vi.hoisted(() => ({
	peekDpopKey: vi.fn(),
	peekDpopKeySync: vi.fn(),
	accessTokenForProofs: vi.fn(),
	recoverAccessTokenForProofs: vi.fn()
}));

vi.mock('$lib/auth/dpop', () => dpopMock);

import {
	createEdgeClient,
	createDpopEdgeFetch,
	EdgeProblemError,
	toEdgeProblemError
} from './client';
import {
	listRules,
	createRule,
	updateRule,
	deleteRule,
	applyRuleRetro,
	getApplyStatus
} from '$lib/api/rules';
import { saveOfflineWindow } from '$lib/api/offline';

describe('edge openapi-fetch client over DPoP httpRequest seam', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
		dpopMock.peekDpopKey.mockReset();
		dpopMock.peekDpopKeySync.mockReset();
		dpopMock.accessTokenForProofs.mockReset();
		dpopMock.recoverAccessTokenForProofs.mockReset();
		dpopMock.peekDpopKeySync.mockReturnValue(null);
		dpopMock.peekDpopKey.mockResolvedValue(null);
		dpopMock.accessTokenForProofs.mockReturnValue(null);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('attaches DPoP proof header with method, htu, and ath via httpRequest', async () => {
		const sign = vi.fn().mockResolvedValue('proof-jwt-1');
		dpopMock.peekDpopKeySync.mockReturnValue({ sign });
		dpopMock.accessTokenForProofs.mockReturnValue('session-token-abc');

		const fetchMock = vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ usedBytes: 100, quotaBytes: 1000 }), {
				status: 200,
				headers: { 'content-type': 'application/json' }
			})
		);
		vi.stubGlobal('fetch', fetchMock);

		const client = createEdgeClient();
		const { data, error, response } = await client.GET('/api/user/quota');

		expect(error).toBeUndefined();
		expect(response.status).toBe(200);
		expect(data).toEqual({ usedBytes: 100, quotaBytes: 1000 });
		expect(sign).toHaveBeenCalledWith(
			'GET',
			`https://${location.host}/api/user/quota`,
			'session-token-abc'
		);
		const [, init] = fetchMock.mock.calls[0];
		expect(new Headers(init.headers).get('DPoP')).toBe('proof-jwt-1');
	});

	it('recovers and replays once on 401 dpop_admission refusal', async () => {
		let currentToken: string | null = 'stale-token';
		const sign = vi.fn(async (_method: string, _htu: string, tok?: string) => `proof:${tok ?? 'none'}`);
		dpopMock.peekDpopKeySync.mockReturnValue({ sign });
		dpopMock.accessTokenForProofs.mockImplementation(() => currentToken);
		dpopMock.recoverAccessTokenForProofs.mockImplementation(async () => {
			currentToken = 'fresh-token';
			return 'fresh-token';
		});

		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						type: 'about:blank',
						title: 'token_binding_failed',
						status: 401,
						detail: 'Token binding verification failed.',
						code: 'dpop_admission'
					}),
					{
						status: 401,
						headers: { 'content-type': 'application/problem+json' }
					}
				)
			)
			.mockResolvedValueOnce(
				new Response(JSON.stringify([]), {
					status: 200,
					headers: { 'content-type': 'application/json' }
				})
			);
		vi.stubGlobal('fetch', fetchMock);

		const client = createEdgeClient({ loginRedirect: null });
		const { data, error } = await client.GET('/api/settings/rules-list');

		expect(error).toBeUndefined();
		expect(data).toEqual([]);
		expect(dpopMock.recoverAccessTokenForProofs).toHaveBeenCalledTimes(1);
		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(new Headers(fetchMock.mock.calls[0][1].headers).get('DPoP')).toBe('proof:stale-token');
		expect(new Headers(fetchMock.mock.calls[1][1].headers).get('DPoP')).toBe('proof:fresh-token');
	});

	it('supports parseAs: stream and parseAs: blob without consuming raw Response bodies', async () => {
		const streamBody = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode('stream-chunk'));
				controller.close();
			}
		});
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(streamBody, {
					status: 200,
					headers: { 'content-type': 'text/plain' }
				})
			)
			.mockResolvedValueOnce(
				new Response('blob-bytes', {
					status: 200,
					headers: { 'content-type': 'application/octet-stream' }
				})
			);
		vi.stubGlobal('fetch', fetchMock);

		const client = createEdgeClient();

		const streamRes = await client.GET('/healthz', { parseAs: 'stream' });
		expect(streamRes.error).toBeUndefined();
		expect(streamRes.data).toBeInstanceOf(ReadableStream);
		const reader = (streamRes.data as ReadableStream<Uint8Array>).getReader();
		const chunk = await reader.read();
		expect(new TextDecoder().decode(chunk.value)).toBe('stream-chunk');

		const blobRes = await client.GET('/healthz', { parseAs: 'blob' });
		expect(blobRes.error).toBeUndefined();
		expect(blobRes.data).toBeInstanceOf(Blob);
		expect(await (blobRes.data as Blob).text()).toBe('blob-bytes');
	});

	it('passes FormData uploads cleanly without clobbering Content-Type boundary', async () => {
		const sign = vi.fn().mockResolvedValue('proof-upload');
		dpopMock.peekDpopKeySync.mockReturnValue({ sign });
		dpopMock.accessTokenForProofs.mockReturnValue('tok-1');

		const fetchMock = vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ status: 'ok' }), {
				status: 200,
				headers: { 'content-type': 'application/json' }
			})
		);
		vi.stubGlobal('fetch', fetchMock);

		const dpopFetch = createDpopEdgeFetch({ loginRedirect: null });
		const form = new FormData();
		form.append('file', new Blob(['hello'], { type: 'text/plain' }), 'hello.txt');

		const res = await dpopFetch('/api/upload', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'X-Custom': 'yes' },
			body: form
		});

		expect(res.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe('/api/upload');
		expect(init.body).toBe(form);
		const headers = new Headers(init.headers);
		// Content-Type must be stripped so the browser/fetch runtime sets multipart/form-data + boundary.
		expect(headers.get('content-type')).toBeNull();
		expect(headers.get('x-custom')).toBe('yes');
		expect(headers.get('DPoP')).toBe('proof-upload');
	});

	it('extracts RFC 9457 application/problem+json into typed EdgeProblemError', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response(
				JSON.stringify({
					type: 'https://setjoin.com/errors/rate-limited',
					title: 'Too many active rule sweeps',
					status: 429,
					detail: 'this mailbox already has the maximum number of rule sweeps in progress',
					code: 'BZ_SWEEP_CAP',
					instance: '/settings/rules/7/apply'
				}),
				{
					status: 429,
					headers: { 'content-type': 'application/problem+json' }
				}
			)
		);
		vi.stubGlobal('fetch', fetchMock);

		const client = createEdgeClient();
		const { data, error, response } = await client.POST('/api/settings/rules/{id}/apply', {
			params: { path: { id: 7 } },
			body: { window: '90d' }
		});

		expect(data).toBeUndefined();
		expect(response.status).toBe(429);
		const problemErr = toEdgeProblemError(error, response);
		expect(problemErr).toBeInstanceOf(EdgeProblemError);
		expect(problemErr.status).toBe(429);
		expect(problemErr.code).toBe('BZ_SWEEP_CAP');
		expect(problemErr.title).toBe('Too many active rule sweeps');
		expect(problemErr.detail).toContain('maximum number of rule sweeps');
		expect(problemErr.instance).toBe('/settings/rules/7/apply');
	});

	it('supports allowStatuses pass-through for 401 when explicitly configured', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response(
				JSON.stringify({
					type: 'about:blank',
					title: 'Unauthorized',
					status: 401,
					detail: 'missing session'
				}),
				{
					status: 401,
					headers: { 'content-type': 'application/problem+json' }
				}
			)
		);
		vi.stubGlobal('fetch', fetchMock);

		const client = createEdgeClient({
			loginRedirect: null,
			allowStatuses: [400, 401, 404, 500]
		});
		const { data, error, response } = await client.GET('/api/settings/rules-list');
		expect(data).toBeUndefined();
		expect(response.status).toBe(401);
		expect(error).toMatchObject({ status: 401, detail: 'missing session' });
	});

	it('preserves full rules API CRUD + retro-apply behavior over edgeClient', async () => {
		const sampleRule = {
			id: 11,
			mailboxId: 1,
			name: 'Archive alerts',
			enabled: true,
			priority: 5,
			runOn: 'server' as const,
			isTransportRule: false,
			conditions: [{ field: 'subject', op: 'contains', value: 'alert' }],
			actions: [{ type: 'mark_read' }],
			stopProcessing: false,
			createdAt: '2026-11-27T00:00:00Z',
			updatedAt: '2026-11-27T00:00:00Z'
		};
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(JSON.stringify([sampleRule]), {
					status: 200,
					headers: { 'content-type': 'application/json' }
				})
			)
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ id: 12 }), {
					status: 201,
					headers: { 'content-type': 'application/json' }
				})
			)
			.mockResolvedValueOnce(new Response(null, { status: 204 }))
			.mockResolvedValueOnce(new Response(null, { status: 204 }))
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ actionId: 'act-1/2', status: 'queued' }), {
					status: 202,
					headers: { 'content-type': 'application/json' }
				})
			)
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ status: 'done', processed: 42, truncated: false }), {
					status: 200,
					headers: { 'content-type': 'application/json' }
				})
			);
		vi.stubGlobal('fetch', fetchMock);

		const rules = await listRules();
		expect(rules).toHaveLength(1);
		expect(rules[0].name).toBe('Archive alerts');

		const createdId = await createRule({
			name: 'New rule',
			enabled: true,
			priority: 1,
			runOn: 'server',
			conditions: [],
			actions: [],
			stopProcessing: false
		});
		expect(createdId).toBe(12);

		await updateRule(12, {
			name: 'Updated rule',
			enabled: false,
			priority: 2,
			runOn: 'both',
			conditions: [],
			actions: [],
			stopProcessing: true
		});

		await deleteRule(12);

		const retro = await applyRuleRetro(11, '90d');
		expect(retro).toEqual({ actionId: 'act-1/2', status: 'queued' });

		const status = await getApplyStatus('act-1/2');
		expect(status).toEqual({ status: 'done', processed: 42, truncated: false });
		expect(fetchMock.mock.calls[5][0]).toBe('/api/settings/rules/apply/act-1%2F2');
	});

	it('throws on empty-body non-2xx responses with Content-Length: 0 across rules and offline mutations', async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(
				new Response(null, { status: 500, headers: { 'Content-Length': '0' } })
			)
			.mockResolvedValueOnce(
				new Response(null, { status: 503, headers: { 'Content-Length': '0' } })
			)
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ defaultView: 'conversation' }), {
					status: 200,
					headers: { 'content-type': 'application/json' }
				})
			)
			.mockResolvedValueOnce(
				new Response(null, { status: 503, headers: { 'Content-Length': '0' } })
			);
		vi.stubGlobal('fetch', fetchMock);

		await expect(
			updateRule(12, {
				name: 'Updated rule',
				enabled: true,
				priority: 1,
				runOn: 'server',
				conditions: [],
				actions: [],
				stopProcessing: false
			})
		).rejects.toThrow('Rule request failed (500)');

		await expect(deleteRule(12)).rejects.toThrow('Rule request failed (503)');

		await expect(saveOfflineWindow('90d')).rejects.toThrow('Failed to save offline window');
	});

	it('preserves openapi-fetch onRequest middleware header mutations', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ usedBytes: 0, quotaBytes: 100 }), {
				status: 200,
				headers: { 'content-type': 'application/json' }
			})
		);
		vi.stubGlobal('fetch', fetchMock);

		const client = createEdgeClient();
		client.use({
			onRequest({ request }) {
				request.headers.set('X-Middleware-Trace', 'trace-561');
				return request;
			}
		});

		const { data, response } = await client.GET('/api/user/quota');
		expect(response.status).toBe(200);
		expect(data).toEqual({ usedBytes: 0, quotaBytes: 100 });
		const [, init] = fetchMock.mock.calls[0];
		expect(new Headers(init.headers).get('X-Middleware-Trace')).toBe('trace-561');
	});

	it('preserves caller-specific problemDetail message on plain non-remediation 403 responses', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response(
				JSON.stringify({
					type: 'about:blank',
					title: 'Forbidden',
					status: 403,
					detail: 'personal rule edits disabled by policy'
				}),
				{
					status: 403,
					headers: { 'content-type': 'application/problem+json' }
				}
			)
		);
		vi.stubGlobal('fetch', fetchMock);

		await expect(listRules()).rejects.toThrow('personal rule edits disabled by policy');
	});
});
