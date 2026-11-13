import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createSettingsResource } from './settings-resource.svelte';

// The composable must route EVERY wire call through the $lib/http seam (which
// owns timeout/abort/401/parseError) and add only route state: pending/error/
// data with supersede + cancellation. These tests drive the REAL seam with a
// stubbed global fetch — the same setup stores/session.test.ts and the page
// suites use.

type Doc = { v: string };

function okResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status });
}

/** Trap window.location so the seam's 401 login redirect is observable. */
function trapLoginRedirect(): { redirects: string[]; restore: () => void } {
	const redirects: string[] = [];
	const original = window.location;
	Object.defineProperty(window, 'location', {
		value: {
			host: 'localhost:5173',
			get href() {
				return 'http://localhost:5173/';
			},
			set href(v: string) {
				redirects.push(v);
			},
		},
		configurable: true,
	});
	return {
		redirects,
		restore: () => Object.defineProperty(window, 'location', { value: original, configurable: true }),
	};
}

function makeResource(initialData: Doc | null = null) {
	return createSettingsResource<Doc>({ load: { url: '/api/settings/thing', method: 'GET' }, initialData });
}

/** A fetch that never completes ON ITS OWN but honors abort like the wire does. */
function hangingFetch(): void {
	fetchMock.mockImplementation((_url: string | URL, init?: RequestInit) => {
		return new Promise<Response>((_resolve, reject) => {
			const signal = init?.signal;
			if (signal?.aborted) {
				reject(new DOMException('Aborted', 'AbortError'));
				return;
			}
			signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
		});
	});
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
	fetchMock = vi.fn();
	vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe('settings-resource load', () => {
	it('decodes and stores a successful load; pending settles', async () => {
		fetchMock.mockResolvedValue(okResponse({ v: 'one' }));
		const res = makeResource();
		expect(res.data).toBeNull();
		const data = await res.load();
		expect(data).toEqual({ v: 'one' });
		expect(res.data).toEqual({ v: 'one' });
		expect(res.pending).toBe(false);
		expect(res.error).toBe('');
	});

	it('exposes initialData before the first load and keeps it on failure', async () => {
		fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
		const seed: Doc = { v: 'seed' };
		const res = makeResource(seed);
		expect(res.data).toEqual(seed);
		const data = await res.load();
		expect(data).toBeNull();
		expect(res.data).toEqual(seed);
		expect(res.error).toBe('Network error — please check your connection');
	});

	it('surfaces the seam\'s typed error for a non-ok response (display-safe)', async () => {
		fetchMock.mockResolvedValue(okResponse({ detail: 'internal' }, 500));
		const res = makeResource();
		const data = await res.load();
		expect(data).toBeNull();
		// The seam deliberately does NOT echo the raw body into the UI.
		expect(res.error).toBe('Request failed (500)');
		expect(res.pending).toBe(false);
	});

	it('surfaces the seam\'s typed network-failure message', async () => {
		fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
		const res = makeResource();
		await res.load();
		expect(res.error).toBe('Network error — please check your connection');
	});

	it('handles 401 through the seam: typed unauthorized error + seam-owned redirect', async () => {
		const trap = trapLoginRedirect();
		try {
			fetchMock.mockResolvedValue(okResponse({ code: 'nope' }, 401));
			const res = makeResource();
			const data = await res.load();
			expect(data).toBeNull();
			// The seam's unauthorized message — the composable adds none of its own.
			expect(res.error).toBe('Session expired — please log in again');
			// The redirect outcome belongs to the seam, not the composable.
			expect(trap.redirects).toEqual(['/']);
			expect(res.pending).toBe(false);
		} finally {
			trap.restore();
		}
	});

	it('surfaces the seam\'s timeout as a failure (own controller NOT aborted)', async () => {
		hangingFetch();
		const res = makeResource();
		const data = await res.load({ timeoutMs: 20 });
		expect(data).toBeNull();
		expect(res.error).toBe('Request cancelled'); // the seam's AbortError-authored text
		expect(res.pending).toBe(false);
	});

	it('clears error when a newer load starts and succeeds', async () => {
		fetchMock.mockResolvedValueOnce(okResponse({}, 500)).mockResolvedValueOnce(okResponse({ v: 'two' }));
		const res = makeResource();
		await res.load();
		expect(res.error).toBe('Request failed (500)');
		expect(await res.load()).toEqual({ v: 'two' });
		expect(res.error).toBe('');
	});
});

describe('settings-resource supersede + cancellation', () => {
	it('a newer load wins; the stale completion must not overwrite newer state', async () => {
		const pending: ((r: Response) => void)[] = [];
		fetchMock.mockImplementation(() => new Promise<Response>((r) => pending.push(r)));
		const res = makeResource();
		const promiseA = res.load();
		const promiseB = res.load();
		await vi.waitFor(() => expect(pending.length).toBe(2));
		// Complete the STALE call first — it must land nowhere.
		pending[0](okResponse({ v: 'stale' }));
		expect(await promiseA).toBeNull();
		pending[1](okResponse({ v: 'fresh' }));
		expect(await promiseB).toEqual({ v: 'fresh' });
		expect(res.data).toEqual({ v: 'fresh' });
		expect(res.error).toBe('');
		expect(res.pending).toBe(false);
	});

	it('a stale FAILURE does not set error over a newer in-flight load', async () => {
		const pending: ((r: Response) => void)[] = [];
		fetchMock.mockImplementation(() => new Promise<Response>((r) => pending.push(r)));
		const res = makeResource();
		const promiseA = res.load();
		const promiseB = res.load();
		await vi.waitFor(() => expect(pending.length).toBe(2));
		pending[0](okResponse({}, 500)); // stale failure
		expect(await promiseA).toBeNull();
		expect(res.error).toBe(''); // the newer call owns the lane's state
		expect(res.pending).toBe(true); // the newer load is still legitimately in flight
		pending[1](okResponse({ v: 'ok' }));
		expect(await promiseB).toEqual({ v: 'ok' });
		expect(res.pending).toBe(false); // ...and pending is not stuck
	});

	it('cleanup() aborts in-flight work: no error, pending settled, wire signal aborted', async () => {
		const captured: AbortSignal[] = [];
		fetchMock.mockImplementation((_url: string | URL, init?: RequestInit) => {
			if (init?.signal) captured.push(init.signal);
			return new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
			});
		});
		const res = makeResource();
		const promise = res.load();
		await vi.waitFor(() => expect(captured.length).toBe(1));
		res.cleanup();
		expect(await promise).toBeNull();
		expect(res.pending).toBe(false);
		expect(res.error).toBe('');
		expect(captured[0].aborted).toBe(true);
	});

	it('an aborted EXTERNAL signal cancels without recording an error', async () => {
		hangingFetch();
		const external = new AbortController();
		const res = makeResource();
		const promise = res.load({ signal: external.signal });
		external.abort();
		expect(await promise).toBeNull();
		expect(res.error).toBe('');
		expect(res.pending).toBe(false);
	});
});

describe('settings-resource save', () => {
	it('saves a JSON body and reports a no-content success', async () => {
		fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
		const res = makeResource();
		const result = await res.save({ url: '/api/settings/thing', method: 'PUT', body: { enabled: true } });
		expect(result).toEqual({ ok: true, data: undefined });
		expect(res.saving).toBe(false);
		expect(res.saveError).toBe('');
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe('/api/settings/thing');
		expect(init.method).toBe('PUT');
		expect(init.body).toBe(JSON.stringify({ enabled: true }));
		expect(init.headers['content-type']).toBe('application/json');
	});

	it('decodes a JSON save result when parse: json is declared', async () => {
		fetchMock.mockResolvedValue(okResponse({ status: 'ok' }));
		const res = makeResource();
		const result = await res.save<{ status: string }>({
			url: '/api/settings/thing', method: 'PUT', body: {}, parse: 'json',
		});
		expect(result).toEqual({ ok: true, data: { status: 'ok' } });
	});

	it('reports a typed failure with the seam message through saveError', async () => {
		fetchMock.mockResolvedValue(okResponse({ error: 'nope' }, 500));
		const res = makeResource();
		const result = await res.save({ url: '/api/settings/thing', method: 'PUT', body: {} });
		expect(result).toEqual({ ok: false });
		expect(res.saveError).toBe('Request failed (500)');
		expect(res.saving).toBe(false);
	});

	it('keeps the authored onError message display-safe', async () => {
		fetchMock.mockResolvedValue(okResponse({ error: 'Could not save' }, 400));
		const res = makeResource();
		const result = await res.save({
			url: '/api/settings/thing', method: 'PUT', body: {},
			onError: async (r) => {
				const b = (await r.json().catch(() => ({}))) as { error?: unknown };
				return typeof b.error === 'string' && b.error ? b.error : 'fallback';
			},
		});
		expect(result).toEqual({ ok: false });
		expect(res.saveError).toBe('Could not save');
	});

	it('supersedes saves: the stale save must not report over the newer one', async () => {
		const pending: ((r: Response) => void)[] = [];
		fetchMock.mockImplementation(() => new Promise<Response>((r) => pending.push(r)));
		const res = makeResource();
		const promiseA = res.save({ url: '/a', method: 'PUT', body: { n: 1 } });
		const promiseB = res.save({ url: '/b', method: 'PUT', body: { n: 2 } });
		await vi.waitFor(() => expect(pending.length).toBe(2));
		pending[0](okResponse({}, 500)); // stale failure lands nowhere
		expect(await promiseA).toEqual({ ok: false });
		expect(res.saveError).toBe('');
		expect(res.saving).toBe(true); // the newer save is still in flight
		pending[1](new Response(null, { status: 204 }));
		expect(await promiseB).toEqual({ ok: true, data: undefined });
		expect(res.saving).toBe(false);
	});

	it('save and load are independent lanes (a save does not abort a load)', async () => {
		const pending: ((r: Response) => void)[] = [];
		fetchMock.mockImplementation(() => new Promise<Response>((r) => pending.push(r)));
		const res = makeResource();
		const loadPromise = res.load();
		const savePromise = res.save({ url: '/api/settings/thing', method: 'PUT', body: {} });
		await vi.waitFor(() => expect(pending.length).toBe(2));
		pending[1](new Response(null, { status: 204 }));
		expect(await savePromise).toEqual({ ok: true, data: undefined });
		expect(res.pending).toBe(true); // load lane untouched by the save
		pending[0](okResponse({ v: 'kept' }));
		expect(await loadPromise).toEqual({ v: 'kept' });
	});
});

describe('settings-resource concurrent instances', () => {
	it('keeps per-instance state: one instance\'s slow failure cannot touch another', async () => {
		const pending: ((r: Response) => void)[] = [];
		fetchMock.mockImplementation(() => new Promise<Response>((r) => pending.push(r)));
		const slow = createSettingsResource<Doc>({ load: { url: '/a', method: 'GET' } });
		const fast = createSettingsResource<Doc>({ load: { url: '/b', method: 'GET' } });
		const slowPromise = slow.load();
		const fastPromise = fast.load();
		await vi.waitFor(() => expect(pending.length).toBe(2));
		pending[1](okResponse({ v: 'fast' }));
		expect(await fastPromise).toEqual({ v: 'fast' });
		expect(fast.pending).toBe(false);
		expect(slow.pending).toBe(true); // still in flight, still its own lane
		pending[0](okResponse({}, 500));
		expect(await slowPromise).toBeNull();
		expect(slow.error).toBe('Request failed (500)');
		expect(fast.error).toBe(''); // the fast instance never saw the slow failure
	});
});
