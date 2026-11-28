import { afterEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

// The auth-generation wiring tests import the REAL auth store (paired with a
// fresh dpop instance); keep its jmap transport import inert.
vi.mock('$lib/jmap/websocket', () => ({ disconnect: vi.fn() }));

import type { DpopRecoveryError } from './dpop';
import {
	generateDpopKey,
	publicJwkForCnf,
	getOrCreateDpopKey,
	peekDpopKey,
	accessTokenForProofs,
	rememberAccessTokenForProofs,
	resetDpopKey
} from './dpop';
describe('dpop', () => {
	// jsdom has no IndexedDB, so getOrCreateDpopKey falls back to an in-memory
	// key for the page session (documented degrade path). This still proves the
	// load-bearing behavior: the SAME key is reused across calls within one
	// session (a fresh key on every call would break DPoP proofs the instant
	// the server had bound cnf.jkt to the first one).
	it('peekDpopKey resolves null before any key has been created (no IndexedDB in this env)', async () => {
		expect(await peekDpopKey()).toBeNull();
	});

	it('getOrCreateDpopKey reuses the same key across repeated calls in one session', async () => {
		const first = await getOrCreateDpopKey();
		const second = await getOrCreateDpopKey();
		expect(second.jwk.x).toBe(first.jwk.x);
		expect(second.jwk.y).toBe(first.jwk.y);
	});

	it('getOrCreateDpopKey is now visible to peekDpopKey (same cached key)', async () => {
		const created = await getOrCreateDpopKey();
		const peeked = await peekDpopKey();
		expect(peeked?.jwk.x).toBe(created.jwk.x);
	});

	it('generates a non-extractable ES256 key and a stable public cnf JWK', async () => {
		const { jwk } = await generateDpopKey();
		const pub = publicJwkForCnf(jwk);
		expect(pub.kty).toBe('EC');
		expect(pub.crv).toBe('P-256');
		expect(pub.x).toBeTruthy();
		expect(pub.y).toBeTruthy();
		expect((pub as JsonWebKey).d).toBeUndefined(); // private component stripped
	});

	it('signs a proof carrying htm/htu/iat/jti', async () => {
		const { sign } = await generateDpopKey();
		const proof = await sign('POST', 'https://x/jmap');
		const [, payloadB64] = proof.split('.');
		const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
		expect(payload.htm).toBe('POST');
		expect(payload.htu).toBe('https://x/jmap');
		expect(payload.jti).toBeTruthy();
		expect(typeof payload.iat).toBe('number');
		expect(payload.ath).toBeUndefined(); // default payload matches the golden-vectored shape
	});

	it('carries the RFC 9449 ath binding (base64url SHA-256) when a token is supplied', async () => {
		const { sign } = await generateDpopKey();
		const proof = await sign('POST', 'https://x/jmap', 'token-material');
		const [, payloadB64] = proof.split('.');
		const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
		expect(typeof payload.ath).toBe('string');
		const expected = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('token-material')))))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');
		expect(payload.ath).toBe(expected);
	});

	it('resetDpopKey drops the cached key so the next create generates a fresh one', async () => {
		const before = await getOrCreateDpopKey();
		await resetDpopKey();
		expect(await peekDpopKey()).toBeNull();
		const after = await getOrCreateDpopKey();
		expect(after.jwk.x).not.toBe(before.jwk.x);
	});
});

// ── Persistence (IndexedDB) ──────────────────────────────────────────────────
// jsdom has no IndexedDB, so the default-environment tests above only exercise
// the documented in-memory degrade path. These tests install a minimal fake
// IndexedDB to drive the REAL persistence seams: open (upgrade + error),
// load (hit / miss / request error), store (commit / tx error), delete, and
// the peekDpopKeySync hot-path read. Each test imports a FRESH module instance
// (vi.resetModules + dynamic import) because the module keeps a page-lifetime
// resolved-key/promise cache; the static instance above stays untouched.
describe('dpop IndexedDB persistence (fake IDB)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	interface FakeReq {
		result?: unknown;
		error?: unknown;
		onsuccess: (() => void) | null;
		onerror: (() => void) | null;
		onupgradeneeded: ((e: { target: { result: unknown } }) => void) | null;
	}

	// Enough IDB surface for openDpopDB/loadStoredEntry/storeEntry/
	// deleteStoredEntry. `rows` models the single object store so a fresh
	// module instance (page reload) reads what an earlier instance put.
	function makeIDB(
		rows: Map<string, unknown>,
		opts: { failOpen?: boolean; failGet?: boolean; failPut?: boolean; failDelete?: boolean } = {}
	) {
		const open = (_name: string, _version: number): FakeReq => {
			const req: FakeReq = { onsuccess: null, onerror: null, onupgradeneeded: null };
			queueMicrotask(() => {
				if (opts.failOpen) {
					req.error = new Error('open failed');
					req.onerror?.();
					return;
				}
				if (!rows.has('__upgraded__')) {
					rows.set('__upgraded__', true);
					req.onupgradeneeded?.({ target: { result: { createObjectStore: () => {} } } });
				}
				req.result = {
					transaction(_store: string, _mode: string) {
						const tx = {
							error: undefined as unknown,
							oncomplete: null as (() => void) | null,
							onerror: null as (() => void) | null,
							objectStore: () => ({
								get: (key: string) => {
									const getReq: FakeReq = {
										result: rows.get(key),
										onsuccess: null,
										onerror: null,
										onupgradeneeded: null
									};
									queueMicrotask(() => {
										if (opts.failGet) {
											getReq.error = new Error('get failed');
											getReq.onerror?.();
										} else {
											getReq.onsuccess?.();
										}
									});
									return getReq;
								},
								put: (value: unknown, key: string) => {
									rows.set(key, value);
									queueMicrotask(() => {
										if (opts.failPut) {
											tx.error = new Error('put failed');
											tx.onerror?.();
										} else {
											tx.oncomplete?.();
										}
									});
									return {};
								},
								delete: (key: string) => {
									rows.delete(key);
									queueMicrotask(() => {
										if (opts.failDelete) {
											tx.error = new Error('delete failed');
											tx.onerror?.();
										} else {
											tx.oncomplete?.();
										}
									});
									return {};
								}
							})
						};
						return tx;
					}
				};
				req.onsuccess?.();
			});
			return req;
		};
		return { open };
	}

	async function freshDpop(rows: Map<string, unknown>, opts?: Parameters<typeof makeIDB>[1]) {
		vi.stubGlobal('indexedDB', makeIDB(rows, opts));
		return await import('./dpop');
	}

	it('peekDpopKeySync is undefined before the first resolution and mirrors the settled key after', async () => {
		vi.resetModules();
		const dpop = await freshDpop(new Map());
		expect(dpop.peekDpopKeySync()).toBeUndefined();
		const key = await dpop.getOrCreateDpopKey();
		expect(dpop.peekDpopKeySync()?.jwk.x).toBe(key.jwk.x);
	});

	it('a reloaded page (fresh module) reuses the persisted keypair, private key included', async () => {
		vi.resetModules();
		const rows = new Map<string, unknown>();
		const first = await freshDpop(rows);
		const created = await first.getOrCreateDpopKey();

		// Simulate a reload: the same store rows, a brand-new module instance.
		vi.resetModules();
		const second = await freshDpop(rows);
		const loaded = await second.peekDpopKey();
		expect(loaded?.jwk.x).toBe(created.jwk.x);

		// The reloaded key actually signs: a proof carries the standard claims.
		const proof = await loaded!.sign('POST', 'https://x/jmap');
		const [, payloadB64] = proof.split('.');
		const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
		expect(payload.htm).toBe('POST');
		expect(payload.htu).toBe('https://x/jmap');
	});

	it('an upgrade-triggering first open still resolves the store (onupgradeneeded path)', async () => {
		vi.resetModules();
		const dpop = await freshDpop(new Map());
		const key = await dpop.getOrCreateDpopKey();
		expect(key.jwk.kty).toBe('EC');
	});

	it('an open failure degrades to null (resolveKey catch), never a thrown keygen', async () => {
		vi.resetModules();
		const dpop = await freshDpop(new Map(), { failOpen: true });
		await expect(dpop.peekDpopKey()).resolves.toBeNull();
	});

	it('a read failure inside the store also degrades to null', async () => {
		vi.resetModules();
		const dpop = await freshDpop(new Map(), { failGet: true });
		await expect(dpop.peekDpopKey()).resolves.toBeNull();
	});

	it('a storage write failure keeps the in-memory key for the session (documented degrade)', async () => {
		vi.resetModules();
		const dpop = await freshDpop(new Map(), { failPut: true });
		const key = await dpop.getOrCreateDpopKey();
		expect(key.jwk.kty).toBe('EC');
		// Still bound in memory even though the put was refused.
		expect(dpop.peekDpopKeySync()?.jwk.x).toBe(key.jwk.x);
	});

	it('resetDpopKey deletes the persisted record so a reload mints a fresh key', async () => {
		vi.resetModules();
		const rows = new Map<string, unknown>();
		const dpop = await freshDpop(rows);
		await dpop.getOrCreateDpopKey();
		const persistedKey = [...rows.keys()].find((k) => k !== '__upgraded__');
		expect(persistedKey).toBeTruthy();

		await dpop.resetDpopKey();
		expect([...rows.keys()].filter((k) => k !== '__upgraded__')).toEqual([]);
		await expect(dpop.peekDpopKey()).resolves.toBeNull();
	});

	it('a failed delete still drops the in-memory key (best-effort rotation)', async () => {
		vi.resetModules();
		const rows = new Map<string, unknown>();
		const dpop = await freshDpop(rows, { failDelete: true });
		await dpop.getOrCreateDpopKey();

		await dpop.resetDpopKey();
		await expect(dpop.peekDpopKey()).resolves.toBeNull();
	});
});

describe('access-token retention for the ath claim (r2 defect 1)', () => {
	afterEach(() => {
		rememberAccessTokenForProofs(null);
	});

	it('remembers a token and hands it back for ath computation', () => {
		expect(accessTokenForProofs()).toBeNull();
		rememberAccessTokenForProofs('tok-abc');
		expect(accessTokenForProofs()).toBe('tok-abc');
	});

	it('forgets the token on logout (null clears, never keeps a stale ath source)', () => {
		rememberAccessTokenForProofs('tok-abc');
		rememberAccessTokenForProofs(null);
		expect(accessTokenForProofs()).toBeNull();
	});

	it('treats an empty string as no token', () => {
		rememberAccessTokenForProofs('');
		expect(accessTokenForProofs()).toBeNull();
	});

	it('round-trips through sessionStorage so a reloaded tab keeps its ath source', () => {
		rememberAccessTokenForProofs('tok-reload');
		expect(sessionStorage.getItem('sj-dpop-access-token')).toBe('tok-reload');
		rememberAccessTokenForProofs(null);
		expect(sessionStorage.getItem('sj-dpop-access-token')).toBeNull();
	});
});

// ── Per-tab admission recovery (r3) ──────────────────────────────────────────
// The session cookie is shared across tabs but the ath cache is per tab: a
// fresh independently opened tab must be able to ADMIT itself (fetch-on-miss
// from /auth/session/token), and a stale tab must follow another tab's
// rotation of the shared cookie. Fresh module instances per test (the module
// keeps page-lifetime caches); fetch stubbed at the global seam.
describe('per-tab access-token admission recovery (r3)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	async function freshModule() {
		vi.resetModules();
		return await import('./dpop');
	}

	it('fresh-tab admission: an empty tab recovers the shared session token and signs admissible proofs', async () => {
		const dpop = await freshModule();
		expect(dpop.accessTokenForProofs()).toBeNull();

		const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-fresh' }), {
			status: 200,
			headers: { 'content-type': 'application/json' }
		}));
		vi.stubGlobal('fetch', fetchMock);

		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-fresh');
		// The recovered string becomes this tab's ath source…
		expect(dpop.accessTokenForProofs()).toBe('tok-fresh');
		// …recovered from the synchronization endpoint, cookie-authenticated.
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/auth/session/token');
		expect(init.credentials).toBe('include');
	});

	it('cross-tab rotation: a stale tab follows the shared cookie to the CURRENT token', async () => {
		const dpop = await freshModule();
		// This tab remembered tok-1 at login; another tab's refresh has since
		// rotated the shared cookie to tok-2 (the server's authority).
		dpop.rememberAccessTokenForProofs('tok-stale');

		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-current' }), {
			status: 200,
			headers: { 'content-type': 'application/json' }
		})));

		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-current');
		expect(dpop.accessTokenForProofs()).toBe('tok-current');
	});

	it('proofs signed after recovery carry ath over the RECOVERED token', async () => {
		const dpop = await freshModule();
		await dpop.getOrCreateDpopKey(); // the persisted-profile key (in-memory degrade here)
		dpop.rememberAccessTokenForProofs('tok-stale');
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-current' }), {
			status: 200,
			headers: { 'content-type': 'application/json' }
		})));
		await dpop.recoverAccessTokenForProofs();

		const key = await dpop.peekDpopKey();
		const proof = await key!.sign('POST', 'https://x/auth/mfa/possession/totp', dpop.accessTokenForProofs() ?? undefined);
		const [, payloadB64] = proof.split('.');
		const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
		const expected = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('tok-current')))))
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '');
		expect(payload.ath).toBe(expected);
	});

	it('concurrent recoveries share ONE fetch (parallel 401s never stampede the endpoint)', async () => {
		const dpop = await freshModule();
		let resolved = 0;
		vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => {
			await new Promise((r) => setTimeout(r, 5));
			resolved += 1;
			return new Response(JSON.stringify({ access_token: 'tok-shared' }), {
				status: 200,
				headers: { 'content-type': 'application/json' }
			});
		}));
		const [a, b, c] = await Promise.all([
			dpop.recoverAccessTokenForProofs(),
			dpop.recoverAccessTokenForProofs(),
			dpop.recoverAccessTokenForProofs()
		]);
		expect(a).toBe('tok-shared');
		expect(b).toBe('tok-shared');
		expect(c).toBe('tok-shared');
		expect(resolved).toBe(1);
	});

	// r4: the recovery is hard-bounded (AbortSignal.timeout) and typed-error
	// settled — a stalled endpoint settles EVERY waiter instead of hanging the
	// page's requests on a promise that never resolves. The mock fetch mimics
	// the real wire: it rejects with an AbortError when its passed signal
	// aborts (exactly what a browser fetch does on timeout). The bound itself
	// is shrunk so the REAL AbortSignal.timeout timer fires inside the test —
	// no clock faking, no cross-realm event synthesis.
	it('the timeout path settles ALL waiting callers with the typed error', async () => {
		const dpop = await freshModule();
		dpop.recoveryTimeout.ms = 15;
		let wireSignal: AbortSignal | null = null;
		vi.stubGlobal('fetch', vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
			wireSignal = init?.signal ?? null;
			expect(wireSignal).toBeInstanceOf(AbortSignal);
			return new Promise((_resolve, reject) => {
				wireSignal!.addEventListener('abort', () =>
					reject(new DOMException('The operation was aborted', 'AbortError'))
				);
			});
		}));
		const third = new AbortController();
		const calls = [
			dpop.recoverAccessTokenForProofs(),
			dpop.recoverAccessTokenForProofs(),
			dpop.recoverAccessTokenForProofs(third.signal)
		];

		const settled = await Promise.allSettled(calls);
		const observedSignal = wireSignal as AbortSignal | null;
		expect(observedSignal?.aborted).toBe(true); // the REAL timeout fired on the wire
		for (const outcome of settled) {
			expect(outcome.status).toBe('rejected');
			const err = (outcome as PromiseRejectedResult).reason as DpopRecoveryError;
			// Class identity is per-fresh-module: instanceof against the dynamic
			// namespace, not the static import.
			expect(err).toBeInstanceOf(dpop.DpopRecoveryError);
			expect(err.reason).toBe('timeout'); // the shared fetch died at its bound
			expect(String(err.message)).toMatch(/timed out/i);
		}
		// The in-flight slot was released: a fresh caller can retry.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-after' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-after');
	});

	it('a caller cancellation propagates INTO the recovery: it settles aborted while the shared fetch continues for the others', async () => {
		const dpop = await freshModule();
		vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => {
			await new Promise((r) => setTimeout(r, 20));
			return new Response(JSON.stringify({ access_token: 'tok-slow' }), {
				status: 200, headers: { 'content-type': 'application/json' }
			});
		}));
		const ownerAbort = new AbortController();
		const sharerAbort = new AbortController();
		const owner = dpop.recoverAccessTokenForProofs(ownerAbort.signal); // owns the wire
		await new Promise((r) => setTimeout(r, 2));
		const sharer = dpop.recoverAccessTokenForProofs(sharerAbort.signal); // joined the shared fetch
		await new Promise((r) => setTimeout(r, 2));

		// The SHARER cancels: it settles immediately with the typed aborted
		// error; the shared fetch (and the owner) are untouched.
		sharerAbort.abort();
		await expect(sharer).rejects.toMatchObject({ name: 'DpopRecoveryError', reason: 'aborted' });
		await expect(owner).resolves.toBe('tok-slow');
		expect(dpop.accessTokenForProofs()).toBe('tok-slow');

		// The OWNER cancels: its signal is folded into the wire fetch, so the
		// in-flight request is genuinely torn down, and the owner settles
		// aborted. A fresh caller afterwards gets a fresh (re-armed) recovery.
		const owner2Abort = new AbortController();
		let abortedOnWire = false;
		vi.stubGlobal('fetch', vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
			return new Promise((_resolve, reject) => {
				init?.signal?.addEventListener('abort', () => {
					abortedOnWire = true;
					reject(new DOMException('The operation was aborted', 'AbortError'));
				});
			});
		}));
		const owner2 = dpop.recoverAccessTokenForProofs(owner2Abort.signal);
		await new Promise((r) => setTimeout(r, 2));
		owner2Abort.abort();
		await expect(owner2).rejects.toMatchObject({ name: 'DpopRecoveryError', reason: 'aborted' });
		expect(abortedOnWire).toBe(true);
	});

	it('a network failure settles every caller with the typed unavailable error and re-arms', async () => {
		const dpop = await freshModule();
		dpop.rememberAccessTokenForProofs(null); // self-contained: clear sessionStorage from other tests
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
		const results = await Promise.allSettled([
			dpop.recoverAccessTokenForProofs(),
			dpop.recoverAccessTokenForProofs()
		]);
		for (const outcome of results) {
			expect(outcome.status).toBe('rejected');
			expect((outcome as PromiseRejectedResult).reason).toBeInstanceOf(dpop.DpopRecoveryError);
			expect((outcome as PromiseRejectedResult).reason.reason).toBe('unavailable');
		}
		expect(dpop.accessTokenForProofs()).toBeNull();
		// Re-armed: the next caller hits the wire again.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-next' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-next');
	});

	it('a caller whose signal is ALREADY aborted settles aborted without touching the wire', async () => {
		const dpop = await freshModule();
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		const controller = new AbortController();
		controller.abort();
		await expect(dpop.recoverAccessTokenForProofs(controller.signal)).rejects.toMatchObject({
			name: 'DpopRecoveryError',
			reason: 'aborted'
		});
		expect(fetchMock).not.toHaveBeenCalled();
		// The pre-aborted caller did not poison the in-flight slot.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok');
	});

	it('a failed recovery resolves null, leaves the cache untouched, and re-arms for the next caller', async () => {
		const dpop = await freshModule();
		dpop.rememberAccessTokenForProofs('keep-me');
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 401 })));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBeNull();
		expect(dpop.accessTokenForProofs()).toBe('keep-me');

		// The next caller retries (the in-flight slot was released).
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-later' }), {
			status: 200,
			headers: { 'content-type': 'application/json' }
		})));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-later');
	});

	it('the recovery proof carries the DPoP key header but NO ath (that is what it recovers)', async () => {
		const dpop = await freshModule();
		await dpop.getOrCreateDpopKey();
		const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok' }), {
			status: 200,
			headers: { 'content-type': 'application/json' }
		}));
		vi.stubGlobal('fetch', fetchMock);
		await dpop.recoverAccessTokenForProofs();
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const proof = (init.headers as Record<string, string>)['DPoP'];
		expect(proof).toBeTruthy();
		const [, payloadB64] = proof.split('.');
		const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
		expect(payload.htm).toBe('GET');
		expect(payload.htu).toContain('/auth/session/token');
		expect(payload.ath).toBeUndefined();
	});
});

// ── Body-transport error contract (r5) ───────────────────────────────────────
// A recovery whose HEADERS arrive (200) but whose BODY never completes is a
// TRANSPORT failure, not a server refusal: the shared promise must REJECT with
// the typed error so every waiter settles (the old `res.json().catch(() =>
// null)` made a stalled body FULFILL every waiter with null — a fake refusal
// on a live session). Only a COMPLETED body with unusable content (malformed
// JSON, empty, no token member) resolves null. The mocks are abort-aware
// response streams: headers resolve immediately, the stream errors when the
// wire signal aborts (exactly what a browser body does).
describe('recovery body-transport error contract (r5)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	async function freshModule() {
		vi.resetModules();
		return await import('./dpop');
	}

	// A 200 whose body stalls until the wire signal aborts (or errors on its
	// own after `failAfterMs` for the no-signal network-failure shape).
	function stubStallingFetch(
		errorOnAbort: boolean,
		opts: { failAfterMs?: number; bodyError?: unknown } = {}
	) {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
				return Promise.resolve(
					new Response(
						new ReadableStream({
							start(controller) {
								const fail = () =>
									controller.error(
										opts.bodyError ?? new DOMException('The operation was aborted', 'AbortError')
									);
								if (opts.failAfterMs !== undefined) {
									setTimeout(fail, opts.failAfterMs);
									return;
								}
								init?.signal?.addEventListener('abort', fail, { once: true });
							}
						}),
						{ status: 200, headers: { 'content-type': 'application/json' } }
					)
				);
			})
		);
	}

	it('a 200 whose BODY stalls to the bound rejects EVERY waiter with the typed timeout — never a null refusal', async () => {
		const dpop = await freshModule();
		dpop.rememberAccessTokenForProofs(null); // self-contained
		dpop.recoveryTimeout.ms = 15; // the REAL bound fires inside the test
		stubStallingFetch(true);

		const [a, b] = await Promise.allSettled([
			dpop.recoverAccessTokenForProofs(),
			dpop.recoverAccessTokenForProofs()
		]);
		for (const outcome of [a, b]) {
			expect(outcome.status).toBe('rejected');
			const err = (outcome as PromiseRejectedResult).reason as DpopRecoveryError;
			expect(err).toBeInstanceOf(dpop.DpopRecoveryError);
			expect(err.reason).toBe('timeout');
			expect(String(err.message)).toMatch(/timed out/i);
		}
		// The stalled body never masqueraded as a refusal: the cache is untouched
		// and the released slot re-arms for the next caller.
		expect(dpop.accessTokenForProofs()).toBeNull();
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ access_token: 'tok-after-stall' }), {
				status: 200, headers: { 'content-type': 'application/json' }
			})
		));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-after-stall');
	});

	it('a caller abort while the response BODY is stalled rejects the SHARED promise typed aborted — no fake refusal for any waiter', async () => {
		const dpop = await freshModule();
		dpop.rememberAccessTokenForProofs('held'); // must survive the cancelled recovery
		dpop.recoveryTimeout.ms = 5000; // must NOT fire — the caller's abort is the cause
		stubStallingFetch(true);
		const controller = new AbortController();

		// The owner (with a signal) shares the recovery with a signal-less
		// waiter — the http seam's shape, where the first 401 may carry no
		// caller signal at all. The abort must reject the SHARED promise as a
		// transport failure (r5: it used to fulfill every waiter with null).
		const owner = dpop.recoverAccessTokenForProofs(controller.signal);
		const sharer = dpop.recoverAccessTokenForProofs();
		await new Promise((r) => setTimeout(r, 5)); // headers landed, body now stalled
		controller.abort();

		await expect(owner).rejects.toMatchObject({ name: 'DpopRecoveryError', reason: 'aborted' });
		await expect(sharer).rejects.toMatchObject({ name: 'DpopRecoveryError', reason: 'aborted' });
		expect(dpop.accessTokenForProofs()).toBe('held');
	});

	it('a network failure MID-BODY rejects typed unavailable (no signal, no bound fired)', async () => {
		const dpop = await freshModule();
		dpop.rememberAccessTokenForProofs(null);
		dpop.recoveryTimeout.ms = 5000; // must NOT fire — the stream dies on its own
		stubStallingFetch(false, { failAfterMs: 5, bodyError: new TypeError('network error: mid-body reset') });

		const results = await Promise.allSettled([
			dpop.recoverAccessTokenForProofs(),
			dpop.recoverAccessTokenForProofs()
		]);
		for (const outcome of results) {
			expect(outcome.status).toBe('rejected');
			const err = (outcome as PromiseRejectedResult).reason as DpopRecoveryError;
			expect(err).toBeInstanceOf(dpop.DpopRecoveryError);
			expect(err.reason).toBe('unavailable');
		}
		expect(dpop.accessTokenForProofs()).toBeNull();
	});

	it('a COMPLETED body with unusable content still resolves null (server-refusal semantics)', async () => {
		const dpop = await freshModule();
		dpop.rememberAccessTokenForProofs('keep-me');
		const json = (body: string) =>
			new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });

		// Malformed JSON — the body COMPLETED (json() rejects SyntaxError), so
		// this is the refusal shape, not a transport failure.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json('not json at all')));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBeNull();

		// Empty body — also completed-and-unusable.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json('')));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBeNull();

		// Valid JSON without a token member.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(JSON.stringify({ nope: 1 }))));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBeNull();

		expect(dpop.accessTokenForProofs()).toBe('keep-me');
	});
});

// ── Recovered-rotation observers (r4 §3.1) ───────────────────────────────────
// The recovery is the one token (re)bind that bypasses the auth store: a stale
// tab discovers mid-request that the shared cookie's token was rotated away by
// another tab. Lifecycle consumers fence on the auth generation, so the
// recovery notifies the registered retire path exactly when it lands a token
// DIFFERENT from the one this page remembered.
describe('recovered-token rotation observers (r4)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		rememberAccessTokenForProofs(null);
	});

	it('a recovery that lands a DIFFERENT token fires the observer with (previous, recovered)', async () => {
		vi.resetModules();
		const dpop = await import('./dpop');
		dpop.rememberAccessTokenForProofs('tok-held');
		const seen: Array<[string, string]> = [];
		const unregister = dpop.onRecoveredAccessTokenRotation((prev, next) => seen.push([prev, next]));
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-current' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));

		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-current');

		expect(seen).toEqual([['tok-held', 'tok-current']]);
		unregister();
		// Unregistered observers stay silent.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-next' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));
		await dpop.recoverAccessTokenForProofs();
		expect(seen).toEqual([['tok-held', 'tok-current']]);
	});

	it('a FIRST-TIME bind (no previously remembered token) and a same-token re-read notify nothing', async () => {
		vi.resetModules();
		const dpop = await import('./dpop');
		const observer = vi.fn();
		dpop.onRecoveredAccessTokenRotation(observer);
		// Fresh Response PER CALL — a body reads once per instance (the old
		// single shared Response only "worked" because the swallowed body error
		// masked the second read; real wire fetches never reuse a Response).
		vi.stubGlobal('fetch', vi.fn().mockImplementation(() => Promise.resolve(
			new Response(JSON.stringify({ access_token: 'tok-fresh' }), {
				status: 200, headers: { 'content-type': 'application/json' }
			})
		)));

		await dpop.recoverAccessTokenForProofs(); // first bind: prev === null
		expect(observer).not.toHaveBeenCalled();

		await dpop.recoverAccessTokenForProofs(); // same token re-read
		expect(observer).not.toHaveBeenCalled();
	});

	it('a throwing observer never fails the recovery', async () => {
		vi.resetModules();
		const dpop = await import('./dpop');
		dpop.rememberAccessTokenForProofs('tok-held');
		dpop.onRecoveredAccessTokenRotation(() => { throw new Error('observer bug'); });
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-current' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));
		await expect(dpop.recoverAccessTokenForProofs()).resolves.toBe('tok-current');
	});
});

// The lifecycle WIRING: auth.ts registers bumpAuthGeneration — the same retire
// path a /auth/refresh rotation drives — on the recovery's rotation observer,
// so a stale tab that follows a cross-tab rotation retires its pending
// ceremony/grant state like any other session-lifecycle move. Fresh instances
// of BOTH modules per test: the module-scope registration binds the paired
// fresh dpop registry.
describe('recovered rotation retires through the auth generation (r4)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
	});

	async function freshPair() {
		vi.resetModules();
		const dpop = await import('./dpop');
		const auth = await import('$lib/stores/auth');
		// Self-contained: the fresh instance must not inherit a token another
		// test left in sessionStorage (it would read as a rotation).
		dpop.rememberAccessTokenForProofs(null);
		return { dpop, auth };
	}

	it('a rotated recovery bumps the auth generation', async () => {
		const { dpop, auth } = await freshPair();
		dpop.rememberAccessTokenForProofs('tok-held');
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-rotated' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));

		const before = get(auth.authGeneration);
		await dpop.recoverAccessTokenForProofs();
		expect(get(auth.authGeneration)).toBe(before + 1);
	});

	it('a first-time recovery bind does not bump the generation', async () => {
		const { dpop, auth } = await freshPair();
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: 'tok-first' }), {
			status: 200, headers: { 'content-type': 'application/json' }
		})));

		const before = get(auth.authGeneration);
		await dpop.recoverAccessTokenForProofs();
		expect(get(auth.authGeneration)).toBe(before);
	});
});
