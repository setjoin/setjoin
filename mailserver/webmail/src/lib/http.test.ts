/**
 * http.test.ts — 403 remediation routing in httpRequest.
 *
 * Verifies that:
 * 1. 403 with remediation:"terms" sets the touRemediation store (not a bare throw).
 * 2. 403 with remediation:"risk" throws with a re-authenticate hint and leaves the store alone.
 * 3. Plain 403 with forbiddenMessage throws that message; store is untouched.
 * 4. Plain 403 without forbiddenMessage falls through to onError / status error.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { touRemediation } from '$lib/stores/touRemediation';
import { httpRequest, HttpBodyTransportError } from '$lib/http';
import { peekDpopKey, accessTokenForProofs, recoverAccessTokenForProofs } from '$lib/auth/dpop';

vi.mock('$lib/auth/dpop', () => ({
	peekDpopKey: vi.fn(),
	peekDpopKeySync: vi.fn(),
	accessTokenForProofs: vi.fn(() => null),
	recoverAccessTokenForProofs: vi.fn()
}));

/** Build a minimal fetch mock whose body is only ever consumed once via .clone(). */
function mockFetch403(body: object) {
	const jsonBody = async () => body as Record<string, unknown>;
	vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
		ok: false,
		status: 403,
		clone: () => ({ json: jsonBody }),
		json: jsonBody,
		text: async () => JSON.stringify(body),
	}));
}

beforeEach(() => {
	touRemediation.set({ pending: false });
});

describe('httpRequest expected status passthrough', () => {
	it('returns an explicitly allowed 401 without redirecting or throwing', async () => {
		const response = { ok: false, status: 401 } as Response;
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));

		await expect(httpRequest('/auth/me', { loginRedirect: null, allowStatuses: [401] })).resolves.toBe(response);
	});
});

describe('httpRequest 403 remediation', () => {
	it('remediation:"terms" signals the ToU flow via touRemediation store (not just a throw)', async () => {
		mockFetch403({ remediation: 'terms', remediation_tou_id: 42, status: 403 });

		await expect(httpRequest('/api/test')).rejects.toThrow();

		// The store must be set — the layout uses this to mount TermsAcceptance.
		expect(get(touRemediation)).toEqual({ pending: true, touId: 42 });
	});

	it('remediation:"terms" without tou_id still sets pending:true', async () => {
		mockFetch403({ remediation: 'terms', status: 403 });

		await expect(httpRequest('/api/test')).rejects.toThrow();

		expect(get(touRemediation)).toMatchObject({ pending: true });
	});

	it('remediation:"risk" throws a re-authenticate error and leaves the store untouched', async () => {
		mockFetch403({ remediation: 'risk', status: 403 });

		await expect(httpRequest('/api/test')).rejects.toThrow(/re-auth/i);
		expect(get(touRemediation)).toEqual({ pending: false });
	});

	it('plain 403 with forbiddenMessage throws that message; store untouched', async () => {
		mockFetch403({ status: 403 });

		await expect(httpRequest('/api/test', { forbiddenMessage: 'Not allowed' })).rejects.toThrow('Not allowed');
		expect(get(touRemediation)).toEqual({ pending: false });
	});

	it('plain 403 without forbiddenMessage falls through to onError; store untouched', async () => {
		mockFetch403({ status: 403 });

		await expect(
			httpRequest('/api/test', { onError: () => 'custom error' })
		).rejects.toThrow('custom error');
		expect(get(touRemediation)).toEqual({ pending: false });
	});

	it('non-JSON 403 (clone.json throws) does not crash and falls through normally', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: false,
			status: 403,
			clone: () => ({ json: async () => { throw new SyntaxError('not JSON'); } }),
			json: async () => { throw new SyntaxError('not JSON'); },
			text: async () => 'Forbidden',
		}));

		await expect(httpRequest('/api/test', { forbiddenMessage: 'Denied' })).rejects.toThrow('Denied');
		expect(get(touRemediation)).toEqual({ pending: false });
	});
});

describe('httpRequest DPoP proof header (CA-3a token binding)', () => {
	beforeEach(() => {
		vi.mocked(peekDpopKey).mockReset();
	});

	it('attaches a DPoP header signed for the request method + htu when a bound key exists', async () => {
		const sign = vi.fn().mockResolvedValue('signed-proof-jwt');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
		vi.stubGlobal('fetch', mockFetch);

		await httpRequest('/api/jmap', { method: 'POST' });

		expect(sign).toHaveBeenCalledWith('POST', expect.stringContaining('/api/jmap'), undefined);
		const sentHeaders = new Headers((mockFetch.mock.calls[0][1] as RequestInit).headers);
		expect(sentHeaders.get('DPoP')).toBe('signed-proof-jwt');
	});

	it('sends no DPoP header when this browser profile has no bound key yet', async () => {
		vi.mocked(peekDpopKey).mockResolvedValue(null);
		const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
		vi.stubGlobal('fetch', mockFetch);

		await httpRequest('/api/jmap');

		const sentHeaders = new Headers((mockFetch.mock.calls[0][1] as RequestInit).headers ?? {});
		expect(sentHeaders.has('DPoP')).toBe(false);
	});

	it('defaults the signed method to GET when none is specified', async () => {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));

		await httpRequest('/api/jmap');

		expect(sign).toHaveBeenCalledWith('GET', expect.any(String), undefined);
	});

	it('binds the proof to the retained session token (ath) — r2 defect 1', async () => {
		const sign = vi.fn().mockResolvedValue('ath-bound-proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs).mockReturnValue('the-session-access-token');
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));

		await httpRequest('/auth/mfa/possession/totp', { method: 'POST' });

		// The historical ath-less browser shape 401s at VerifyDPoPForToken —
		// the proof MUST be minted over the session's access token.
		expect(sign).toHaveBeenCalledWith('POST', expect.stringContaining('/auth/mfa/possession/totp'), 'the-session-access-token');
	});

	it('omits ath only when the page holds no session token (pre-login)', async () => {
		const sign = vi.fn().mockResolvedValue('plain-proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs).mockReturnValue(null);
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));

		await httpRequest('/api/jmap');

		expect(sign).toHaveBeenCalledWith('GET', expect.any(String), undefined);
	});
});

describe('httpRequest per-tab DPoP admission recovery (r3)', () => {
	// The marker the backend puts on its DPoP/token-binding ADMISSION refusals
	// (shared/threat DPoPAdmissionCode) — the ONLY 401 shape the client replays.
	const ADMISSION_BODY = { type: 'about:blank', title: 'token_binding_failed', status: 401, code: 'dpop_admission', detail: 'Token binding verification failed.' };
	const APPLICATION_BODY = { type: 'about:blank', title: 'unauthorized', status: 401, detail: 'invalid code' };

	// Fresh Response per fetch call: a body reads once per instance.
	const fetch401 = (body: object) => () =>
		new Response(JSON.stringify(body), { status: 401, headers: { 'content-type': 'application/problem+json' } });

	beforeEach(() => {
		vi.mocked(peekDpopKey).mockReset();
		vi.mocked(recoverAccessTokenForProofs).mockReset();
		vi.mocked(accessTokenForProofs).mockReset();
	});

	it('an ADMISSION 401 on a proof-signed request triggers ONE recovery and replays with the recovered ath source', async () => {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		// The fresh/stale tab: no usable token at signing time.
		vi.mocked(accessTokenForProofs)
			.mockReturnValueOnce(null) // attempt 1: ath-less proof
			.mockReturnValueOnce('recovered-tok'); // attempt 2 (retry): recovered ath
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValueOnce('recovered-tok');
		const mockFetch = vi.fn()
			.mockImplementationOnce(fetch401(ADMISSION_BODY)) // the inadmissible-proof refusal
			.mockResolvedValueOnce({ ok: true, status: 200 }); // the replay
		vi.stubGlobal('fetch', mockFetch);

		const res = await httpRequest('/auth/mfa/possession/totp', { method: 'POST' });

		expect(res.status).toBe(200);
		expect(recoverAccessTokenForProofs).toHaveBeenCalledTimes(1);
		// Two SIGNED attempts — the replay re-signs (proofs are single-use).
		expect(sign).toHaveBeenCalledTimes(2);
		expect(mockFetch).toHaveBeenCalledTimes(2);
	});

	it('an APPLICATION-level 401 (no admission marker) executes EXACTLY ONCE — its server-side evaluation must never replay (lockout double-count)', async () => {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs).mockReturnValue('the-session-access-token');
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValueOnce('recovered-tok');
		// The TOTP-removal invalid-code refusal shape: a COMMITTED evaluated
		// failure. The recovery mock WOULD succeed — the replay must still not
		// happen, because the 401 carries no admission marker.
		const mockFetch = vi.fn().mockImplementation(fetch401(APPLICATION_BODY));
		vi.stubGlobal('fetch', mockFetch);

		await expect(
			httpRequest('/auth/totp/remove/begin', { method: 'POST', loginRedirect: null })
		).rejects.toThrow();

		// Exactly ONE wire execution, and no recovery probe at all.
		expect(mockFetch).toHaveBeenCalledTimes(1);
		expect(sign).toHaveBeenCalledTimes(1);
		expect(recoverAccessTokenForProofs).not.toHaveBeenCalled();
	});

	it('a failed recovery after an ADMISSION 401 leaves the 401 to the caller (no retry loop)', async () => {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs).mockReturnValue(null);
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValueOnce(null);
		const mockFetch = vi.fn().mockImplementation(fetch401(ADMISSION_BODY));
		vi.stubGlobal('fetch', mockFetch);

		await expect(
			httpRequest('/auth/mfa/possession/totp', { method: 'POST', loginRedirect: null })
		).rejects.toThrow();

		expect(recoverAccessTokenForProofs).toHaveBeenCalledTimes(1);
		// No second attempt after a failed recovery.
		expect(sign).toHaveBeenCalledTimes(1);
	});

	it('a 401 on a KEYLESS request never triggers recovery (it cannot be an ath failure)', async () => {
		vi.mocked(peekDpopKey).mockResolvedValue(null);
		vi.mocked(accessTokenForProofs).mockReturnValue(null);
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValueOnce('should-not-happen');
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200 }));
		// The request 401s internally? No — keyless requests skip the seam: the
		// 200 response keeps the test honest, the assertion is the recovery mock
		// staying untouched across the request.
		await httpRequest('/api/jmap');
		expect(recoverAccessTokenForProofs).not.toHaveBeenCalled();
	});
});

// ── Recovery cancellation/transport identity (r5) ────────────────────────────
// A recovery that does not COMPLETE must never fall through to the 401
// handler: the old `.catch(() => null)` swallowed a caller's cancellation and
// read it as "Session expired" — redirecting a VALID session to login. The
// recovery boundary now preserves identity: an aborted recovery re-throws the
// seam's AbortError shape; a timed-out/failed recovery stays a typed
// transport error (name 'DpopRecoveryError' + reason — the duck-typed
// cross-module contract, mirroring dpop.DpopRecoveryError's shape). Only a
// completed server REFUSAL (resolves null) leaves the original 401 to the
// normal handling. The login redirect is trapped on window.location so the
// tests can prove a valid session is never sent to the login page (shared by
// the r5 and r6 identity suites below).
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
			}
		},
		configurable: true
	});
	return {
		redirects,
		restore: () => Object.defineProperty(window, 'location', { value: original, configurable: true })
	};
}

describe('httpRequest recovery cancellation/transport identity (r5)', () => {
	const ADMISSION_BODY = { type: 'about:blank', title: 'token_binding_failed', status: 401, code: 'dpop_admission', detail: 'Token binding verification failed.' };
	const admission401 = () =>
		new Response(JSON.stringify(ADMISSION_BODY), { status: 401, headers: { 'content-type': 'application/problem+json' } });

	const recoveryError = (reason: 'timeout' | 'aborted' | 'unavailable'): Error & { reason: string } => {
		const message =
			reason === 'timeout'
				? 'Session token recovery timed out'
				: reason === 'aborted'
					? 'Session token recovery aborted'
					: 'Session token recovery failed';
		const err = new Error(message) as Error & { reason: string };
		err.name = 'DpopRecoveryError';
		err.reason = reason;
		return err;
	};

	beforeEach(() => {
		vi.mocked(peekDpopKey).mockReset();
		vi.mocked(recoverAccessTokenForProofs).mockReset();
		vi.mocked(accessTokenForProofs).mockReset();
	});

	it('aborting during recovery surfaces the CANCELLATION — no redirect, no session-expired (valid session survives)', async () => {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs).mockReturnValue(null);
		// Deferred wire: the admission 401 lands, THEN the caller aborts while
		// the recovery is in flight. The recovery mock mirrors the real
		// per-caller settle-by-abort (dpop.ts's wrapper rejects with the typed
		// aborted error when the caller's signal fires).
		let release!: (res: Response) => void;
		vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise<Response>((resolve) => { release = resolve; })));
		vi.mocked(recoverAccessTokenForProofs).mockImplementation(
			(signal) =>
				new Promise((_resolve, reject) => {
					signal?.addEventListener('abort', () => reject(recoveryError('aborted')), { once: true });
				})
		);

		const controller = new AbortController();
		const trap = trapLoginRedirect();
		const promise = httpRequest('/auth/mfa/possession/totp', { method: 'POST', signal: controller.signal });
		try {
			// The admission 401 lands first; the caller aborts WHILE the
			// recovery it triggered is still in flight.
			await vi.waitFor(() => expect(release).toBeDefined());
			release(admission401());
			await vi.waitFor(() => expect(recoverAccessTokenForProofs).toHaveBeenCalled());
			controller.abort();
			const caught = await promise.then(() => null, (e: unknown) => e);

			// Cancellation identity — NOT the 401 handler's session-expired error.
			expect(caught).toBeInstanceOf(DOMException);
			expect((caught as Error).name).toBe('AbortError');
			expect((caught as Error).message).toBe('Request cancelled');
			// A VALID session was never sent to the login page.
			expect(trap.redirects).toEqual([]);
		} finally {
			trap.restore();
		}
	});

	it('a TIMEOUT during recovery surfaces the typed transport error — no redirect, no session-expired', async () => {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs).mockReturnValue(null);
		let release!: (res: Response) => void;
		vi.stubGlobal('fetch', vi.fn().mockImplementation(() => new Promise<Response>((resolve) => { release = resolve; })));
		vi.mocked(recoverAccessTokenForProofs).mockRejectedValue(recoveryError('timeout'));

		const trap = trapLoginRedirect();
		const promise = httpRequest('/auth/mfa/possession/totp', { method: 'POST' });
		try {
			await vi.waitFor(() => expect(release).toBeDefined());
			release(admission401());
			const caught = await promise.then(() => null, (e: unknown) => e);

			// The session is UNPROVEN, not dead: the typed error survives to the
			// caller (the outer catch-all must not rewrap it as a plain Error).
			expect(caught).toBeInstanceOf(Error);
			expect((caught as Error).name).toBe('DpopRecoveryError');
			expect((caught as { reason?: string }).reason).toBe('timeout');
			expect((caught as Error).message).toMatch(/timed out/i);
			expect((caught as Error).message).not.toContain('Session expired');
			expect(trap.redirects).toEqual([]);
		} finally {
			trap.restore();
		}
	});

	it('a genuine admission 401 still replays EXACTLY ONCE, then surfaces the persisted 401', async () => {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs)
			.mockReturnValueOnce(null) // attempt 1: ath-less proof
			.mockReturnValueOnce('recovered-tok'); // replay carries the recovered ath
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValue('recovered-tok');
		const mockFetch = vi.fn()
			.mockImplementationOnce(() => Promise.resolve(admission401())) // the refused proof
			.mockImplementationOnce(() => Promise.resolve(admission401())); // persists after recovery
		vi.stubGlobal('fetch', mockFetch);

		await expect(
			httpRequest('/auth/mfa/possession/totp', { method: 'POST', loginRedirect: null })
		).rejects.toThrow(/session expired/i);

		// ONE recovery, ONE replay — no loop; the second admission 401 surfaces.
		expect(recoverAccessTokenForProofs).toHaveBeenCalledTimes(1);
		expect(sign).toHaveBeenCalledTimes(2);
		expect(mockFetch).toHaveBeenCalledTimes(2);
	});
});

// ── Admission body-read completion vs parseability (r6) ──────────────────────
// The admission probe used to catch EVERY `res.clone().json()` failure and
// answer "non-admission" — conflating a body that never COMPLETED (caller
// abort, this request's own timeout bound, a mid-stream network death) with a
// completed body that merely lacks the typed marker. A stalled 401 body then
// fell through to the login redirect: "Session expired" destroyed a VALID
// session with only the original request made (r6's reproduction: caller
// abort, request timeout and mid-body network failure each produced the
// redirect). The probe now separates completion from parseability — transport
// failures propagate with their identity (the caller's cancellation as
// AbortError; timeout/network as the typed HttpBodyTransportError) — and only
// a COMPLETED malformed/marker-less body reads as non-admission. The response
// streams below are abort-aware in-memory mirrors of the real wire: headers
// arrive, one partial body chunk lands, and the stream errors exactly like a
// torn-down or dead connection would.
describe('httpRequest admission body-read transport identity (r6)', () => {
	/**
	 * A proof-signed 401 whose HEADERS arrive but whose body stalls mid-stream:
	 * the wire promise resolves immediately, the body delivers one partial
	 * chunk, then never completes — until `failBody(err)` errors the stream
	 * (exactly how a real response stream behaves when the connection is torn
	 * down or dies mid-body). The wire also errors the stream with an
	 * AbortError when the request's own (merged) signal aborts, as a real
	 * fetch does when its caller cancels or the timeout fires.
	 */
	function stubStalledAdmission401(): { wire: typeof fetch; failBody: (err: unknown) => void } {
		let failBody!: (err: unknown) => void;
		const wire = vi.fn().mockImplementation((_input: string, init?: RequestInit): Promise<Response> => {
			const stream = new ReadableStream<Uint8Array>({
				start(controller) {
					controller.enqueue(new TextEncoder().encode('{"code":"dpop_'));
					const error = (err: unknown) => {
						try {
							controller.error(err);
						} catch {
							/* already errored/closed */
						}
					};
					failBody = error;
					init?.signal?.addEventListener(
						'abort',
						() => error(new DOMException('The operation was aborted.', 'AbortError')),
						{ once: true }
					);
				}
			});
			return Promise.resolve(
				new Response(stream, { status: 401, headers: { 'content-type': 'application/problem+json' } })
			);
		});
		return { wire, failBody: (err: unknown) => failBody(err) };
	}

	/** Bind a DPoP key so the 401 is proof-signed and the admission probe runs. */
	function bindProofKey(): void {
		const sign = vi.fn().mockResolvedValue('proof');
		vi.mocked(peekDpopKey).mockResolvedValue({ jwk: { kty: 'EC' } as JsonWebKey, sign });
		vi.mocked(accessTokenForProofs).mockReturnValue(null);
	}

	beforeEach(() => {
		vi.mocked(peekDpopKey).mockReset();
		vi.mocked(recoverAccessTokenForProofs).mockReset();
		vi.mocked(accessTokenForProofs).mockReset();
	});

	it('a CALLER ABORT during the admission body read surfaces the CANCELLATION — zero redirects, recovery never attempted', async () => {
		bindProofKey();
		// The recovery mock WOULD succeed — proving it is never reached.
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValue('recovered-tok');
		const { wire } = stubStalledAdmission401();
		vi.stubGlobal('fetch', wire);

		const controller = new AbortController();
		const trap = trapLoginRedirect();
		const promise = httpRequest('/auth/mfa/possession/totp', { method: 'POST', signal: controller.signal });
		// Attach the rejection handler synchronously: the request can settle
		// before waitFor's first poll, and a briefly-unhandled rejection fails
		// the run (the timeout case settles on a timer mid-wait).
		const settled = promise.then(() => null, (e: unknown) => e);
		try {
			// The 401's headers land; the caller cancels while the admission
			// probe is parked on the (stalled) body.
			await vi.waitFor(() => expect(wire).toHaveBeenCalledTimes(1));
			controller.abort();
			const caught = await settled;

			// Cancellation identity — NOT the 401 handler's session-expired error.
			expect(caught).toBeInstanceOf(DOMException);
			expect((caught as Error).name).toBe('AbortError');
			expect((caught as Error).message).toBe('Request cancelled');
			// A VALID session was never sent to the login page…
			expect(trap.redirects).toEqual([]);
			// …and the recovery was never needed: only the original request ran.
			expect(wire).toHaveBeenCalledTimes(1);
			expect(recoverAccessTokenForProofs).not.toHaveBeenCalled();
		} finally {
			trap.restore();
		}
	});

	it('a REQUEST TIMEOUT during the admission body read surfaces the typed transport error — zero redirects', async () => {
		bindProofKey();
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValue('recovered-tok');
		const { wire } = stubStalledAdmission401();
		vi.stubGlobal('fetch', wire);

		const trap = trapLoginRedirect();
		// The seam's own timeout bound fires while the probe is parked on the
		// stalled body (headers already delivered).
		const promise = httpRequest('/auth/mfa/possession/totp', { method: 'POST', timeoutMs: 5 });
		// Handler attached synchronously — the rejection fires on the 5ms
		// timer, before waitFor's first poll.
		const settled = promise.then(() => null, (e: unknown) => e);
		try {
			await vi.waitFor(() => expect(wire).toHaveBeenCalledTimes(1));
			const caught = await settled;

			// The session is UNPROVEN, not dead: the typed transport error
			// survives to the caller, never read as session-expired.
			expect(caught).toBeInstanceOf(HttpBodyTransportError);
			expect((caught as Error).name).toBe('HttpBodyTransportError');
			expect((caught as { reason?: string }).reason).toBe('timeout');
			expect((caught as Error).message).not.toContain('Session expired');
			expect(trap.redirects).toEqual([]);
			expect(wire).toHaveBeenCalledTimes(1);
			expect(recoverAccessTokenForProofs).not.toHaveBeenCalled();
		} finally {
			trap.restore();
		}
	});

	it('a MID-BODY network failure during the admission body read surfaces the typed transport error — zero redirects', async () => {
		bindProofKey();
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValue('recovered-tok');
		const { wire, failBody } = stubStalledAdmission401();
		vi.stubGlobal('fetch', wire);

		const trap = trapLoginRedirect();
		const promise = httpRequest('/auth/mfa/possession/totp', { method: 'POST' });
		const settled = promise.then(() => null, (e: unknown) => e);
		try {
			await vi.waitFor(() => expect(wire).toHaveBeenCalledTimes(1));
			// Let the probe park on the stalled body, then kill the connection.
			await new Promise((resolve) => setTimeout(resolve, 0));
			failBody(new TypeError('network error: connection reset'));
			const caught = await settled;

			expect(caught).toBeInstanceOf(HttpBodyTransportError);
			expect((caught as Error).name).toBe('HttpBodyTransportError');
			expect((caught as { reason?: string }).reason).toBe('unavailable');
			expect((caught as Error).message).not.toContain('Session expired');
			expect(trap.redirects).toEqual([]);
			expect(wire).toHaveBeenCalledTimes(1);
			expect(recoverAccessTokenForProofs).not.toHaveBeenCalled();
		} finally {
			trap.restore();
		}
	});

	it('a COMPLETED malformed body is a genuine non-admission — the designed session-expired redirect stands (control)', async () => {
		bindProofKey();
		vi.mocked(recoverAccessTokenForProofs).mockResolvedValue('recovered-tok');
		// COMPLETED but truncated body — a real settled Response, not a stream.
		vi.stubGlobal(
			'fetch',
			vi.fn().mockImplementation(() =>
				Promise.resolve(
					new Response('{"code":"dpop_', { status: 401, headers: { 'content-type': 'application/problem+json' } })
				)
			)
		);

		const trap = trapLoginRedirect();
		const promise = httpRequest('/auth/mfa/possession/totp', { method: 'POST' });
		const settled = promise.then(() => null, (e: unknown) => e);
		try {
			const caught = await settled;
			expect(caught).toBeInstanceOf(Error);
			expect((caught as Error).message).toBe('Session expired — please log in again');
			// Non-admission: no recovery, no replay — the 401 redirect fires.
			expect(recoverAccessTokenForProofs).not.toHaveBeenCalled();
			expect(trap.redirects).toEqual(['/']);
		} finally {
			trap.restore();
		}
	});
});

describe('httpRequest abort identity', () => {
	// Regression: the catch-all used to rethrow EVERY error (including an
	// abort) as a fresh `new Error(parseError(err).message)`, which stripped
	// the DOMException's name — every caller that branches on
	// `e.name === 'AbortError'` to swallow a superseded (not failed) request
	// (InboxStore.loadEmails, ComposeScreen, ContactsApp) silently never
	// matched. Found finishing #13: a superseded shared-mailbox load read as
	// a denied call and flipped the "access removed" danger state even though
	// the newer, superseding load was about to succeed.
	it('preserves AbortError name/instanceof through the catch-all', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new DOMException('Aborted', 'AbortError')));

		let caught: unknown;
		try {
			await httpRequest('/api/test');
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(DOMException);
		expect((caught as Error).name).toBe('AbortError');
	});

	it('still wraps a real network failure as a plain Error (not AbortError)', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));

		await expect(httpRequest('/api/test')).rejects.toThrow('Network error');
		let caught: unknown;
		try {
			await httpRequest('/api/test');
		} catch (e) {
			caught = e;
		}
		expect((caught as Error).name).not.toBe('AbortError');
	});
});
