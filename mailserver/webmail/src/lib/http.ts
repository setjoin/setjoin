// The typed-fetch seam for the webmail client.
//
// This module owns, in exactly one place: an AbortController timeout, optional
// caller-supplied AbortSignal merging, 401/403 auth handling (login redirect),
// non-ok status → a typed error via parseError(), and JSON parsing. The JMAP
// client (jmapCall/loadSession in jmap/client.ts), the admin client
// (adminFetch in admin/client.ts), the AI-assist clients
// (admin/assist.ts + jmap/client.ts assistComplete), the
// session-capabilities load (stores/session.ts), the message-recall call
// (stores/emailActionStore.svelte.ts), and the pre-login auth flows
// (stores/auth.ts) all route through here instead of re-implementing this
// machinery.
//
// Deliberately exempt — login() and loginWithCaptcha() (stores/auth.ts): they
// must READ the response BODY for 401/403/429/202 to do threat / MFA /
// force-password-change parsing, but httpRequest THROWS on those statuses before
// the body is reachable. So those two keep a hand-rolled fetch with their own
// timeout/abort. Everything else funnels through this seam.
//
// See docs/specs/LOADING_STATES.md for the combined loading + error pattern.

import { parseError } from '$lib/errors';
import { touRemediation } from '$lib/stores/touRemediation';
import { riskRemediation } from '$lib/stores/riskRemediation';
import { peekDpopKey, peekDpopKeySync, accessTokenForProofs, recoverAccessTokenForProofs } from '$lib/auth/dpop';

/** Default request timeout (ms). Matches the legacy jmapCall/adminFetch value. */
export const DEFAULT_TIMEOUT_MS = 30000;

export interface HttpOptions extends Omit<RequestInit, 'signal'> {
	/** Caller AbortSignal, merged with the internal timeout controller. */
	signal?: AbortSignal | null;
	/** Override the timeout (ms). Defaults to {@link DEFAULT_TIMEOUT_MS}. */
	timeoutMs?: number;
	/**
	 * Where to redirect the browser on a 401. Defaults to '/'. Pass null to
	 * skip the redirect entirely (the error is still thrown).
	 */
	loginRedirect?: string | null;
	/** Message thrown on a 401 (after the redirect). */
	unauthorizedMessage?: string;
	/**
	 * Message thrown on a 403. When omitted, 403 is treated like any other
	 * non-ok status and flows through {@link HttpOptions.onError}.
	 */
	forbiddenMessage?: string;
	/**
	 * Build the Error message for a non-ok (and non-401/403-handled) response.
	 * Receives the Response so the caller can read status or body. Defaults to
	 * reading the response text. Return value is thrown as a new Error.
	 */
	onError?: (res: Response) => string | Promise<string>;
	/**
	 * HTTP status codes that should be returned as-is rather than thrown.
	 * Use for expected non-2xx responses (e.g. 404 meaning "not found" is valid).
	 */
	allowStatuses?: number[];
}

function responseProblemDetail(body: Record<string, unknown>, status: number): string {
	if (typeof body.detail === 'string') return body.detail;
	if (typeof body.title === 'string') return body.title;
	return `Request failed (${status})`;
}

/**
 * The machine-readable problem `code` the backend's DPoP/token-binding
 * ADMISSION refusals carry (shared/threat's DPoPAdmissionCode — emitted by the
 * gateway's token-binding denies, authserver RequireAuth's binding arm, and
 * the possession endpoints' T1 admission). It is the ONLY 401 shape the
 * per-tab recovery may replay: a live shared session presented an inadmissible
 * per-tab proof, so re-deriving the ath source and re-signing is both safe and
 * idempotent. Any 401 WITHOUT the marker is an application-level refusal whose
 * server-side evaluation has already committed (e.g. the TOTP-removal invalid
 * code, counted toward the factor lockout) and must execute exactly once.
 */
const DPoP_ADMISSION_PROBLEM_CODE = 'dpop_admission';

/**
 * A body-transport failure of the 401 admission probe (r6): the response
 * HEADERS arrived but the body never COMPLETED — this request's own timeout
 * bound fired, or the connection died mid-stream. Typed so the outer catch
 * preserves its identity (like the AbortError and DpopRecoveryError arms): a
 * session that is merely UNPROVEN must never read as the 401 handler's
 * "Session expired" — a login redirect would destroy a valid session.
 */
export class HttpBodyTransportError extends Error {
	/** `timeout` = this request's own bound; `unavailable` = network/mid-stream. */
	readonly reason: 'timeout' | 'unavailable';
	constructor(reason: 'timeout' | 'unavailable', cause?: unknown) {
		super(reason === 'timeout' ? 'Request timed out' : 'Request failed — connection lost', { cause });
		this.name = 'HttpBodyTransportError';
		this.reason = reason;
	}
}

/**
 * Reads the 401 body (via clone — the response itself stays consumable for the
 * caller's error path) and reports whether it is a typed admission refusal.
 *
 * Completion and parseability are checked SEPARATELY (r6): `.json()` on the
 * clone conflates a body that never COMPLETED (abort/timeout/network
 * mid-stream — a TRANSPORT failure) with one that completed but is not the
 * typed marker (a genuine non-admission). The old catch-all answered `false`
 * for BOTH, so a stalled 401 body read as non-admission and a VALID session
 * fell through to the login redirect (r6's reproduction: caller abort,
 * request timeout and mid-body network failure each produced "Session
 * expired" + redirect with only the original request made). Now:
 *
 *   - the caller's cancellation → AbortError (cancellation identity);
 *   - this request's own timeout bound / a mid-stream network failure →
 *     {@link HttpBodyTransportError};
 *   - only a COMPLETED body with malformed or marker-less content → `false`.
 *
 * The identity rules mirror the downstream recovery path (r5, dpop.ts).
 */
async function isDpopAdmissionRefusal(
	res: Response,
	externalSignal: AbortSignal | null | undefined,
	effectiveSignal: AbortSignal
): Promise<boolean> {
	let text: string;
	try {
		// `text()` resolves only when the body COMPLETES; its rejection is the
		// transport failure (all mid-stream failures land here — see the
		// matching split in dpop.ts's recovery body read).
		text = await res.clone().text();
	} catch (err) {
		// Classification order mirrors the recovery block (r5): the caller's
		// cancellation wins, then this request's own timeout bound.
		if (externalSignal?.aborted) {
			throw new DOMException('Request cancelled', 'AbortError');
		}
		if (effectiveSignal.aborted) {
			throw new HttpBodyTransportError('timeout', err);
		}
		if (err instanceof DOMException && err.name === 'AbortError') {
			// An AbortError from the wire without our signals firing is still
			// a cancellation — preserve its identity either way.
			throw new DOMException('Request cancelled', 'AbortError');
		}
		throw new HttpBodyTransportError('unavailable', err);
	}
	try {
		const body = JSON.parse(text) as Record<string, unknown>;
		return body?.code === DPoP_ADMISSION_PROBLEM_CODE;
	} catch {
		// COMPLETED body, unusable content: a genuine non-admission.
		return false;
	}
}

/**
 * Duck-typed recognition of dpop's typed recovery failure. Deliberately NOT an
 * `instanceof DpopRecoveryError`: that would make http.ts hold a hard class
 * reference into $lib/auth/dpop, and every suite that partially mocks that
 * module (stores/auth, meet/api, …) would turn the shared error path below
 * into a `TypeError` on the missing export. The class stamps
 * `name = 'DpopRecoveryError'` and carries a string `reason` (dpop.ts) — that
 * shape IS the cross-module contract.
 */
function asDpopRecoveryError(err: unknown): (Error & { reason: string }) | null {
	if (err instanceof Error && err.name === 'DpopRecoveryError') {
		return err as Error & { reason: string };
	}
	return null;
}

/**
 * Perform an HTTP request with the shared timeout / abort / auth machinery and
 * return the raw {@link Response} on success (2xx). Throws a parseError-shaped
 * Error on timeout, abort, network failure, or non-ok status.
 *
 * Use this for non-JSON success bodies (blob, text, manual JSON parsing).
 * For JSON responses, prefer {@link typedFetch}.
 */
export async function httpRequest(input: string, opts: HttpOptions = {}): Promise<Response> {
	const {
		signal: externalSignal,
		timeoutMs = DEFAULT_TIMEOUT_MS,
		loginRedirect = '/',
		unauthorizedMessage = 'Session expired — please log in again',
		forbiddenMessage,
		onError,
		allowStatuses,
		credentials,
		...init
	} = opts;

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	const effectiveSignal = externalSignal
		? AbortSignal.any([controller.signal, externalSignal])
		: controller.signal;

	try {
		// CA-3a token binding: attach a DPoP proof header when this browser
		// profile has a key bound at login (peekDpopKey never CREATES one — an
		// anonymous/pre-login request stays header-free).
		//
		// ponytail: read the SYNCHRONOUS cache first (peekDpopKeySync) and only
		// `await peekDpopKey()` on the (at most once per page load) cache miss —
		// mirroring jmap/client.ts's `hasCapability('deviceProof')` guard ("an
		// unconditional await asyncFn() yields even on early return, which races
		// with test-controlled mock-fetch resolvers"). An unconditional await here
		// reproduced exactly that race in svelte-component tests using deferred
		// fetch mocks (waitFor timing around loading-state buttons).
		//
		// The send is a closure because the per-tab admission recovery (r3)
		// replays it ONCE after re-deriving the ath source — proofs are
		// single-use, so the replay RE-SIGNS with the recovered token rather
		// than reusing the refused proof.
		let proofSigned = false;
		const wireFetch = (headers: HeadersInit | undefined): Promise<Response> =>
			fetch(input, {
				...init,
				headers,
				credentials: credentials ?? 'include',
				signal: effectiveSignal
			});
		const signedFetch = (dpop: NonNullable<Awaited<ReturnType<typeof peekDpopKey>>>): Promise<Response> =>
			// The only async hop left on a proof-signing send. Deliberately an
			// async IIFE rather than an async sendOnce — see the ponytail note at
			// sendOnce below.
			(async () => {
				const method = (init.method ?? 'GET').toString().toUpperCase();
				// Every call site here passes a root-relative path (never a full
				// absolute URL) — strip any query/hash directly rather than routing
				// through `new URL(input, location.origin)`, whose base is an opaque
				// "null" origin outside a real page load (e.g. jsdom's default
				// about:blank in tests). Must mirror the gateway's htu exactly:
				// "https://" + r.Host + r.URL.Path (runtime_access.go).
				const path = input.split('?')[0].split('#')[0];
				const htu = `https://${location.host}${path}`;
				const headers = new Headers(init.headers);
				// r2 defect 1: proofs for a KNOWN session token carry the RFC 9449
				// ath binding — VerifyDPoPForToken refuses cnf-bound tokens whose
				// proof lacks ath, so the historical ath-less browser shape turned
				// every legitimate cookie-session possession begin/finish into a
				// 401. Token-less pages (pre-login) keep the header shape minus
				// ath; the gateway-side verifier tolerates its absence.
				const token = accessTokenForProofs();
				headers.set('DPoP', await dpop.sign(method, htu, token ?? undefined));
				proofSigned = true;
				return wireFetch(headers);
			})();
		// ponytail (again): sendOnce must NOT be an `async function`. An async
		// wrapper adds one microtask before the wire call on EVERY send — even
		// the keyless fast path — and that extra hop flips the microtask-ordering
		// race described above in svelte-component tests that hand httpRequest a
		// DEFERRED fetch mock: the component's fetch must grab the deferred
		// promise before the test resolves-and-replaces it (observed on the
		// calendar RSVP / device-lockdown / signin-log loading-state suites as a
		// hung "Responding..." state). With the DPoP key state already resolved
		// synchronously — every request after the first of the page — the
		// returned promise IS the fetch promise, byte-identical in timing to the
		// pre-r3 inline `await fetch(...)`.
		const sendOnce = (): Promise<Response> => {
			if (typeof location !== 'undefined') {
				const sync = peekDpopKeySync();
				if (sync !== undefined) return sync ? signedFetch(sync) : wireFetch(init.headers);
				// Cache miss — paid at most once per page load. Promise.resolve
				// mirrors the old `await peekDpopKey()` exactly, including for
				// mocked accessors that return a bare value instead of a promise.
				return Promise.resolve(peekDpopKey()).then((dpop) => (dpop ? signedFetch(dpop) : wireFetch(init.headers)));
			}
			return wireFetch(init.headers);
		};

		let res = await sendOnce();

		// Per-tab DPoP admission recovery (r3): the session cookie is shared
		// across tabs but the ath source is per-tab — a freshly opened tab has
		// no token string at all and a stale tab hashes one another tab's
		// refresh rotated away, so the SERVER refuses the proof (401) with the
		// session itself alive. Before giving up, re-derive this tab's ath
		// source from the shared session (GET /auth/session/token) and replay
		// once. Recovery only fires when a proof was actually signed — a
		// keyless request can never be an ath failure — and ONLY when the 401
		// body carries the backend's typed ADMISSION marker
		// (dpop_admission): an application-level 401 (the TOTP-removal
		// invalid-code refusal, whose evaluated failure has already been
		// committed toward the factor lockout) executes EXACTLY ONCE —
		// replaying it would double-count toward lockout. The recovered
		// source is remembered module-side, so every parallel admission 401
		// shares one recovery fetch.
		// r6: the admission probe separates a COMPLETED non-admission body from
		// a body that never completed (abort/timeout/network mid-stream). A
		// transport failure of the probe propagates with its identity — the
		// whole request settles cancelled/typed BELOW, and the 401 handler
		// (login redirect) is never reached for a session that is merely
		// unproven.
		if (
			res.status === 401 &&
			proofSigned &&
			(await isDpopAdmissionRefusal(res, externalSignal, effectiveSignal))
		) {
			// The caller's cancellation (supersede, unmount, the merged timeout)
			// propagates INTO the recovery: it settles this caller immediately
			// and, when this request owns the in-flight fetch, tears the wire
			// call down. A recovery that does not COMPLETE keeps the caller's
			// cancellation/transport identity — it must never fall through to
			// the 401 handler below (r5: a swallowed cancellation read as
			// "Session expired" and redirected a VALID session to login).
			//
			// Only a completed server REFUSAL (recovery resolves null — the
			// session endpoint answered "no session") leaves the original 401
			// to the normal handling below: there the session is genuinely
			// dead, so the redirect is correct.
			let recovered: string | null;
			try {
				recovered = await recoverAccessTokenForProofs(effectiveSignal);
			} catch (err) {
				const recovery = asDpopRecoveryError(err);
				// Cancellation identity wins: the effective signal carries the
				// caller's supersede/unmount AND this request's own timeout, and
				// the recovery settles typed-aborted for it. Re-throw the same
				// AbortError shape the rest of this seam preserves so callers
				// keep branching on `e.name === 'AbortError'`.
				if (effectiveSignal.aborted || recovery?.reason === 'aborted') {
					throw new DOMException('Request cancelled', 'AbortError');
				}
				// A timeout/network failure of the recovery itself is a typed
				// transport error (DpopRecoveryError), NOT session-expired: the
				// session is unproven, not dead, and a login redirect would
				// destroy it. The outer catch preserves the class identity.
				throw err;
			}
			if (recovered) {
				res = await sendOnce();
			}
		}

		clearTimeout(timeoutId);

		// Expected non-2xx responses are data for the caller. This must precede
		// generic auth redirects/errors so a pre-login probe can distinguish an
		// anonymous 401 from an unavailable server without bypassing this seam.
		if (!res.ok && allowStatuses?.includes(res.status)) return res;

		if (res.status === 401) {
			if (loginRedirect !== null && typeof window !== 'undefined') {
				window.location.href = loginRedirect;
			}
			throw new Error(unauthorizedMessage);
		}
		if (res.status === 403) {
			// Parse remediation hint from the body without consuming res (clone preserves it
			// for the !res.ok fallback / onError path when there's no remediation action).
			let remediation: string | undefined;
			let remediationTouId: number | undefined;
			try {
				const body = await res.clone().json() as Record<string, unknown>;
				if (typeof body.remediation === 'string') remediation = body.remediation;
				if (typeof body.remediation_tou_id === 'number') remediationTouId = body.remediation_tou_id;
			} catch { /* non-JSON 403 or mock without .clone() — fall through */ }

			if (remediation === 'terms') {
				// Signal the layout to mount TermsAcceptance; do NOT just throw.
				touRemediation.set({ pending: true, touId: remediationTouId });
				throw new Error('Terms of use acceptance required');
			}
			if (remediation === 'risk') {
				// Signal the layout to mount RiskRemediation; do NOT just throw.
				let signals: string[] | undefined;
				let correlationId: string | undefined;
				try {
					const rb = await res.clone().json() as Record<string, unknown>;
					if (Array.isArray(rb.signals)) signals = rb.signals as string[];
					if (typeof rb.correlation_id === 'string') correlationId = rb.correlation_id;
				} catch { /* non-JSON body — signals/correlationId stay undefined */ }
				riskRemediation.set({ pending: true, signals, correlationId });
				throw new Error('Risk re-auth required');
			}
			if (forbiddenMessage !== undefined) {
				throw new Error(forbiddenMessage);
			}
			// No remediation + no forbiddenMessage: fall through to !res.ok handler.
		}
		if (!res.ok) {
			// Default to a generic status string — never echo the raw server body
			// (a 500 stack/SQL fragment or a proxy HTML error page) into the UI,
			// which would break errors.ts's "authored messages are display-safe"
			// assumption. Callers opt into reading the body via onError.
			const message = onError
				? await onError(res)
				: `Request failed (${res.status})`;
			throw new Error(message);
		}
		return res;
	} catch (err) {
		clearTimeout(timeoutId);
		// Preserve AbortError identity: callers branch on `e.name === 'AbortError'`
		// to tell an intentional supersede-cancel (a newer call aborted this one)
		// from a real failure (inboxStore's loadEmails, ComposeScreen, ContactsApp).
		// The old code wrapped EVERY error in a fresh `new Error(parseError(err)
		// .message)`, which stripped the DOMException's name — all three checks
		// silently never matched (a superseded in-flight shared-mailbox load read
		// as a denied call and flipped the full-pane "access removed" danger state
		// even though the newer load was about to succeed — bug found finishing
		// #13). Keep parseError's friendly "Request cancelled" text (still a
		// DOMException, so `instanceof DOMException && name==='AbortError'` and
		// `.message` both hold) rather than the raw browser string ("The
		// operation was aborted") — display code reads the message directly.
		if (err instanceof DOMException && err.name === 'AbortError') {
			// DOMException has no ErrorOptions/cause constructor; preserve its name.
			throw new DOMException(parseError(err).message, 'AbortError');
		}
		// The recovery's typed transport failure keeps its identity + reason
		// (the recovery block above relies on this to never read as
		// session-expired), exactly like the AbortError arm above.
		if (asDpopRecoveryError(err)) throw err;
		// The admission probe's typed body-transport failure (r6) likewise
		// keeps its identity — a body that never completed is never
		// session-expired, and the redirect must not fire on it.
		if (err instanceof HttpBodyTransportError) throw err;
		// Callers consume the normalized transport message, not the raw body/error.
		// eslint-disable-next-line preserve-caught-error
		throw new Error(parseError(err).message);
	}
}

/**
 * Perform an HTTP request and parse the JSON body as {@code T}. Wraps
 * {@link httpRequest} with the same timeout / abort / auth / error handling and
 * adds JSON parsing of the success body.
 */
export async function typedFetch<T>(input: string, opts: HttpOptions = {}): Promise<T> {
	const res = await httpRequest(input, opts);
	try {
		return (await res.json()) as T;
	} catch (err) {
		// JSON parse failures are normalized to the same public transport error.
		// eslint-disable-next-line preserve-caught-error
		throw new Error(parseError(err).message);
	}
}

// ── RFC 7807 problem transport (arch review #A1) ────────────────────────────
//
// chat/meet/drive each reimplemented this ~80-line seam verbatim (ChatError/
// MeetError/DriveError + problemOnError + decodeProblem + xFetch/xFetchVoid,
// differing only in DriveError's holderId field): httpRequest's outer catch
// above always rewraps a thrown error as `new Error(parseError(err).message)`
// (parseError passes an Error's own .message through unchanged — see
// $lib/errors.ts), which erases a thrown ProblemError's subclass identity.
// So `onError` instead returns the RFC 7807 body JSON-encoded as the message
// string, and problemFetch's returned fetch/fetchVoid decode it back into a
// ProblemError on the way out. ponytail: string-encode-and-decode beats
// forking httpRequest.

const PROBLEM_STANDARD_FIELDS = new Set(['type', 'title', 'status', 'detail', 'instance', 'code']);

export interface ProblemShape {
	status: number;
	code: string;
	detail: string;
	/** Extension members beyond the RFC 7807 standard fields — e.g. drive's
	 *  BZ149 `holderId` (problem.go's `HolderID` extension). Omitted/empty for
	 *  a caller with no extensions of its own (every direct `new
	 *  ProblemError({status,code,detail})` construction, e.g. test fixtures). */
	extensions?: Record<string, unknown>;
}

export class ProblemError extends Error {
	status: number;
	code: string;
	detail: string;
	extensions: Record<string, unknown>;
	constructor(shape: ProblemShape) {
		super(shape.detail);
		this.status = shape.status;
		this.code = shape.code;
		this.detail = shape.detail;
		this.extensions = shape.extensions ?? {};
	}
}

async function problemOnError(res: Response): Promise<string> {
	const body = (await res.json().catch(() => ({}))) as Record<string, unknown> & {
		detail?: string;
		code?: string;
		title?: string;
	};
	const extensions: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(body)) {
		if (!PROBLEM_STANDARD_FIELDS.has(k)) extensions[k] = v;
	}
	const shape: ProblemShape = {
		status: res.status,
		code: typeof body.code === 'string' ? body.code : '',
		detail: responseProblemDetail(body, res.status),
		extensions,
	};
	return JSON.stringify(shape);
}

function decodeProblem(message: string): ProblemShape | null {
	try {
		const p = JSON.parse(message) as Partial<ProblemShape>;
		if (typeof p.status === 'number' && typeof p.detail === 'string') return { extensions: {}, ...p } as ProblemShape;
	} catch {
		/* not our encoded problem — a network/timeout/auth error, pass through as-is */
	}
	return null;
}

/**
 * Binds a `/api/<area>` base path to a `{fetch, fetchVoid, fetchResponse}` set that decode
 * a non-ok response into a {@link ProblemError} instead of a generic Error —
 * the one seam chat/meet/drive's api.ts modules now share (previously three
 * verbatim copies). Callers branch on `.code`/`.status`/`.extensions`.
 */
export function problemFetch(base: string): {
	fetch: <T>(path: string, opts?: HttpOptions) => Promise<T>;
	fetchVoid: (path: string, opts?: HttpOptions) => Promise<void>;
	fetchResponse: (path: string, opts?: HttpOptions) => Promise<Response>;
} {
	return {
		async fetch<T>(path: string, opts: HttpOptions = {}): Promise<T> {
			try {
				return await typedFetch<T>(base + path, { ...opts, onError: problemOnError });
			} catch (err) {
				if (err instanceof Error) {
					const shape = decodeProblem(err.message);
					if (shape) throw new ProblemError(shape);
				}
				throw err;
			}
		},
		async fetchVoid(path: string, opts: HttpOptions = {}): Promise<void> {
			try {
				await httpRequest(base + path, { ...opts, onError: problemOnError });
			} catch (err) {
				if (err instanceof Error) {
					const shape = decodeProblem(err.message);
					if (shape) throw new ProblemError(shape);
				}
				throw err;
			}
		},
		async fetchResponse(path: string, opts: HttpOptions = {}): Promise<Response> {
			try {
				return await httpRequest(base + path, { ...opts, onError: problemOnError });
			} catch (err) {
				if (err instanceof Error) {
					const shape = decodeProblem(err.message);
					if (shape) throw new ProblemError(shape);
				}
				throw err;
			}
		},
	};
}
