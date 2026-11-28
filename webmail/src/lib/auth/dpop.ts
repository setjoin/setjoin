// DPoP (RFC 9449) software-key binding for the web client. The private key is
// non-extractable (WebCrypto); only the public JWK leaves the page (at login,
// as cnf). Defeats off-device token replay — NOT in-page XSS (see spec §9).
//
// The keypair is persisted in IndexedDB — a non-extractable CryptoKey object is
// still structured-clonable (the WebCrypto spec allows storing the CryptoKey
// object itself; only exportKey() on the raw material is blocked), so a page
// reload keeps signing proofs with the SAME key the server bound cnf.jkt to at
// login. getOrCreateDpopKey() (create-or-reuse, used by login) and peekDpopKey()
// (reuse-only, used by the http client so an anonymous request never triggers
// key generation) share one cached in-memory promise on top of that store.
import { bufferToBase64url } from '$lib/util/base64url';

export function publicJwkForCnf(jwk: JsonWebKey): JsonWebKey {
	return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

export interface DpopKey {
	jwk: JsonWebKey;
	/**
	 * Signs a DPoP proof for htm/htu. `ath` is the RFC 9449 §4.3
	 * access-token binding: whenever the session's access token is known, the
	 * proof MUST carry `ath = base64url(SHA-256(token))` — the server-side
	 * verifier (VerifyDPoPForToken) refuses cnf-bound token presentations
	 * whose proof lacks it. r2 defect 1: the historical ath-less browser
	 * shape turned every legitimate cookie-session possession
	 * begin/finish into a 401. Omitted only when no access token is known to
	 * the page (pre-login, or an unbound token).
	 */
	sign: (htm: string, htu: string, ath?: string) => Promise<string>;
}

// ── Access-token retention for the ath claim ────────────────────────────────
//
// ath = base64url(SHA-256(access token)), so the browser must KNOW the token
// string to mint an admissible proof. The token arrives in the login/verify/
// refresh response bodies (the SPA's cookie is HttpOnly and unreadable), so
// the responses that (re-)establish a session remember it here, and http.ts
// feeds it to sign(). sessionStorage (not localStorage): per-tab lifetime —
// a fresh tab re-derives the session server-side, and the proof's jkt binds
// every proof to THIS profile's key regardless.
//
// Threat note (spec §9): this does not widen the XSS surface in any
// meaningful way — an XSS that can read sessionStorage already runs in the
// page and can call the signing key directly. ath binds the PROOF to the
// TOKEN so a captured proof alone cannot be replayed with another token
// (and a captured token without a proof cannot bind a ceremony).

const ACCESS_TOKEN_STORAGE_KEY = 'sj-dpop-access-token';

let cachedAccessToken: string | null | undefined;

/**
 * Remembers the session's access token (the login/verify/refresh response
 * body's access_token member) so DPoP proofs can carry the RFC 9449 ath
 * binding the server verifier enforces. Pass null to forget (logout).
 */
export function rememberAccessTokenForProofs(token: string | null): void {
	cachedAccessToken = token && token.length > 0 ? token : null;
	try {
		if (cachedAccessToken === null) {
			sessionStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
		} else {
			sessionStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, cachedAccessToken);
		}
	} catch {
		// sessionStorage unavailable (private mode, sandboxed iframe): the
		// in-memory value still covers this page load's proofs.
	}
}

/**
 * The remembered access token for ath computation, or null when the page has
 * none (pre-login, cleared at logout, or a storage failure with no in-memory
 * value). Backed by the in-memory cache, falling back to sessionStorage for a
 * reloaded tab.
 */
export function accessTokenForProofs(): string | null {
	if (cachedAccessToken !== undefined) return cachedAccessToken;
	try {
		cachedAccessToken = sessionStorage.getItem(ACCESS_TOKEN_STORAGE_KEY);
	} catch {
		cachedAccessToken = null;
	}
	return cachedAccessToken;
}

// ── Per-tab admission recovery (r3) ─────────────────────────────────────────
//
// The session cookie is shared by every tab of the browser profile, but THIS
// cache is per tab: a freshly opened tab holds the cookie and the persisted
// signing key yet NO token (its ath-less proofs are inadmissible for a
// cnf-bound session), and a stale tab hashes a token another tab's refresh
// already rotated away — both fail authentication with no way back. GET
// /auth/session/token is the synchronization point: the authserver hands the
// PRESENTED token string back through an admission funnel that enforces
// everything EXCEPT the ath claim (a cnf-bound token still requires a DPoP
// proof bound to its cnf.jkt — VerifyDPoP's documented caller class), so the
// tab re-derives its ath source without minting or rotating anything (the
// other tabs' view of the session is untouched).

const SESSION_TOKEN_PATH = '/auth/session/token';

/**
 * The recovery fetch is hard-bounded: the caller of the request that triggered
 * it is already showing a failure, so an endpoint that never answers must not
 * stretch the wait past this bound (AbortSignal.timeout). Deliberately well
 * under the http seam's DEFAULT_TIMEOUT_MS.
 */
export const RECOVERY_TIMEOUT_MS = 10_000;

/** Call-time holder for the bound — fresh-module tests shrink it so the REAL
 *  AbortSignal.timeout timer fires inside the test (no clock faking, no
 *  cross-realm event synthesis). */
export const recoveryTimeout = { ms: RECOVERY_TIMEOUT_MS };

/** Why a recovery failed. `aborted` = a CALLER's cancellation; `timeout` = the
 *  recovery's own hard bound; `unavailable` = a network/transport failure. */
export type DpopRecoveryFailure = 'timeout' | 'aborted' | 'unavailable';

/**
 * The typed error a failed/stalled recovery settles with. The shared in-flight
 * recovery rejects with ONE instance-shaped error (timeout, network) so EVERY
 * waiting caller settles instead of hanging on a stalled promise; a caller
 * whose own AbortSignal fires settles with `reason: 'aborted'` even while
 * sharing a recovery it did not start.
 */
export class DpopRecoveryError extends Error {
	readonly reason: DpopRecoveryFailure;
	constructor(reason: DpopRecoveryFailure, cause?: unknown) {
		super(
			reason === 'timeout'
				? 'Session token recovery timed out'
				: reason === 'aborted'
					? 'Session token recovery aborted'
					: 'Session token recovery failed',
			{ cause }
		);
		this.name = 'DpopRecoveryError';
		this.reason = reason;
	}
}

let recoveryInFlight: Promise<string | null> | null = null;

// ── Rotation observers (r4 §3.1 lifecycle fencing) ──────────────────────────
//
// The recovery is the one token (re)bind that does NOT flow through the auth
// store: a stale tab whose shared-cookie token was rotated away by another tab
// discovers the rotation HERE, mid-request. Consumers fence pending
// ceremony/grant state on the auth generation (the retire path refreshSession
// uses for exactly this "token rotated under the page" case), so the recovery
// notifies registered observers whenever it lands a token DIFFERENT from the
// one this page remembered (a first bind on a freshly opened tab — no previous
// token — is not a rotation and notifies nothing).
type AccessTokenRotationObserver = (previous: string, recovered: string) => void;
const rotationObservers = new Set<AccessTokenRotationObserver>();

/**
 * Registers a callback fired when the recovery discovers the shared session's
 * token has rotated under this page (recovered !== previously remembered).
 * auth.ts subscribes bumpAuthGeneration here — the same retire path a
 * /auth/refresh rotation drives. Returns the unregister function.
 */
export function onRecoveredAccessTokenRotation(observer: AccessTokenRotationObserver): () => void {
	rotationObservers.add(observer);
	return () => rotationObservers.delete(observer);
}

function notifyRecoveredRotation(previous: string, recovered: string): void {
	for (const observer of rotationObservers) {
		try {
			observer(previous, recovered);
		} catch {
			// A broken observer must never fail the recovery itself.
		}
	}
}

/**
 * Recovers this tab's ath source from the shared session: GET
 * /auth/session/token presents the ambient cookie plus an ath-less DPoP
 * proof bound to the profile's key, and the response's access_token — the
 * very token this tab has been carrying — becomes the remembered source.
 * Concurrent callers share one fetch. Settles:
 *
 *   - token string — recovery succeeded;
 *   - `null` — the server answered and refused (no session, or a COMPLETED
 *     body with unusable content — non-JSON, empty, no token member): a clean
 *     "nothing to recover", the cache untouched;
 *   - {@link DpopRecoveryError} — the fetch or its response BODY failed to
 *     complete (network, the {@link RECOVERY_TIMEOUT_MS} bound, or THIS
 *     caller's `signal` aborting). The shared in-flight promise carries the
 *     same typed error, so a stalled or failed recovery settles every waiter
 *     — nobody is left behind on a promise that never resolves, and a stalled
 *     body never masquerades as a server refusal.
 *
 * The FIRST caller's `signal` is folded into the wire fetch's abort set
 * (alongside the timeout), so its cancellation genuinely tears down the
 * in-flight request; later callers sharing the in-flight fetch keep their
 * own settle-by-abort without killing the fetch for the others. Unlike
 * {@link accessTokenForProofs} this ALWAYS goes to the wire: the stale-token
 * case has a non-empty cache and still needs the server's current string.
 */
export function recoverAccessTokenForProofs(signal?: AbortSignal): Promise<string | null> {
	// A caller that has already cancelled settles immediately — it must not
	// start (or join, with a dead signal folded into) the shared wire fetch.
	if (signal?.aborted) return Promise.reject(new DpopRecoveryError('aborted'));
	if (!recoveryInFlight) {
		const timeout = AbortSignal.timeout(recoveryTimeout.ms);
		const wire = signal ? AbortSignal.any([timeout, signal]) : timeout;
		recoveryInFlight = (async () => {
			try {
				const headers: Record<string, string> = {};
				const key = await peekDpopKey();
				if (key) {
					// ath-less by construction: the token string is what this call
					// recovers; the server's recovery admission binds the proof to
					// cnf.jkt without the ath claim. The htu mirrors http.ts's
					// signing (client-facing scheme + host + path).
					headers['DPoP'] = await key.sign('GET', `https://${location.host}${SESSION_TOKEN_PATH}`);
				}
				const res = await fetch(SESSION_TOKEN_PATH, {
					method: 'GET',
					headers,
					credentials: 'include',
					signal: wire
				});
				if (!res.ok) return null;
				// Error contract (r5): a COMPLETED body with unusable content is
				// the server-refusal shape (resolve null below), while a body
				// that never completes — abort/timeout/network mid-stream — is a
				// TRANSPORT failure that must reject the shared promise with the
				// typed error. The old `res.json().catch(() => null)` swallowed
				// the distinction: a 200 whose body stalled to the bound made
				// every waiter FULFILL with null (a fake refusal) instead of
				// rejecting typed. Completion and parseability are therefore
				// checked SEPARATELY: res.text() rejects only when the body does
				// not complete (its rejection falls into the shared
				// classification below — signal aborted > bound > unavailable;
				// note "already read"/mid-stream failures and network errors are
				// all TypeErrors here, and ALL of them are loud), and only a
				// resolved string goes to JSON.parse, whose SyntaxError means
				// the body completed but carries no usable token.
				let data: { access_token?: unknown } | null = null;
				try {
					data = JSON.parse(await res.text()) as { access_token?: unknown };
				} catch (err) {
					if (!(err instanceof SyntaxError)) throw err;
				}
				const token = typeof data?.access_token === 'string' ? data.access_token : '';
				if (!token) return null;
				const previous = accessTokenForProofs();
				rememberAccessTokenForProofs(token);
				// A DIFFERENT token means the shared cookie rotated under this
				// page while it held a stale ath source: notify lifecycle
				// consumers (auth.ts bumps the auth generation — the same retire
				// path a refresh rotation drives). A first bind (no previous
				// token) and a same-token re-read notify nothing.
				if (previous && previous !== token) notifyRecoveredRotation(previous, token);
				return token;
			} catch (err) {
				// Classification: the caller's cancellation wins over the bound,
				// the bound over generic transport failure. The shared promise
				// rejects with the typed error so ALL waiters settle.
				if (signal?.aborted) throw new DpopRecoveryError('aborted', err);
				if (timeout.aborted) throw new DpopRecoveryError('timeout', err);
				throw new DpopRecoveryError('unavailable', err);
			} finally {
				recoveryInFlight = null;
			}
		})();
	}
	// Per-caller settle-by-abort: a caller that cancelled while sharing a
	// recovery it did not start must not wait out the shared fetch (bounded
	// only by the timeout). Its own signal settles it immediately; the shared
	// fetch keeps running for the remaining waiters.
	if (!signal) return recoveryInFlight;
	const shared = recoveryInFlight;
	if (signal.aborted) return Promise.reject(new DpopRecoveryError('aborted'));
	return new Promise<string | null>((resolve, reject) => {
		const onAbort = () => reject(new DpopRecoveryError('aborted'));
		signal.addEventListener('abort', onAbort, { once: true });
		shared.then(
			(value) => {
				signal.removeEventListener('abort', onAbort);
				resolve(value);
			},
			(err) => {
				signal.removeEventListener('abort', onAbort);
				reject(err);
			}
		);
	});
}

function signer(privateKey: CryptoKey, jwk: JsonWebKey): DpopKey['sign'] {
	return async (htm: string, htu: string, ath?: string): Promise<string> => {
		const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwkForCnf(jwk) };
		const payload: Record<string, unknown> = {
			htm,
			htu,
			iat: Math.floor(Date.now() / 1000),
			jti: crypto.randomUUID()
		};
		if (ath !== undefined) {
			payload.ath = bufferToBase64url(
				await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ath))
			);
		}
		const enc = (o: unknown) =>
			bufferToBase64url(new TextEncoder().encode(JSON.stringify(o)).buffer as ArrayBuffer);
		const signingInput = `${enc(header)}.${enc(payload)}`;
		const sig = await crypto.subtle.sign(
			{ name: 'ECDSA', hash: 'SHA-256' },
			privateKey,
			new TextEncoder().encode(signingInput)
		);
		return `${signingInput}.${bufferToBase64url(sig)}`;
	};
}

async function generateKeyPair(): Promise<{ pair: CryptoKeyPair; jwk: JsonWebKey }> {
	const pair = await crypto.subtle.generateKey(
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false, // ponytail: non-extractable private key — never leaves the browser key store
		['sign']
	);
	const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
	return { pair, jwk };
}

/** Generates a fresh (unpersisted) key. Kept for direct unit testing of the
 *  crypto shape; production code should use getOrCreateDpopKey/peekDpopKey. */
export async function generateDpopKey(): Promise<DpopKey> {
	const { pair, jwk } = await generateKeyPair();
	return { jwk, sign: signer(pair.privateKey, jwk) };
}

// --- Persistence (IndexedDB) ------------------------------------------------

const DB_NAME = 'setjoin_dpop';
const STORE_NAME = 'keys';
const RECORD_ID = 'dpop-keypair';

interface StoredEntry {
	pair: CryptoKeyPair;
	jwk: JsonWebKey;
}

function openDpopDB(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, 1);
		req.onerror = () => reject(req.error);
		req.onsuccess = () => resolve(req.result);
		req.onupgradeneeded = (e) => {
			(e.target as IDBOpenDBRequest).result.createObjectStore(STORE_NAME);
		};
	});
}

async function loadStoredEntry(): Promise<StoredEntry | null> {
	const db = await openDpopDB();
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readonly');
		const req = tx.objectStore(STORE_NAME).get(RECORD_ID);
		req.onsuccess = () => resolve((req.result as StoredEntry | undefined) ?? null);
		req.onerror = () => reject(req.error);
	});
}

async function storeEntry(entry: StoredEntry): Promise<void> {
	const db = await openDpopDB();
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		tx.objectStore(STORE_NAME).put(entry, RECORD_ID);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}

async function deleteStoredEntry(): Promise<void> {
	if (typeof indexedDB === 'undefined') return;
	const db = await openDpopDB();
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		tx.objectStore(STORE_NAME).delete(RECORD_ID);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}

// `resolvedKey` is the synchronous source of truth once known this page load:
// `undefined` = not yet checked; `null` = checked, no key; a DpopKey = bound.
// http.ts's per-request hot path reads it via peekDpopKeySync() with NO await —
// mirroring jmap/client.ts's `hasCapability('deviceProof')` guard (see its
// comment: "an unconditional await asyncFn() yields even on early return, which
// races with test-controlled mock-fetch resolvers"). Paying an unconditional
// microtask on every request reproduces exactly that race in svelte
// component tests (deferred-promise fetch mocks + waitFor timing). The async
// IndexedDB check happens (at most) once per page load, memoized in `pending`.
let resolvedKey: DpopKey | null | undefined;
let pending: Promise<DpopKey | null> | null = null;

function resolveKey(): Promise<DpopKey | null> {
	if (!pending) {
		pending = (typeof indexedDB === 'undefined' ? Promise.resolve(null) : loadStoredEntry())
			.then((entry) => (entry ? { jwk: entry.jwk, sign: signer(entry.pair.privateKey, entry.jwk) } : null))
			.catch(() => null)
			.then((key) => {
				resolvedKey = key;
				return key;
			});
	}
	return pending;
}

/**
 * Returns the persisted DPoP key for this browser profile if one already
 * exists, WITHOUT creating one. Used by the http client so a pre-login /
 * anonymous request never triggers key generation — only login does that
 * (getOrCreateDpopKey).
 */
export function peekDpopKey(): Promise<DpopKey | null> {
	if (resolvedKey !== undefined) return Promise.resolve(resolvedKey);
	return resolveKey();
}

/**
 * Synchronous read of the SAME state peekDpopKey() resolves to: `undefined`
 * when this page load hasn't checked yet (caller falls back to
 * `await peekDpopKey()` — paid at most once), otherwise the settled key or
 * null. Lets the http client skip the await entirely on the common path.
 */
export function peekDpopKeySync(): DpopKey | null | undefined {
	return resolvedKey;
}

/**
 * Returns the persisted key, generating + persisting a new ECDSA P-256
 * keypair on first use. Reused across logins/reloads/tabs in the same browser
 * profile so a server-bound cnf.jkt keeps matching this client's proofs.
 *
 * When IndexedDB is unavailable (or the write fails), degrades to an
 * in-memory-only key for the current page session — binding still works
 * within that session, it just re-issues cnf on the next reload.
 */
export async function getOrCreateDpopKey(): Promise<DpopKey> {
	const existing = await peekDpopKey();
	if (existing) return existing;
	const { pair, jwk } = await generateKeyPair();
	const key: DpopKey = { jwk, sign: signer(pair.privateKey, jwk) };
	resolvedKey = key;
	pending = Promise.resolve(key);
	await storeEntry({ pair, jwk }).catch(() => {
		// ponytail: storage failure degrades to a fresh key each reload — see doc above.
	});
	return key;
}

/**
 * Key-rotation path: deletes the persisted keypair and drops this page's
 * cached key, so the next getOrCreateDpopKey() generates a FRESH keypair.
 * Safe to call at session teardown (logout): the server re-issues cnf.jkt on
 * the next login, so rotation self-heals — proofs signed with the old key are
 * simply rejected until re-bind. Resolution failure of the store delete is
 * swallowed (the in-memory key is always dropped; a persisted survivor is
 * reused only until a successful teardown run).
 */
export async function resetDpopKey(): Promise<void> {
	resolvedKey = null;
	pending = null;
	rememberAccessTokenForProofs(null); // the bound token rotates with the key
	await deleteStoredEntry().catch(() => {
		// ponytail: best-effort — see doc above.
	});
}
