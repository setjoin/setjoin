import { writable, derived, get } from 'svelte/store';
import { browser } from '$app/environment';
import { logger } from '$lib/logger';
import { httpRequest } from '$lib/http';
import { problemDetail } from '$lib/errors';
import { loadSessionStore, jmapSession } from '$lib/stores/session';
import type { ConsoleId } from '$lib/admin/consoles';
import { getOrCreateDpopKey, rememberAccessTokenForProofs, onRecoveredAccessTokenRotation } from '$lib/auth/dpop';
import { Base64UrlDecodeError, base64urlToBuffer, bufferToBase64url } from '$lib/util/base64url';
import { disconnect } from '$lib/jmap/websocket';
import { resetJmapAuthContext } from '$lib/jmap/client';

// These auth calls are PRE-LOGIN: pass loginRedirect:null so a 401 throws the
// caller's own message instead of redirect-looping back to '/'. They route the
// raw fetch + timeout + abort through httpRequest; the business-logic response
// parsing (success body, error copy) stays in the caller, exactly as before.
//
// login()/loginWithCaptcha() are the deliberate exception: they must READ the
// 401/403/429/202 response BODY (threat / MFA / force-change parsing in
// parseLoginResponse), and httpRequest throws on those statuses before the body
// is reachable — so they keep their hand-rolled fetch. The header comment in
// http.ts records this exemption.

export interface AuthUser {
	email: string;
	displayName?: string;
	isAdmin: boolean;
	hasMailbox: boolean;
	totp_enabled?: boolean;
	totp_enabled_at?: string;
	delegates?: Array<{ id: number; email: string; permission: string }>;
	/** whole-pipeline review UX #17 — the caller's own numeric user id, straight
	 *  from the validated JWT claims (never a client-derived guess). Optional so
	 *  a pre-this-change gateway (no `user_id` field on /auth/me) degrades
	 *  gracefully — callers needing self-identity should still fall back to a
	 *  displayName match when this is absent. */
	userId?: number;
	/** Server-derived account class (P14): 'guest' renders the External badge
	 *  and fail-closes the rail. Absent on pre-G0 gateways => member. */
	accountType?: 'member' | 'guest';
}

export type AuthResolution =
	| { state: 'probing'; attempt: number }
	| { state: 'anonymous'; attempt: number; status: 401 }
	| { state: 'authenticated'; attempt: number; user: AuthUser }
	| { state: 'unavailable'; attempt: number; cause: 'offline' | 'timeout' | 'server' | 'invalid-response' }
	| { state: 'offline-authorized-native'; attempt: number; user: AuthUser };

export const authenticated = writable<boolean>(false);
export const user = writable<AuthUser | null>(null);
export const authInitializing = writable<boolean>(true);
export const authResolution = writable<AuthResolution>({ state: 'probing', attempt: 0 });
export const impersonating = writable<boolean>(false);

/**
 * Bumped on every SESSION lifecycle transition (r2 defect 10 / scheme v7
 * §3.1): a new session established (password, captcha, passkey, TOTP/push
 * completion), a token rotation (refreshSession), impersonation, and every
 * teardown (logout, reset, account switch). Identity-only fencing misses the
 * same-account case — logout → login as the SAME user, or a /auth/refresh
 * rotation — leaves pending ceremony/grant state pointing at a DEAD session
 * (grants bind the access JTI; a rotated or replaced session can never
 * consume them). Consumers (the settings MFA surfaces) retire pending proofs,
 * secrets and responses on ANY change of [$authGeneration, accountIdentity].
 */
export const authGeneration = writable<number>(0);
export function bumpAuthGeneration(): void {
	authGeneration.update((n) => n + 1);
}

// r4 §3.1: the per-tab admission recovery is the one token (re)bind that does
// NOT flow through this store — a stale tab whose shared-cookie token was
// rotated away by another tab discovers the rotation mid-request in dpop.ts.
// Subscribe the SAME retire path a /auth/refresh rotation drives: whenever the
// recovery lands a token DIFFERENT from the one this page remembered, the
// generation bumps and every lifecycle consumer (both settings MFA surfaces)
// retires pending ceremony/grant state whose grants bind a dead JTI.
onRecoveredAccessTokenRotation(() => bumpAuthGeneration());

/**
 * Remembers (or forgets) the session's access token so DPoP proofs carry the
 * RFC 9449 ath binding the authserver verifier enforces (r2 defect 1). Every
 * response body that (re-)establishes a session carries access_token; a
 * session change WITHOUT a readable token (impersonation, teardown) must
 * FORGET the stale one — a stale ath binds proofs to a dead token and 401s
 * every possession call.
 */
function rememberSessionToken(data: Record<string, unknown> | null | undefined): void {
	const token = data?.access_token;
	if (typeof token === 'string' && token.length > 0) {
		rememberAccessTokenForProofs(token);
	} else {
		rememberAccessTokenForProofs(null);
	}
}

// User-scoped process singletons (ChatStore today) register here instead of
// auth.ts importing them directly. That keeps the auth boundary authoritative
// for logout/reset/identity switches without creating auth <-> feature-store
// cycles. The WebSocket hub is transport infrastructure, so auth owns its
// explicit disconnect directly.
const authSessionTeardowns = new Set<() => void>([resetJmapAuthContext]);

export function registerAuthSessionTeardown(teardown: () => void): () => void {
	authSessionTeardowns.add(teardown);
	return () => authSessionTeardowns.delete(teardown);
}

function teardownAuthSession(): void {
	bumpAuthGeneration(); // pending ceremony/grant state belongs to a dead session
	rememberAccessTokenForProofs(null); // its token is equally dead
	retainedRegistrationOptions = null; // its registration ceremony too
	disconnect();
	for (const teardown of authSessionTeardowns) {
		try {
			teardown();
		} catch (err) {
			logger.error('auth session teardown failed', err);
		}
	}
}

/**
 * The account's lifecycle identity, derived the same way for every consumer:
 * the JWT-claim user id when the gateway provides it, else the email. Exported
 * so identity-sensitive consumers (e.g. the E5 settings race guard) bind the
 * REAL account identity instead of re-deriving their own.
 */
export function authIdentity(value: Pick<AuthUser, 'email' | 'userId'>): string {
	return value.userId != null ? `user:${value.userId}` : `email:${value.email.toLowerCase()}`;
}

/**
 * Admin consoles the current user may access, derived from the
 * urn:setjoin:params:jmap:mail vendor capability in /jmap/session.
 * Falls back to [] when the session has not loaded or the key is absent.
 */
export const adminConsoles = derived(jmapSession, ($session): ConsoleId[] => {
	const mailCaps = $session?.capabilities?.['urn:setjoin:params:jmap:mail'];
	if (mailCaps && typeof mailCaps === 'object' && mailCaps !== null) {
		const admin = (mailCaps as Record<string, unknown>).admin;
		if (admin && typeof admin === 'object' && admin !== null) {
			const consoles = (admin as Record<string, unknown>).consoles;
			if (Array.isArray(consoles)) return consoles as ConsoleId[];
		}
	}
	return [];
});

/**
 * The current admin's OWN resolved permissions, parsed from the same
 * urn:setjoin:params:jmap:mail vendor-capability admin block in /jmap/session.
 *
 * This replaces the old always-false `isReadOnly` stub: a read-tier admin now
 * gets each write control disabled (via hasPermission below) instead of an
 * enabled button that 403s on click. The server remains the single source of
 * truth — it permission-gates every write endpoint — so this only mirrors the
 * enforced set for UX. Falls back to [] when the session has not loaded or the
 * admin block is absent (a non-admin gets []).
 */
export const adminPermissions = derived(jmapSession, ($session): string[] => {
	const mailCaps = $session?.capabilities?.['urn:setjoin:params:jmap:mail'];
	if (mailCaps && typeof mailCaps === 'object' && mailCaps !== null) {
		const admin = (mailCaps as Record<string, unknown>).admin;
		if (admin && typeof admin === 'object' && admin !== null) {
			const perms = (admin as Record<string, unknown>).permissions;
			if (Array.isArray(perms)) return perms as string[];
		}
	}
	return [];
});

/**
 * True iff the resolved permission set `perms` grants `perm`. Pure membership
 * helper for gating admin write controls, e.g.
 * `disabled={!hasPermission($adminPermissions, 'queue.write')}`. Reactivity comes
 * from subscribing to `$adminPermissions`; the server still enforces every write.
 */
export function hasPermission(perms: string[], perm: string): boolean {
	return perms.includes(perm);
}

let authAttempt = 0;
let checkAuthController: AbortController | null = null;

type AuthProbe = { resolution: AuthResolution; impersonating: boolean };

function validAuthPayload(data: unknown): data is {
	email: string;
	display_name?: string;
	is_admin: boolean;
	has_mailbox: boolean;
	totp_enabled?: boolean;
	totp_enabled_at?: string;
	delegates?: Array<{ id: number; email: string; permission: string }>;
	impersonating?: boolean;
	user_id?: number;
	account_type?: 'member' | 'guest';
} {
	if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
	const value = data as Record<string, unknown>;
	return typeof value.email === 'string' && value.email.length > 0 &&
		typeof value.is_admin === 'boolean' && typeof value.has_mailbox === 'boolean';
}

async function doCheckAuth(attempt: number, signal: AbortSignal): Promise<AuthProbe> {
	logger.log('checkAuth: fetching /auth/me');
	// Pre-login probe: never redirect on 401 and never throw on non-ok — we treat
	// a non-ok response as "not authenticated" and reset the stores. The shared
	// timeout/abort still applies via httpRequest. onError captures the Response
	// so the warn + return-false path below is reached identically to before.
	let nonOk: Response | null = null;
	const res = await httpRequest('/auth/me', {
		method: 'GET',
		signal,
		loginRedirect: null,
		allowStatuses: [401],
		onError: (r) => {
			nonOk = r;
			return '';
		}
	}).catch((err) => {
		if (nonOk) return nonOk;
		throw err;
	});
	logger.log('checkAuth: /auth/me response', { status: res.status, ok: res.ok });
	if (res.status === 401) {
		return { resolution: { state: 'anonymous', attempt, status: 401 }, impersonating: false };
	}
	if (res.ok) {
		let data: unknown;
		try {
			data = await res.json();
		} catch {
			return { resolution: { state: 'unavailable', attempt, cause: 'invalid-response' }, impersonating: false };
		}
		if (!validAuthPayload(data)) {
			return { resolution: { state: 'unavailable', attempt, cause: 'invalid-response' }, impersonating: false };
		}
		// Never log the full /auth/me payload — it carries PII (email, display_name, delegates).
		// ?debug=1 enables the logger in prod, so log only non-PII flow flags.
		logger.log('checkAuth: success', { isAdmin: data.is_admin, hasMailbox: data.has_mailbox });
		const nextUser = { email: data.email, displayName: data.display_name, isAdmin: data.is_admin, hasMailbox: data.has_mailbox, totp_enabled: data.totp_enabled, totp_enabled_at: data.totp_enabled_at, delegates: data.delegates, userId: data.user_id, accountType: data.account_type } satisfies AuthUser;
		return { resolution: { state: 'authenticated', attempt, user: nextUser }, impersonating: data.impersonating === true };
	}
	logger.warn('checkAuth: /auth/me not ok', { status: res.status });
	return { resolution: { state: 'unavailable', attempt, cause: 'server' }, impersonating: false };
}

function applyProbe(probe: AuthProbe): boolean {
	const resolution = probe.resolution;
	if (resolution.attempt !== authAttempt) return get(authenticated);
	authResolution.set(resolution);
	if (resolution.state === 'authenticated' || resolution.state === 'offline-authorized-native') {
		const priorUser = get(user);
		if (priorUser && authIdentity(priorUser) !== authIdentity(resolution.user)) teardownAuthSession();
		user.set(resolution.user);
		authenticated.set(true);
		impersonating.set(probe.impersonating);
		void loadSessionStore();
		return true;
	}
	if (get(user) !== null || get(authenticated)) teardownAuthSession();
	user.set(null);
	authenticated.set(false);
	impersonating.set(false);
	return false;
}

/**
 * Re-mint the access token, then re-derive auth + live capabilities.
 *
 * Used by JIT activation's cold-start path (D6): when a non-admin is granted an
 * eligible role and activates it, the live token still carries is_admin=false —
 * POST /auth/refresh rotates it (re-deriving is_admin=true), then checkAuth()
 * reloads /auth/me and /jmap/session so $adminConsoles / $adminPermissions /
 * effectiveCaps reflect the now-active role. The refresh failure is swallowed:
 * checkAuth still runs so the UI converges on the server's truth.
 */
export async function refreshSession(): Promise<void> {
	await httpRequest('/auth/refresh', { method: 'POST', loginRedirect: null })
		.then(async (res) => {
			// The rotation response carries the NEW access token (new JTI): every
			// outstanding grant stopped being consumable at rotation (§2.5) —
			// re-bind the ath source and retire pending grant state (r2 defect 10).
			if (res.ok) rememberSessionToken((await res.json().catch(() => null)) as Record<string, unknown> | null);
			else rememberAccessTokenForProofs(null);
		})
		.catch(() => {
			/* non-fatal: fall through to checkAuth, which reloads from the current token */
		});
	bumpAuthGeneration();
	await checkAuth();
}

// Check auth state by calling the backend. HttpOnly cookies are sent automatically.
export async function checkAuth(): Promise<boolean> {
	logger.log('checkAuth: start');
	if (!browser) {
		authResolution.set({ state: 'anonymous', attempt: authAttempt, status: 401 });
		authInitializing.set(false);
		logger.log('checkAuth: not browser, abort');
		return false;
	}
	const attempt = ++authAttempt;
	checkAuthController?.abort();
	const controller = new AbortController();
	checkAuthController = controller;
	authInitializing.set(true);
	authResolution.set({ state: 'probing', attempt });
	try {
		return applyProbe(await doCheckAuth(attempt, controller.signal));
	} catch (err) {
		if (attempt !== authAttempt) return get(authenticated);
		logger.error('checkAuth: network/error', err);
		const cause: Extract<AuthResolution, { state: 'unavailable' }>['cause'] =
			err instanceof DOMException && err.name === 'AbortError'
				? 'timeout'
				: typeof navigator !== 'undefined' && navigator.onLine === false
					? 'offline'
					: 'server';
		return applyProbe({ resolution: { state: 'unavailable', attempt, cause }, impersonating: false });
	} finally {
		if (attempt === authAttempt) {
			checkAuthController = null;
			authInitializing.set(false);
		}
	}
}

let initialAuthProbeStarted = false;

/**
 * Start the one page-load auth probe from the application shell.
 *
 * This is explicit instead of a module-import side effect: public booking
 * imports the root layout but must not contact authenticated `/auth` or JMAP
 * surfaces merely because the auth store was evaluated.
 */
export function ensureInitialAuthProbe(): void {
	const resolution = get(authResolution);
	if (!browser || initialAuthProbeStarted || resolution.state !== 'probing' || resolution.attempt !== 0) return;
	initialAuthProbeStarted = true;
	logger.log('auth.ts: application shell calling checkAuth');
	void checkAuth();
}

/**
 * The SPA's DPoP public JWK (CA-3a token binding), or undefined when key
 * generation fails (unsupported browser / blocked storage). Absent ⇒ the
 * server issues an unbound token (buildCnf treats a missing jwk as opt-out) —
 * login must never fail because binding could not be set up.
 */
async function dpopJwkForLogin(): Promise<JsonWebKey | undefined> {
	try {
		return (await getOrCreateDpopKey()).jwk;
	} catch (err) {
		logger.warn('login: DPoP key unavailable, issuing unbound token', err);
		return undefined;
	}
}

export async function login(email: string, password: string, rememberDevice: boolean = false): Promise<Record<string, unknown>> {
	logger.log('login: start', { rememberDevice });
	const dpop_jwk = await dpopJwkForLogin();
	const res = await fetch('/auth/login', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		credentials: 'include',
		body: JSON.stringify({ email, password, remember_device: rememberDevice, dpop_jwk })
	});
	logger.log('login: /auth/login response', { status: res.status, ok: res.ok });
	const data = await parseLoginResponse(res);
	rememberSessionToken(data);
	bumpAuthGeneration();
	logger.log('login: success, calling checkAuth');
	const authOk = await checkAuth();
	logger.log('login: checkAuth result', { authOk });
	return data;
}

export class ForcePasswordChangeError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ForcePasswordChangeError';
	}
}

export interface PushChallenge {
	method: 'push';
	nonce?: string;
	ttlSeconds?: number;
	fallback?: string[];
}

export class MFARequiredError extends Error {
	mfaToken: string;
	challenge?: PushChallenge;
	constructor(message: string, mfaToken: string, challenge?: PushChallenge) {
		super(message);
		this.name = 'MFARequiredError';
		this.mfaToken = mfaToken;
		this.challenge = challenge;
	}
}

export class MFAEnrollmentRequiredError extends Error {
	mfaToken: string;
	constructor(message: string, mfaToken: string) {
		super(message);
		this.name = 'MFAEnrollmentRequiredError';
		this.mfaToken = mfaToken;
	}
}

export class ThreatBlockedError extends Error {
	category: string;
	captchaPrompt?: string;
	captchaToken?: string;
	retryAfterSecs?: number;
	constructor(category: string, prompt?: string, token?: string, retryAfter?: number) {
		super(category);
		this.name = 'ThreatBlockedError';
		this.category = category;
		this.captchaPrompt = prompt;
		this.captchaToken = token;
		this.retryAfterSecs = retryAfter;
	}
}

/**
 * Shared response parser for login and loginWithCaptcha.
 * Checks threat, MFA, force-change, and generic error responses.
 */
async function parseLoginResponse(res: Response): Promise<Record<string, unknown>> {
	if (res.status === 403) {
		const data = await res.json().catch(() => ({})) as Record<string, unknown>;
		if (data.status === 'force_password_change') {
			throw new ForcePasswordChangeError('You must change your password before signing in');
		}
		if (data.status === 'mfa_enrollment_required') {
			const msg = (data.message as string) || 'MFA enrollment is required';
			const mfaToken = data.mfa_token as string | undefined;
			if (!mfaToken) throw new Error('MFA enrollment could not be started. Sign in again.');
			throw new MFAEnrollmentRequiredError(msg, mfaToken);
		}
		const error = data.error as string | undefined;
		if (error === 'captcha' || error === 'blocked' || error === 'geo_blocked' || error === 'spray_detected' || error === 'lockout') {
			throw new ThreatBlockedError(
				error,
				data.captcha_prompt as string | undefined,
				data.captcha_token as string | undefined,
				data.retry_after as number | undefined
			);
		}
	}
	if (res.status === 429) {
		const data = await res.json().catch(() => ({})) as Record<string, unknown>;
		throw new ThreatBlockedError(
			(data.error as string) || 'rate_limited',
			undefined,
			undefined,
			data.retry_after as number | undefined
		);
	}
	if (res.status === 202) {
		const data = await res.json().catch(() => ({})) as Record<string, unknown>;
		if (data.status === 'mfa_required') {
			const mfaToken = data.mfa_token as string;
			const method = (data.mfa_method as string) || 'totp';
			const challenge = method === 'push'
				? {
					method: 'push' as const,
					nonce: data.nonce as string | undefined,
					ttlSeconds: data.ttl_seconds as number | undefined,
					fallback: data.fallback as string[] | undefined
				}
				: undefined;
			throw new MFARequiredError('MFA verification required', mfaToken, challenge);
		}
	}
	if (!res.ok) {
		const prob = await res.json().catch(() => ({ detail: '' })) as { detail?: string };
		throw new Error(prob.detail || 'Wrong password.');
	}
	return (await res.json()) as Record<string, unknown>;
}

export async function loginWithCaptcha(
	email: string,
	password: string,
	captchaToken: string,
	captchaAnswer: string,
	rememberDevice: boolean
): Promise<Record<string, unknown>> {
	logger.log('loginWithCaptcha: start');
	const dpop_jwk = await dpopJwkForLogin();
	const res = await fetch('/auth/login', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-Captcha-Token': captchaToken,
			'X-Captcha-Answer': captchaAnswer
		},
		credentials: 'include',
		body: JSON.stringify({ email, password, remember_device: rememberDevice, dpop_jwk })
	});
	logger.log('loginWithCaptcha: /auth/login response', { status: res.status, ok: res.ok });
	const data = await parseLoginResponse(res);
	rememberSessionToken(data);
	bumpAuthGeneration();
	logger.log('loginWithCaptcha: success, calling checkAuth');
	const authOk = await checkAuth();
	logger.log('loginWithCaptcha: checkAuth result', { authOk });
	return data;
}

// Base64url <-> ArrayBuffer helpers live in $lib/util/base64url (also used by
// auth/dpop.ts). Re-exported here so existing WebAuthn call sites (below +
// settings passkey enrollment) are unchanged.
export { base64urlToBuffer, bufferToBase64url };

// WebAuthn wire descriptors arrive as JSON with the credential id still a
// base64url STRING (Go base64.RawURLEncoding), but navigator.credentials needs
// ArrayBuffer ids — casting the array through makes any NONEMPTY allowCredentials
// fail credential.get outright (Astra r1 P1, auth.ts:831). Decode every
// descriptor id; malformed input fails closed on the typed Base64UrlDecodeError
// before any ceremony is attempted.
interface WireCredentialDescriptor {
	id?: unknown;
	type?: unknown;
	transports?: unknown;
}

function decodeCredentialDescriptors(
	wire: unknown[] | undefined
): PublicKeyCredentialDescriptor[] | undefined {
	return wire?.map((entry) => {
		const desc = entry as WireCredentialDescriptor;
		if (typeof desc.id !== 'string' || desc.id === '') {
			throw new Base64UrlDecodeError('credential descriptor without an id');
		}
		return {
			id: base64urlToBuffer(desc.id),
			type: (typeof desc.type === 'string' ? desc.type : 'public-key') as PublicKeyCredentialType,
			transports: desc.transports as AuthenticatorTransport[] | undefined
		};
	});
}

export async function startWebAuthnLogin(email: string): Promise<void> {
	logger.log('startWebAuthnLogin: begin');

	// Step 1: GET /auth/webauthn/login/begin
	const beginRes = await httpRequest(`/auth/webauthn/login/begin?email=${encodeURIComponent(email)}`, {
		loginRedirect: null,
		unauthorizedMessage: 'Passkey login unavailable',
		onError: () => 'Passkey login unavailable'
	});
	const beginData = await beginRes.json() as { publicKey: { challenge: string; rpId: string; allowCredentials?: unknown[] } };
	const pkOptions = beginData.publicKey;

	// Step 2: Prepare PublicKeyCredentialRequestOptions
	const publicKey: PublicKeyCredentialRequestOptions = {
		challenge: base64urlToBuffer(pkOptions.challenge),
		rpId: pkOptions.rpId,
		allowCredentials: decodeCredentialDescriptors(pkOptions.allowCredentials),
		userVerification: 'preferred'
	};

	// Step 3: Call navigator.credentials.get()
	let assertion: PublicKeyCredential | null;
	try {
		assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
	} catch {
		throw new Error('Passkey authentication cancelled');
	}
	if (!assertion) {
		throw new Error('Passkey authentication cancelled');
	}

	// Step 4: Serialize the assertion for JSON transport
	const response = assertion.response as AuthenticatorAssertionResponse;
	// CA-3a/DPoP: WebAuthn login is passwordless, so this IS the completion
	// request — there is no earlier password step to have sent a JWK on. The
	// server reads dpop_jwk as an extra top-level field alongside the
	// assertion (authserver webauthn.go:WebAuthnLoginFinish).
	const dpop_jwk = await dpopJwkForLogin();
	const serialized = {
		id: assertion.id,
		rawId: bufferToBase64url(assertion.rawId),
		response: {
			authenticatorData: bufferToBase64url(response.authenticatorData),
			clientDataJSON: bufferToBase64url(response.clientDataJSON),
			signature: bufferToBase64url(response.signature),
			userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null
		},
		type: assertion.type,
		dpop_jwk
	};

	// Step 5: POST /auth/webauthn/login/finish
	const finishRes = await httpRequest('/auth/webauthn/login/finish', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(serialized),
		loginRedirect: null,
		unauthorizedMessage: 'Passkey authentication failed',
		onError: () => 'Passkey authentication failed'
	});

	const finishData = await finishRes.json().catch(() => ({})) as Record<string, unknown>;

	// Step 6: Check for MFA still required after passkey
	if (finishData.status === 'mfa_required' || finishData.mfa_required) {
		const mfaToken = finishData.mfa_token as string;
		const method = (finishData.mfa_method as string) || 'totp';
		const challenge = method === 'push'
			? {
				method: 'push' as const,
				nonce: finishData.nonce as string | undefined,
				ttlSeconds: finishData.ttl_seconds as number | undefined,
				fallback: finishData.fallback as string[] | undefined
			}
			: undefined;
		throw new MFARequiredError('MFA verification required', mfaToken, challenge);
	}

	// Step 7: Success — bind the ath source to the issued token, retire any
	// pre-login pending state, and check auth.
	rememberSessionToken(finishData);
	bumpAuthGeneration();
	await checkAuth();
}

export async function verifyTOTP(code: string, mfaToken: string): Promise<Record<string, unknown>> {
	// CA-3a/DPoP: TOTP verify is a SEPARATE request from the password step that
	// issued mfaToken, so the JWK can't ride request context server-side — the
	// SPA re-sends it here (see stores/auth.test.ts + authserver totp.go).
	const dpop_jwk = await dpopJwkForLogin();
	const res = await httpRequest('/auth/totp/verify', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ code, mfa_token: mfaToken, dpop_jwk }),
		loginRedirect: null,
		unauthorizedMessage: 'TOTP verification failed',
		onError: (r) => problemDetail(r, 'TOTP verification failed')
	});
	const data = (await res.json()) as Record<string, unknown>;
	rememberSessionToken(data);
	bumpAuthGeneration();
	await checkAuth();
	return data;
}

/**
 * Complete a number-match push MFA sign-in by POLLING for OUT-OF-BAND approval.
 *
 * The correct number rides only the enrolled device (ECIES native push /
 * webpush); the browser never receives it and so cannot submit an answer — doing
 * so was the C10 2FA bypass (a password-only attacker could read the answer from
 * the login response and replay it). Instead the device approves on its own
 * channel (/auth/mfa/approve, which stamps approved_at) and the browser polls
 * /auth/push/status until the server reports approval, at which point that
 * response carries the issued session (and sets the HttpOnly cookie).
 *
 * Resolves once approved (after checkAuth converges auth state); throws on an
 * invalid/expired session or if the challenge TTL elapses with no approval.
 */
export async function verifyPush(nonce: string, mfaToken: string): Promise<Record<string, unknown>> {
	const POLL_INTERVAL_MS = 2000;
	const deadline = Date.now() + 130_000; // challenge TTL is 120s; small margin.
	// CA-3a/DPoP: fetched once before the poll loop (not per-iteration) — the
	// key is IndexedDB-cached anyway, but only the poll that actually resolves
	// (approved:true) has its cnf embedded server-side.
	const dpop_jwk = await dpopJwkForLogin();
	for (;;) {
		const res = await httpRequest('/auth/push/status', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ nonce, mfa_token: mfaToken, dpop_jwk }),
			loginRedirect: null,
			unauthorizedMessage: 'Push verification failed',
			onError: (r) => problemDetail(r, 'Push verification failed')
		});
		const data = (await res.json()) as Record<string, unknown>;
		if (data.approved !== false) {
			// Approved out-of-band: the session cookie is set; converge and return.
			rememberSessionToken(data);
			bumpAuthGeneration();
			await checkAuth();
			return data;
		}
		if (Date.now() >= deadline) {
			throw new Error('Push approval timed out. Try again.');
		}
		await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
	}
}

export interface PasskeyCredential {
	id: string;
	device_name: string;
	created_at: string;
	/** Possession scheme v7 §1.2: the server persists the attestation's
	 *  user-verified flag per credential. OPTIONAL on the wire so a
	 *  pre-possession gateway degrades gracefully — absent (or false) means the
	 *  client must NOT offer the WebAuthn-UV proof for it (fail-closed; the
	 *  server remains the cohort authority and refuses a mis-offered proof). */
	uv_capable?: boolean;
}

export async function fetchPasskeyCredentials(): Promise<PasskeyCredential[]> {
	const res = await httpRequest('/auth/webauthn/credentials', {
		loginRedirect: null,
		unauthorizedMessage: 'Failed to load passkeys',
		onError: () => 'Failed to load passkeys'
	});
	const data = await res.json() as { credentials: PasskeyCredential[] };
	return data.credentials ?? [];
}

export interface TOTPSetupDetails {
	secret: string;
	provisioningUri: string;
	/** Possession scheme v7 §1.6: the setup arm binds the grant one-time to the
	 *  pending enrollment and issues this id; confirm must present it back.
	 *  Optional so a pre-binding gateway (no enrollment_id member) keeps
	 *  working — the server, not the client, enforces the binding. */
	enrollmentId?: string;
}

// ── ER5 s07 first-factor step-up re-auth contract (authserver mfa_reauth.go) ──
//
// Enrolling the FIRST authenticator (no existing verified factor) and
// regenerating recovery codes require a FRESH re-authentication: the server
// answers the gated arm with a typed 403 problem+json (Type
// .../errors/reauth-required, Code "reauth_required", Remediation "reauth",
// challenge path in the Detail). The client then POSTs the account password
// to MFA_REAUTH_CHALLENGE_PATH and retries the gated call with the issued
// single-use, session-bound reauth_token.

export const MFA_REAUTH_CHALLENGE_PATH = '/auth/mfa/reauth';

export class ReauthRequiredError extends Error {
	/** The authenticated challenge path that mints a reauth_token. */
	challengePath: string;
	constructor(challengePath: string = MFA_REAUTH_CHALLENGE_PATH) {
		super('reauth_required');
		this.name = 'ReauthRequiredError';
		this.challengePath = challengePath;
	}
}

// ponytail: httpRequest's outer catch rewraps every thrown error as a plain
// Error (parseError passes only .message through — see $lib/http.ts's own
// problemOnError/decodeProblem note), so the onError seam JSON-encodes the
// typed re-auth contract into the message string and decodeReauthRequired
// unpacks it into a ReauthRequiredError on the way out. String-encode-and-
// decode beats forking httpRequest.
function reauthAwareOnError(fallback: string) {
	return async (res: Response): Promise<string> => {
		if (res.status === 403) {
			const body = (await res.clone().json().catch(() => null)) as { code?: unknown } | null;
			if (body && body.code === 'reauth_required') {
				return JSON.stringify({ reauth_required: true });
			}
		}
		return problemDetail(res, fallback);
	};
}

function decodeReauthRequired(err: unknown): ReauthRequiredError | null {
	if (err instanceof Error) {
		try {
			const marker = JSON.parse(err.message) as { reauth_required?: unknown };
			if (marker && marker.reauth_required === true) return new ReauthRequiredError();
		} catch {
			// not the reauth marker — the original error passes through
		}
	}
	return null;
}

export interface MFAReauthToken {
	reauthToken: string;
	expiresIn: number;
}

// ── Possession scheme v7 — operation kinds (spec §1.3) ──
//
// Every proof grant authorizes exactly ONE operation: the request that mints a
// grant declares what it may be consumed for, and the gated arm re-checks the
// binding. `bootstrap.totp.enroll` is mfa_pending-scope only (login bootstrap)
// and is never minted from a session.
export type MFAReauthOperation =
	| 'totp.enroll'
	| 'totp.replace'
	| 'webauthn.register'
	| 'webauthn.revoke'
	| 'recovery.regenerate'
	| 'device.register.native'
	| 'bootstrap.totp.enroll';

export const POSSESSION_TOTP_PATH = '/auth/mfa/possession/totp';
export const POSSESSION_WEBAUTHN_BEGIN_PATH = '/auth/mfa/possession/webauthn/begin';
export const POSSESSION_WEBAUTHN_FINISH_PATH = '/auth/mfa/possession/webauthn/finish';

// v7 §3.2 T3.1/T4: `target_ref` is REQUIRED iff the operation is
// `webauthn.revoke` and FORBIDDEN on every other operation (one proof
// authorizes exactly one target) — so the body builder includes it only there.
function operationBody(operation: MFAReauthOperation, targetRef?: string): Record<string, unknown> {
	const body: Record<string, unknown> = { operation };
	if (operation === 'webauthn.revoke' && targetRef) body.target_ref = targetRef;
	return body;
}

// Begin the fresh re-authentication challenge: verify the session holder's
// account password and receive the single-use, session-bound reauth_token the
// gated arms consume. v7 §3: the request declares the §1.3 operation the grant
// will carry (issuance-time binding), plus target_ref for webauthn.revoke.
export async function beginMFAReauth(
	password: string,
	operation: MFAReauthOperation,
	targetRef?: string
): Promise<MFAReauthToken> {
	const res = await httpRequest(MFA_REAUTH_CHALLENGE_PATH, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password, ...operationBody(operation, targetRef) }),
		loginRedirect: null,
		unauthorizedMessage: 'Re-authentication failed',
		onError: (r) => problemDetail(r, 'Re-authentication failed')
	});
	const data = (await res.json()) as { reauth_token?: string; expires_in?: number };
	if (!data.reauth_token) throw new Error('Re-authentication failed');
	return { reauthToken: data.reauth_token, expiresIn: data.expires_in ?? 0 };
}

// ── Possession scheme v7 — C1 possession proofs (spec §3, §3.2) ──
//
// A C1 (possession-capable) account proves with an enrolled factor instead of
// the password: a current TOTP code, or a WebAuthn user-verification
// assertion. Both mint the same session-scope, single-use reauth_token the
// password path returns; the C2/C3 password refusal from these endpoints is
// the wire signal that the account belongs to the password step-up cohort.

// TOTP possession proof: verify a current code from the enabled authenticator
// inside the server's issuance transaction (spec §3 row / §3.2 T3.2).
export async function possessionTOTPProof(
	operation: MFAReauthOperation,
	code: string,
	targetRef?: string
): Promise<MFAReauthToken> {
	const res = await httpRequest(POSSESSION_TOTP_PATH, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ ...operationBody(operation, targetRef), code }),
		loginRedirect: null,
		unauthorizedMessage: 'Verification failed',
		onError: (r) => problemDetail(r, 'Verification failed')
	});
	const data = (await res.json()) as { reauth_token?: string; expires_in?: number };
	if (!data.reauth_token) throw new Error('Verification failed');
	return { reauthToken: data.reauth_token, expiresIn: data.expires_in ?? 0 };
}

// Session-scope finish returns the minted token; a bootstrap caller admitted
// by its mfa_pending token instead gets `{"granted": true}` with NO new secret
// — the grant binds the presented pending token (spec §3.2 T3.4).
export type PossessionProof =
	| { scope: 'session'; reauthToken: string; expiresIn: number }
	| { scope: 'mfa_pending'; granted: true };

export interface PossessionWebAuthnOptions {
	/** mfa_pending bootstrap token (login enrollment flow). When present the
	 *  begin/finish pair rides Mode B admission (spec §3.2 T1 Mode B) and the
	 *  grant binds the pending JTI instead of minting a session token. */
	mfaToken?: string;
	/** Required iff operation === 'webauthn.revoke' (spec §3.2 T4). */
	targetRef?: string;
}

interface PossessionFinishBody {
	reauth_token?: string;
	expires_in?: number;
	granted?: boolean;
}

// Run the full management-assertion ceremony against the possession endpoints:
// begin (assertion options, UV forced required server-side) →
// navigator.credentials.get → finish (assertion + operation binding). The
// caller receives either a session reauth_token or the bootstrap `granted`
// acknowledgement (spec §1.4, §3.2 T3.3/T3.4).
export async function provePossessionWebAuthn(
	operation: MFAReauthOperation,
	opts: PossessionWebAuthnOptions = {}
): Promise<PossessionProof> {
	const beginBody: Record<string, unknown> = { operation };
	if (opts.mfaToken) beginBody.mfa_token = opts.mfaToken;
	if (operation === 'webauthn.revoke' && opts.targetRef) beginBody.target_ref = opts.targetRef;

	// Step 1: begin — assertion options with userVerification 'required' set
	// server-side; NO ceremony cookie — the server-side ceremony row is the
	// authority and the client's only finish obligation is the assertion.
	const beginRes = await httpRequest(POSSESSION_WEBAUTHN_BEGIN_PATH, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(beginBody),
		loginRedirect: null,
		unauthorizedMessage: 'Passkey verification unavailable',
		onError: (r) => problemDetail(r, 'Passkey verification unavailable')
	});
	const beginData = await beginRes.json() as { publicKey: { challenge: string; rpId: string; allowCredentials?: unknown[] } };
	const pkOptions = beginData.publicKey;

	// Step 2: ask the authenticator for a USER-VERIFIED assertion. The server
	// already forces 'required' on the ceremony; requesting it here too keeps
	// the browser's prompt honest even if served options lag.
	const publicKey: PublicKeyCredentialRequestOptions = {
		challenge: base64urlToBuffer(pkOptions.challenge),
		rpId: pkOptions.rpId,
		allowCredentials: decodeCredentialDescriptors(pkOptions.allowCredentials),
		userVerification: 'required'
	};

	// Step 3: the UV gesture itself.
	let assertion: PublicKeyCredential | null;
	try {
		assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
	} catch {
		throw new Error('Passkey verification cancelled');
	}
	if (!assertion) throw new Error('Passkey verification cancelled');

	// Step 4: serialize the assertion plus the ceremony bindings as top-level
	// members (the dpop_jwk extra-member precedent, spec §3.2 T3.4).
	const response = assertion.response as AuthenticatorAssertionResponse;
	const finishBody: Record<string, unknown> = {
		id: assertion.id,
		rawId: bufferToBase64url(assertion.rawId),
		response: {
			authenticatorData: bufferToBase64url(response.authenticatorData),
			clientDataJSON: bufferToBase64url(response.clientDataJSON),
			signature: bufferToBase64url(response.signature),
			userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null
		},
		type: assertion.type,
		operation
	};
	if (opts.mfaToken) finishBody.mfa_token = opts.mfaToken;
	if (operation === 'webauthn.revoke' && opts.targetRef) finishBody.target_ref = opts.targetRef;

	// Step 5: finish — ceremony row consumed and the grant issued in one tx.
	const finishRes = await httpRequest(POSSESSION_WEBAUTHN_FINISH_PATH, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(finishBody),
		loginRedirect: null,
		unauthorizedMessage: 'Passkey verification failed',
		onError: (r) => problemDetail(r, 'Passkey verification failed')
	});
	const data = (await finishRes.json().catch(() => ({}))) as PossessionFinishBody;
	if (data.granted === true) return { scope: 'mfa_pending', granted: true };
	if (!data.reauth_token) throw new Error('Passkey verification failed');
	return { scope: 'session', reauthToken: data.reauth_token, expiresIn: data.expires_in ?? 0 };
}

// ── Passkey registration under the possession gate (spec §3 row, §3.1) ──
//
// `GET /auth/webauthn/register/begin` + `POST /auth/webauthn/register/finish`
// are gated: begin carries the grant in the X-MFA-Reauth header (GET has no
// body), finish in the reauth_token body member. The reauth_required 403 from
// either arm surfaces as ReauthRequiredError so the settings flow can run the
// method-aware handoff and retry with the minted proof.
export async function enrollPasskey(reauthToken?: string): Promise<void> {
	try {
		await enrollPasskeyInner(reauthToken);
	} catch (err) {
		// A 403 problem with code reauth_required surfaces as ReauthRequiredError
		// so the settings flow can run the method-aware handoff — never silent.
		const reauth = decodeReauthRequired(err);
		if (reauth) throw reauth;
		throw err;
	}
}

// The creation options the FIRST begin on the current grant minted, retained
// for the §1.6 RESUME semantics (r2 defect 9 / scheme v7 §1.6): a repeated
// begin on the same grant answers 200 {"status":"bound"} — no second ceremony
// is ever minted — and the client reuses its ALREADY-ISSUED options. Chosen
// per the scheme's explicit wording ("the client reuses its already-issued
// creation options ... no second ceremony for a bound grant") over requiring
// a fresh proof, which would discard a perfectly bound grant every time the
// user cancels the authenticator gesture. Cleared on success (the grant is
// consumed) and on session teardown. If retention is lost while the grant
// stays bound (a second tab holding the token after this page reloaded),
// enrollment surfaces reauth_required — a fresh proof re-binds a fresh
// ceremony honestly.
let retainedRegistrationOptions: PublicKeyCredentialCreationOptions | null = null;

interface RegistrationBeginBody {
	status?: string;
	publicKey?: {
		challenge: string;
		user: { id: string; name: string; displayName: string };
		excludeCredentials?: { id: string; type: string; transports?: string[] }[];
	} & Record<string, unknown>;
}

function creationOptionsFromBegin(publicKey: NonNullable<RegistrationBeginBody['publicKey']>): PublicKeyCredentialCreationOptions {
	// The server sends challenge / user.id / excludeCredentials[].id as
	// base64url strings; navigator.credentials.create needs ArrayBuffers.
	return {
		...(publicKey as unknown as PublicKeyCredentialCreationOptions),
		challenge: base64urlToBuffer(publicKey.challenge),
		user: {
			...publicKey.user,
			id: base64urlToBuffer(publicKey.user.id)
		},
		excludeCredentials: publicKey.excludeCredentials?.map((c) => ({
			id: base64urlToBuffer(c.id),
			type: c.type as PublicKeyCredentialType,
			transports: c.transports as AuthenticatorTransport[] | undefined
		}))
	};
}

async function enrollPasskeyInner(reauthToken?: string): Promise<void> {
	// Step 1: begin — creation options (the grant binds one-time to the
	// ceremony's challenge hash server-side, spec §1.6). A grant ALREADY bound
	// to its live ceremony answers {"status":"bound"}: resume with the
	// retained options instead of assuming a fresh publicKey payload.
	const headers: Record<string, string> = {};
	if (reauthToken) headers['X-MFA-Reauth'] = reauthToken;
	const beginRes = await httpRequest('/auth/webauthn/register/begin', {
		headers,
		loginRedirect: null,
		unauthorizedMessage: 'Passkey enrollment unavailable',
		onError: reauthAwareOnError('Passkey enrollment unavailable')
	});
	const beginData = await beginRes.json() as RegistrationBeginBody;

	let publicKey: PublicKeyCredentialCreationOptions;
	if (beginData.status === 'bound') {
		if (!retainedRegistrationOptions) {
			// Retention lost but the grant stays bound: require a FRESH proof.
			// The handoff mints one; the new grant's begin binds a new ceremony
			// (§1.6 fail-closed strictness) instead of guessing at options this
			// page never received.
			throw new ReauthRequiredError();
		}
		publicKey = retainedRegistrationOptions;
	} else {
		if (!beginData.publicKey) throw new Error('Passkey enrollment unavailable');
		publicKey = creationOptionsFromBegin(beginData.publicKey);
		retainedRegistrationOptions = publicKey;
	}

	// Step 2: the credential-creation gesture.
	let cred: PublicKeyCredential | null;
	try {
		cred = await navigator.credentials.create({ publicKey }) as PublicKeyCredential | null;
	} catch {
		throw new Error('Passkey enrollment cancelled');
	}
	if (!cred) throw new Error('Passkey enrollment cancelled');

	// Step 3: serialize the attestation (ArrayBuffers → base64url) and finish
	// with the grant so the gated arm can consume it.
	const att = cred.response as AuthenticatorAttestationResponse;
	const serialized = {
		id: cred.id,
		rawId: bufferToBase64url(cred.rawId),
		type: cred.type,
		response: {
			attestationObject: bufferToBase64url(att.attestationObject),
			clientDataJSON: bufferToBase64url(att.clientDataJSON)
		},
		...(reauthToken ? { reauth_token: reauthToken } : {})
	};
	await httpRequest('/auth/webauthn/register/finish', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(serialized),
		loginRedirect: null,
		unauthorizedMessage: 'Failed to register passkey',
		onError: reauthAwareOnError('Failed to register passkey')
	});
	// The finish consumed the ceremony + grant: nothing to resume.
	retainedRegistrationOptions = null;
}

// Regenerate every recovery code. Gated for EVERY account: the reauth_token
// from beginMFAReauth is consumed before any code is minted. The first
// attempt legitimately carries no token — the server's typed 403 contract is
// what triggers the re-auth handoff.
export async function generateBackupCodes(reauthToken?: string): Promise<string[]> {
	try {
		const res = await httpRequest('/auth/backup-codes/generate', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(reauthToken ? { reauth_token: reauthToken } : {}),
			loginRedirect: null,
			unauthorizedMessage: 'Recovery code generation failed',
			onError: reauthAwareOnError('Recovery code generation failed')
		});
		const data = (await res.json()) as { backup_codes?: string[] };
		return data.backup_codes ?? [];
	} catch (err) {
		const reauth = decodeReauthRequired(err);
		if (reauth) throw reauth;
		throw err;
	}
}

function parseTOTPSetup(data: { provisioning_uri?: string; enrollment_id?: string }): TOTPSetupDetails {
	const provisioningUri = data.provisioning_uri ?? '';
	let secret = '';
	try {
		secret = new URL(provisioningUri).searchParams.get('secret') ?? '';
	} catch {
		// The caller receives one constant error for malformed/missing server data.
	}
	if (!provisioningUri || !secret) throw new Error('TOTP setup returned an invalid provisioning URI');
	const details: TOTPSetupDetails = { secret, provisioningUri };
	// v7 §1.6: the setup arm's issued enrollment id rides to confirm. Absent on
	// a pre-binding gateway — tolerated there, required once the backend ships.
	if (data.enrollment_id) details.enrollmentId = data.enrollment_id;
	return details;
}

export async function setupTOTP(reauthToken?: string): Promise<TOTPSetupDetails> {
	// ER5 s07 first-factor step-up: the GET arm carries the reauth_token in
	// the X-MFA-Reauth header (fetch refuses a body on GET). A 403 problem
	// with code "reauth_required" surfaces as a ReauthRequiredError so the
	// settings flow can offer the re-auth challenge handoff — never silent.
	const headers: Record<string, string> = {};
	if (reauthToken) headers['X-MFA-Reauth'] = reauthToken;
	try {
		const res = await httpRequest('/auth/totp/setup', {
			headers,
			loginRedirect: null,
			unauthorizedMessage: 'TOTP setup failed',
			onError: reauthAwareOnError('TOTP setup failed')
		});
		return parseTOTPSetup((await res.json()) as { provisioning_uri?: string });
	} catch (err) {
		const reauth = decodeReauthRequired(err);
		if (reauth) throw reauth;
		throw err;
	}
}

export interface TOTPConfirmOptions {
	/** The single-use reauth_token the gated confirm arm consumes. */
	reauthToken?: string;
	/** v7 §1.6: the enrollment_id setup issued — confirm must reference the
	 *  binding, so stale (grant, enrollment) combinations refuse by design. */
	enrollmentId?: string;
}

export async function confirmTOTP(code: string, opts: TOTPConfirmOptions = {}): Promise<void> {
	const body: Record<string, unknown> = { code };
	if (opts.reauthToken) body.reauth_token = opts.reauthToken;
	if (opts.enrollmentId) body.enrollment_id = opts.enrollmentId;
	try {
		await httpRequest('/auth/totp/confirm', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
			loginRedirect: null,
			unauthorizedMessage: 'TOTP confirmation failed',
			onError: reauthAwareOnError('TOTP confirmation failed')
		});
	} catch (err) {
		const reauth = decodeReauthRequired(err);
		if (reauth) throw reauth;
		throw err;
	}
}

// Bootstrap enrollment setup (mfa_pending scope, login flow). For a C2/C3
// account the password bootstrap grant was committed at login, so the bare
// token works. For a C1 passkey-holder NO grant exists yet: the arm answers
// the typed 403 reauth_required (§1.6 zero-rows rule) and the caller must run
// the webauthn_uv management ceremony (provePossessionWebAuthn with the SAME
// mfa_token) before retrying — v7 §1.5.1 step 5. Returns the setup-issued
// enrollmentId the confirm arm must present (§1.6).
export async function setupTOTPEnrollment(mfaToken: string): Promise<TOTPSetupDetails> {
	try {
		const res = await httpRequest('/auth/totp/enroll/setup', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ mfa_token: mfaToken }),
			loginRedirect: null,
			unauthorizedMessage: 'MFA enrollment could not be started',
			onError: reauthAwareOnError('MFA enrollment could not be started')
		});
		return parseTOTPSetup((await res.json()) as { provisioning_uri?: string; enrollment_id?: string });
	} catch (err) {
		const reauth = decodeReauthRequired(err);
		if (reauth) throw reauth;
		throw err;
	}
}

// Bootstrap enrollment confirm: consumes the mfa_pending grant in the
// promotion tx. The setup-issued enrollmentId rides the request per §1.6 so
// stale (grant, enrollment) combinations refuse by construction.
export async function confirmTOTPEnrollment(
	code: string,
	mfaToken: string,
	enrollmentId?: string
): Promise<Record<string, unknown>> {
	const dpop_jwk = await dpopJwkForLogin();
	const body: Record<string, unknown> = { code, mfa_token: mfaToken, dpop_jwk };
	if (enrollmentId) body.enrollment_id = enrollmentId;
	const res = await httpRequest('/auth/totp/enroll/confirm', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
		loginRedirect: null,
		unauthorizedMessage: 'MFA enrollment confirmation failed',
		onError: (r) => problemDetail(r, 'MFA enrollment confirmation failed')
	});
	const data = (await res.json()) as Record<string, unknown>;
	// The completion response carries the ISSUED session (the server bound the
	// token to the dpop_jwk this request presented), so apply the SAME
	// token-retention + generation transition verifyTOTP applies BEFORE
	// probing (r3: bootstrap completion previously called checkAuth with no
	// remembered token and no generation advance — with binding enabled every
	// subsequent proof omitted ath or hashed a stale token, and the fresh
	// session authenticated nowhere).
	rememberSessionToken(data);
	bumpAuthGeneration();
	await checkAuth();
	return data;
}

export interface TOTPRemovalStepUp {
	stepUpToken: string;
	expiresIn: number;
}

// Begin MFA de-enrollment: verify the session password plus a second factor —
// the current TOTP code, or a recovery code when the authenticator is lost —
// per the server's factor/recovery decision table. Returns a single-use,
// session-bound step-up token that removeTOTP() consumes. A user with no
// authenticator and no recovery codes is refused here (self-service path
// ends; the admin/support recovery flow applies).
export async function beginTOTPRemoval(password: string, code: string): Promise<TOTPRemovalStepUp> {
	const res = await httpRequest('/auth/totp/remove/begin', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password, code }),
		loginRedirect: null,
		unauthorizedMessage: 'TOTP removal failed',
		onError: (r) => problemDetail(r, 'TOTP removal failed')
	});
	const data = (await res.json()) as { step_up_token?: string; expires_in?: number };
	if (!data.step_up_token) throw new Error('TOTP removal failed');
	return { stepUpToken: data.step_up_token, expiresIn: data.expires_in ?? 0 };
}

// Complete MFA de-enrollment: consume the step-up token with the typed
// confirmation. The server removes the factor and every recovery code in one
// serialized transaction; replayed tokens and double-submissions are refused.
export async function removeTOTP(stepUpToken: string): Promise<void> {
	await httpRequest('/auth/totp/remove', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ step_up_token: stepUpToken, confirm: 'REMOVE' }),
		loginRedirect: null,
		unauthorizedMessage: 'TOTP removal failed',
		onError: (r) => problemDetail(r, 'TOTP removal failed')
	});
}

export async function changePassword(oldPassword: string, newPassword: string): Promise<Record<string, unknown>> {
	logger.log('changePassword: start');
	const res = await httpRequest('/auth/change-password', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ oldPassword, newPassword }),
		loginRedirect: null,
		unauthorizedMessage: 'Password change failed',
		onError: async (r) => {
			const detail = await problemDetail(r, 'Password change failed');
			logger.error('changePassword: failed', { status: r.status, body: detail });
			return detail;
		}
	});
	logger.log('changePassword: response', { status: res.status, ok: res.ok });
	const data = (await res.json()) as Record<string, unknown>;
	logger.log('changePassword: success, calling checkAuth');
	const authOk = await checkAuth();
	logger.log('changePassword: checkAuth result', { authOk });
	return data;
}

export async function logout(): Promise<void> {
	logger.log('logout: start');
	try {
		// Silent-on-error by design: the finally always resets local auth state,
		// so the user is logged out client-side even if the server call fails.
		// loginRedirect:null keeps a 401 from redirect-looping instead of resetting.
		const res = await httpRequest('/auth/logout', {
			method: 'POST',
			loginRedirect: null
		});
		logger.log('logout: /auth/logout response', { status: res.status });
	} catch (err) {
		logger.error('logout: error', err);
	} finally {
		const attempt = ++authAttempt;
		checkAuthController?.abort();
		checkAuthController = null;
		teardownAuthSession();
		user.set(null);
		authenticated.set(false);
		authResolution.set({ state: 'anonymous', attempt, status: 401 });
		authInitializing.set(false);
		impersonating.set(false);
		logger.log('logout: auth state reset');
	}
}

// Impersonate another user as an admin. Returns the target email on success.
export async function impersonateUser(userId: number): Promise<string> {
	const res = await httpRequest(`/auth/admin/users/${userId}/impersonate`, {
		method: 'POST',
		loginRedirect: null,
		unauthorizedMessage: 'Impersonation failed',
		onError: (r) => problemDetail(r, 'Impersonation failed')
	});
	const data = (await res.json()) as { target_email: string; impersonating: boolean };
	// The impersonation cookie swapped the session for one this page never saw
	// a token for — a stale ath would 401 every possession call (r2 defect 1).
	rememberAccessTokenForProofs(null);
	bumpAuthGeneration();
	// Re-check auth — the impersonation cookie is now set, /auth/me returns target user
	await checkAuth();
	return data.target_email;
}

export function reset() {
	teardownAuthSession();
	checkAuthController?.abort();
	checkAuthController = null;
	authAttempt = 0;
	authenticated.set(false);
	user.set(null);
	impersonating.set(false);
	authInitializing.set(true);
	authResolution.set({ state: 'probing', attempt: 0 });
}
