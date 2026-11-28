import { writable, derived, get } from 'svelte/store';
import { browser } from '$app/environment';
import { logger } from '$lib/logger';
import { problemDetail } from '$lib/errors';
import { createEdgeClient, EDGE_DEFAULT_ALLOW_STATUSES } from '$lib/edge/client';
import { loadSessionStore, jmapSession } from '$lib/stores/session';
import type { ConsoleId } from '$lib/admin/consoles';
import { getOrCreateDpopKey, rememberAccessTokenForProofs, onRecoveredAccessTokenRotation } from '$lib/auth/dpop';
import { Base64UrlDecodeError, base64urlToBuffer, bufferToBase64url } from '$lib/util/base64url';
import { disconnect } from '$lib/jmap/websocket';
import { resetJmapAuthContext } from '$lib/jmap/client';

// All /auth/* calls route through schema-first openapi-fetch clients backed by
// $lib/http's DPoP / timeout / abort machinery with loginRedirect: null so
// pre-login 401s never redirect-loop back to '/'.

const ALL_STATUSES_PASSTHROUGH = [400, 401, 403, 404, 405, 409, 410, 412, 413, 415, 422, 423, 429, 500, 502, 503, 504];

const AUTH_UNAUTHORIZED_SENTINEL = '__setjoin_auth_unauthorized__';
const AUTH_ERROR_FALLBACK_SENTINEL = '__setjoin_auth_fallback__';
const REAUTH_REQUIRED_MARKER = JSON.stringify({ reauth_required: true });

// Pre-login / raw-response client ONLY for /auth/me, /auth/login, and
// loginWithCaptcha where callers must inspect 202/401/403/429 bodies directly.
const authRawEdge = createEdgeClient({
	loginRedirect: null,
	allowStatuses: ALL_STATUSES_PASSTHROUGH
});

// Strict-throw client for /auth/refresh and /auth/logout: throws on any non-2xx
// so refreshSession()'s catch preserves existing token retention semantics.
const authRefreshEdge = createEdgeClient({
	loginRedirect: null,
	allowStatuses: []
});

async function authProblemOnError(res: Response): Promise<string> {
	if (res.status === 403) {
		const body = (await (typeof res.clone === 'function' ? res.clone() : res)
			.json()
			.catch(() => null)) as { code?: unknown } | null;
		if (body && body.code === 'reauth_required') {
			return REAUTH_REQUIRED_MARKER;
		}
	}
	return problemDetail(res, AUTH_ERROR_FALLBACK_SENTINEL);
}

// Shared authenticated /auth/* client:
// - 401 is NOT in allowStatuses -> httpRequest runs DPoP admission recovery + replay.
// - 403 is NOT in allowStatuses -> httpRequest runs ToU & Risk remediation hooks
//   BEFORE falling through to authProblemOnError (reauth_required / problemDetail).
const authEdge = createEdgeClient({
	loginRedirect: null,
	unauthorizedMessage: AUTH_UNAUTHORIZED_SENTINEL,
	onError: authProblemOnError,
	allowStatuses: [...EDGE_DEFAULT_ALLOW_STATUSES, 423]
});

function extractAuthErrorMessage(error: unknown, fallback: string): string {
	if (error && typeof error === 'object') {
		const obj = error as Record<string, unknown>;
		if (typeof obj.detail === 'string' && obj.detail.trim()) return obj.detail;
		if (typeof obj.title === 'string' && obj.title.trim()) return obj.title;
	}
	return fallback;
}

function mapThrownAuthError(
	err: unknown,
	fallback: string,
	opts: { allowReauth?: boolean; forceFallbackOnNonReauth?: boolean } = {}
): Error {
	if (err instanceof Error) {
		if (opts.allowReauth && err.message === REAUTH_REQUIRED_MARKER) {
			return new ReauthRequiredError();
		}
		if (
			err.message === AUTH_UNAUTHORIZED_SENTINEL ||
			err.message === AUTH_ERROR_FALLBACK_SENTINEL ||
			err.message === REAUTH_REQUIRED_MARKER ||
			opts.forceFallbackOnNonReauth
		) {
			return new Error(fallback);
		}
		return err;
	}
	return new Error(fallback);
}

async function runAuthCall<T>(
	call: () => Promise<{ data?: T; error?: unknown; response: Response }>,
	fallback: string,
	opts: { allowReauth?: boolean; forceFallback?: boolean } = {}
): Promise<{ data?: T; error?: unknown; response: Response }> {
	let result: { data?: T; error?: unknown; response: Response };
	try {
		result = await call();
	} catch (err) {
		throw mapThrownAuthError(err, fallback, {
			allowReauth: opts.allowReauth,
			forceFallbackOnNonReauth: opts.forceFallback
		});
	}
	if (!result.response.ok || result.error !== undefined) {
		const msg = opts.forceFallback ? fallback : extractAuthErrorMessage(result.error, fallback);
		throw new Error(msg);
	}
	return result;
}

export interface AuthUser {
	email: string;
	displayName?: string;
	isAdmin: boolean;
	hasMailbox: boolean;
	totp_enabled?: boolean;
	totp_enabled_at?: string;
	delegates?: Array<{ id: number; email: string; permission: string }>;
	userId?: number;
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

export const authGeneration = writable<number>(0);
export function bumpAuthGeneration(): void {
	authGeneration.update((n) => n + 1);
}

onRecoveredAccessTokenRotation(() => bumpAuthGeneration());

function rememberSessionToken(data: Record<string, unknown> | null | undefined): void {
	const token = data?.access_token;
	if (typeof token === 'string' && token.length > 0) {
		rememberAccessTokenForProofs(token);
	} else {
		rememberAccessTokenForProofs(null);
	}
}

const authSessionTeardowns = new Set<() => void>([resetJmapAuthContext]);

export function registerAuthSessionTeardown(teardown: () => void): () => void {
	authSessionTeardowns.add(teardown);
	return () => authSessionTeardowns.delete(teardown);
}

function teardownAuthSession(): void {
	bumpAuthGeneration();
	rememberAccessTokenForProofs(null);
	retainedRegistrationOptions = null;
	disconnect();
	for (const teardown of authSessionTeardowns) {
		try {
			teardown();
		} catch (err) {
			logger.error('auth session teardown failed', err);
		}
	}
}

export function authIdentity(value: Pick<AuthUser, 'email' | 'userId'>): string {
	return value.userId != null ? `user:${value.userId}` : `email:${value.email.toLowerCase()}`;
}

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
	const { response: res } = await authRawEdge.GET('/auth/me', {
		signal,
		parseAs: 'stream'
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
 */
export async function refreshSession(): Promise<void> {
	await authRefreshEdge
		.POST('/auth/refresh', { parseAs: 'stream' })
		.then(async ({ response: res }) => {
			if (res.ok) rememberSessionToken((await res.json().catch(() => null)) as Record<string, unknown> | null);
		})
		.catch(() => {
			/* non-fatal: fall through to checkAuth, which reloads from the current token */
		});
	bumpAuthGeneration();
	await checkAuth();
}

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

export function ensureInitialAuthProbe(): void {
	const resolution = get(authResolution);
	if (!browser || initialAuthProbeStarted || resolution.state !== 'probing' || resolution.attempt !== 0) return;
	initialAuthProbeStarted = true;
	logger.log('auth.ts: application shell calling checkAuth');
	void checkAuth();
}

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
	const { error, response: res } = await authRawEdge.POST('/auth/login', {
		credentials: 'include',
		parseAs: 'stream',
		body: {
			email,
			password,
			remember_device: rememberDevice,
			dpop_jwk: dpop_jwk as Record<string, unknown> | undefined
		}
	});
	logger.log('login: /auth/login response', { status: res.status, ok: res.ok });
	const data = await parseLoginResponse(res, error);
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

async function readLoginErrorBody(res: Response, parsedError: unknown): Promise<Record<string, unknown>> {
	if (parsedError && typeof parsedError === 'object') {
		return parsedError as Record<string, unknown>;
	}
	return (await res.json().catch(() => ({}))) as Record<string, unknown>;
}

async function parseLoginResponse(res: Response, parsedError?: unknown): Promise<Record<string, unknown>> {
	if (res.status === 403) {
		const data = await readLoginErrorBody(res, parsedError);
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
		const data = await readLoginErrorBody(res, parsedError);
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
		const prob = await readLoginErrorBody(res, parsedError) as { detail?: string };
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
	const { error, response: res } = await authRawEdge.POST('/auth/login', {
		credentials: 'include',
		parseAs: 'stream',
		params: {
			header: {
				'X-Captcha-Token': captchaToken,
				'X-Captcha-Answer': captchaAnswer
			}
		},
		body: {
			email,
			password,
			remember_device: rememberDevice,
			dpop_jwk: dpop_jwk as Record<string, unknown> | undefined
		}
	});
	logger.log('loginWithCaptcha: /auth/login response', { status: res.status, ok: res.ok });
	const data = await parseLoginResponse(res, error);
	rememberSessionToken(data);
	bumpAuthGeneration();
	logger.log('loginWithCaptcha: success, calling checkAuth');
	const authOk = await checkAuth();
	logger.log('loginWithCaptcha: checkAuth result', { authOk });
	return data;
}

export { base64urlToBuffer, bufferToBase64url };

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

	const { data: beginData } = await runAuthCall(
		() => authEdge.GET('/auth/webauthn/login/begin', { params: { query: { email } } }),
		'Passkey login unavailable',
		{ forceFallback: true }
	);
	if (!beginData?.publicKey) {
		throw new Error('Passkey login unavailable');
	}
	const pkOptions = beginData.publicKey as { challenge: string; rpId: string; allowCredentials?: unknown[] };

	const publicKey: PublicKeyCredentialRequestOptions = {
		challenge: base64urlToBuffer(pkOptions.challenge),
		rpId: pkOptions.rpId,
		allowCredentials: decodeCredentialDescriptors(pkOptions.allowCredentials),
		userVerification: 'preferred'
	};

	let assertion: PublicKeyCredential | null;
	try {
		assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
	} catch {
		throw new Error('Passkey authentication cancelled');
	}
	if (!assertion) {
		throw new Error('Passkey authentication cancelled');
	}

	const response = assertion.response as AuthenticatorAssertionResponse;
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
		dpop_jwk: dpop_jwk as Record<string, unknown> | undefined
	};

	const { data: finishPayload } = await runAuthCall(
		() => authEdge.POST('/auth/webauthn/login/finish', { body: serialized }),
		'Passkey authentication failed',
		{ forceFallback: true }
	);
	const finishData = (finishPayload ?? {}) as Record<string, unknown>;

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

	rememberSessionToken(finishData);
	bumpAuthGeneration();
	await checkAuth();
}

export async function verifyTOTP(code: string, mfaToken: string): Promise<Record<string, unknown>> {
	const dpop_jwk = await dpopJwkForLogin();
	const { data } = await runAuthCall(
		() =>
			authEdge.POST('/auth/totp/verify', {
				body: {
					code,
					mfa_token: mfaToken,
					dpop_jwk: dpop_jwk as Record<string, unknown> | undefined
				}
			}),
		'TOTP verification failed'
	);
	if (data === undefined) throw new Error('TOTP verification failed');
	const payload = data as Record<string, unknown>;
	rememberSessionToken(payload);
	bumpAuthGeneration();
	await checkAuth();
	return payload;
}

export async function verifyPush(nonce: string, mfaToken: string): Promise<Record<string, unknown>> {
	const POLL_INTERVAL_MS = 2000;
	const deadline = Date.now() + 130_000;
	const dpop_jwk = await dpopJwkForLogin();
	for (;;) {
		const { data } = await runAuthCall(
			() =>
				authEdge.POST('/auth/push/status', {
					body: {
						nonce,
						mfa_token: mfaToken,
						dpop_jwk: dpop_jwk as Record<string, unknown> | undefined
					}
				}),
			'Push verification failed'
		);
		if (data === undefined) throw new Error('Push verification failed');
		const payload = data as Record<string, unknown>;
		if (payload.approved !== false) {
			rememberSessionToken(payload);
			bumpAuthGeneration();
			await checkAuth();
			return payload;
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
	uv_capable?: boolean;
}

export async function fetchPasskeyCredentials(): Promise<PasskeyCredential[]> {
	const { data } = await runAuthCall(
		() => authEdge.GET('/auth/webauthn/credentials'),
		'Failed to load passkeys',
		{ forceFallback: true }
	);
	return (data?.credentials ?? []) as PasskeyCredential[];
}

export interface TOTPSetupDetails {
	secret: string;
	provisioningUri: string;
	enrollmentId?: string;
}

export const MFA_REAUTH_CHALLENGE_PATH = '/auth/mfa/reauth';

export class ReauthRequiredError extends Error {
	challengePath: string;
	constructor(challengePath: string = MFA_REAUTH_CHALLENGE_PATH) {
		super('reauth_required');
		this.name = 'ReauthRequiredError';
		this.challengePath = challengePath;
	}
}

export interface MFAReauthToken {
	reauthToken: string;
	expiresIn: number;
}

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

function operationBody(operation: MFAReauthOperation, targetRef?: string): { operation: MFAReauthOperation; target_ref?: string } {
	const body: { operation: MFAReauthOperation; target_ref?: string } = { operation };
	if (operation === 'webauthn.revoke' && targetRef) body.target_ref = targetRef;
	return body;
}

export async function beginMFAReauth(
	password: string,
	operation: MFAReauthOperation,
	targetRef?: string
): Promise<MFAReauthToken> {
	const { data } = await runAuthCall(
		() =>
			authEdge.POST('/auth/mfa/reauth', {
				body: { password, ...operationBody(operation, targetRef) }
			}),
		'Re-authentication failed'
	);
	if (!data?.reauth_token) throw new Error('Re-authentication failed');
	return { reauthToken: data.reauth_token, expiresIn: data.expires_in ?? 0 };
}

export async function possessionTOTPProof(
	operation: MFAReauthOperation,
	code: string,
	targetRef?: string
): Promise<MFAReauthToken> {
	const { data } = await runAuthCall(
		() =>
			authEdge.POST('/auth/mfa/possession/totp', {
				body: { ...operationBody(operation, targetRef), code }
			}),
		'Verification failed'
	);
	if (!data?.reauth_token) throw new Error('Verification failed');
	return { reauthToken: data.reauth_token, expiresIn: data.expires_in ?? 0 };
}

export type PossessionProof =
	| { scope: 'session'; reauthToken: string; expiresIn: number }
	| { scope: 'mfa_pending'; granted: true };

export interface PossessionWebAuthnOptions {
	mfaToken?: string;
	targetRef?: string;
}

export async function provePossessionWebAuthn(
	operation: MFAReauthOperation,
	opts: PossessionWebAuthnOptions = {}
): Promise<PossessionProof> {
	const beginBody: { operation: MFAReauthOperation; mfa_token?: string; target_ref?: string } = { operation };
	if (opts.mfaToken) beginBody.mfa_token = opts.mfaToken;
	if (operation === 'webauthn.revoke' && opts.targetRef) beginBody.target_ref = opts.targetRef;

	const { data: beginData } = await runAuthCall(
		() => authEdge.POST('/auth/mfa/possession/webauthn/begin', { body: beginBody }),
		'Passkey verification unavailable'
	);
	if (!beginData?.publicKey) {
		throw new Error('Passkey verification unavailable');
	}
	const pkOptions = beginData.publicKey as { challenge: string; rpId: string; allowCredentials?: unknown[] };

	const publicKey: PublicKeyCredentialRequestOptions = {
		challenge: base64urlToBuffer(pkOptions.challenge),
		rpId: pkOptions.rpId,
		allowCredentials: decodeCredentialDescriptors(pkOptions.allowCredentials),
		userVerification: 'required'
	};

	let assertion: PublicKeyCredential | null;
	try {
		assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
	} catch {
		throw new Error('Passkey verification cancelled');
	}
	if (!assertion) throw new Error('Passkey verification cancelled');

	const response = assertion.response as AuthenticatorAssertionResponse;
	const finishBody: {
		id: string;
		rawId: string;
		type: string;
		response: {
			authenticatorData: string;
			clientDataJSON: string;
			signature: string;
			userHandle: string | null;
		};
		operation: MFAReauthOperation;
		mfa_token?: string;
		target_ref?: string;
	} = {
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

	const { data } = await runAuthCall(
		() => authEdge.POST('/auth/mfa/possession/webauthn/finish', { body: finishBody }),
		'Passkey verification failed'
	);
	if (data?.granted === true) return { scope: 'mfa_pending', granted: true };
	if (!data?.reauth_token) throw new Error('Passkey verification failed');
	return { scope: 'session', reauthToken: data.reauth_token, expiresIn: data.expires_in ?? 0 };
}

export async function enrollPasskey(reauthToken?: string): Promise<void> {
	await enrollPasskeyInner(reauthToken);
}

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
	const { data: rawBeginData } = await runAuthCall(
		() =>
			authEdge.GET('/auth/webauthn/register/begin', {
				params: {
					header: reauthToken ? { 'X-MFA-Reauth': reauthToken } : undefined
				}
			}),
		'Passkey enrollment unavailable',
		{ allowReauth: true }
	);
	const beginData = (rawBeginData ?? {}) as RegistrationBeginBody;

	let publicKey: PublicKeyCredentialCreationOptions;
	if (beginData.status === 'bound') {
		if (!retainedRegistrationOptions) {
			throw new ReauthRequiredError();
		}
		publicKey = retainedRegistrationOptions;
	} else {
		if (!beginData.publicKey) throw new Error('Passkey enrollment unavailable');
		publicKey = creationOptionsFromBegin(beginData.publicKey);
		retainedRegistrationOptions = publicKey;
	}

	let cred: PublicKeyCredential | null;
	try {
		cred = await navigator.credentials.create({ publicKey }) as PublicKeyCredential | null;
	} catch {
		throw new Error('Passkey enrollment cancelled');
	}
	if (!cred) throw new Error('Passkey enrollment cancelled');

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
	await runAuthCall(
		() => authEdge.POST('/auth/webauthn/register/finish', { body: serialized }),
		'Failed to register passkey',
		{ allowReauth: true }
	);
	retainedRegistrationOptions = null;
}

export async function generateBackupCodes(reauthToken?: string): Promise<string[]> {
	const { data } = await runAuthCall(
		() =>
			authEdge.POST('/auth/backup-codes/generate', {
				body: reauthToken ? { reauth_token: reauthToken } : {}
			}),
		'Recovery code generation failed',
		{ allowReauth: true }
	);
	return data?.backup_codes ?? [];
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
	if (data.enrollment_id) details.enrollmentId = data.enrollment_id;
	return details;
}

export async function setupTOTP(reauthToken?: string): Promise<TOTPSetupDetails> {
	const { data } = await runAuthCall(
		() =>
			authEdge.GET('/auth/totp/setup', {
				params: {
					header: reauthToken ? { 'X-MFA-Reauth': reauthToken } : undefined
				}
			}),
		'TOTP setup failed',
		{ allowReauth: true }
	);
	return parseTOTPSetup(data ?? {});
}

export interface TOTPConfirmOptions {
	reauthToken?: string;
	enrollmentId?: string;
}

export async function confirmTOTP(code: string, opts: TOTPConfirmOptions = {}): Promise<void> {
	const body: { code: string; reauth_token?: string; enrollment_id?: string } = { code };
	if (opts.reauthToken) body.reauth_token = opts.reauthToken;
	if (opts.enrollmentId) body.enrollment_id = opts.enrollmentId;
	await runAuthCall(
		() => authEdge.POST('/auth/totp/confirm', { body }),
		'TOTP confirmation failed',
		{ allowReauth: true }
	);
}

export async function setupTOTPEnrollment(mfaToken: string): Promise<TOTPSetupDetails> {
	const { data } = await runAuthCall(
		() => authEdge.POST('/auth/totp/enroll/setup', { body: { mfa_token: mfaToken } }),
		'MFA enrollment could not be started',
		{ allowReauth: true }
	);
	return parseTOTPSetup(data ?? {});
}

export async function confirmTOTPEnrollment(
	code: string,
	mfaToken: string,
	enrollmentId?: string
): Promise<Record<string, unknown>> {
	const dpop_jwk = await dpopJwkForLogin();
	const body: { code: string; mfa_token: string; dpop_jwk?: Record<string, unknown>; enrollment_id?: string } = {
		code,
		mfa_token: mfaToken,
		dpop_jwk: dpop_jwk as Record<string, unknown> | undefined
	};
	if (enrollmentId) body.enrollment_id = enrollmentId;
	const { data } = await runAuthCall(
		() => authEdge.POST('/auth/totp/enroll/confirm', { body }),
		'MFA enrollment confirmation failed'
	);
	if (data === undefined) throw new Error('MFA enrollment confirmation failed');
	const payload = data as Record<string, unknown>;
	rememberSessionToken(payload);
	bumpAuthGeneration();
	await checkAuth();
	return payload;
}

export interface TOTPRemovalStepUp {
	stepUpToken: string;
	expiresIn: number;
}

export async function beginTOTPRemoval(password: string, code: string): Promise<TOTPRemovalStepUp> {
	const { data } = await runAuthCall(
		() => authEdge.POST('/auth/totp/remove/begin', { body: { password, code } }),
		'TOTP removal failed'
	);
	if (!data?.step_up_token) throw new Error('TOTP removal failed');
	return { stepUpToken: data.step_up_token, expiresIn: data.expires_in ?? 0 };
}

export async function removeTOTP(stepUpToken: string): Promise<void> {
	await runAuthCall(
		() => authEdge.POST('/auth/totp/remove', { body: { step_up_token: stepUpToken, confirm: 'REMOVE' } }),
		'TOTP removal failed'
	);
}

export async function changePassword(oldPassword: string, newPassword: string): Promise<Record<string, unknown>> {
	logger.log('changePassword: start');
	const { data, response } = await runAuthCall(
		() => authEdge.POST('/auth/change-password', { body: { oldPassword, newPassword } }),
		'Password change failed'
	);
	logger.log('changePassword: response', { status: response.status, ok: response.ok });
	if (data === undefined) throw new Error('Password change failed');
	logger.log('changePassword: success, calling checkAuth');
	const authOk = await checkAuth();
	logger.log('changePassword: checkAuth result', { authOk });
	return data as Record<string, unknown>;
}

export async function logout(): Promise<void> {
	logger.log('logout: start');
	try {
		const { response } = await authRefreshEdge.POST('/auth/logout', { parseAs: 'stream' });
		logger.log('logout: /auth/logout response', { status: response.status });
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

export async function impersonateUser(userId: number): Promise<string> {
	const { data } = await runAuthCall(
		() =>
			authEdge.POST('/auth/admin/users/{id}/impersonate', {
				params: { path: { id: userId } }
			}),
		'Impersonation failed'
	);
	if (data === undefined) throw new Error('Impersonation failed');
	rememberAccessTokenForProofs(null);
	bumpAuthGeneration();
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
