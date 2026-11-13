import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';
const disconnectMock = vi.hoisted(() => vi.fn());
const rotationObservers = vi.hoisted(() => new Set<() => void>());
vi.mock('$lib/jmap/websocket', () => ({ disconnect: disconnectMock }));
import {
	authenticated,
	user,
	login,
	logout,
	changePassword,
	checkAuth,
	authGeneration,
	authResolution,
	ForcePasswordChangeError,
	MFAEnrollmentRequiredError,
	ThreatBlockedError,
	loginWithCaptcha,
	startWebAuthnLogin,
	verifyTOTP,
	setupTOTP,
	confirmTOTP,
	setupTOTPEnrollment,
	confirmTOTPEnrollment,
	beginTOTPRemoval,
	removeTOTP,
	verifyPush,
	beginMFAReauth,
	possessionTOTPProof,
	provePossessionWebAuthn,
	enrollPasskey,
	generateBackupCodes,
	ReauthRequiredError,
	MFA_REAUTH_CHALLENGE_PATH,
	POSSESSION_TOTP_PATH,
	POSSESSION_WEBAUTHN_BEGIN_PATH,
	POSSESSION_WEBAUTHN_FINISH_PATH,
	bufferToBase64url,
	adminPermissions,
	hasPermission,
	registerAuthSessionTeardown,
	reset,
} from './auth';
import { Base64UrlDecodeError } from '$lib/util/base64url';
import { jmapSession } from './session';
import type { JmapSession } from '$lib/types/jmap';
import { getOrCreateDpopKey, rememberAccessTokenForProofs } from '$lib/auth/dpop';
import { getAccountId, loadSession } from '$lib/jmap/client';

// Real WebCrypto/IndexedDB key generation is covered by auth/dpop.test.ts; here
// we only need login() to carry WHATEVER jwk the key module hands back, so this
// suite mocks it — a real getOrCreateDpopKey() call would populate the module's
// singleton key cache and leak a real DPoP header into every OTHER test in this
// file that calls httpRequest (checkAuth, startWebAuthnLogin, …), which is
// unrelated to what they're testing. $lib/http's own peekDpopKey (unmocked
// here — see http.test.ts) stays undefined for calls this file doesn't stub.
vi.mock('$lib/auth/dpop', () => ({
	getOrCreateDpopKey: vi.fn(),
	peekDpopKey: vi.fn().mockResolvedValue(null),
	peekDpopKeySync: vi.fn().mockReturnValue(null),
	rememberAccessTokenForProofs: vi.fn(),
	accessTokenForProofs: vi.fn(() => null),
	recoverAccessTokenForProofs: vi.fn().mockResolvedValue(null),
	// Real registry: auth.ts registers its rotation->generation retire path at
	// module scope, and this suite (recovery-rotation test below) drives it.
	onRecoveredAccessTokenRotation: (fn: () => void) => {
		rotationObservers.add(fn);
		return () => rotationObservers.delete(fn);
	}
}));

const FAKE_DPOP_JWK = { kty: 'EC', crv: 'P-256', x: 'fake-x', y: 'fake-y' } as JsonWebKey;

// Helper: build a /jmap/session payload whose vendor admin block carries the
// caller's own resolved permissions (the real wire shape adminPermissions reads).
function sessionWithAdminPerms(perms: string[]): JmapSession {
	return {
		capabilities: {
			'urn:setjoin:params:jmap:mail': { admin: { consoles: [], permissions: perms } }
		}
	} as unknown as JmapSession;
}

describe('auth store', () => {
	beforeEach(() => {
		reset();
		disconnectMock.mockReset();
		authenticated.set(false);
		user.set(null);
		vi.mocked(getOrCreateDpopKey).mockResolvedValue({ jwk: FAKE_DPOP_JWK, sign: vi.fn() });
		vi.stubGlobal('fetch', vi.fn());
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	// Per-permission admin gating (replaces the old always-false isReadOnly stub):
	// the SPA reads the caller's OWN resolved perms from /jmap/session and disables
	// write controls it lacks, so a read-tier admin no longer sees buttons that 403.
	describe('admin permissions gating', () => {
		afterEach(() => {
			jmapSession.set(null);
		});

		it('hasPermission is a pure membership check', () => {
			expect(hasPermission(['queue.write', 'audit.read'], 'queue.write')).toBe(true);
			expect(hasPermission(['audit.read'], 'queue.write')).toBe(false);
			expect(hasPermission([], 'roles.manage')).toBe(false);
		});

		it('adminPermissions parses the vendor admin block from the session', () => {
			jmapSession.set(sessionWithAdminPerms(['queue.write', 'domains.read']));
			expect(get(adminPermissions)).toEqual(['queue.write', 'domains.read']);
		});

		it('adminPermissions falls back to [] when the session or admin block is absent', () => {
			jmapSession.set(null);
			expect(get(adminPermissions)).toEqual([]);
			jmapSession.set({ capabilities: {} } as unknown as JmapSession);
			expect(get(adminPermissions)).toEqual([]);
		});

		it('a read-tier admin (only read perms) gates OFF every write control', () => {
			// Auditor / read_only: holds read perms, zero write perms.
			jmapSession.set(sessionWithAdminPerms(['audit.read', 'users.read', 'queue.read']));
			const perms = get(adminPermissions);
			for (const writePerm of ['queue.write', 'system.config', 'roles.manage']) {
				expect(hasPermission(perms, writePerm)).toBe(false);
			}
		});

		it('a scoped admin gates each control independently (mixed role)', () => {
			// Holds queue.write but NOT roles.manage / system.config: queue actions
			// enabled, roles + features disabled — the precise gating the old global
			// flag could not express.
			jmapSession.set(sessionWithAdminPerms(['queue.read', 'queue.write']));
			const perms = get(adminPermissions);
			expect(hasPermission(perms, 'queue.write')).toBe(true);
			expect(hasPermission(perms, 'roles.manage')).toBe(false);
			expect(hasPermission(perms, 'system.config')).toBe(false);
		});
	});

	describe('checkAuth', () => {
		it('returns true and sets stores on 200', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ email: 'alice@example.com', is_admin: true, has_mailbox: true })
			});
			vi.stubGlobal('fetch', mockFetch);

			const result = await checkAuth();
			expect(result).toBe(true);
			expect(get(authenticated)).toBe(true);
			expect(get(user)).toEqual({ email: 'alice@example.com', isAdmin: true, hasMailbox: true });
		});

		it('returns false and resets stores on 401', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 401,
				text: async () => 'Unauthorized'
			});
			vi.stubGlobal('fetch', mockFetch);

			const result = await checkAuth();
			expect(result).toBe(false);
			expect(get(authenticated)).toBe(false);
			expect(get(user)).toBeNull();
			expect(get(authResolution)).toMatchObject({ state: 'anonymous', status: 401 });
		});

		it('returns false on network error', async () => {
			const mockFetch = vi.fn().mockRejectedValue(new Error('network'));
			vi.stubGlobal('fetch', mockFetch);

			const result = await checkAuth();
			expect(result).toBe(false);
			expect(get(authenticated)).toBe(false);
			expect(get(authResolution)).toMatchObject({ state: 'unavailable', cause: 'server' });
		});

		it('classifies a malformed success body as unavailable, never anonymous', async () => {
			vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ email: 'alice@example.com' }),
			}));

			await expect(checkAuth()).resolves.toBe(false);
			expect(get(authResolution)).toMatchObject({ state: 'unavailable', cause: 'invalid-response' });
			expect(get(user)).toBeNull();
		});

		it('fences a late result from an older probe attempt', async () => {
			let resolveFirst!: (value: unknown) => void;
			let resolveSecond!: (value: unknown) => void;
			const firstResponse = new Promise((resolve) => { resolveFirst = resolve; });
			const secondResponse = new Promise((resolve) => { resolveSecond = resolve; });
			vi.stubGlobal('fetch', vi.fn()
				.mockReturnValueOnce(firstResponse)
				.mockReturnValueOnce(secondResponse));

			const first = checkAuth();
			const second = checkAuth();
			resolveSecond({
				ok: true,
				status: 200,
				json: async () => ({ email: 'new@example.com', is_admin: false, has_mailbox: true, user_id: 2 }),
			});
			await expect(second).resolves.toBe(true);
			resolveFirst({
				ok: true,
				status: 200,
				json: async () => ({ email: 'old@example.com', is_admin: false, has_mailbox: true, user_id: 1 }),
			});
			await first;

			expect(get(user)?.email).toBe('new@example.com');
			expect(get(authResolution)).toMatchObject({ state: 'authenticated', user: { userId: 2 } });
		});

		it('tears down user-scoped state and transport before an identity switch', async () => {
			const teardown = vi.fn();
			const unregister = registerAuthSessionTeardown(teardown);
			user.set({ email: 'admin@example.com', isAdmin: true, hasMailbox: true, userId: 1 });
			authenticated.set(true);
			vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ email: 'target@example.com', is_admin: false, has_mailbox: true, user_id: 2, impersonating: true }),
			}));

			await checkAuth();

			expect(disconnectMock).toHaveBeenCalledOnce();
			expect(teardown).toHaveBeenCalledOnce();
			expect(get(user)?.userId).toBe(2);
			unregister();
		});
	});

	describe('login', () => {
		it('returns data and updates stores on success', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ status: 'ok' })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			const data = await login('alice@example.com', 'secret');
			expect(data.status).toBe('ok');
			expect(get(authenticated)).toBe(true);
		});

		it('throws ForcePasswordChangeError on 403 force_password_change', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ status: 'force_password_change' })
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(login('alice@example.com', 'secret')).rejects.toBeInstanceOf(
				ForcePasswordChangeError
			);
		});

		it('carries the server mfa_token on mandatory enrollment', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ status: 'mfa_enrollment_required', mfa_token: 'enroll-token', message: 'Enroll now' })
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('login should require enrollment');
			} catch (err) {
				expect(err).toBeInstanceOf(MFAEnrollmentRequiredError);
				expect((err as MFAEnrollmentRequiredError).mfaToken).toBe('enroll-token');
			}
		});

		it('throws generic Error with fallback message on other failures', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 500,
				json: async () => ({})
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(login('alice@example.com', 'secret')).rejects.toThrow('Wrong password.');
		});

		// CA-3a token binding: the login request must carry the SPA's DPoP public
		// JWK as `dpop_jwk` so authserver can embed cnf.jkt (buildCnf, auth.go:282).
		// Without this the server always issues an unbound token and
		// feature.token_binding can never engage (TODOS.md CA-3a blocker).
		it('sends the DPoP public JWK as dpop_jwk in the login body', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ status: 'ok' }) })
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			await login('alice@example.com', 'secret');

			const loginCall = mockFetch.mock.calls[0];
			expect(loginCall[0]).toBe('/auth/login');
			const body = JSON.parse(loginCall[1].body as string);
			expect(body.dpop_jwk).toEqual(FAKE_DPOP_JWK);
		});

		it('omits dpop_jwk (issues an unbound token) when DPoP key setup fails', async () => {
			vi.mocked(getOrCreateDpopKey).mockRejectedValue(new Error('WebCrypto unavailable'));
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ status: 'ok' }) })
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			// Login must still succeed — binding is opt-in, never a login blocker.
			await expect(login('alice@example.com', 'secret')).resolves.toBeTruthy();
			const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
			expect(body.dpop_jwk).toBeUndefined();
		});
	});

	describe('changePassword', () => {
		it('returns data and updates stores on success', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ status: 'ok' })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			const data = await changePassword('old', 'newpassword8');
			expect(data.status).toBe('ok');
		});

		it('throws on failure', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 401,
				text: async () => 'Unauthorized'
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(changePassword('old', 'new')).rejects.toThrow(
				'Password change failed'
			);
		});
	});

	describe('logout', () => {
		it('logout fences delayed user-A discovery before user-B discovery', async () => {
			let resolveUserA!: (value: unknown) => void;
			const userABody = new Promise((resolve) => { resolveUserA = resolve; });
			const fetchMock = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: () => userABody })
				.mockResolvedValueOnce({ ok: true, status: 204 })
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

			const delayedUserA = loadSession();
			await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
			await logout();
			await expect(loadSession()).resolves.toMatchObject({ accounts: { 'user-b': expect.anything() } });

			resolveUserA({
				apiUrl: '/jmap',
				accounts: { 'user-a': {} },
				primaryAccounts: { 'urn:ietf:params:jmap:mail': 'user-a' }
			});
			await expect(delayedUserA).rejects.toThrow('auth context changed');
			expect(await getAccountId()).toBe('user-b');
			expect(fetchMock).toHaveBeenCalledTimes(3);
		});

		it('reset synchronously clears the JMAP account and session cache', async () => {
			const fetchMock = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						apiUrl: '/jmap',
						accounts: { 'user-a': {} },
						primaryAccounts: { 'urn:ietf:params:jmap:mail': 'user-a' }
					})
				})
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

			await loadSession();
			expect(await getAccountId()).toBe('user-a');
			reset();
			expect(await getAccountId()).toBe('user-b');
			expect(fetchMock).toHaveBeenCalledTimes(2);
		});

		it('resets stores even if fetch fails', async () => {
			authenticated.set(true);
			user.set({ email: 'alice@example.com', isAdmin: false, hasMailbox: true });

			const mockFetch = vi.fn().mockRejectedValue(new Error('network'));
			vi.stubGlobal('fetch', mockFetch);

			await logout();
			expect(get(authenticated)).toBe(false);
			expect(get(user)).toBeNull();
		});

		it('resets stores on success', async () => {
			authenticated.set(true);
			user.set({ email: 'alice@example.com', isAdmin: false, hasMailbox: true });

			const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 204 });
			vi.stubGlobal('fetch', mockFetch);

			await logout();
			expect(get(authenticated)).toBe(false);
			expect(get(user)).toBeNull();
			expect(disconnectMock).toHaveBeenCalledOnce();
		});

		it('runs registered singleton teardown on reset()', () => {
			const teardown = vi.fn();
			const unregister = registerAuthSessionTeardown(teardown);

			reset();

			expect(disconnectMock).toHaveBeenCalledOnce();
			expect(teardown).toHaveBeenCalledOnce();
			unregister();
		});
	});

	describe('ForcePasswordChangeError', () => {
		it('has correct name', () => {
			const err = new ForcePasswordChangeError('must change');
			expect(err.name).toBe('ForcePasswordChangeError');
			expect(err.message).toBe('must change');
		});
	});

	describe('ThreatBlockedError', () => {
		it('is instance of Error', () => {
			const err = new ThreatBlockedError('captcha', 'What is 3+7?', 'token-abc', 30);
			expect(err).toBeInstanceOf(Error);
		});

		it('has correct name', () => {
			const err = new ThreatBlockedError('captcha');
			expect(err.name).toBe('ThreatBlockedError');
		});

		it('sets category from constructor', () => {
			const err = new ThreatBlockedError('blocked');
			expect(err.category).toBe('blocked');
		});

		it('sets captchaPrompt and captchaToken when provided', () => {
			const err = new ThreatBlockedError('captcha', 'What is 3+7?', 'token-xyz');
			expect(err.captchaPrompt).toBe('What is 3+7?');
			expect(err.captchaToken).toBe('token-xyz');
		});

		it('sets retryAfterSecs when provided', () => {
			const err = new ThreatBlockedError('rate_limited', undefined, undefined, 15);
			expect(err.retryAfterSecs).toBe(15);
		});

		it('leaves optional fields undefined when not provided', () => {
			const err = new ThreatBlockedError('spray_detected');
			expect(err.captchaPrompt).toBeUndefined();
			expect(err.captchaToken).toBeUndefined();
			expect(err.retryAfterSecs).toBeUndefined();
		});
	});

	describe('login threat detection', () => {
		it('throws ThreatBlockedError on 403 captcha', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({
					error: 'captcha',
					captcha_prompt: 'What is 3 + 7?',
					captcha_token: 'ctok-123'
				})
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('Expected login to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('captcha');
				expect((err as ThreatBlockedError).captchaPrompt).toBe('What is 3 + 7?');
				expect((err as ThreatBlockedError).captchaToken).toBe('ctok-123');
			}
		});

		it('throws ThreatBlockedError on 403 blocked', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ error: 'blocked' })
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('Expected login to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('blocked');
			}
		});

		it('throws ThreatBlockedError on 403 geo_blocked', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ error: 'geo_blocked' })
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('Expected login to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('geo_blocked');
			}
		});

		it('throws ThreatBlockedError on 403 spray_detected', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ error: 'spray_detected' })
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('Expected login to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('spray_detected');
			}
		});

		it('throws ThreatBlockedError on 403 lockout', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ error: 'lockout', retry_after: 300 })
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('Expected login to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('lockout');
				expect((err as ThreatBlockedError).retryAfterSecs).toBe(300);
			}
		});

		it('throws ThreatBlockedError on 429 rate limited', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 429,
				json: async () => ({ error: 'rate_limited', retry_after: 60 })
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('Expected login to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('rate_limited');
				expect((err as ThreatBlockedError).retryAfterSecs).toBe(60);
			}
		});

		it('throws ThreatBlockedError on 429 with default category when error field missing', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 429,
				json: async () => ({})
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await login('alice@example.com', 'secret');
				expect.fail('Expected login to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('rate_limited');
			}
		});

		it('still throws ForcePasswordChangeError on 403 force_password_change (checks before threat)', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ status: 'force_password_change' })
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(login('alice@example.com', 'secret')).rejects.toBeInstanceOf(
				ForcePasswordChangeError
			);
		});
	});

	describe('loginWithCaptcha', () => {
		it('sends X-Captcha-Token and X-Captcha-Answer headers', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ status: 'ok' })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			await loginWithCaptcha('alice@example.com', 'secret', 'ctok-abc', '10', true);

			const loginCall = mockFetch.mock.calls[0];
			expect(loginCall[0]).toBe('/auth/login');
			const headers = loginCall[1].headers as Record<string, string>;
			expect(headers['X-Captcha-Token']).toBe('ctok-abc');
			expect(headers['X-Captcha-Answer']).toBe('10');
			const body = JSON.parse(loginCall[1].body as string);
			expect(body.remember_device).toBe(true);
		});

		it('resolves on success', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ status: 'ok' })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			const data = await loginWithCaptcha('alice@example.com', 'secret', 'ctok', 'ans', false);
			expect(data.status).toBe('ok');
		});

		it('throws ThreatBlockedError on 403 captcha from captcha login', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 403,
				json: async () => ({ error: 'captcha', captcha_prompt: 'New challenge' })
			});
			vi.stubGlobal('fetch', mockFetch);

			try {
				await loginWithCaptcha('alice@example.com', 'secret', 'ctok', 'wrong', false);
				expect.fail('Expected loginWithCaptcha to throw');
			} catch (err) {
				expect(err).toBeInstanceOf(ThreatBlockedError);
				expect((err as ThreatBlockedError).category).toBe('captcha');
			}
		});
	});

	describe('startWebAuthnLogin', () => {
		it('calls GET begin then navigator.credentials.get then POST finish', async () => {
			const mockCredGet = vi.fn().mockResolvedValue({
				id: 'cred-id-1',
				rawId: new Uint8Array([1, 2, 3]).buffer,
				response: {
					authenticatorData: new Uint8Array([4, 5, 6]).buffer,
					clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
					signature: new Uint8Array([10, 11, 12]).buffer,
					userHandle: new Uint8Array([13, 14, 15]).buffer
				},
				type: 'public-key'
			});

			vi.stubGlobal('navigator', {
				credentials: {
					get: mockCredGet
				}
			});

			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						publicKey: {
							challenge: 'YWJj',
							rpId: 'localhost',
							allowCredentials: []
						}
					})
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ status: 'ok' })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				})
				// loadSessionStore triggered by checkAuth
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({})
				});
			vi.stubGlobal('fetch', mockFetch);

			await startWebAuthnLogin('alice@example.com');

			expect(mockFetch).toHaveBeenCalledWith(
				'/auth/webauthn/login/begin?email=alice%40example.com',
				expect.objectContaining({ credentials: 'include' })
			);
			expect(mockCredGet).toHaveBeenCalled();
			expect(mockFetch).toHaveBeenCalledWith(
				'/auth/webauthn/login/finish',
				expect.objectContaining({
					method: 'POST',
					credentials: 'include',
					headers: expect.objectContaining({ 'Content-Type': 'application/json' })
				})
			);
			expect(mockFetch).toHaveBeenCalledTimes(4); // begin + finish + checkAuth + loadSessionStore

			// CA-3a/DPoP: WebAuthn login is passwordless, so the finish request IS
			// the completion — it must carry the JWK (authserver webauthn.go reads
			// it as an extra top-level field alongside the assertion).
			const finishCall = mockFetch.mock.calls.find(
				(c) => c[0] === '/auth/webauthn/login/finish'
			);
			const finishBody = JSON.parse(finishCall![1].body as string);
			expect(finishBody.dpop_jwk).toEqual(FAKE_DPOP_JWK);
		});

		it('throws on begin failure', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 400
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(startWebAuthnLogin('alice@example.com')).rejects.toThrow(
				'Passkey login unavailable'
			);
		});

		it('throws when navigator.credentials.get returns null', async () => {
			const mockCredGet = vi.fn().mockResolvedValue(null);
			vi.stubGlobal('navigator', { credentials: { get: mockCredGet } });

			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({
					publicKey: { challenge: 'YWJj', rpId: 'localhost', allowCredentials: [] }
				})
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(startWebAuthnLogin('alice@example.com')).rejects.toThrow(
				'Passkey authentication cancelled'
			);
		});

		// Astra r1 P1: allowCredentials ids ride the wire as UNPADDED base64url
		// strings (Go base64.RawURLEncoding); credential.get needs ArrayBuffer ids.
		// A NONEMPTY list must decode, not cast through — this is the login site of
		// the shared descriptor decoder.
		it('decodes unpadded base64url allowCredentials ids to ArrayBuffers before credential.get', async () => {
			const mockCredGet = vi.fn().mockResolvedValue({
				id: 'cred-id-1',
				rawId: new Uint8Array([1, 2, 3]).buffer,
				response: {
					authenticatorData: new Uint8Array([4, 5, 6]).buffer,
					clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
					signature: new Uint8Array([10, 11, 12]).buffer,
					userHandle: null
				},
				type: 'public-key'
			});
			vi.stubGlobal('navigator', { credentials: { get: mockCredGet } });

			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						publicKey: {
							challenge: 'YWJj',
							rpId: 'localhost',
							allowCredentials: [{ id: 'AQIDBAU', type: 'public-key' }]
						}
					})
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ status: 'ok' })
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				})
				// loadSessionStore triggered by checkAuth
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({})
				});
			vi.stubGlobal('fetch', mockFetch);

			await startWebAuthnLogin('alice@example.com');

			const asked = mockCredGet.mock.calls[0][0].publicKey;
			const [desc] = asked.allowCredentials as PublicKeyCredentialDescriptor[];
			expect(Array.from(new Uint8Array(desc.id as ArrayBuffer))).toEqual([1, 2, 3, 4, 5]);
			// Round-trip: encode(decode(wire id)) === the original unpadded form.
			expect(bufferToBase64url(desc.id as ArrayBuffer)).toBe('AQIDBAU');
		});
	});

	// CA-3a/DPoP MFA-completion binding: TOTP verify and the push status poll
	// are SEPARATE requests from the password step that issued mfaToken, so the
	// JWK can't ride request context server-side (see authserver totp.go /
	// push.go — the ctxKeyCALogin stash is per-request). The SPA must re-send
	// its DPoP JWK on each completion call for the server to bind the token.
	describe('verifyTOTP', () => {
		it('sends the DPoP public JWK as dpop_jwk alongside the code', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ access_token: 'tok' }) })
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			await verifyTOTP('123456', 'mfa-token-abc');

			const call = mockFetch.mock.calls.find((c) => c[0] === '/auth/totp/verify');
			const body = JSON.parse(call![1].body as string);
			expect(body).toEqual({ code: '123456', mfa_token: 'mfa-token-abc', dpop_jwk: FAKE_DPOP_JWK });
		});
	});

	describe('TOTP setup payloads and mandatory enrollment', () => {
		const provisioningUri = 'otpauth://totp/SetJoin:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=SetJoin';

		it('maps the authenticated setup provisioning URI to a manual secret', async () => {
			vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ provisioning_uri: provisioningUri })
			}));

			await expect(setupTOTP()).resolves.toEqual({
				secret: 'JBSWY3DPEHPK3PXP',
				provisioningUri
			});
		});

		it('starts mandatory enrollment with only the short-lived mfa token', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: true,
				status: 200,
				json: async () => ({ provisioning_uri: provisioningUri })
			});
			vi.stubGlobal('fetch', mockFetch);

			const setup = await setupTOTPEnrollment('enroll-token');
			expect(setup.secret).toBe('JBSWY3DPEHPK3PXP');
			const call = mockFetch.mock.calls.find((c) => c[0] === '/auth/totp/enroll/setup');
			expect(JSON.parse(call![1].body as string)).toEqual({ mfa_token: 'enroll-token' });
		});

		it('re-sends the DPoP JWK when enrollment confirmation mints the session', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ access_token: 'tok' }) })
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			await confirmTOTPEnrollment('123456', 'enroll-token');
			const call = mockFetch.mock.calls.find((c) => c[0] === '/auth/totp/enroll/confirm');
			expect(JSON.parse(call![1].body as string)).toEqual({
				code: '123456',
				mfa_token: 'enroll-token',
				dpop_jwk: FAKE_DPOP_JWK
			});
		});
	});

	describe('verifyPush', () => {
		it('sends the DPoP public JWK as dpop_jwk on the status poll', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ access_token: 'tok' }) })
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ email: 'alice@example.com', is_admin: false, has_mailbox: true })
				});
			vi.stubGlobal('fetch', mockFetch);

			await verifyPush('deadbeef', 'mfa-token-abc');

			const call = mockFetch.mock.calls.find((c) => c[0] === '/auth/push/status');
			const body = JSON.parse(call![1].body as string);
			expect(body).toEqual({ nonce: 'deadbeef', mfa_token: 'mfa-token-abc', dpop_jwk: FAKE_DPOP_JWK });
		});
	});

	describe('login 401 error message parsing', () => {
		it('throws with parsed detail from RFC 7807 problem JSON', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 401,
				json: async () => ({ detail: 'Invalid credentials.' })
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(login('alice@example.com', 'wrong')).rejects.toThrow('Invalid credentials.');
		});

		it('throws fallback when 401 body is not JSON', async () => {
			const mockFetch = vi.fn().mockResolvedValue({
				ok: false,
				status: 401,
				json: async () => { throw new Error('not json'); }
			});
			vi.stubGlobal('fetch', mockFetch);

			await expect(login('alice@example.com', 'wrong')).rejects.toThrow('Wrong password.');
		});
	});

		// Task 7: AuthUser extension + fetchPasskeyCredentials
		describe('AuthUser type', () => {
			it('accepts totp_enabled and totp_enabled_at fields', () => {
				const u = { email: 'alice@example.com', isAdmin: false, hasMailbox: true, totp_enabled: true, totp_enabled_at: '2026-01-01T00:00:00Z' };
				expect(u.totp_enabled).toBe(true);
				expect(u.totp_enabled_at).toBe('2026-01-01T00:00:00Z');
			});
		});

		describe('checkAuth with TOTP fields', () => {
			it('sets totp_enabled from /auth/me response', async () => {
				const mockFetch = vi.fn().mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => ({
						email: 'alice@example.com',
						is_admin: false,
						has_mailbox: true,
						totp_enabled: true,
						totp_enabled_at: '2026-03-15T08:00:00Z'
					})
				});
				vi.stubGlobal('fetch', mockFetch);

				const result = await checkAuth();
				expect(result).toBe(true);
				expect(get(user)?.totp_enabled).toBe(true);
				expect(get(user)?.totp_enabled_at).toBe('2026-03-15T08:00:00Z');
			});

			it('totp_enabled is undefined when not returned from /auth/me', async () => {
				const mockFetch = vi.fn().mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => ({
						email: 'alice@example.com',
						is_admin: false,
						has_mailbox: true
					})
				});
				vi.stubGlobal('fetch', mockFetch);

				const result = await checkAuth();
				expect(result).toBe(true);
				expect(get(user)?.totp_enabled).toBeUndefined();
			});
		});

		describe('fetchPasskeyCredentials', () => {
			it('calls GET /auth/webauthn/credentials and returns credentials array', async () => {
				const mockCreds = [
					{ id: 'abc123', device_name: 'Chrome on Mac', created_at: '2026-01-15T10:00:00Z' }
				];
				const mockFetch = vi.fn().mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => ({ credentials: mockCreds })
				});
				vi.stubGlobal('fetch', mockFetch);

				const { fetchPasskeyCredentials } = await import('./auth');
				const creds = await fetchPasskeyCredentials();
				expect(mockFetch).toHaveBeenCalledWith('/auth/webauthn/credentials', expect.objectContaining({ credentials: 'include' }));
				expect(creds).toEqual(mockCreds);
			});

			it('returns empty array when credentials field is missing', async () => {
				const mockFetch = vi.fn().mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => ({})
				});
				vi.stubGlobal('fetch', mockFetch);

				const { fetchPasskeyCredentials } = await import('./auth');
				const creds = await fetchPasskeyCredentials();
				expect(creds).toEqual([]);
			});

			it('throws on non-ok response', async () => {
				const mockFetch = vi.fn().mockResolvedValue({
					ok: false,
					status: 401
				});
				vi.stubGlobal('fetch', mockFetch);

				const { fetchPasskeyCredentials } = await import('./auth');
				await expect(fetchPasskeyCredentials()).rejects.toThrow('Failed to load passkeys');
			});
		});

		// TOTP removal (self-service MFA de-enrollment, authserver totp.go): begin
		// exchanges the session password + a second factor (TOTP code or recovery
		// code) for a single-use, session-bound step-up token; remove consumes it
		// with the typed confirmation. The server drops the authenticator and
		// every recovery code in one serialized transaction and refuses replayed
		// tokens / double-submissions.
		describe('TOTP removal step-up', () => {
			it('beginTOTPRemoval POSTs password + code and returns the step-up token', async () => {
				const mockFetch = vi.fn().mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => ({ step_up_token: 'step-up-1', expires_in: 300 })
				});
				vi.stubGlobal('fetch', mockFetch);

				await expect(beginTOTPRemoval('correct horse', '123456')).resolves.toEqual({
					stepUpToken: 'step-up-1',
					expiresIn: 300
				});
				const call = mockFetch.mock.calls.find((c) => c[0] === '/auth/totp/remove/begin');
				expect(call![1]).toMatchObject({ method: 'POST' });
				expect(JSON.parse(call![1].body as string)).toEqual({
					password: 'correct horse',
					code: '123456'
				});
			});

			it('beginTOTPRemoval defaults expiresIn to 0 when the server omits it', async () => {
				vi.stubGlobal(
					'fetch',
					vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: async () => ({ step_up_token: 'step-up-2' })
					})
				);

				await expect(beginTOTPRemoval('pw', '654321')).resolves.toEqual({
					stepUpToken: 'step-up-2',
					expiresIn: 0
				});
			});

			it('beginTOTPRemoval refuses a well-formed response without a step-up token', async () => {
				vi.stubGlobal(
					'fetch',
					vi.fn().mockResolvedValue({
						ok: true,
						status: 200,
						json: async () => ({ expires_in: 5 })
					})
				);

				await expect(beginTOTPRemoval('pw', '654321')).rejects.toThrow('TOTP removal failed');
			});

			it('beginTOTPRemoval surfaces the RFC 7807 detail on failure (no factor on file)', async () => {
				vi.stubGlobal(
					'fetch',
					vi.fn().mockResolvedValue({
						ok: false,
						status: 400,
						json: async () => ({ detail: 'No authenticator or recovery codes on file' })
					})
				);

				await expect(beginTOTPRemoval('pw', '654321')).rejects.toThrow(
					'No authenticator or recovery codes on file'
				);
			});

			it('removeTOTP POSTs the step-up token with the typed REMOVE confirmation', async () => {
				const mockFetch = vi.fn().mockResolvedValue({
					ok: true,
					status: 200,
					json: async () => ({})
				});
				vi.stubGlobal('fetch', mockFetch);

				await expect(removeTOTP('step-up-1')).resolves.toBeUndefined();
				const call = mockFetch.mock.calls.find((c) => c[0] === '/auth/totp/remove');
				expect(call![1]).toMatchObject({ method: 'POST' });
				expect(JSON.parse(call![1].body as string)).toEqual({
					step_up_token: 'step-up-1',
					confirm: 'REMOVE'
				});
			});

			it('removeTOTP surfaces the parsed problem detail on failure (replayed token)', async () => {
				vi.stubGlobal(
					'fetch',
					vi.fn().mockResolvedValue({
						ok: false,
						status: 409,
						json: async () => ({ detail: 'Removal token already used' })
					})
				);

				await expect(removeTOTP('step-up-1')).rejects.toThrow('Removal token already used');
			});
		});
	});

// ── ER5 s07 first-factor step-up re-auth contract (mfa_reauth.go) ──
describe('auth store — first-factor re-auth contract', () => {
	beforeEach(() => {
		reset();
		authenticated.set(false);
		user.set(null);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	function jsonResponse(data: unknown, status = 200): Response {
		return new Response(JSON.stringify(data), {
			status,
			headers: { 'content-type': 'application/json' }
		});
	}

	function reauthRequiredResponse(): Response {
		return jsonResponse(
			{
				type: 'https://setjoin.com/errors/reauth-required',
				title: 'Re-authentication required',
				status: 403,
				detail: 'present your account password at /auth/mfa/reauth and retry with the issued reauth_token',
				code: 'reauth_required',
				remediation: 'reauth'
			},
			403
		);
	}

	it('setupTOTP surfaces the typed 403 reauth_required as ReauthRequiredError with the challenge path', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reauthRequiredResponse()));
		try {
			await setupTOTP();
			expect.unreachable('setupTOTP should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(ReauthRequiredError);
			expect((err as ReauthRequiredError).challengePath).toBe('/auth/mfa/reauth');
		}
	});

	it('setupTOTP carries the reauth_token in the X-MFA-Reauth header (GET has no body) and parses the provisioning URI', async () => {
		const mockFetch = vi.fn().mockResolvedValue(
			jsonResponse({ provisioning_uri: 'otpauth://totp/setjoin:u?secret=ABC234' })
		);
		vi.stubGlobal('fetch', mockFetch);
		const details = await setupTOTP('tok-1');
		expect(details).toEqual({ secret: 'ABC234', provisioningUri: 'otpauth://totp/setjoin:u?secret=ABC234' });
		const init = mockFetch.mock.calls[0][1] as RequestInit;
		expect(new Headers(init.headers).get('X-MFA-Reauth')).toBe('tok-1');
	});

	it('confirmTOTP posts the reauth_token and surfaces reauth_required as ReauthRequiredError', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reauthRequiredResponse()));
		await expect(confirmTOTP('123456', { reauthToken: 'tok-1' })).rejects.toBeInstanceOf(ReauthRequiredError);
		const call = vi.mocked(fetch).mock.calls[0];
		expect(call[0]).toBe('/auth/totp/confirm');
		expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({ code: '123456', reauth_token: 'tok-1' });
	});

	it('confirmTOTP carries the setup-issued enrollment_id alongside the token (v7 §1.6)', async () => {
		const ok = vi.fn().mockResolvedValue(jsonResponse({}));
		vi.stubGlobal('fetch', ok);
		await confirmTOTP('123456', { reauthToken: 'tok-1', enrollmentId: 'e-uuid-1' });
		const call = ok.mock.calls[0];
		expect(call[0]).toBe('/auth/totp/confirm');
		expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({
			code: '123456',
			reauth_token: 'tok-1',
			enrollment_id: 'e-uuid-1'
		});
	});

	it('beginMFAReauth posts the password with the declared operation and maps the issued reauth_token (v7 §3)', async () => {
		const mockFetch = vi.fn().mockResolvedValue(jsonResponse({ reauth_token: 'tok-9', expires_in: 300 }));
		vi.stubGlobal('fetch', mockFetch);
		const issued = await beginMFAReauth('correct-horse-battery', 'recovery.regenerate');
		expect(issued).toEqual({ reauthToken: 'tok-9', expiresIn: 300 });
		const call = mockFetch.mock.calls[0];
		expect(call[0]).toBe(MFA_REAUTH_CHALLENGE_PATH);
		expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({
			password: 'correct-horse-battery',
			operation: 'recovery.regenerate'
		});
	});

	it('beginMFAReauth carries target_ref ONLY for webauthn.revoke (v7 §3.2 T4)', async () => {
		const revoke = vi.fn().mockResolvedValue(jsonResponse({ reauth_token: 'tok-r', expires_in: 300 }));
		vi.stubGlobal('fetch', revoke);
		await beginMFAReauth('pw', 'webauthn.revoke', 'cred-1');
		expect(JSON.parse((revoke.mock.calls[0][1] as RequestInit).body as string)).toEqual({
			password: 'pw',
			operation: 'webauthn.revoke',
			target_ref: 'cred-1'
		});

		const enroll = vi.fn().mockResolvedValue(jsonResponse({ reauth_token: 'tok-e', expires_in: 300 }));
		vi.stubGlobal('fetch', enroll);
		await beginMFAReauth('pw', 'totp.enroll', 'should-be-dropped');
		expect(JSON.parse((enroll.mock.calls[0][1] as RequestInit).body as string)).toEqual({
			password: 'pw',
			operation: 'totp.enroll'
		});
	});

	it('setupTOTP parses the setup-issued enrollment_id (v7 §1.6)', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
			jsonResponse({ provisioning_uri: 'otpauth://totp/setjoin:u?secret=ABC234', enrollment_id: 'e-uuid-9' })
		));
		const details = await setupTOTP('tok-1');
		expect(details.enrollmentId).toBe('e-uuid-9');
	});

	it('generateBackupCodes posts the reauth_token and returns the codes; reauth_required stays a ReauthRequiredError', async () => {
		const ok = vi.fn().mockResolvedValue(jsonResponse({ backup_codes: ['aaa11111', 'bbb22222'] }));
		vi.stubGlobal('fetch', ok);
		await expect(generateBackupCodes('tok-1')).resolves.toEqual(['aaa11111', 'bbb22222']);
		const call = ok.mock.calls[0];
		expect(call[0]).toBe('/auth/backup-codes/generate');
		expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({ reauth_token: 'tok-1' });

		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(reauthRequiredResponse()));
		await expect(generateBackupCodes('tok-2')).rejects.toBeInstanceOf(ReauthRequiredError);
	});

	it('a 403 WITHOUT the reauth_required code keeps the plain problem-detail error path', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(jsonResponse({ detail: 'invalid password' }, 403))
		);
		await expect(beginMFAReauth('wrong', 'recovery.regenerate')).rejects.toThrow('invalid password');
	});
});

// ── Possession scheme v7 — C1 possession proofs (§3 possession endpoints) ──
describe('auth store — possession proof endpoints', () => {
	beforeEach(() => {
		reset();
		authenticated.set(false);
		user.set(null);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	function jsonResponse(data: unknown, status = 200): Response {
		return new Response(JSON.stringify(data), {
			status,
			headers: { 'content-type': 'application/json' }
		});
	}

	function fakeAssertion() {
		return {
			id: 'cred-id-1',
			rawId: new Uint8Array([1, 2, 3]).buffer,
			response: {
				authenticatorData: new Uint8Array([4, 5, 6]).buffer,
				clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
				signature: new Uint8Array([10, 11, 12]).buffer,
				userHandle: new Uint8Array([13, 14, 15]).buffer
			},
			type: 'public-key'
		};
	}

	it('possessionTOTPProof posts operation + code and maps the issued reauth_token (§3.2 T3.2)', async () => {
		const mockFetch = vi.fn().mockResolvedValue(jsonResponse({ reauth_token: 'tok-t', expires_in: 300 }));
		vi.stubGlobal('fetch', mockFetch);
		const issued = await possessionTOTPProof('totp.replace', '654321');
		expect(issued).toEqual({ reauthToken: 'tok-t', expiresIn: 300 });
		const call = mockFetch.mock.calls[0];
		expect(call[0]).toBe(POSSESSION_TOTP_PATH);
		expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({
			operation: 'totp.replace',
			code: '654321'
		});
	});

	it('possessionTOTPProof carries target_ref only for webauthn.revoke (§3.2 T4)', async () => {
		const mockFetch = vi.fn().mockResolvedValue(jsonResponse({ reauth_token: 'tok-t', expires_in: 300 }));
		vi.stubGlobal('fetch', mockFetch);
		await possessionTOTPProof('webauthn.revoke', '654321', 'cred-7');
		expect(JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string)).toEqual({
			operation: 'webauthn.revoke',
			code: '654321',
			target_ref: 'cred-7'
		});

		const noRef = vi.fn().mockResolvedValue(jsonResponse({ reauth_token: 'tok-t', expires_in: 300 }));
		vi.stubGlobal('fetch', noRef);
		await possessionTOTPProof('recovery.regenerate', '654321', 'must-drop');
		expect(JSON.parse((noRef.mock.calls[0][1] as RequestInit).body as string)).toEqual({
			operation: 'recovery.regenerate',
			code: '654321'
		});
	});

	it('provePossessionWebAuthn: begin → UV assertion → finish minting a session token', async () => {
		const mockCredGet = vi.fn().mockResolvedValue(fakeAssertion());
		vi.stubGlobal('navigator', { credentials: { get: mockCredGet } });
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(jsonResponse({ publicKey: { challenge: 'YWJj', rpId: 'localhost', allowCredentials: [] } }))
			.mockResolvedValueOnce(jsonResponse({ reauth_token: 'tok-w', expires_in: 300 }));
		vi.stubGlobal('fetch', mockFetch);

		const proof = await provePossessionWebAuthn('webauthn.register');
		expect(proof).toEqual({ scope: 'session', reauthToken: 'tok-w', expiresIn: 300 });

		const beginCall = mockFetch.mock.calls[0];
		expect(beginCall[0]).toBe(POSSESSION_WEBAUTHN_BEGIN_PATH);
		expect(JSON.parse((beginCall[1] as RequestInit).body as string)).toEqual({ operation: 'webauthn.register' });

		// The management ceremony is UV-enforced server-side; the browser ask
		// must request 'required' as well (spec §1.4 — login stays 'preferred').
		const askedOptions = mockCredGet.mock.calls[0][0].publicKey;
		expect(askedOptions.userVerification).toBe('required');

		const finishCall = mockFetch.mock.calls[1];
		expect(finishCall[0]).toBe(POSSESSION_WEBAUTHN_FINISH_PATH);
		const finishBody = JSON.parse((finishCall[1] as RequestInit).body as string);
		expect(finishBody.operation).toBe('webauthn.register');
		expect(finishBody.id).toBe('cred-id-1');
		expect(finishBody.mfa_token).toBeUndefined();
	});

	it('provePossessionWebAuthn (Mode B): the pending token rides begin and finish; granted has NO token', async () => {
		const mockCredGet = vi.fn().mockResolvedValue(fakeAssertion());
		vi.stubGlobal('navigator', { credentials: { get: mockCredGet } });
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(jsonResponse({ publicKey: { challenge: 'YWJj', rpId: 'localhost' } }))
			.mockResolvedValueOnce(jsonResponse({ granted: true }));
		vi.stubGlobal('fetch', mockFetch);

		const proof = await provePossessionWebAuthn('bootstrap.totp.enroll', { mfaToken: 'pending-jwt' });
		expect(proof).toEqual({ scope: 'mfa_pending', granted: true });

		expect(JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string)).toEqual({
			operation: 'bootstrap.totp.enroll',
			mfa_token: 'pending-jwt'
		});
		const finishBody = JSON.parse((mockFetch.mock.calls[1][1] as RequestInit).body as string);
		expect(finishBody.mfa_token).toBe('pending-jwt');
		expect(finishBody.operation).toBe('bootstrap.totp.enroll');
	});

	it('provePossessionWebAuthn throws the cancellation message when the gesture is dismissed', async () => {
		vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockRejectedValue(new DOMException('NotAllowedError')) } });
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(jsonResponse({ publicKey: { challenge: 'YWJj', rpId: 'localhost' } }));
		vi.stubGlobal('fetch', mockFetch);

		await expect(provePossessionWebAuthn('recovery.regenerate')).rejects.toThrow('Passkey verification cancelled');
		expect(mockFetch).toHaveBeenCalledTimes(1); // no finish after a cancelled gesture
	});

	// Astra r1 P1 (auth.ts:831): server assertion options carry allowCredentials
	// ids as UNPADDED base64url strings (Go base64.RawURLEncoding). The browser
	// needs ArrayBuffer ids — a realistic NONEMPTY list must decode to the exact
	// bytes and round-trip, not cast through and fail credential.get.
	it('provePossessionWebAuthn decodes UNPADDED base64url descriptor ids to exact bytes and round-trips', async () => {
		const mockCredGet = vi.fn().mockResolvedValue(fakeAssertion());
		vi.stubGlobal('navigator', { credentials: { get: mockCredGet } });
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(jsonResponse({
				publicKey: {
					challenge: 'AQIDBAU', // 5 bytes — unpadded, RawURLEncoding shape
					rpId: 'localhost',
					allowCredentials: [
						{ id: 'AQIDBAU', type: 'public-key', transports: ['internal'] }, // bytes [1,2,3,4,5]
						{ id: '-__-', type: 'public-key' } // url-safe alphabet, bytes [251,255,254]
					]
				}
			}))
			.mockResolvedValueOnce(jsonResponse({ reauth_token: 'tok-w', expires_in: 300 }));
		vi.stubGlobal('fetch', mockFetch);

		await provePossessionWebAuthn('webauthn.register');

		const asked = mockCredGet.mock.calls[0][0].publicKey;
		const [first, second] = asked.allowCredentials as PublicKeyCredentialDescriptor[];
		// Exact decoded bytes: unpadded input, high bytes intact (no unicode corruption).
		expect(Array.from(new Uint8Array(first.id as ArrayBuffer))).toEqual([1, 2, 3, 4, 5]);
		expect(Array.from(new Uint8Array(second.id as ArrayBuffer))).toEqual([0xfb, 0xff, 0xfe]);
		// Round-trip: encode(decode(wire id)) === the original unpadded form.
		expect(bufferToBase64url(first.id as ArrayBuffer)).toBe('AQIDBAU');
		expect(bufferToBase64url(second.id as ArrayBuffer)).toBe('-__-');
	});

	it('provePossessionWebAuthn fails closed on a malformed descriptor id with the typed decode error', async () => {
		const mockCredGet = vi.fn();
		vi.stubGlobal('navigator', { credentials: { get: mockCredGet } });
		const mockFetch = vi.fn().mockResolvedValueOnce(jsonResponse({
			publicKey: {
				challenge: 'YWJj',
				rpId: 'localhost',
				allowCredentials: [{ id: '!!!not-base64url!!!', type: 'public-key' }]
			}
		}));
		vi.stubGlobal('fetch', mockFetch);

		await expect(provePossessionWebAuthn('webauthn.register')).rejects.toBeInstanceOf(Base64UrlDecodeError);
		// Fail-closed: no UV gesture is attempted and no finish is posted.
		expect(mockCredGet).not.toHaveBeenCalled();
		expect(mockFetch).toHaveBeenCalledTimes(1);
	});

	it('provePossessionWebAuthn fails closed on a descriptor without an id', async () => {
		const mockCredGet = vi.fn();
		vi.stubGlobal('navigator', { credentials: { get: mockCredGet } });
		vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(jsonResponse({
			publicKey: { challenge: 'YWJj', rpId: 'localhost', allowCredentials: [{ type: 'public-key' }] }
		})));

		await expect(provePossessionWebAuthn('webauthn.register')).rejects.toThrow('credential descriptor without an id');
		expect(mockCredGet).not.toHaveBeenCalled();
	});

	it('setupTOTPEnrollment surfaces the C1 refusal as ReauthRequiredError; the retry after the UV ceremony works', async () => {
		// Passkey-holder bootstrap (v7 §1.5.1): no password grant exists, so the
		// bare enroll/setup answers the typed 403 reauth_required — the client
		// must run the webauthn_uv ceremony with the SAME mfa_token and retry.
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(
			{ type: 'https://setjoin.com/errors/reauth-required', code: 'reauth_required' }, 403
		)));
		await expect(setupTOTPEnrollment('pending-jwt')).rejects.toBeInstanceOf(ReauthRequiredError);

		const ok = vi.fn().mockResolvedValue(jsonResponse(
			{ provisioning_uri: 'otpauth://totp/setjoin:u?secret=ABC234', enrollment_id: 'e-uuid-5' }
		));
		vi.stubGlobal('fetch', ok);
		const setup = await setupTOTPEnrollment('pending-jwt');
		expect(setup.secret).toBe('ABC234');
		expect(setup.enrollmentId).toBe('e-uuid-5');
		const call = ok.mock.calls[0];
		expect(JSON.parse((call[1] as RequestInit).body as string)).toEqual({ mfa_token: 'pending-jwt' });
	});

	it('confirmTOTPEnrollment presents the setup-issued enrollment_id (v7 §1.6)', async () => {
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(jsonResponse({ access_token: 'tok' }))
			.mockResolvedValueOnce(jsonResponse({ email: 'a@b', is_admin: false, has_mailbox: true }));
		vi.stubGlobal('fetch', mockFetch);
		await confirmTOTPEnrollment('123456', 'pending-jwt', 'e-uuid-5');
		const call = mockFetch.mock.calls.find((c) => c[0] === '/auth/totp/enroll/confirm');
		expect(JSON.parse((call![1] as RequestInit).body as string)).toEqual({
			code: '123456',
			mfa_token: 'pending-jwt',
			enrollment_id: 'e-uuid-5',
			dpop_jwk: FAKE_DPOP_JWK
		});
	});

	it('confirmTOTPEnrollment remembers the issued token and advances the generation BEFORE probing (r3: usable bound browser sessions)', async () => {
		const genBefore = get(authGeneration);
		// The /auth/me probe records what the token-retention seam held at the
		// moment the probe fired — the ordering the bound-session failure turns
		// on (a proof hashed over a stale/absent token authenticates nowhere).
		let rememberedCallsAtProbe = -1;
		let rememberedArgAtProbe: string | null = null;
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(jsonResponse({ access_token: 'enroll-tok' }))
			.mockImplementationOnce(async () => {
				const calls = vi.mocked(rememberAccessTokenForProofs).mock.calls;
				rememberedCallsAtProbe = calls.length;
				rememberedArgAtProbe = (calls.at(-1)?.[0] as string | null) ?? null;
				return jsonResponse({ email: 'a@b', is_admin: false, has_mailbox: true });
			});
		vi.stubGlobal('fetch', mockFetch);

		await confirmTOTPEnrollment('123456', 'pending-jwt', 'e-uuid-5');

		// The completion response's access_token was remembered BEFORE the
		// /auth/me probe — verifyTOTP's transition, applied here too.
		expect(rememberedCallsAtProbe).toBeGreaterThanOrEqual(1);
		expect(rememberedArgAtProbe).toBe('enroll-tok');
		// The auth generation advanced so pending pre-completion ceremony
		// state retires with the session that just changed.
		expect(get(authGeneration)).toBeGreaterThan(genBefore);
	});

	it('enrollPasskey carries the grant on begin (header) and finish (body member)', async () => {
		const mockCredCreate = vi.fn().mockResolvedValue({
			id: 'cred-id-2',
			rawId: new Uint8Array([1, 2, 3]).buffer,
			response: {
				attestationObject: new Uint8Array([4, 5, 6]).buffer,
				clientDataJSON: new Uint8Array([7, 8, 9]).buffer
			},
			type: 'public-key'
		});
		vi.stubGlobal('navigator', { credentials: { create: mockCredCreate } });
		const mockFetch = vi.fn()
			.mockResolvedValueOnce(jsonResponse({ publicKey: { challenge: 'YWJj', rp: 'localhost', user: { id: 'dXNlcg', name: 'u', displayName: 'u' } } }))
			.mockResolvedValueOnce(jsonResponse({}));
		vi.stubGlobal('fetch', mockFetch);

		await enrollPasskey('tok-reg');
		const beginInit = mockFetch.mock.calls[0][1] as RequestInit;
		expect(new Headers(beginInit.headers).get('X-MFA-Reauth')).toBe('tok-reg');
		const finishBody = JSON.parse((mockFetch.mock.calls[1][1] as RequestInit).body as string);
		expect(finishBody.reauth_token).toBe('tok-reg');
		expect(finishBody.id).toBe('cred-id-2');
	});

	it('enrollPasskey surfaces reauth_required as ReauthRequiredError so the page opens the handoff', async () => {
		vi.stubGlobal('navigator', { credentials: { create: vi.fn() } });
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(
			{ type: 'https://setjoin.com/errors/reauth-required', code: 'reauth_required' }, 403
		)));
		await expect(enrollPasskey()).rejects.toBeInstanceOf(ReauthRequiredError);
	});
});
