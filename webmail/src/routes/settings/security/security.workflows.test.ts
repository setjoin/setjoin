import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import type { AuthUser } from '$lib/stores/auth';

// The page + the shared MfaReauthHandoff component import these from the auth
// store; the writable user store is required at render time ($user), so the
// mock supplies it together with the identity helper.
const mocks = await vi.hoisted(async () => {
	const { writable } = await import('svelte/store');
	return {
		goto: vi.fn(),
		setupTOTP: vi.fn(),
		confirmTOTP: vi.fn(),
		beginTOTPRemoval: vi.fn(),
		removeTOTP: vi.fn(),
		beginMFAReauth: vi.fn(),
		possessionTOTPProof: vi.fn(),
		provePossessionWebAuthn: vi.fn(),
		fetchPasskeyCredentials: vi.fn().mockResolvedValue([]),
		generateBackupCodes: vi.fn(),
		user: writable<AuthUser | null>({ email: 'alice@example.com', isAdmin: false, hasMailbox: true }),
		authGeneration: writable(0),
		authIdentity: (v: Pick<AuthUser, 'email' | 'userId'>): string =>
			v.userId != null ? `user:${v.userId}` : `email:${v.email.toLowerCase()}`
	};
});

// vi.mock factories are hoisted above top-level declarations, so the class
// the factory exports must itself be hoisted (same pattern as the mocks bag).
const ReauthRequiredError = vi.hoisted(
	() =>
		class ReauthRequiredError extends Error {
			challengePath = '/auth/mfa/reauth';
			constructor() {
				super('reauth_required');
				this.name = 'ReauthRequiredError';
			}
		}
);

vi.mock('$app/navigation', () => ({ goto: mocks.goto }));
vi.mock('$lib/stores/auth', () => ({
	setupTOTP: mocks.setupTOTP,
	confirmTOTP: mocks.confirmTOTP,
	beginTOTPRemoval: mocks.beginTOTPRemoval,
	removeTOTP: mocks.removeTOTP,
	beginMFAReauth: mocks.beginMFAReauth,
	possessionTOTPProof: mocks.possessionTOTPProof,
	provePossessionWebAuthn: mocks.provePossessionWebAuthn,
	fetchPasskeyCredentials: mocks.fetchPasskeyCredentials,
	generateBackupCodes: mocks.generateBackupCodes,
	ReauthRequiredError,
	user: mocks.user,
	authGeneration: mocks.authGeneration,
	authIdentity: mocks.authIdentity
}));

import Page from './+page.svelte';

type Handler = (url: string, init?: RequestInit) => Promise<Response>;

function json(data: unknown, status = 200): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { 'content-type': 'application/json' },
	});
}

function installFetch(handler?: Handler) {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input);
		calls.push({ url, init });
		if (handler) {
			const response = await handler(url, init);
			if (response) return response;
		}
		if (url.includes('/api/user/devices')) return json({ devices: [] });
		if (url.includes('/api/user/security-score')) return json(null);
		if (url.includes('/api/user/login-history')) return json({ items: [], total: 0 });
		if (url.includes('/api/user/sessions')) return json({ sessions: [] });
		if (url.includes('/api/user/cert-status')) return json({ status: 'none' });
		if (url.includes('/auth/me/smime/recipient-certs')) return json({ certs: [] });
		if (url.includes('/auth/me/smime/certs')) return json({ certs: [] });
		if (url.endsWith('/auth/me')) return json({ totp_enabled: false });
		// The authedBootstrap probe reads the session document — any JSON body
		// proves a freshly installed document and unlocks the protected loaders.
		if (url.includes('/.well-known/jmap')) return json({ capabilities: {} });
		return json({});
	});
	vi.stubGlobal('fetch', fetchMock);
	return { calls, fetchMock };
}

// The $lib/http seam always sends an explicit method (GET for reads); GET
// detection must accept both the seam's shape and the legacy init-less one.
const isGet = (init?: RequestInit): boolean => (init?.method ?? 'GET').toUpperCase() === 'GET';

describe('security settings — mutation workflows', () => {
	beforeEach(() => {
		mocks.goto.mockReset();
		mocks.setupTOTP.mockReset();
		mocks.confirmTOTP.mockReset();
		mocks.beginTOTPRemoval.mockReset();
		mocks.removeTOTP.mockReset();
		mocks.beginMFAReauth.mockReset();
		mocks.generateBackupCodes.mockReset();
	});

	afterEach(() => vi.unstubAllGlobals());

	it('revokes a remote session, announces it, and reloads the session list', async () => {
		let sessionReads = 0;
		const { calls } = installFetch(async (url, init) => {
			if (url.endsWith('/api/user/sessions') && isGet(init)) {
				sessionReads += 1;
				return json({ sessions: sessionReads === 1 ? [{ id: 'remote', device: 'Firefox', location: 'Paris' }] : [] });
			}
			if (url.endsWith('/api/user/sessions/remote') && init?.method === 'DELETE') return json({});
			return undefined as never;
		});
		render(Page, { props: { initialTab: 'history', initialSignIns: [], initialLoading: false } as never });
		await waitFor(() => expect(screen.getByTestId('session-revoke-remote')).toBeInTheDocument());
		await fireEvent.click(screen.getByTestId('session-revoke-remote'));
		await fireEvent.click(screen.getByText('Sign out', { selector: '[role="dialog"] button' }));
		await waitFor(() => expect(calls.some((call) => call.url.endsWith('/sessions/remote') && call.init?.method === 'DELETE')).toBe(true));
		expect(screen.getByTestId('security-live').textContent).toContain('Firefox');
		expect(sessionReads).toBe(2);
	});

	it('redirects after revoking the current session and after revoke-all succeeds', async () => {
		installFetch(async (url, init) => {
			if (url.endsWith('/api/user/sessions/current') && init?.method === 'DELETE') return json({});
			if (url.endsWith('/api/user/sessions/revoke-all') && init?.method === 'POST') return json({});
			return undefined as never;
		});
		render(Page, { props: {
			initialTab: 'history', initialSignIns: [], initialLoading: false,
			initialSessions: [{ id: 'current', current: true, device: 'This browser' }],
		} as never });
		await fireEvent.click(screen.getByTestId('session-revoke-current'));
		await fireEvent.click(screen.getByText('Sign out', { selector: '[role="dialog"] button' }));
		await waitFor(() => expect(mocks.goto).toHaveBeenCalledWith('/login'));
		mocks.goto.mockClear();
		await fireEvent.click(screen.getByTestId('revoke-all-trigger'));
		await fireEvent.click(screen.getByTestId('revoke-all-confirm'));
		await waitFor(() => expect(mocks.goto).toHaveBeenCalledWith('/login'));
	});

	it('shows safe failure feedback when session mutation and secure-account calls fail', async () => {
		installFetch(async (url, init) => {
			if (url.includes('/api/user/sessions/fail') && init?.method === 'DELETE') return json({}, 500);
			if (url.endsWith('/api/user/sessions/revoke-all') && init?.method === 'POST') return json({}, 500);
			if (url.endsWith('/api/user/sign-ins/secure-account')) return json({}, 500);
			return undefined as never;
		});
		render(Page, { props: {
			initialTab: 'history', initialSignIns: [], initialLoading: false,
			initialSessions: [{ id: 'fail', device: 'Tablet' }],
		} as never });
		await fireEvent.click(screen.getByTestId('session-revoke-fail'));
		await fireEvent.click(screen.getByText('Sign out', { selector: '[role="dialog"] button' }));
		await waitFor(() => expect(screen.getByText(/could not sign out that session/i)).toBeInTheDocument());
		await fireEvent.click(screen.getByTestId('revoke-all-trigger'));
		await fireEvent.click(screen.getByTestId('revoke-all-confirm'));
		await waitFor(() => expect(screen.getByText(/could not sign out everywhere/i)).toBeInTheDocument());
		await fireEvent.click(screen.getByTestId('secure-account-trigger'));
		await fireEvent.input(screen.getByTestId('secure-account-type'), { target: { value: 'SECURE' } });
		await waitFor(() => expect(screen.getByTestId('secure-account-confirm')).not.toBeDisabled());
		await fireEvent.click(screen.getByTestId('secure-account-confirm'));
		await waitFor(() => expect(screen.getByText(/account has not been changed/i)).toBeInTheDocument());
		expect(mocks.goto).not.toHaveBeenCalled();
	});

	it('lists remote sessions before securing the account and accepts a 401 terminal response', async () => {
		installFetch(async (url, init) => {
			if (url.endsWith('/api/user/sessions') && isGet(init)) return json({ sessions: [
				{ id: 'self', current: true, device: 'Current' },
				{ id: 'other', device: 'Phone', last_used_at: '2026-07-20T10:00:00Z' },
			] });
			if (url.endsWith('/api/user/sign-ins/secure-account')) return json({}, 401);
			return undefined as never;
		});
		render(Page, { props: { initialTab: 'history', initialSignIns: [], initialLoading: false, initialSessions: [] } as never });
		await fireEvent.click(screen.getByTestId('secure-account-trigger'));
		await waitFor(() => expect(screen.getByText(/Phone/)).toBeInTheDocument());
		expect(screen.queryByText(/^Current/)).toBeNull();
		await fireEvent.input(screen.getByTestId('secure-account-type'), { target: { value: 'SECURE' } });
		await fireEvent.click(screen.getByTestId('secure-account-confirm'));
		await waitFor(() => expect(mocks.goto).toHaveBeenCalledWith('/?secured=1'));
	});

	it('covers TOTP setup, confirmation, step-up removal, and their recoverable errors', async () => {
		installFetch();
		mocks.setupTOTP.mockResolvedValueOnce({ secret: 'SECRET', provisioningUri: 'otpauth://setjoin' });
		mocks.confirmTOTP.mockRejectedValueOnce(new Error('bad code')).mockResolvedValueOnce(undefined);
		mocks.beginTOTPRemoval
			.mockRejectedValueOnce(new Error('network'))
			.mockResolvedValueOnce({ stepUpToken: 'tok-1', expiresIn: 300 });
		mocks.removeTOTP.mockResolvedValueOnce(undefined);
		render(Page, { props: { initialTab: 'totp', initialLoading: false, initialSignIns: [], initialSessions: [] } as never });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the TOTP workflow — otherwise the mount
		// bootstrap can land mid-ceremony and flip the card state.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		await waitFor(() => expect(screen.getByText('SECRET')).toBeInTheDocument());
		const code = screen.getByLabelText('Verification code');
		await fireEvent.input(code, { target: { value: '123456' } });
		await fireEvent.click(screen.getByText('Verify & enable'));
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Invalid code'));
		await fireEvent.click(screen.getByText('Verify & enable'));
		await waitFor(() => expect(screen.getByText('Active')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Disable'));
		await waitFor(() => expect(screen.getByTestId('totp-remove-form')).toBeInTheDocument());
		// The confirm control stays disabled until password + code + typed REMOVE.
		await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'pw' } });
		await fireEvent.input(screen.getByLabelText('Authenticator or recovery code'), { target: { value: '123456' } });
		expect(screen.getByTestId('totp-remove-confirm')).toBeDisabled();
		await fireEvent.input(screen.getByLabelText('Type REMOVE to confirm'), { target: { value: 'remove' } });
		expect(screen.getByTestId('totp-remove-confirm')).toBeDisabled();
		await fireEvent.input(screen.getByLabelText('Type REMOVE to confirm'), { target: { value: 'REMOVE' } });
		await fireEvent.click(screen.getByTestId('totp-remove-confirm'));
		// Begin failure (e.g. wrong code): recoverable, form stays open.
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Failed to remove TOTP'));
		// Second attempt completes the step-up and the typed-confirmation removal.
		await fireEvent.input(screen.getByLabelText('Authenticator or recovery code'), { target: { value: '654321' } });
		await fireEvent.click(screen.getByTestId('totp-remove-confirm'));
		await waitFor(() => expect(mocks.removeTOTP).toHaveBeenCalledWith('tok-1'));
		await waitFor(() => expect(screen.getByText('Set up authenticator')).toBeInTheDocument());
		expect(mocks.beginTOTPRemoval).toHaveBeenNthCalledWith(2, 'pw', '654321');
	});

	it('uploads, defaults, and deletes an S/MIME identity certificate', async () => {
		let deleted = false;
		const { calls } = installFetch(async (url, init) => {
			if (url.endsWith('/auth/me/smime/certs') && isGet(init)) {
				return json({ certs: deleted ? [] : [{
					id: 'cert-1', label: 'Work', isDefault: false,
					issuedAt: '2025-01-01', expiresAt: '2025-02-01',
				}] });
			}
			if (url.endsWith('/auth/me/smime/certs/cert-1') && init?.method === 'DELETE') deleted = true;
			if (url.includes('/auth/me/smime/certs') && init?.method) return json({});
			return undefined as never;
		});
		const { container } = render(Page, { props: { initialLoading: false, initialSignIns: [], initialSessions: [] } as never });
		await waitFor(() => expect(screen.getByText('Work')).toBeInTheDocument());
		await fireEvent.click(screen.getByText('Set as default'));
		await waitFor(() => expect(calls.some((call) => call.url.endsWith('/cert-1/default'))).toBe(true));
		await waitFor(() => expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		await fireEvent.click(screen.getByText('Delete', { selector: '[role="dialog"] button' }));
		await waitFor(() => expect(calls.some((call) => call.url.endsWith('/cert-1') && call.init?.method === 'DELETE')).toBe(true));

		const label = screen.getByLabelText('Label');
		await fireEvent.input(label, { target: { value: ' Personal ' } });
		const files = container.querySelectorAll<HTMLInputElement>('.sj-smime-file-input');
		await fireEvent.change(files[0], { target: { files: [new File(['cert'], 'cert.pem')] } });
		await fireEvent.change(files[1], { target: { files: [new File(['key'], 'key.pem')] } });
		await fireEvent.click(screen.getByText('Upload'));
		await waitFor(() => expect(calls.some((call) => call.url.endsWith('/smime/certs') && call.init?.method === 'POST')).toBe(true));
	});

	it('imports and deletes a contact certificate and renders the expiring-soon boundary', async () => {
		let deleted = false;
		const soon = new Date(Date.now() + 10 * 86400 * 1000).toISOString();
		const { calls } = installFetch(async (url, init) => {
			if (url.endsWith('/auth/me/smime/recipient-certs') && isGet(init)) {
				return json({ certs: deleted ? [] : [{
					id: 7, email: 'friend@example.test', label: 'Friend', source: 'imported',
					notBefore: '2026-01-01', notAfter: soon, fingerprint: 'abc', isEncryptCapable: true,
				}] });
			}
			if (url.endsWith('/auth/me/smime/recipient-certs/7') && init?.method === 'DELETE') deleted = true;
			if (url.includes('/auth/me/smime/recipient-certs') && init?.method) return json({});
			return undefined as never;
		});
		const { container } = render(Page, { props: { initialLoading: false, initialSignIns: [], initialSessions: [] } as never });
		await waitFor(() => expect(screen.getByText('Expiring soon')).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		await fireEvent.click(screen.getByText('Delete', { selector: '[role="dialog"] button' }));
		await waitFor(() => expect(calls.some((call) => call.url.endsWith('/recipient-certs/7') && call.init?.method === 'DELETE')).toBe(true));
		const contactFile = container.querySelectorAll<HTMLInputElement>('.sj-smime-file-input')[2];
		await fireEvent.change(contactFile, { target: { files: [new File(['cert'], 'friend.crt')] } });
		await fireEvent.click(screen.getByText('Import'));
		await waitFor(() => expect(calls.some((call) => call.url.endsWith('/recipient-certs') && call.init?.method === 'POST')).toBe(true));
	});
});
