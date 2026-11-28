import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import type { AuthUser } from '$lib/stores/auth';

// Possession scheme v7 §3.1 + §4.3: the /settings/security reauth handoff is
// METHOD-AWARE — a C1 account (TOTP enabled or an enrolled UV-capable passkey)
// is offered the WebAuthn-UV / TOTP possession proofs (§3 possession
// endpoints); the password challenge appears only for the C2/C3 cohorts.
// Held-proof discipline, honest retry-after-proof loops and auth-generation
// fencing (identity change drops secrets / discards late responses) are pinned.

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
		fetchPasskeyCredentials: vi.fn(),
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

function json(data: unknown, status = 200): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: { 'content-type': 'application/json' },
	});
}

function installFetch(opts: { totpEnabled?: boolean } = {}) {
	vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input);
		if (url.includes('/api/user/devices')) return json({ devices: [] });
		if (url.includes('/api/user/security-score')) return json(null);
		if (url.includes('/api/user/login-history')) return json({ items: [], total: 0 });
		if (url.includes('/api/user/sessions')) return json({ sessions: [] });
		if (url.includes('/api/user/cert-status')) return json({ status: 'none' });
		if (url.includes('/auth/me/smime/recipient-certs')) return json({ certs: [] });
		if (url.includes('/auth/me/smime/certs')) return json({ certs: [] });
		if (url.endsWith('/auth/me')) return json({ totp_enabled: opts.totpEnabled === true });
		return json({});
	}));
}

const BASE = { initialTab: 'totp', initialLoading: false, initialSignIns: [], initialSessions: [] };

describe('security settings — v7 §3.1 method-aware reauth handoff', () => {
	beforeEach(() => {
		for (const key of ['goto', 'setupTOTP', 'confirmTOTP', 'beginTOTPRemoval', 'removeTOTP', 'beginMFAReauth', 'possessionTOTPProof', 'provePossessionWebAuthn', 'fetchPasskeyCredentials', 'generateBackupCodes'] as const) {
			mocks[key].mockReset();
		}
		mocks.fetchPasskeyCredentials.mockResolvedValue([]);
		mocks.user.set({ email: 'alice@example.com', isAdmin: false, hasMailbox: true });
		mocks.authGeneration.set(0);
	});

	afterEach(() => vi.unstubAllGlobals());

	it('C2/C3 (no possession factor): first-factor setup surfaces the PASSWORD handoff, then retries setup with the minted token', async () => {
		installFetch();
		mocks.setupTOTP
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce({ secret: 'SECRET', provisioningUri: 'otpauth://setjoin' });
		mocks.beginMFAReauth.mockResolvedValueOnce({ reauthToken: 'tok-1', expiresIn: 300 });
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		const form = await waitFor(() => screen.getByTestId('mfa-reauth-form'));
		expect(form).toBeInTheDocument();
		expect(screen.getByTestId('mfa-reauth-confirm')).toBeDisabled();
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		// The password challenge declares the operation it authorizes (§3 T3.1).
		await waitFor(() => expect(mocks.beginMFAReauth).toHaveBeenCalledWith('pw', 'totp.enroll'));
		// The gated call retries with the freshly minted, single-use token.
		await waitFor(() => expect(mocks.setupTOTP).toHaveBeenNthCalledWith(2, 'tok-1'));
		await waitFor(() => expect(screen.getByText('SECRET')).toBeInTheDocument());
		expect(screen.queryByTestId('mfa-reauth-form')).toBeNull();
	});

	it('C1 with TOTP enabled: re-enroll offers the TOTP possession proof — no password challenge', async () => {
		installFetch({ totpEnabled: true });
		mocks.setupTOTP
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce({ secret: 'SECRET2', provisioningUri: 'otpauth://setjoin2' });
		mocks.possessionTOTPProof.mockResolvedValueOnce({ reauthToken: 'tok-totp', expiresIn: 300 });
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(await screen.findByText('Re-enroll'));
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument());
		// Method-aware: possession method only — no password field.
		expect(screen.queryByLabelText('Account password')).toBeNull();
		expect(screen.getByLabelText('Authenticator code')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Authenticator code'), { target: { value: '123456' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		// Proof runs against the possession endpoint with the replace operation.
		await waitFor(() => expect(mocks.possessionTOTPProof).toHaveBeenCalledWith('totp.replace', '123456'));
		expect(mocks.beginMFAReauth).not.toHaveBeenCalled();
		await waitFor(() => expect(mocks.setupTOTP).toHaveBeenNthCalledWith(2, 'tok-totp'));
		await waitFor(() => expect(screen.getByText('SECRET2')).toBeInTheDocument());
	});

	it('C1 with a UV-capable passkey only: the handoff offers the WebAuthn-UV assertion (§3 possession endpoints)', async () => {
		installFetch();
		mocks.fetchPasskeyCredentials.mockResolvedValue([
			{ id: 'cred-1', device_name: 'iPhone', created_at: '2026-01-01T00:00:00Z', uv_capable: true }
		]);
		mocks.setupTOTP
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce({ secret: 'SECRET3', provisioningUri: 'otpauth://setjoin3' });
		mocks.provePossessionWebAuthn.mockResolvedValueOnce({ scope: 'session', reauthToken: 'tok-uv', expiresIn: 300 });
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument());
		// The credential read resolves mid-handoff: the offered method corrects
		// to the UV assertion once enrollment info lands.
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-passkey')).toBeInTheDocument());
		expect(screen.queryByLabelText('Account password')).toBeNull();
		// The credential read lands mid-handoff: wait for the offered method to
		// settle on the UV arm (password input gone) before interacting.
		await waitFor(() => expect(screen.queryByLabelText('Account password')).toBeNull());
		// One macrotask so both render passes of the method flip are flushed
		// before the button node is queried and clicked.
		await new Promise((r) => setTimeout(r, 0));
		await fireEvent.click(screen.getByTestId('mfa-reauth-passkey'));
		await waitFor(() => expect(mocks.provePossessionWebAuthn).toHaveBeenCalledWith('totp.enroll'));
		await waitFor(() => expect(mocks.setupTOTP).toHaveBeenNthCalledWith(2, 'tok-uv'));
		await waitFor(() => expect(screen.getByText('SECRET3')).toBeInTheDocument());
	});

	it('CONFIRM: a stale proof mid-enrollment restarts SETUP after the fresh proof — the new enrollment binding replaces the dead one (v7 §1.6, r3 #8)', async () => {
		installFetch();
		mocks.setupTOTP
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce({ secret: 'SECRET', provisioningUri: 'otpauth://setjoin', enrollmentId: 'e-uuid-1' })
			// The RESTART after the confirm handoff's fresh proof: a NEW pending
			// secret bound to a NEW enrollment id.
			.mockResolvedValueOnce({ secret: 'SECRET-NEW', provisioningUri: 'otpauth://setjoin-new', enrollmentId: 'e-uuid-2' });
		mocks.beginMFAReauth
			.mockResolvedValueOnce({ reauthToken: 'tok-1', expiresIn: 300 })
			.mockResolvedValueOnce({ reauthToken: 'tok-2', expiresIn: 300 });
		mocks.confirmTOTP.mockRejectedValueOnce(new ReauthRequiredError());
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(screen.getByText('SECRET')).toBeInTheDocument());
		const code = screen.getByLabelText('Verification code');
		await fireEvent.input(code, { target: { value: '123456' } });
		await fireEvent.click(screen.getByText('Verify & enable'));
		// The confirm's stale-proof refusal reopens the handoff…
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		// …and the fresh proof RESTARTS SETUP (never a re-confirm of the dead
		// (grant, enrollment) pairing): a new secret and enrollment binding.
		await waitFor(() => expect(mocks.setupTOTP).toHaveBeenNthCalledWith(3, 'tok-2'));
		await waitFor(() => expect(screen.getByText('SECRET-NEW')).toBeInTheDocument());
		expect(screen.getByLabelText('Verification code')).toHaveValue('');
		// The old enrollment was never re-confirmed.
		expect(mocks.confirmTOTP).toHaveBeenCalledTimes(1);
		// The user confirms against the NEW binding with a fresh code.
		await fireEvent.input(screen.getByLabelText('Verification code'), { target: { value: '654321' } });
		await fireEvent.click(screen.getByText('Verify & enable'));
		await waitFor(() =>
			expect(mocks.confirmTOTP).toHaveBeenNthCalledWith(2, '654321', { reauthToken: 'tok-2', enrollmentId: 'e-uuid-2' })
		);
		await waitFor(() => expect(screen.getByText('Active')).toBeInTheDocument());
	});

	it('CONFIRM carries the setup-issued enrollment_id (v7 §1.6)', async () => {
		installFetch();
		mocks.setupTOTP.mockResolvedValue({ secret: 'SECRET', provisioningUri: 'otpauth://setjoin', enrollmentId: 'e-uuid-1' });
		mocks.setupTOTP.mockRejectedValueOnce(new ReauthRequiredError());
		mocks.beginMFAReauth.mockResolvedValueOnce({ reauthToken: 'tok-1', expiresIn: 300 });
		mocks.confirmTOTP.mockResolvedValueOnce(undefined);
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(screen.getByText('SECRET')).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText('Verification code'), { target: { value: '123456' } });
		await fireEvent.click(screen.getByText('Verify & enable'));
		await waitFor(() =>
			expect(mocks.confirmTOTP).toHaveBeenCalledWith('123456', { reauthToken: 'tok-1', enrollmentId: 'e-uuid-1' })
		);
	});

	it('RECOVERY regeneration: gated for every account; handoff then displays the new codes once', async () => {
		installFetch();
		mocks.generateBackupCodes
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce(['aaa11111', 'bbb22222', 'ccc33333', 'ddd44444', 'eee55555', 'fff66666', 'ggg77777', 'hhh88888', 'iii99999', 'jjj00000']);
		mocks.beginMFAReauth.mockResolvedValueOnce({ reauthToken: 'tok-3', expiresIn: 300 });
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByTestId('recovery-regenerate'));
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(mocks.generateBackupCodes).toHaveBeenNthCalledWith(2, 'tok-3'));
		const codes = await waitFor(() => screen.getByTestId('recovery-codes'));
		expect(codes.textContent).toContain('aaa11111');
		expect(codes.textContent).toContain('jjj00000');
	});

	it('wrong password: recoverable error inside the handoff form; the gated call is not retried', async () => {
		installFetch();
		mocks.setupTOTP.mockRejectedValueOnce(new ReauthRequiredError());
		mocks.beginMFAReauth.mockRejectedValueOnce(new Error('invalid password'));
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'wrong' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('invalid password'));
		expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument();
		expect(mocks.setupTOTP).toHaveBeenCalledTimes(1);
	});

	it('AUTH-GENERATION FENCING (r4 #10): a SAME-ACCOUNT session-lifecycle move — an authGeneration bump with an unchanged identity — retires the grant/secret/pending state on this page too', async () => {
		installFetch();
		mocks.setupTOTP.mockResolvedValue({ secret: 'MINE-ONLY', provisioningUri: 'otpauth://setjoin' });
		mocks.setupTOTP.mockRejectedValueOnce(new ReauthRequiredError());
		mocks.beginMFAReauth.mockResolvedValueOnce({ reauthToken: 'tok-1', expiresIn: 300 });
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		// A staged secret + a held grant exist mid-ceremony.
		await waitFor(() => expect(screen.getByText('MINE-ONLY')).toBeInTheDocument());

		// A /auth/refresh rotation — SAME account ($user untouched) — bumps the
		// auth generation (as does an admission recovery that discovered the
		// shared cookie's token rotated under this page). The fence must fire:
		// the staged secret drops, the held grant and pending handoff state
		// retire. Identity-only fencing kept all of it alive across the
		// rotation (r4 #10 fail-before).
		mocks.authGeneration.update((n) => n + 1);
		await waitFor(() => expect(screen.queryByText('MINE-ONLY')).toBeNull());
		expect(screen.queryByTestId('mfa-reauth-form')).toBeNull();
		expect(screen.getByText('Set up authenticator')).toBeInTheDocument();
	});

	it('AUTH-GENERATION FENCING: an account identity change drops the displayed secret and closes the handoff (§3.1)', async () => {
		installFetch();
		mocks.setupTOTP.mockResolvedValue({ secret: 'MINE-ONLY', provisioningUri: 'otpauth://setjoin' });
		mocks.setupTOTP.mockRejectedValueOnce(new ReauthRequiredError());
		mocks.beginMFAReauth.mockResolvedValueOnce({ reauthToken: 'tok-1', expiresIn: 300 });
		render(Page, { props: { ...BASE } });
		// Let the authedBootstrap initial loads settle (the /auth/me read stages
		// totpEnabled) before driving the handoff workflows.
		await screen.findByText(/saved automatically when you receive signed mail/);
		await fireEvent.click(screen.getByText('Set up authenticator'));
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(screen.getByText('MINE-ONLY')).toBeInTheDocument());

		// checkAuth observes a different account identity.
		mocks.user.set({ email: 'mallory@example.com', isAdmin: false, hasMailbox: true });
		await waitFor(() => expect(screen.queryByText('MINE-ONLY')).toBeNull());
		expect(screen.queryByTestId('mfa-reauth-form')).toBeNull();
	});
});
