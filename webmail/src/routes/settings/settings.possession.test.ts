import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import type { AuthUser } from '$lib/stores/auth';

// Possession scheme v7 §3.1: the /settings general page routes passkey
// registration AND TOTP setup/confirm through the shared method-aware handoff
// — every gated call carries the grant and the 403 reauth_required contract
// drives the handoff; confirm calls carry the setup-issued enrollment_id;
// an account identity change drops displayed secrets (§4.3).

const mocks = await vi.hoisted(async () => {
	const { writable } = await import('svelte/store');
	return {
		checkAuth: vi.fn(),
		setupTOTP: vi.fn(),
		confirmTOTP: vi.fn(),
		beginTOTPRemoval: vi.fn(),
		removeTOTP: vi.fn(),
		enrollPasskey: vi.fn(),
		fetchPasskeyCredentials: vi.fn(),
		beginMFAReauth: vi.fn(),
		possessionTOTPProof: vi.fn(),
		provePossessionWebAuthn: vi.fn(),
		user: writable<AuthUser | null>({ email: 'alice@example.com', isAdmin: false, hasMailbox: true }),
		authGeneration: writable(0),
		authIdentity: (v: Pick<AuthUser, 'email' | 'userId'>): string =>
			v.userId != null ? `user:${v.userId}` : `email:${v.email.toLowerCase()}`
	};
});

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

vi.mock('$lib/stores/auth', () => ({
	user: mocks.user,
	checkAuth: mocks.checkAuth,
	authIdentity: mocks.authIdentity,
	authGeneration: mocks.authGeneration,
	setupTOTP: mocks.setupTOTP,
	confirmTOTP: mocks.confirmTOTP,
	beginTOTPRemoval: mocks.beginTOTPRemoval,
	removeTOTP: mocks.removeTOTP,
	enrollPasskey: mocks.enrollPasskey,
	fetchPasskeyCredentials: mocks.fetchPasskeyCredentials,
	beginMFAReauth: mocks.beginMFAReauth,
	possessionTOTPProof: mocks.possessionTOTPProof,
	provePossessionWebAuthn: mocks.provePossessionWebAuthn,
	ReauthRequiredError
}));

import Page from './+page.svelte';

describe('settings page — v7 §3.1 possession handoff', () => {
	beforeEach(() => {
		mocks.checkAuth.mockReset();
		mocks.setupTOTP.mockReset();
		mocks.confirmTOTP.mockReset();
		mocks.beginTOTPRemoval.mockReset();
		mocks.removeTOTP.mockReset();
		mocks.enrollPasskey.mockReset();
		mocks.beginMFAReauth.mockReset();
		mocks.possessionTOTPProof.mockReset();
		mocks.provePossessionWebAuthn.mockReset();
		mocks.fetchPasskeyCredentials.mockReset();
		mocks.fetchPasskeyCredentials.mockResolvedValue([]);
		mocks.user.set({ email: 'alice@example.com', isAdmin: false, hasMailbox: true });
		mocks.authGeneration.set(0);
		vi.stubGlobal('fetch', vi.fn(async () =>
			new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } })
		));
	});

	afterEach(() => vi.unstubAllGlobals());

	it('PASSKEY REGISTRATION: a gated begin opens the handoff, and the fresh proof retries with the token', async () => {
		mocks.enrollPasskey
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce(undefined);
		mocks.beginMFAReauth.mockResolvedValue({ reauthToken: 'tok-1', expiresIn: 300 });
		render(Page);
		await fireEvent.click(await screen.findByText('Add passkey'));
		const form = await waitFor(() => screen.getByTestId('mfa-reauth-form'));
		expect(form).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		// First call: no token (the 403 drove the handoff). Retry: the minted
		// proof rides the gated registration call.
		await waitFor(() => expect(mocks.enrollPasskey).toHaveBeenNthCalledWith(2, 'tok-1'));
		expect(mocks.enrollPasskey).toHaveBeenNthCalledWith(1, undefined);
	});

	it('TOTP SETUP: reauth_required opens the handoff; the retry mints the pending secret', async () => {
		mocks.setupTOTP
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce({ secret: 'SECRET', provisioningUri: 'otpauth://setjoin' });
		mocks.beginMFAReauth.mockResolvedValue({ reauthToken: 'tok-1', expiresIn: 300 });
		render(Page);
		await fireEvent.click(await screen.findByText('Set up authenticator'));
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(mocks.setupTOTP).toHaveBeenNthCalledWith(2, 'tok-1'));
		await waitFor(() => expect(screen.getByText('SECRET')).toBeInTheDocument());
	});

	it('TOTP CONFIRM: carries the grant and the setup-issued enrollment_id (v7 §1.6)', async () => {
		mocks.setupTOTP
			.mockRejectedValueOnce(new ReauthRequiredError())
			.mockResolvedValueOnce({ secret: 'SECRET', provisioningUri: 'otpauth://setjoin', enrollmentId: 'e-uuid-7' });
		mocks.beginMFAReauth.mockResolvedValue({ reauthToken: 'tok-1', expiresIn: 300 });
		mocks.confirmTOTP.mockResolvedValueOnce(undefined);
		render(Page);
		await fireEvent.click(await screen.findByText('Set up authenticator'));
		await waitFor(() => expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(screen.getByText('SECRET')).toBeInTheDocument());
		await fireEvent.input(screen.getByLabelText('Verification code'), { target: { value: '123456' } });
		await fireEvent.click(screen.getByText('Verify & enable'));
		await waitFor(() =>
			expect(mocks.confirmTOTP).toHaveBeenCalledWith('123456', { reauthToken: 'tok-1', enrollmentId: 'e-uuid-7' })
		);
	});

	it('AUTH-GENERATION FENCING: a SAME-ACCOUNT session change (refresh/rotation) drops the displayed secret and pending handoff (§3.1, r2 defect 10)', async () => {
		mocks.setupTOTP.mockResolvedValue({ secret: 'STALE-SESSION', provisioningUri: 'otpauth://setjoin' });
		render(Page);
		await fireEvent.click(await screen.findByText('Set up authenticator'));
		await waitFor(() => expect(screen.getByText('STALE-SESSION')).toBeInTheDocument());

		// The account identity is UNCHANGED — the session underneath it is not:
		// logout → login as the same user, or a /auth/refresh rotation. Grants
		// bind the access JTI, so pending state pointing at the old session is
		// dead and the secret must drop even though identity never moved.
		mocks.authGeneration.update((n) => n + 1);
		await waitFor(() => expect(screen.queryByText('STALE-SESSION')).toBeNull());
		expect(screen.queryByTestId('mfa-reauth-form')).toBeNull();
	});

	it('AUTH-GENERATION FENCING: an account identity change drops the displayed secret and pending handoff (§3.1)', async () => {
		mocks.setupTOTP.mockResolvedValue({ secret: 'MINE-ONLY', provisioningUri: 'otpauth://setjoin' });
		mocks.beginMFAReauth.mockResolvedValue({ reauthToken: 'tok-1', expiresIn: 300 });
		render(Page);
		await fireEvent.click(await screen.findByText('Set up authenticator'));
		await waitFor(() => expect(screen.getByText('MINE-ONLY')).toBeInTheDocument());

		// checkAuth observes a different account identity mid-enrollment.
		mocks.user.set({ email: 'mallory@example.com', isAdmin: false, hasMailbox: true });
		await waitFor(() => expect(screen.queryByText('MINE-ONLY')).toBeNull());
		expect(screen.queryByTestId('mfa-reauth-form')).toBeNull();
	});
});
