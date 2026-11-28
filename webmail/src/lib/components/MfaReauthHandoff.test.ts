import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import type { AuthUser, MFAReauthOperation } from '$lib/stores/auth';

// Possession scheme v7 §3.1: the shared method-aware reauth handoff. C1
// accounts prove with WebAuthn-UV or a current TOTP code (the §3 possession
// endpoints); the password challenge appears only for the C2/C3 cohorts.
// An account identity change mid-ceremony must fence the proof: a late
// ceremony result is discarded, never delivered to the page.

const mocks = await vi.hoisted(async () => {
	const { writable } = await import('svelte/store');
	return {
		beginMFAReauth: vi.fn(),
		possessionTOTPProof: vi.fn(),
		provePossessionWebAuthn: vi.fn(),
		user: writable<AuthUser | null>({ email: 'alice@example.com', isAdmin: false, hasMailbox: true }),
		authIdentity: (v: Pick<AuthUser, 'email' | 'userId'>): string =>
			v.userId != null ? `user:${v.userId}` : `email:${v.email.toLowerCase()}`
	};
});

vi.mock('$lib/stores/auth', () => ({
	user: mocks.user,
	authIdentity: mocks.authIdentity,
	beginMFAReauth: mocks.beginMFAReauth,
	possessionTOTPProof: mocks.possessionTOTPProof,
	provePossessionWebAuthn: mocks.provePossessionWebAuthn
}));

import MfaReauthHandoff from './MfaReauthHandoff.svelte';

function renderHandoff(
	methods: ('webauthn_uv' | 'totp' | 'password')[],
	onproof = vi.fn(),
	oncancel = vi.fn(),
	operation: MFAReauthOperation = 'recovery.regenerate'
) {
	return render(MfaReauthHandoff, {
		props: { operation, methods, onproof, oncancel }
	});
}

describe('MfaReauthHandoff (v7 §3.1 method-aware handoff)', () => {
	beforeEach(() => {
		mocks.beginMFAReauth.mockReset();
		mocks.possessionTOTPProof.mockReset();
		mocks.provePossessionWebAuthn.mockReset();
		mocks.user.set({ email: 'alice@example.com', isAdmin: false, hasMailbox: true });
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('PASSWORD cohort (C2/C3): password-only methods render the password challenge and mint the proof with the declared operation', async () => {
		const onproof = vi.fn();
		mocks.beginMFAReauth.mockResolvedValue({ reauthToken: 'tok-p', expiresIn: 300 });
		renderHandoff(['password'], onproof);
		expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument();
		expect(screen.queryByTestId('mfa-reauth-method-totp')).toBeNull();
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'pw' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(mocks.beginMFAReauth).toHaveBeenCalledWith('pw', 'recovery.regenerate'));
		await waitFor(() => expect(onproof).toHaveBeenCalledWith({ method: 'password', token: 'tok-p' }));
	});

	it('TOTP cohort: a current code proves at the possession endpoint, never the password', async () => {
		const onproof = vi.fn();
		mocks.possessionTOTPProof.mockResolvedValue({ reauthToken: 'tok-t', expiresIn: 300 });
		renderHandoff(['totp'], onproof, vi.fn(), 'totp.replace');
		expect(screen.queryByLabelText('Account password')).toBeNull();
		await fireEvent.input(screen.getByLabelText('Authenticator code'), { target: { value: '123456' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(mocks.possessionTOTPProof).toHaveBeenCalledWith('totp.replace', '123456'));
		await waitFor(() => expect(onproof).toHaveBeenCalledWith({ method: 'totp', token: 'tok-t' }));
		expect(mocks.beginMFAReauth).not.toHaveBeenCalled();
	});

	it('C1 with BOTH methods: a chooser renders, defaults to WebAuthn-UV, and switching exposes the TOTP arm', async () => {
		const onproof = vi.fn();
		mocks.provePossessionWebAuthn.mockResolvedValue({ scope: 'session', reauthToken: 'tok-w', expiresIn: 300 });
		renderHandoff(['webauthn_uv', 'totp'], onproof);
		expect(screen.getByTestId('mfa-reauth-method-webauthn_uv')).toBeInTheDocument();
		expect(screen.getByTestId('mfa-reauth-method-totp')).toBeInTheDocument();
		expect(screen.getByTestId('mfa-reauth-passkey')).toBeInTheDocument();
		await fireEvent.click(screen.getByTestId('mfa-reauth-passkey'));
		await waitFor(() => expect(mocks.provePossessionWebAuthn).toHaveBeenCalledWith('recovery.regenerate'));
		await waitFor(() => expect(onproof).toHaveBeenCalledWith({ method: 'webauthn_uv', token: 'tok-w' }));
	});

	it('switching to the TOTP method swaps the arm; the WebAuthn ceremony is not started', async () => {
		mocks.possessionTOTPProof.mockResolvedValue({ reauthToken: 'tok-t2', expiresIn: 300 });
		renderHandoff(['webauthn_uv', 'totp']);
		await fireEvent.click(screen.getByTestId('mfa-reauth-method-totp'));
		await fireEvent.input(screen.getByLabelText('Authenticator code'), { target: { value: '999999' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(mocks.possessionTOTPProof).toHaveBeenCalled());
		expect(mocks.provePossessionWebAuthn).not.toHaveBeenCalled();
	});

	it('a refused proof stays inline and recoverable — onproof is not called', async () => {
		const onproof = vi.fn();
		mocks.beginMFAReauth.mockRejectedValue(new Error('invalid password'));
		renderHandoff(['password'], onproof);
		await fireEvent.input(screen.getByLabelText('Account password'), { target: { value: 'wrong' } });
		await fireEvent.click(screen.getByTestId('mfa-reauth-confirm'));
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('invalid password'));
		expect(onproof).not.toHaveBeenCalled();
		expect(screen.getByTestId('mfa-reauth-form')).toBeInTheDocument();
	});

	it('AUTH-GENERATION FENCING: an identity change during the ceremony discards the late proof', async () => {
		const onproof = vi.fn();
		let resolveProof: (value: { scope: string; reauthToken: string; expiresIn: number }) => void = () => {};
		mocks.provePossessionWebAuthn.mockImplementation(
			() => new Promise((resolve) => { resolveProof = resolve; })
		);
		renderHandoff(['webauthn_uv'], onproof);
		await fireEvent.click(screen.getByTestId('mfa-reauth-passkey'));
		await waitFor(() => expect(mocks.provePossessionWebAuthn).toHaveBeenCalled());
		// The account switches (checkAuth observes a different identity) while
		// the UV ceremony is in flight.
		mocks.user.set({ email: 'mallory@example.com', isAdmin: false, hasMailbox: true });
		resolveProof({ scope: 'session', reauthToken: 'late-token', expiresIn: 300 });
		await Promise.resolve();
		await new Promise((r) => setTimeout(r, 0));
		expect(onproof).not.toHaveBeenCalled();
		expect(mocks.provePossessionWebAuthn).toHaveBeenCalledTimes(1);
	});

	it('cancel closes through the page callback', async () => {
		const oncancel = vi.fn();
		renderHandoff(['password'], vi.fn(), oncancel);
		await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
		expect(oncancel).toHaveBeenCalled();
	});
});
