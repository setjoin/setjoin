import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';

// Possession scheme v7 §1.5.1 (login-flow C1 bootstrap): the enrollment-
// required login returns the SAME mfa_token for both cohorts, but a
// passkey-holder (C1) has NO password bootstrap grant — the bare
// /auth/totp/enroll/setup answers the typed 403 reauth_required, the client
// runs the webauthn_uv management ceremony (Mode B admission via the SAME
// mfa_token, finish {"granted": true}), and only then retries setup.
// Confirm presents the setup-issued enrollment_id (§1.6). A superseded
// attempt (new submit, back link) fences in-flight responses (§3.1).

const mocks = await vi.hoisted(async () => {
	class ForcePasswordChangeError extends Error {
		constructor(message: string) { super(message); this.name = 'ForcePasswordChangeError'; }
	}
	class MFARequiredError extends Error {
		mfaToken: string;
		constructor(message: string, mfaToken: string) { super(message); this.name = 'MFARequiredError'; this.mfaToken = mfaToken; }
	}
	class MFAEnrollmentRequiredError extends Error {
		mfaToken: string;
		constructor(message: string, mfaToken: string) { super(message); this.name = 'MFAEnrollmentRequiredError'; this.mfaToken = mfaToken; }
	}
	class ThreatBlockedError extends Error {
		category: string;
		constructor(category: string) { super(category); this.name = 'ThreatBlockedError'; this.category = category; }
	}
	class ReauthRequiredError extends Error {
		challengePath = '/auth/mfa/reauth';
		constructor() { super('reauth_required'); this.name = 'ReauthRequiredError'; }
	}
	return {
		login: vi.fn(),
		loginWithCaptcha: vi.fn(),
		changePassword: vi.fn(),
		startWebAuthnLogin: vi.fn(),
		verifyTOTP: vi.fn(),
		setupTOTPEnrollment: vi.fn(),
		confirmTOTPEnrollment: vi.fn(),
		provePossessionWebAuthn: vi.fn(),
		ForcePasswordChangeError,
		MFARequiredError,
		MFAEnrollmentRequiredError,
		ThreatBlockedError,
		ReauthRequiredError
	};
});

vi.mock('$lib/stores/auth', () => ({
	login: mocks.login,
	loginWithCaptcha: mocks.loginWithCaptcha,
	changePassword: mocks.changePassword,
	startWebAuthnLogin: mocks.startWebAuthnLogin,
	verifyTOTP: mocks.verifyTOTP,
	setupTOTPEnrollment: mocks.setupTOTPEnrollment,
	confirmTOTPEnrollment: mocks.confirmTOTPEnrollment,
	provePossessionWebAuthn: mocks.provePossessionWebAuthn,
	ForcePasswordChangeError: mocks.ForcePasswordChangeError,
	MFARequiredError: mocks.MFARequiredError,
	MFAEnrollmentRequiredError: mocks.MFAEnrollmentRequiredError,
	ThreatBlockedError: mocks.ThreatBlockedError,
	ReauthRequiredError: mocks.ReauthRequiredError
}));

import LoginPage from './+page.svelte';

const PENDING_TOKEN = 'pending-jwt-token';

async function submitPassword() {
	await fireEvent.input(screen.getByLabelText('Email'), { target: { value: 'alice@example.com' } });
	await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'pw' } });
	await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));
}

async function enterCodeAndConfirm(code: string) {
	const input = screen.getByPlaceholderText('000 000');
	await fireEvent.input(input, { target: { value: code } });
	await fireEvent.click(screen.getByRole('button', { name: /Enable and sign in/ }));
}

describe('login flow — v7 §1.5.1 possession bootstrap handoff', () => {
	beforeEach(() => {
		for (const key of ['login', 'loginWithCaptcha', 'changePassword', 'startWebAuthnLogin', 'verifyTOTP', 'setupTOTPEnrollment', 'confirmTOTPEnrollment', 'provePossessionWebAuthn'] as const) {
			mocks[key].mockReset();
		}
		vi.stubGlobal('fetch', vi.fn(async () =>
			new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } })
		));
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('C2/C3 bootstrap (grant minted at login): setup works with the bare token; confirm carries the enrollment_id', async () => {
		mocks.login.mockRejectedValueOnce(
			new mocks.MFAEnrollmentRequiredError('MFA enrollment is required', PENDING_TOKEN)
		);
		mocks.setupTOTPEnrollment.mockResolvedValueOnce({
			secret: 'BOOTSECRET',
			provisioningUri: 'otpauth://totp/setjoin:u?secret=BOOTSECRET',
			enrollmentId: 'e-uuid-1'
		});
		mocks.confirmTOTPEnrollment.mockResolvedValueOnce({ status: 'ok' });
		render(LoginPage);
		await submitPassword();
		// Setup rode the pending token alone — no proof required for C2/C3.
		await waitFor(() => expect(mocks.setupTOTPEnrollment).toHaveBeenCalledWith(PENDING_TOKEN));
		await waitFor(() => expect(screen.getByText('BOOTSECRET')).toBeInTheDocument());
		expect(mocks.provePossessionWebAuthn).not.toHaveBeenCalled();

		await enterCodeAndConfirm('123456');
		await waitFor(() =>
			expect(mocks.confirmTOTPEnrollment).toHaveBeenCalledWith('123456', PENDING_TOKEN, 'e-uuid-1')
		);
	});

	it('C1 passkey-holder: setup refuses reauth_required → UV ceremony (Mode B) → setup retried with the SAME token', async () => {
		mocks.login.mockRejectedValueOnce(
			new mocks.MFAEnrollmentRequiredError('MFA enrollment is required', PENDING_TOKEN)
		);
		mocks.setupTOTPEnrollment
			.mockRejectedValueOnce(new mocks.ReauthRequiredError())
			.mockResolvedValueOnce({
				secret: 'C1SECRET',
				provisioningUri: 'otpauth://totp/setjoin:u?secret=C1SECRET',
				enrollmentId: 'e-uuid-2'
			});
		mocks.provePossessionWebAuthn.mockResolvedValueOnce({ scope: 'mfa_pending', granted: true });
		render(LoginPage);
		await submitPassword();

		// The refusal routes to the passkey step — no secret is shown yet.
		await waitFor(() => expect(screen.getByRole('button', { name: /Use your passkey/ })).toBeInTheDocument());
		expect(screen.queryByText(/Manual setup key/)).toBeNull();
		expect(screen.queryByText('000 000')).toBeNull();

		await fireEvent.click(screen.getByRole('button', { name: /Use your passkey/ }));
		await waitFor(() =>
			expect(mocks.provePossessionWebAuthn).toHaveBeenCalledWith('bootstrap.totp.enroll', { mfaToken: PENDING_TOKEN })
		);
		// The retry re-runs setup with the UNCHANGED pending token (§1.5.1).
		await waitFor(() => expect(mocks.setupTOTPEnrollment).toHaveBeenNthCalledWith(2, PENDING_TOKEN));
		await waitFor(() => expect(screen.getByText('C1SECRET')).toBeInTheDocument());

		await enterCodeAndConfirm('654321');
		await waitFor(() =>
			expect(mocks.confirmTOTPEnrollment).toHaveBeenCalledWith('654321', PENDING_TOKEN, 'e-uuid-2')
		);
	});

	it('a refused proof after the ceremony reopens the passkey step honestly (retry-after-proof loop)', async () => {
		mocks.login.mockRejectedValueOnce(
			new mocks.MFAEnrollmentRequiredError('MFA enrollment is required', PENDING_TOKEN)
		);
		// The ceremony succeeded but the staged grant is already gone (e.g.
		// TTL elapsed): the retried setup refuses again — the prompt returns.
		mocks.setupTOTPEnrollment.mockRejectedValue(new mocks.ReauthRequiredError());
		mocks.provePossessionWebAuthn.mockResolvedValue({ scope: 'mfa_pending', granted: true });
		render(LoginPage);
		await submitPassword();
		await waitFor(() => expect(screen.getByRole('button', { name: /Use your passkey/ })).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: /Use your passkey/ }));
		await waitFor(() => expect(mocks.setupTOTPEnrollment).toHaveBeenCalledTimes(2));
		// The honest loop: the passkey step is offered again, never a bare error.
		await waitFor(() => expect(screen.getByRole('button', { name: /Use your passkey/ })).toBeInTheDocument());
		expect(screen.queryByText(/Manual setup key/)).toBeNull();
	});

	it('GENERATION FENCING: a superseded attempt (back link) discards the late setup response', async () => {
		mocks.login.mockRejectedValueOnce(
			new mocks.MFAEnrollmentRequiredError('MFA enrollment is required', PENDING_TOKEN)
		);
		let resolveSetup: (value: { secret: string; provisioningUri: string; enrollmentId?: string }) => void = () => {};
		mocks.setupTOTPEnrollment.mockImplementationOnce(
			() => new Promise((resolve) => { resolveSetup = resolve; })
		);
		render(LoginPage);
		await submitPassword();
		await waitFor(() => expect(mocks.setupTOTPEnrollment).toHaveBeenCalled());

		// The user bails to the password form while setup is in flight.
		await fireEvent.click(screen.getByRole('button', { name: /Back to sign in/ }));
		await waitFor(() => expect(screen.getByLabelText('Password')).toBeInTheDocument());

		// The late setup result lands after the attempt was retired.
		resolveSetup({ secret: 'LATESECRET', provisioningUri: 'otpauth://totp/x?secret=LATESECRET', enrollmentId: 'e-late' });
		await new Promise((r) => setTimeout(r, 0));
		expect(screen.queryByText('LATESECRET')).toBeNull();
		expect(mocks.confirmTOTPEnrollment).not.toHaveBeenCalled();
	});

	it('a cancelled UV ceremony shows the inline error and keeps the passkey step offered', async () => {
		mocks.login.mockRejectedValueOnce(
			new mocks.MFAEnrollmentRequiredError('MFA enrollment is required', PENDING_TOKEN)
		);
		mocks.setupTOTPEnrollment.mockRejectedValue(new mocks.ReauthRequiredError());
		mocks.provePossessionWebAuthn.mockRejectedValue(new Error('Passkey verification cancelled'));
		render(LoginPage);
		await submitPassword();
		await waitFor(() => expect(screen.getByRole('button', { name: /Use your passkey/ })).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: /Use your passkey/ }));
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Passkey verification cancelled'));
		// Recoverable: the passkey step is still offered.
		expect(screen.getByRole('button', { name: /Use your passkey/ })).toBeInTheDocument();
	});
});
