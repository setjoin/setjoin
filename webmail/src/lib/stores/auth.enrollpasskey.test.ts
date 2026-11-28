import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// auth.enrollpasskey.test.ts — the v7 §1.6 registration RESUME semantics at
// the store boundary (r2 defect 9): a begin on a grant already bound to its
// live ceremony answers 200 {"status":"bound"} — no second ceremony is ever
// minted — and the client must REUSE its already-issued creation options.
// The historical code assumed every begin returns {publicKey: ...}, so the
// retry after a cancelled authenticator gesture crashed on the bound
// response (opts.publicKey === undefined) while the grant sat bound.

const mocks = await vi.hoisted(async () => {
	return {
		httpRequest: vi.fn(),
		getOrCreateDpopKey: vi.fn(),
		rememberAccessTokenForProofs: vi.fn(),
		recoverAccessTokenForProofs: vi.fn(async () => null),
		onRecoveredAccessTokenRotation: vi.fn(() => () => {})
	};
});

vi.mock('$lib/http', () => ({ httpRequest: mocks.httpRequest }));
vi.mock('$lib/auth/dpop', () => ({
	getOrCreateDpopKey: mocks.getOrCreateDpopKey,
	rememberAccessTokenForProofs: mocks.rememberAccessTokenForProofs,
	recoverAccessTokenForProofs: mocks.recoverAccessTokenForProofs,
	onRecoveredAccessTokenRotation: mocks.onRecoveredAccessTokenRotation
}));
vi.mock('$lib/jmap/websocket', () => ({ disconnect: vi.fn() }));
vi.mock('$lib/jmap/client', () => ({ resetJmapAuthContext: vi.fn() }));

import {
	enrollPasskey,
	ReauthRequiredError,
	// import after the mocks are registered
	reset
} from './auth';

const BEGIN_OPTIONS = {
	publicKey: {
		challenge: 'Q0gx', // "CH1" base64url
		user: { id: 'dXNlci0x', name: 'alice@example.test', displayName: 'alice@example.test' },
		rp: { name: 'SetJoin' },
		pubKeyCredParams: [{ type: 'public-key', alg: -7 }]
	}
};

function beginResponse(body: Record<string, unknown>) {
	return {
		ok: true,
		status: 200,
		json: async () => body
	} as Response;
}

describe('enrollPasskey — §1.6 bound-grant resume', () => {
	beforeEach(() => {
		mocks.httpRequest.mockReset();
		mocks.httpRequest.mockImplementation(async (path: string) => {
			if (path === '/auth/webauthn/register/begin') {
				// The FIRST begin binds the grant and mints options; any LATER
				// begin on the same (still unconsumed) grant answers bound.
				mocks.httpRequest.mock.calls.push();
				return beginResponse(BEGIN_OPTIONS);
			}
			return beginResponse({});
		});
		reset();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('reuses the retained creation options when a retry hits a bound grant (r2 defect 9)', async () => {
		const create = vi
			.fn()
			// First gesture: the user cancels the authenticator prompt.
			.mockRejectedValueOnce(new DOMException('NotAllowedError', 'NotAllowedError'))
			// Second gesture (after retry): succeeds.
			.mockResolvedValueOnce({
				id: 'cred-1',
				rawId: new Uint8Array([1, 2, 3]),
				type: 'public-key',
				response: {
					attestationObject: new Uint8Array([4]),
					clientDataJSON: new Uint8Array([5])
				}
			});
		vi.stubGlobal('navigator', { credentials: { create } });

		let beginCalls = 0;
		mocks.httpRequest.mockImplementation(async (path: string) => {
			if (path === '/auth/webauthn/register/begin') {
				beginCalls += 1;
				return beginResponse(beginCalls === 1 ? BEGIN_OPTIONS : { status: 'bound' });
			}
			return beginResponse({});
		});

		// Attempt 1: begin binds the grant, the gesture is cancelled — the
		// grant stays bound to its ceremony (nothing was finished).
		await expect(enrollPasskey('tok-1')).rejects.toThrow('Passkey enrollment cancelled');

		// Attempt 2: the same grant answers {"status":"bound"} — the client
		// resumes with the ALREADY-ISSUED options (no crash, no re-mint).
		await enrollPasskey('tok-1');

		// Both gestures saw the SAME challenge (the one ceremony's options).
		const first = create.mock.calls[0][0] as { publicKey: { challenge: ArrayBuffer } };
		const second = create.mock.calls[1][0] as { publicKey: { challenge: ArrayBuffer } };
		expect(new Uint8Array(second.publicKey.challenge)).toEqual(new Uint8Array(first.publicKey.challenge));

		// The finish consumed the SAME grant token.
		const finishCall = mocks.httpRequest.mock.calls.find(
			([path]) => path === '/auth/webauthn/register/finish'
		);
		expect(finishCall).toBeTruthy();
		const [, init] = finishCall as [string, { body: string }];
		expect(JSON.parse(init.body).reauth_token).toBe('tok-1');
	});

	it('requires a FRESH proof when a bound grant has no retained options (fresh page, dead retention)', async () => {
		vi.stubGlobal('navigator', { credentials: { create: vi.fn() } });
		mocks.httpRequest.mockImplementation(async (path: string) =>
			path === '/auth/webauthn/register/begin'
				? beginResponse({ status: 'bound' })
				: beginResponse({})
		);

		// This page never received the bound ceremony's options — guessing is
		// impossible, so the enrollment surfaces reauth_required: the handoff
		// mints a fresh proof whose begin binds a fresh ceremony (§1.6).
		await expect(enrollPasskey('tok-orphan')).rejects.toBeInstanceOf(ReauthRequiredError);
		expect(mocks.httpRequest.mock.calls.some(([path]) => path === '/auth/webauthn/register/finish')).toBe(false);
	});
});
