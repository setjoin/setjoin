import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import GuestInviteAcceptPage from './+page.svelte';

const { mockGoto, mockState } = vi.hoisted(() => ({
	mockGoto: vi.fn(),
	mockState: {
		url: new URL('https://mail.example.com/guest-invite/accept?token=secret-invite-token')
	}
}));

vi.mock('$app/navigation', () => ({ goto: mockGoto }));
vi.mock('$app/state', () => ({
	get page() {
		return { url: mockState.url };
	}
}));

function response(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' }
	});
}

const disclosure = {
	org_name: 'Example Org',
	invited_email: 'guest@partner.test',
	channels: ['Project Alpha'],
	disclosure_text: 'Your content is retained and may be reviewed by authorized administrators.',
	disclosure_version: 'v1',
	expires_at: '2026-08-05T12:00:00Z'
};

const passwordPolicy = {
	minLength: 12,
	maxBytes: 72,
	requireUppercase: true,
	requireLowercase: true,
	requireDigit: true,
	requireSpecial: true
};

function successfulLoadFetch(postBody?: unknown) {
	return vi.fn()
		.mockResolvedValueOnce(response(disclosure))
		.mockResolvedValueOnce(response(passwordPolicy))
		.mockResolvedValueOnce(response(postBody ?? {
			message: 'Account activated. You may now sign in.',
			invited_email: disclosure.invited_email
		}));
}

describe('Guest invite acceptance page', () => {
	beforeEach(() => {
		mockState.url = new URL('https://mail.example.com/guest-invite/accept?token=secret-invite-token');
		mockGoto.mockReset();
		vi.spyOn(history, 'replaceState');
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	it('loads the server disclosure, strips the credential from history, and never renders it', async () => {
		const fetchMock = successfulLoadFetch();
		vi.stubGlobal('fetch', fetchMock);

		const { container } = render(GuestInviteAcceptPage);

		await waitFor(() => expect(screen.getByRole('heading', { name: 'Join Example Org' })).toBeTruthy());
		expect(fetchMock).toHaveBeenCalledWith(
			'/auth/guest-invite/accept?token=secret-invite-token',
			expect.objectContaining({ credentials: 'include' })
		);
		expect(fetchMock).toHaveBeenCalledWith(
			'/auth/password-policy',
			expect.objectContaining({ credentials: 'include' })
		);
		expect(history.replaceState).toHaveBeenCalledWith(history.state, '', '/guest-invite/accept');
		expect(screen.getByText('External guest')).toBeTruthy();
		expect(screen.getByText(/You were invited as guest@partner\.test/)).toBeTruthy();
		expect(screen.getByText('Project Alpha')).toBeTruthy();
		expect(container.textContent).not.toContain('secret-invite-token');
	});

	it('posts explicit disclosure acceptance and the password, then clears the form', async () => {
		const fetchMock = successfulLoadFetch();
		vi.stubGlobal('fetch', fetchMock);
		render(GuestInviteAcceptPage);

		await waitFor(() => expect(screen.getByLabelText('Create password')).toBeTruthy());
		await fireEvent.input(screen.getByLabelText('Create password'), {
			target: { value: 'StrongGuestPassword1!' }
		});
		await fireEvent.input(screen.getByLabelText('Confirm password'), {
			target: { value: 'StrongGuestPassword1!' }
		});
		await fireEvent.click(screen.getByLabelText(
			'I understand and accept the data retention and monitoring disclosure.'
		));
		await fireEvent.click(screen.getByRole('button', { name: 'Activate guest account' }));

		await waitFor(() => expect(screen.getByRole('heading', { name: 'Guest account activated' })).toBeTruthy());
		const post = fetchMock.mock.calls[2];
		expect(post[0]).toBe('/auth/guest-invite/accept');
		expect(JSON.parse((post[1] as RequestInit).body as string)).toEqual({
			token: 'secret-invite-token',
			disclosure_accepted: true,
			new_password: 'StrongGuestPassword1!'
		});
		expect(document.querySelector('input[type="password"]')).toBeNull();
	});

	it('keeps activation disabled until passwords match and disclosure is accepted', async () => {
		vi.stubGlobal('fetch', successfulLoadFetch());
		render(GuestInviteAcceptPage);

		await waitFor(() => expect(screen.getByRole('button', { name: 'Activate guest account' })).toBeTruthy());
		const button = screen.getByRole('button', { name: 'Activate guest account' }) as HTMLButtonElement;
		expect(button.disabled).toBe(true);

		await fireEvent.input(screen.getByLabelText('Create password'), {
			target: { value: 'StrongGuestPassword1!' }
		});
		await fireEvent.input(screen.getByLabelText('Confirm password'), {
			target: { value: 'different' }
		});
		await fireEvent.click(screen.getByLabelText(
			'I understand and accept the data retention and monitoring disclosure.'
		));
		expect(screen.getByText('Passwords do not match')).toBeTruthy();
		expect(button.disabled).toBe(true);
	});

	it('mirrors the configured password policy before activation', async () => {
		vi.stubGlobal('fetch', successfulLoadFetch());
		render(GuestInviteAcceptPage);

		await waitFor(() => expect(screen.getByLabelText('Create password')).toBeTruthy());
		await fireEvent.input(screen.getByLabelText('Create password'), {
			target: { value: 'lowercase-only' }
		});
		await fireEvent.input(screen.getByLabelText('Confirm password'), {
			target: { value: 'lowercase-only' }
		});
		await fireEvent.click(screen.getByLabelText(
			'I understand and accept the data retention and monitoring disclosure.'
		));

		expect(screen.getByText('Password must contain an uppercase letter')).toBeTruthy();
		expect((screen.getByLabelText('Create password') as HTMLInputElement).minLength).toBe(12);
		expect((screen.getByRole('button', { name: 'Activate guest account' }) as HTMLButtonElement).disabled).toBe(true);
	});

	it('blocks a multibyte password beyond the configured byte boundary', async () => {
		vi.stubGlobal('fetch', successfulLoadFetch());
		render(GuestInviteAcceptPage);

		await waitFor(() => expect(screen.getByLabelText('Create password')).toBeTruthy());
		const tooLong = `${'好'.repeat(25)}Aa1!`;
		await fireEvent.input(screen.getByLabelText('Create password'), {
			target: { value: tooLong }
		});
		await fireEvent.input(screen.getByLabelText('Confirm password'), {
			target: { value: tooLong }
		});
		await fireEvent.click(screen.getByLabelText(
			'I understand and accept the data retention and monitoring disclosure.'
		));

		expect(screen.getByText('Password is too long for this installation (maximum 72 UTF-8 bytes)')).toBeTruthy();
		expect((screen.getByRole('button', { name: 'Activate guest account' }) as HTMLButtonElement).disabled).toBe(true);
	});

	it('offers a retry for transient disclosure failures without exposing the credential', async () => {
		const fetchMock = vi.fn()
			.mockResolvedValueOnce(response({ error: 'temporary failure' }, 503))
			.mockResolvedValueOnce(response(disclosure))
			.mockResolvedValueOnce(response(passwordPolicy));
		vi.stubGlobal('fetch', fetchMock);
		const { container } = render(GuestInviteAcceptPage);

		await waitFor(() => expect(screen.getByRole('heading', { name: 'Invitation could not be loaded' })).toBeTruthy());
		expect(container.textContent).not.toContain('secret-invite-token');
		await fireEvent.click(screen.getByRole('button', { name: 'Try again' }));

		await waitFor(() => expect(screen.getByRole('heading', { name: 'Join Example Org' })).toBeTruthy());
		expect(container.textContent).not.toContain('secret-invite-token');
	});

	it('shows the same terminal message for a missing or rejected credential', async () => {
		mockState.url = new URL('https://mail.example.com/guest-invite/accept');
		vi.stubGlobal('fetch', vi.fn());
		const first = render(GuestInviteAcceptPage);
		await waitFor(() => expect(screen.getByRole('heading', { name: 'Invitation unavailable' })).toBeTruthy());
		expect(screen.getByText('This invitation link is invalid, expired, or has already been used.')).toBeTruthy();
		first.unmount();

		mockState.url = new URL('https://mail.example.com/guest-invite/accept?token=rejected');
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ error: 'different server detail' }, 401)));
		render(GuestInviteAcceptPage);
		await waitFor(() => expect(screen.getByRole('heading', { name: 'Invitation unavailable' })).toBeTruthy());
		expect(screen.getByText('This invitation link is invalid, expired, or has already been used.')).toBeTruthy();
		expect(screen.queryByText('different server detail')).toBeNull();
	});
});
