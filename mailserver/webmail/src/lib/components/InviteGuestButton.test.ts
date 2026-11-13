import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';
import InviteGuestButton from './InviteGuestButton.svelte';

const request = vi.fn();
vi.mock('$lib/http', () => ({ httpRequest: (...args: unknown[]) => request(...args) }));

describe('InviteGuestButton', () => {
	it('stays visible but explains when member approvals are disabled', () => {
		render(InviteGuestButton, { guestAccountsEnabled: true, guestInviteEnabled: false });
		const button = screen.getByRole('button', { name: 'Invite guest' });
		expect(button).toBeDisabled();
		expect(button.getAttribute('title')).toContain('approval');
	});

	it('posts the normalized request surface and reports success', async () => {
		request.mockResolvedValueOnce(new Response(JSON.stringify({ requestId: 41 }), { status: 201 }));
		render(InviteGuestButton, { guestAccountsEnabled: true, guestInviteEnabled: true });
		await fireEvent.click(screen.getByRole('button', { name: 'Invite guest' }));
		await fireEvent.input(screen.getByLabelText('Guest email'), { target: { value: 'person@example.net' } });
		await fireEvent.input(screen.getByLabelText('Message (optional)'), { target: { value: 'Join this project' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Submit for approval' }));
		await waitFor(() => expect(request).toHaveBeenCalledWith('/api/me/guest-invites', expect.objectContaining({
			method: 'POST', body: JSON.stringify({ invitedEmail: 'person@example.net', message: 'Join this project' }),
		})));
		expect(await screen.findByText('Guest invite request submitted.')).toBeTruthy();
	});

	it('renders an API failure without claiming success', async () => {
		request.mockRejectedValueOnce(new Error('policy missing'));
		render(InviteGuestButton, { guestAccountsEnabled: true, guestInviteEnabled: true });
		await fireEvent.click(screen.getByRole('button', { name: 'Invite guest' }));
		await fireEvent.input(screen.getByLabelText('Guest email'), { target: { value: 'person@example.net' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Submit for approval' }));
		expect(await screen.findByText('policy missing')).toBeTruthy();
		expect(screen.queryByText('Guest invite request submitted.')).toBeNull();
	});
});
