import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ShareMailboxDialog from './ShareMailboxDialog.svelte';

const getSharingOverview = vi.fn();
const grantDelegate = vi.fn(async () => {});
const revokeDelegate = vi.fn(async () => {});

vi.mock('$lib/api/sharing', () => ({
	getSharingOverview: (...a: unknown[]) => getSharingOverview(...(a as [])),
	grantDelegate: (...a: unknown[]) => grantDelegate(...(a as [])),
	revokeDelegate: (...a: unknown[]) => revokeDelegate(...(a as []))
}));

const OVERVIEW = {
	delegates: [
		{ userId: 2, email: 'bob@test.local', name: 'Bob', permission: 'send_on_behalf', grantedAt: '2026-07-01' }
	],
	calendarGrants: [],
	myDefaults: [],
	inheritedDefaults: [],
	defaultsEnabled: false
};

describe('ShareMailboxDialog', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		getSharingOverview.mockResolvedValue(OVERVIEW);
	});

	it('lists current delegates with email and permission label', async () => {
		render(ShareMailboxDialog, { open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText('bob@test.local')).toBeTruthy());
		const row = screen.getByText('bob@test.local').closest('li')!;
		expect(row.textContent).toContain('Send on behalf');
	});

	it('shows the empty state with the add-delegate row still visible', async () => {
		getSharingOverview.mockResolvedValue({ ...OVERVIEW, delegates: [] });
		render(ShareMailboxDialog, { open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText('No one else has access')).toBeTruthy());
		expect(screen.getByLabelText('Person (email)')).toBeTruthy();
	});

	it('grants a delegate at the picked permission and announces it', async () => {
		render(ShareMailboxDialog, { open: true, onClose: () => {} });
		await waitFor(() => expect(getSharingOverview).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText('Person (email)'), {
			target: { value: 'carol@test.local' }
		});
		await fireEvent.change(screen.getByLabelText('Access level'), {
			target: { value: 'send_as' }
		});
		await fireEvent.click(screen.getByText('Grant access').closest('button')!);

		await waitFor(() => {
			expect(grantDelegate).toHaveBeenCalledWith('carol@test.local', 'send_as');
		});
	});

	it('shows the permission helper for the selected level', async () => {
		render(ShareMailboxDialog, { open: true, onClose: () => {} });
		await waitFor(() => expect(getSharingOverview).toHaveBeenCalled());
		expect(screen.getByText('Can read mail in your mailbox')).toBeTruthy();
		await fireEvent.change(screen.getByLabelText('Access level'), {
			target: { value: 'full_access' }
		});
		expect(screen.getByText('Can read and manage everything in your mailbox')).toBeTruthy();
	});

	it('revokes a delegate', async () => {
		render(ShareMailboxDialog, { open: true, onClose: () => {} });
		await waitFor(() => expect(screen.getByText('bob@test.local')).toBeTruthy());
		await fireEvent.click(screen.getByText('Remove access').closest('button')!);
		await waitFor(() => expect(revokeDelegate).toHaveBeenCalledWith(2));
	});

	it('renders a rejected grant inline as role=alert (BZ115 detail)', async () => {
		grantDelegate.mockRejectedValueOnce(new Error('Invalid delegate permission level'));
		render(ShareMailboxDialog, { open: true, onClose: () => {} });
		await waitFor(() => expect(getSharingOverview).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText('Person (email)'), {
			target: { value: 'carol@test.local' }
		});
		await fireEvent.click(screen.getByText('Grant access').closest('button')!);

		await waitFor(() => {
			const alert = screen.getByRole('alert');
			expect(alert.textContent).toContain('Invalid delegate permission level');
		});
	});
});
