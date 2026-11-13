import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import SharingPage from './+page.svelte';

const getSharingOverview = vi.fn();
const revokeDelegate = vi.fn(async () => {});
const clearMyDefault = vi.fn(async () => {});
const grantDelegate = vi.fn(async () => {});

vi.mock('$lib/api/sharing', () => ({
	getSharingOverview: (...a: unknown[]) => getSharingOverview(...(a as [])),
	revokeDelegate: (...a: unknown[]) => revokeDelegate(...(a as [])),
	clearMyDefault: (...a: unknown[]) => clearMyDefault(...(a as [])),
	grantDelegate: (...a: unknown[]) => grantDelegate(...(a as []))
}));

const revokeShare = vi.fn(async () => {});
vi.mock('$lib/stores/calendar', () => ({
	revokeShare: (...a: unknown[]) => revokeShare(...(a as []))
}));

const EMPTY = {
	delegates: [],
	calendarGrants: [],
	myDefaults: [],
	inheritedDefaults: [],
	defaultsEnabled: false
};

const POPULATED = {
	delegates: [
		{ userId: 2, email: 'bob@test.local', name: 'Bob', permission: 'send_on_behalf', grantedAt: '2026-07-01' }
	],
	calendarGrants: [
		{ calendarId: 9, calendarName: 'Work', userEmail: 'carol@test.local', userName: 'Carol', level: 'freebusy' }
	],
	myDefaults: [],
	inheritedDefaults: [{ id: 1, ownerScope: 'org', audience: 'everyone', audienceRef: 1, level: 'freebusy' }],
	defaultsEnabled: true
};

describe('/settings/sharing (§6-C who-can-see panel)', () => {
	beforeEach(() => vi.clearAllMocks());

	it('shows skeleton lists while loading', async () => {
		getSharingOverview.mockReturnValue(new Promise(() => {})); // never resolves
		render(SharingPage);
		expect(screen.getByTestId('sharing-skeleton')).toBeTruthy();
	});

	it('shows "Only you can see this" for both sections when nothing is shared', async () => {
		getSharingOverview.mockResolvedValue(EMPTY);
		render(SharingPage);
		await waitFor(() => {
			expect(screen.getAllByText('Only you can see this').length).toBe(2);
		});
	});

	it('lists calendar grants + mailbox delegates and the default-active banner', async () => {
		getSharingOverview.mockResolvedValue(POPULATED);
		render(SharingPage);
		await waitFor(() => expect(screen.getByText('bob@test.local')).toBeTruthy());
		expect(screen.getByText('carol@test.local')).toBeTruthy();
		// active-default banner names audience + level
		expect(screen.getByText(/Everyone in my org can see your calendar \(Free-busy\) by default/)).toBeTruthy();
	});

	it('revoking a delegate calls the API and announces "Access removed" via aria-live', async () => {
		getSharingOverview.mockResolvedValue(POPULATED);
		const { container } = render(SharingPage);
		await waitFor(() => expect(screen.getByText('bob@test.local')).toBeTruthy());

		const mailRow = screen.getByText('bob@test.local').closest('li')!;
		await fireEvent.click(mailRow.querySelector('button')!);

		await waitFor(() => expect(revokeDelegate).toHaveBeenCalledWith(2));
		const live = container.querySelector('[aria-live="polite"]')!;
		expect(live.textContent).toContain('Access removed');
	});

	it('revoking a calendar grant routes through the calendar share reducer path', async () => {
		getSharingOverview.mockResolvedValue(POPULATED);
		render(SharingPage);
		await waitFor(() => expect(screen.getByText('carol@test.local')).toBeTruthy());

		const calRow = screen.getByText('carol@test.local').closest('li')!;
		await fireEvent.click(calRow.querySelector('button')!);

		await waitFor(() => expect(revokeShare).toHaveBeenCalledWith('9', 'carol@test.local'));
	});

	it('load failure renders an alert with a working Retry', async () => {
		getSharingOverview.mockRejectedValueOnce(new Error('boom'));
		getSharingOverview.mockResolvedValueOnce(EMPTY);
		render(SharingPage);

		await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('boom'));
		await fireEvent.click(screen.getByText('Retry').closest('button')!);
		await waitFor(() => {
			expect(screen.getAllByText('Only you can see this').length).toBe(2);
		});
	});
});
