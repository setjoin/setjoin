import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ShareCalendarDialog from './ShareCalendarDialog.svelte';

const loadShares = vi.fn(async () => [{ userEmail: 'bob@x.test', name: 'Bob', level: 'read' }]);
const shareCalendar = vi.fn(async () => {});
const revokeShare = vi.fn(async () => {});

vi.mock('$lib/stores/calendar', () => ({
	loadShares: (...a: unknown[]) => loadShares(...(a as [])),
	shareCalendar: (...a: unknown[]) => shareCalendar(...(a as [])),
	revokeShare: (...a: unknown[]) => revokeShare(...(a as []))
}));

const getSharingOverview = vi.fn();
const setMyDefault = vi.fn(async () => 7);

vi.mock('$lib/api/sharing', () => ({
	getSharingOverview: (...a: unknown[]) => getSharingOverview(...(a as [])),
	setMyDefault: (...a: unknown[]) => setMyDefault(...(a as []))
}));

vi.mock('$lib/stores/directory', () => ({
	setDirectoryAccountId: () => {},
	directoryTree: async () => [
		{ id: '5', name: 'Engineering', parentId: null, path: '/eng', depth: 0, memberCount: 3, hasManagers: false }
	]
}));

const OVERVIEW_OFF = {
	delegates: [],
	calendarGrants: [],
	myDefaults: [],
	inheritedDefaults: [],
	defaultsEnabled: false
};

describe('ShareCalendarDialog', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		getSharingOverview.mockResolvedValue(OVERVIEW_OFF);
		setMyDefault.mockResolvedValue(7);
	});

	it('lists an existing grant with an email and a level control', async () => {
		render(ShareCalendarDialog, { open: true, calendarId: 'cal1', calendarName: 'Work', onClose: () => {} });
		await waitFor(() => {
			expect(screen.getByText('bob@x.test')).toBeTruthy();
		});
	});

	it('adds a new grant at the picked level (Full details → write)', async () => {
		render(ShareCalendarDialog, { open: true, calendarId: 'cal1', calendarName: 'Work', onClose: () => {} });
		await waitFor(() => expect(loadShares).toHaveBeenCalledWith('cal1'));

		const emailInput = screen.getByLabelText('Add person (email)') as HTMLInputElement;
		await fireEvent.input(emailInput, { target: { value: 'carol@x.test' } });

		// Pick the "Full details (Editor)" level via the add-level select.
		const addLevel = screen.getByLabelText('access level') as HTMLSelectElement;
		await fireEvent.change(addLevel, { target: { value: 'write' } });

		const addBtn = screen.getByText('Add').closest('button')!;
		await fireEvent.click(addBtn);

		await waitFor(() => {
			expect(shareCalendar).toHaveBeenCalledWith('cal1', 'carol@x.test', 'write');
		});
	});

	it('revokes an existing grant', async () => {
		render(ShareCalendarDialog, { open: true, calendarId: 'cal1', calendarName: 'Work', onClose: () => {} });
		await waitFor(() => expect(screen.getByText('bob@x.test')).toBeTruthy());

		const revokeBtn = screen.getByText('Remove').closest('button')!;
		await fireEvent.click(revokeBtn);

		await waitFor(() => {
			expect(revokeShare).toHaveBeenCalledWith('cal1', 'bob@x.test');
		});
	});

	// ── Default visibility section (§6-A) ──

	it('hides the default-visibility section when sharing.defaults is OFF', async () => {
		render(ShareCalendarDialog, { open: true, calendarId: 'cal1', onClose: () => {} });
		await waitFor(() => expect(getSharingOverview).toHaveBeenCalled());
		expect(screen.queryByRole('radiogroup')).toBeNull();
	});

	it('renders the section when enabled and saves the picked audience + level', async () => {
		getSharingOverview.mockResolvedValue({ ...OVERVIEW_OFF, defaultsEnabled: true });
		render(ShareCalendarDialog, { open: true, calendarId: 'cal1', onClose: () => {} });

		await waitFor(() => expect(screen.getByRole('radiogroup', { name: 'Visibility level' })).toBeTruthy());

		// segmented control: pick 闲忙 (free-busy)
		await fireEvent.click(screen.getByRole('radio', { name: 'Free-busy' }));
		await fireEvent.click(screen.getByText('Save').closest('button')!);

		await waitFor(() => {
			expect(setMyDefault).toHaveBeenCalledWith('everyone', 0, 'freebusy');
		});
	});

	it('prefills from the existing user default and shows the inherited baseline line', async () => {
		getSharingOverview.mockResolvedValue({
			...OVERVIEW_OFF,
			defaultsEnabled: true,
			myDefaults: [{ id: 3, ownerScope: 'user', audience: 'everyone', audienceRef: 1, level: 'read' }],
			inheritedDefaults: [{ id: 1, ownerScope: 'org', audience: 'everyone', audienceRef: 1, level: 'freebusy' }]
		});
		render(ShareCalendarDialog, { open: true, calendarId: 'cal1', onClose: () => {} });

		await waitFor(() => {
			expect(screen.getByRole('radio', { name: 'Full detail' }).getAttribute('aria-checked')).toBe('true');
		});
		// inherited status line names the org baseline and the override semantics
		expect(screen.getByText(/Org default: Free-busy — your setting overrides it/)).toBeTruthy();
	});

	it('keeps the prior value selected when the save fails (§6-D)', async () => {
		getSharingOverview.mockResolvedValue({
			...OVERVIEW_OFF,
			defaultsEnabled: true,
			myDefaults: [{ id: 3, ownerScope: 'user', audience: 'everyone', audienceRef: 1, level: 'none' }]
		});
		setMyDefault.mockRejectedValueOnce(new Error('save failed'));
		render(ShareCalendarDialog, { open: true, calendarId: 'cal1', onClose: () => {} });
		await waitFor(() => expect(screen.getByRole('radiogroup', { name: 'Visibility level' })).toBeTruthy());

		await fireEvent.click(screen.getByRole('radio', { name: 'Full detail' }));
		await fireEvent.click(screen.getByText('Save').closest('button')!);

		await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('save failed'));
		// reverted to the persisted 'none'
		expect(screen.getByRole('radio', { name: 'None' }).getAttribute('aria-checked')).toBe('true');
	});
});
