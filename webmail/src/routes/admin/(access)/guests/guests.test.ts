import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';
import { page } from '$app/state';
import { createRawSnippet } from 'svelte';
import GuestsPage from './+page.svelte';
import AdminLayout from '../../+layout.svelte';

const api = vi.hoisted(() => ({
	listGuests: vi.fn(), getGuest: vi.fn(), listGuestProfiles: vi.fn(), listGuestProfileDomains: vi.fn(),
	createGuestProfile: vi.fn(), updateGuestProfile: vi.fn(), deleteGuestProfile: vi.fn(),
	assignGuestProfile: vi.fn(), disableGuest: vi.fn(), enableGuest: vi.fn(),
	extendGuest: vi.fn(), inviteGuest: vi.fn(), reinviteGuest: vi.fn(), revokeGuestInvite: vi.fn(),
	listGuestSponsorOptions: vi.fn(), transferGuest: vi.fn(),
	InviteDeliveryUnconfirmedError: class InviteDeliveryUnconfirmedError extends Error {
		constructor(readonly inviteId: string, readonly guestUserId: number) { super('delivery unconfirmed'); }
	},
	GuestInviteStateError: class GuestInviteStateError extends Error {
		constructor(readonly status: 404 | 409, message: string) { super(message); }
	},
}));

vi.mock('$lib/admin/guests', () => api);

const summary = {
	id: 17, displayName: 'Pat Guest', invitedEmail: 'pat@example.net', status: 'active',
	effectiveStatus: 'expired', expiresAt: '2026-07-01T00:00:00Z', sponsorUserId: 2,
	sponsorDisplayName: 'Sam Sponsor', profileId: 4, profileName: 'Partner',
	sponsorNeedsReview: false, pendingInvite: false, channelGrantCount: 3,
	createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-06-01T00:00:00Z',
};

const detail = {
	...summary,
	invitedBy: 2,
	invitedByEmail: 'sam@example.com',
	pendingInvite: null,
	inviteHistory: [],
	inviteHistoryHasMore: false,
	channelGrants: [{ channelId: 5, kind: 'channel', name: 'Partners', role: 'member', canPost: true, historyFloorSeq: 10 }],
	appEntitlements: { mail: false, calendar: false, contacts: false, tasks: false, chat: true, drive: true, meet: false },
};

const profile = {
	id: 4, hostDomainId: 1, name: 'Partner', canPost: true, historyFromJoin: true,
	allowDownload: false, allowMeetCreate: false, allowMeetHost: false, canInitiateDm: true,
	allowNativeShell: false, defaultExpiryDays: 30, apps: ['chat', 'drive'], assignedCount: 0,
	createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
};

const emptyChildren = createRawSnippet(() => ({ render: () => '<div></div>' }));

function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (reason?: unknown) => void;
	const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
	return { promise, resolve, reject };
}

function setAdminSession(permissions: string[]) {
	jmapSession.set({
		accounts: { a1: { name: 'admin@example.com', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: { consoles: ['access'], permissions },
			},
		},
	} as any);
}

async function renderPage(permissions = ['guests.view', 'guests.manage']) {
	const result = await renderAsUser(GuestsPage, {}, { isAdmin: true });
	setAdminSession(permissions);
	return result;
}

describe('admin guests console', () => {
	beforeEach(() => {
		resetStores();
		for (const fn of Object.values(api)) if (vi.isMockFunction(fn)) fn.mockReset();
		api.listGuests.mockResolvedValue([
			summary,
			{ ...summary, id: 18, displayName: 'Jamie Invite', invitedEmail: 'jamie@example.net', status: 'invited', effectiveStatus: 'invited', expiresAt: null, channelGrantCount: 0 },
		]);
		api.getGuest.mockResolvedValue(detail);
		api.listGuestProfiles.mockResolvedValue([profile]);
		api.listGuestProfileDomains.mockResolvedValue([{ id: 1, name: 'Acme Corp' }]);
		api.createGuestProfile.mockResolvedValue(profile);
		api.updateGuestProfile.mockResolvedValue(profile);
		api.deleteGuestProfile.mockResolvedValue(undefined);
		api.assignGuestProfile.mockResolvedValue(undefined);
		api.disableGuest.mockResolvedValue(undefined);
		api.enableGuest.mockResolvedValue(undefined);
		api.extendGuest.mockResolvedValue(undefined);
		api.inviteGuest.mockResolvedValue({});
		api.reinviteGuest.mockResolvedValue({ guestUserId: 17, inviteId: '9001', expiresAt: '2099-01-01T00:00:00Z' });
		api.revokeGuestInvite.mockResolvedValue(undefined);
		api.listGuestSponsorOptions.mockResolvedValue([]);
		api.transferGuest.mockResolvedValue({ channelOwnersTransferred: 0, driveSpacesTransferred: 0 });
	});

	afterEach(() => vi.restoreAllMocks());

	it('lists External identity, effective expired status, and grant count; detail shows seven derived apps', async () => {
		await renderPage();
		await waitFor(() => expect(screen.getByText('Pat Guest')).toBeInTheDocument());
		expect(screen.getAllByText('External')).toHaveLength(2);
		expect(screen.getByText('Expired')).toBeInTheDocument();
		expect(screen.getByText('Invited')).toBeInTheDocument();
		expect(screen.getByText('3 grants')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Pat Guest' }));
		await waitFor(() => expect(api.getGuest).toHaveBeenCalledWith(17));
		expect(screen.getAllByRole('switch')).toHaveLength(7);
		expect(screen.getByText('Partners')).toBeInTheDocument();
	});

	it('moves focus into guest detail, closes on Escape, and returns focus to the invoking row button', async () => {
		await renderPage();
		const trigger = await screen.findByRole('button', { name: 'Pat Guest' });
		trigger.focus();
		await fireEvent.click(trigger);

		const dialog = await screen.findByRole('dialog', { name: 'Pat Guest' });
		expect(dialog).toContainElement(document.activeElement as HTMLElement);

		await fireEvent.keyDown(document, { key: 'Escape' });
		await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Pat Guest' })).not.toBeInTheDocument());
		expect(trigger).toHaveFocus();
	});

	it('blocks background pointer access with a backdrop that closes the modal sheet', async () => {
		const { container } = await renderPage();
		const trigger = await screen.findByRole('button', { name: 'Pat Guest' });
		trigger.focus();
		await fireEvent.click(trigger);
		const dialog = await screen.findByRole('dialog', { name: 'Pat Guest' });
		expect(dialog).toHaveAttribute('aria-modal', 'true');
		const backdrop = container.querySelector('.guest-sheet-backdrop');
		expect(backdrop).toBeInTheDocument();
		await fireEvent.click(backdrop!);
		expect(screen.queryByRole('dialog', { name: 'Pat Guest' })).not.toBeInTheDocument();
		expect(trigger).toHaveFocus();
	});

	it('closes only the topmost lifecycle dialog on Escape, then closes detail and restores row focus', async () => {
		api.getGuest.mockResolvedValue({ ...detail, status: 'active', effectiveStatus: 'active', expiresAt: '2099-07-01T00:00:00Z' });
		await renderPage();
		const trigger = await screen.findByRole('button', { name: 'Pat Guest' });
		trigger.focus();
		await fireEvent.click(trigger);

		const detailDialog = await screen.findByRole('dialog', { name: 'Pat Guest' });
		const disable = screen.getByRole('button', { name: 'Disable guest' });
		disable.focus();
		await fireEvent.click(disable);
		expect(screen.getByRole('dialog', { name: 'Disable guest' })).toHaveFocus();

		await fireEvent.keyDown(document, { key: 'Escape' });
		await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Disable guest' })).not.toBeInTheDocument());
		expect(detailDialog).toBeInTheDocument();
		expect(disable).toHaveFocus();

		await fireEvent.keyDown(document, { key: 'Escape' });
		await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Pat Guest' })).not.toBeInTheDocument());
		expect(trigger).toHaveFocus();
	});

	it.each([
		['guests.view', false],
		['guests.manage', true],
	] as const)('%s alone loads the guest page', async (permission, canManage) => {
		await renderPage([permission]);
		expect(await screen.findByRole('button', { name: 'Pat Guest' })).toBeInTheDocument();
		expect(api.listGuests).toHaveBeenCalledTimes(1);
		expect(screen.queryByRole('button', { name: 'New profile' }) !== null).toBe(canManage);
	});

	it('denies the guest page and does not load data without either guest permission', async () => {
		await renderPage([]);
		expect(screen.getByText('You do not have permission to view guests.')).toBeInTheDocument();
		expect(api.listGuests).not.toHaveBeenCalled();
		expect(api.listGuestProfiles).not.toHaveBeenCalled();
	});

	it.each(['guests.view', 'guests.manage'])('%s alone shows Guests in admin navigation', async (permission) => {
		(page as { url: { pathname: string } }).url.pathname = '/admin/guests';
		await renderAsUser(AdminLayout, { children: emptyChildren }, { isAdmin: true });
		setAdminSession([permission]);
		expect(await screen.findByText('Guests')).toBeInTheDocument();
	});

	it('hides Guests in admin navigation without either guest permission', async () => {
		(page as { url: { pathname: string } }).url.pathname = '/admin/guests';
		await renderAsUser(AdminLayout, { children: emptyChildren }, { isAdmin: true });
		setAdminSession([]);
		await waitFor(() => expect(screen.queryByText('Guests')).not.toBeInTheDocument());
	});

	it('an elapsed guest offers extend, never enable, and validates a future expiry client-side', async () => {
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		await screen.findByText('Partners');

		expect(screen.queryByRole('button', { name: 'Enable guest' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Disable guest' })).not.toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Extend access' }));
		expect(screen.getByText('Access is restored and 3 retained channel memberships become active again.')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('New expiry'), { target: { value: '2020-01-01T00:00' } });
		expect(screen.getByText('Choose a future expiry.')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Confirm' })).toBeDisabled();
		await fireEvent.input(screen.getByLabelText('New expiry'), { target: { value: '2099-01-01T00:00' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
		expect(api.extendGuest).toHaveBeenCalledWith(17, new Date('2099-01-01T00:00').toISOString());
	});

	it.each([
		['a future expiry', '2099-07-01T00:00:00Z'],
		['no expiry', null],
	] as const)('a disabled guest with %s can enable without claiming grants return', async (_case, expiresAt) => {
		api.getGuest.mockResolvedValue({ ...detail, status: 'disabled', effectiveStatus: 'disabled', expiresAt });
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		await screen.findByText('Partners');

		expect(screen.getByRole('button', { name: 'Extend access' })).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Disable guest' })).not.toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Enable guest' }));
		expect(screen.getByText('Enables sign-in again. Previous channel grants are not restored.')).toBeInTheDocument();
		expect(screen.queryByText(/retained channel memberships become active/i)).not.toBeInTheDocument();
	});

	it.each([
		['active', 'active'],
		['invited', 'invited'],
	] as const)('an %s guest can be disabled and extended, but not enabled', async (_case, status) => {
		api.getGuest.mockResolvedValue({ ...detail, status, effectiveStatus: status, expiresAt: '2099-07-01T00:00:00Z' });
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		await screen.findByText('Partners');

		expect(screen.getByRole('button', { name: 'Extend access' })).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Enable guest' })).not.toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Disable guest' }));
		expect(screen.getByText('Removes 3 active channel grants. Re-enable starts with no access.')).toBeInTheDocument();
	});

	it('assigns profiles and re-invites expired guests through the recovery endpoint with a future expiry', async () => {
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		await screen.findByText('Partners');
		await fireEvent.change(screen.getByLabelText('Profile'), { target: { value: '4' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Assign profile' }));
		expect(api.assignGuestProfile).toHaveBeenCalledWith(17, 4);

		await fireEvent.click(screen.getByRole('button', { name: 'Re-invite' }));
		expect(screen.getByText(/Signs out current sessions/)).toBeInTheDocument();
		const confirm = screen.getByRole('button', { name: 'Send replacement invitation' });
		expect(confirm).toBeDisabled();
		await fireEvent.input(screen.getByLabelText('New expiry'), { target: { value: '2099-01-01T00:00' } });
		await fireEvent.click(confirm);
		expect(api.reinviteGuest).toHaveBeenCalledWith(17, new Date('2099-01-01T00:00').toISOString());
		expect(api.inviteGuest).not.toHaveBeenCalled();
	});

	it('shows exact invitation history and revokes with compare-and-set identity', async () => {
		api.getGuest.mockResolvedValue({
			...detail,
			pendingInvite: { inviteId: '9007199254740993', createdAt: '2026-07-20T00:00:00Z', expiresAt: '2099-07-20T00:00:00Z', createdByEmail: null },
			inviteHistory: [
				{ inviteId: '9007199254740993', state: 'pending', createdAt: '2026-07-20T00:00:00Z', expiresAt: '2099-07-20T00:00:00Z', terminalAt: null, createdByEmail: null },
				{ inviteId: '42', state: 'superseded', createdAt: '2026-07-19T00:00:00Z', expiresAt: '2026-07-26T00:00:00Z', terminalAt: '2026-07-20T00:00:00Z', createdByEmail: 'admin@example.com' },
			],
			inviteHistoryHasMore: true,
		});
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		expect(await screen.findAllByText('9007199254740993')).toHaveLength(2);
		expect(screen.getByText('Superseded')).toBeInTheDocument();
		expect(screen.getByText('Showing the 10 most recent invitations.')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Revoke invitation' }));
		expect(api.revokeGuestInvite).toHaveBeenCalledWith(17, '9007199254740993');
	});

	it('retains an unconfirmed delivery warning only for the matching committed invite', async () => {
		const pendingDetail = {
			...detail,
			pendingInvite: { inviteId: '9002', createdAt: '2026-07-20T00:00:00Z', expiresAt: '2099-07-20T00:00:00Z', createdByEmail: 'admin@example.com' },
			inviteHistory: [{ inviteId: '9002', state: 'pending', createdAt: '2026-07-20T00:00:00Z', expiresAt: '2099-07-20T00:00:00Z', terminalAt: null, createdByEmail: 'admin@example.com' }],
		};
		api.getGuest.mockResolvedValue(pendingDetail);
		api.reinviteGuest.mockRejectedValueOnce(new api.InviteDeliveryUnconfirmedError('9002', 17));
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Re-invite' }));
		await fireEvent.input(screen.getByLabelText('New expiry'), { target: { value: '2099-01-01T00:00' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Send replacement invitation' }));
		expect(await screen.findByText('Delivery not confirmed')).toBeInTheDocument();
		expect(screen.getAllByText('9002').length).toBeGreaterThan(0);
		expect(api.reinviteGuest).toHaveBeenCalledTimes(1);
	});

	it('guards profile assignment and re-invite independently against double clicks', async () => {
		const assignment = deferred<void>();
		const reinvite = deferred<{ guestUserId: number; inviteId: string; expiresAt: string }>();
		api.assignGuestProfile.mockReturnValue(assignment.promise);
		api.reinviteGuest.mockReturnValue(reinvite.promise);
		api.getGuest.mockResolvedValue({ ...detail, status: 'active', effectiveStatus: 'active', expiresAt: '2099-07-01T00:00:00Z' });
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		await screen.findByText('Partners');

		const assign = screen.getByRole('button', { name: 'Assign profile' });
		await fireEvent.click(assign);
		await fireEvent.click(assign);
		expect(api.assignGuestProfile).toHaveBeenCalledTimes(1);
		expect(assign).toBeDisabled();
		expect(assign).toHaveAttribute('aria-busy', 'true');
		assignment.resolve(undefined);
		await waitFor(() => expect(screen.getByRole('button', { name: 'Assign profile' })).not.toBeDisabled());

		await fireEvent.click(screen.getByRole('button', { name: 'Re-invite' }));
		const reinviteButton = screen.getByRole('button', { name: 'Send replacement invitation' });
		await fireEvent.click(reinviteButton);
		await fireEvent.click(reinviteButton);
		expect(api.reinviteGuest).toHaveBeenCalledTimes(1);
		expect(reinviteButton).toBeDisabled();
		expect(reinviteButton).toHaveAttribute('aria-busy', 'true');
		reinvite.resolve({ guestUserId: 17, inviteId: '9001', expiresAt: '2099-07-01T00:00:00Z' });
		await waitFor(() => expect(screen.queryByRole('button', { name: 'Send replacement invitation' })).not.toBeInTheDocument());
	});

	it('creates, updates, and deletes profiles with a named locked domain; native-shell defaults on and stays advisory', async () => {
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'New profile' }));
		expect(screen.getByText('Advisory only. Native-shell detection is not a security boundary.')).toBeInTheDocument();
		expect(screen.getByRole('combobox', { name: 'Host domain' })).toHaveValue('1');
		expect(screen.getByRole('option', { name: 'Acme Corp' })).toBeInTheDocument();
		expect(screen.getByRole('switch', { name: /^Allow native shell/ })).toBeChecked();
		await fireEvent.input(screen.getByLabelText('Profile name'), { target: { value: 'Vendor' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
		expect(api.createGuestProfile).toHaveBeenCalledWith(expect.objectContaining({ hostDomainId: 1, allowNativeShell: true }));

		await fireEvent.click(await screen.findByRole('button', { name: 'Edit Partner' }));
		expect(screen.getByRole('combobox', { name: 'Host domain' })).toBeDisabled();
		await fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));
		expect(api.updateGuestProfile).toHaveBeenCalledWith(4, expect.objectContaining({ name: 'Partner' }));

		await fireEvent.click(await screen.findByRole('button', { name: 'Delete Partner' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm delete profile' }));
		expect(api.deleteGuestProfile).toHaveBeenCalledWith(4);
	});

	it('can create the first profile from the first reachable domain', async () => {
		api.listGuestProfiles.mockResolvedValue([]);
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'New profile' }));
		expect(screen.getByRole('combobox', { name: 'Host domain' })).toHaveValue('1');
		await fireEvent.input(screen.getByLabelText('Profile name'), { target: { value: 'First profile' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Create profile' }));
		expect(api.createGuestProfile).toHaveBeenCalledWith(expect.objectContaining({ hostDomainId: 1 }));
	});

	it('ignores a stale A response after B opens', async () => {
		const a = deferred<typeof detail>();
		api.getGuest.mockImplementation((id: number) => id === 17
			? a.promise
			: Promise.resolve({ ...detail, id: 18, displayName: 'Jamie Invite', invitedEmail: 'jamie@example.net' }));
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Jamie Invite' }));
		expect(await screen.findByRole('dialog', { name: 'Jamie Invite' })).toBeInTheDocument();

		a.resolve(detail);
		await Promise.resolve();
		expect(screen.getByRole('dialog', { name: 'Jamie Invite' })).toBeInTheDocument();
		expect(screen.queryByRole('dialog', { name: 'Pat Guest' })).not.toBeInTheDocument();
	});

	it('closing while detail is pending invalidates the response', async () => {
		const pending = deferred<typeof detail>();
		api.getGuest.mockReturnValue(pending.promise);
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		const loadingDialog = await screen.findByRole('dialog', { name: 'Pat Guest' });
		expect(within(loadingDialog).getAllByRole('status', { name: 'Loading' })).toHaveLength(1);
		await fireEvent.click(within(loadingDialog).getByRole('button', { name: 'Close' }));
		expect(screen.queryByRole('dialog', { name: 'Pat Guest' })).not.toBeInTheDocument();

		pending.resolve(detail);
		await Promise.resolve();
		expect(screen.queryByRole('dialog', { name: 'Pat Guest' })).not.toBeInTheDocument();
	});

	it('closes the current detail generation when getGuest rejects', async () => {
		const pending = deferred<typeof detail>();
		api.getGuest.mockReturnValue(pending.promise);
		const { container } = await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		expect(await screen.findByRole('dialog', { name: 'Pat Guest' })).toBeInTheDocument();
		pending.reject(new Error('detail unavailable'));

		await waitFor(() => {
			expect(screen.queryByRole('dialog', { name: 'Pat Guest' })).not.toBeInTheDocument();
			expect(container.querySelector('.guest-sheet-backdrop')).not.toBeInTheDocument();
		});
	});

	it('renders nullable DM, full-history, and legacy posting grant fields safely', async () => {
		api.getGuest.mockResolvedValue({
			...detail,
			channelGrants: [{ channelId: 9, kind: 'dm', name: null, role: 'member', canPost: null, historyFloorSeq: null }],
		});
		await renderPage();
		await fireEvent.click(await screen.findByRole('button', { name: 'Pat Guest' }));
		expect(await screen.findByText('Direct message')).toBeInTheDocument();
		expect(screen.getByText('Channel policy')).toBeInTheDocument();
		expect(screen.getByText('Full history')).toBeInTheDocument();
	});
});
