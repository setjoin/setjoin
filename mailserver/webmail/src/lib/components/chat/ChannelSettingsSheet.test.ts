import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ChannelSettingsSheet from './ChannelSettingsSheet.svelte';
import type { FederationRoomRoster } from '$lib/chat/api';
import { jmapSession } from '$lib/stores/session';
import { InviteDeliveryUnconfirmedError } from '$lib/admin/guests';

const previewGuest = vi.fn();
const addMember = vi.fn();
const inviteGuest = vi.fn();
const reinviteGuest = vi.fn();

const updateChannel = vi.fn();
const setChannelNotif = vi.fn();
const bindFederationRoom = vi.fn();
const getFederationRoomRoster = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		updateChannel: (...a: unknown[]) => updateChannel(...a),
		setChannelNotif: (...a: unknown[]) => setChannelNotif(...a),
		bindFederationRoom: (...a: unknown[]) => bindFederationRoom(...a),
		getFederationRoomRoster: (...a: unknown[]) => getFederationRoomRoster(...a),
		previewGuest: (...a: unknown[]) => previewGuest(...a),
		addMember: (...a: unknown[]) => addMember(...a),
	};
});

vi.mock('$lib/admin/guests', () => ({
	inviteGuest: (...a: unknown[]) => inviteGuest(...a),
	reinviteGuest: (...a: unknown[]) => reinviteGuest(...a),
	InviteDeliveryUnconfirmedError: class InviteDeliveryUnconfirmedError extends Error {
		constructor(readonly inviteId: string, readonly guestUserId: number) { super('delivery unconfirmed'); }
	},
}));

const noop = vi.fn();

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((done) => (resolve = done));
	return { promise, resolve };
}

function roster(over: Partial<FederationRoomRoster> = {}): FederationRoomRoster {
	return { roomId: 'room1@hub.test', hubDomain: 'hub.test', isHub: true, removedAt: null, members: [], ...over };
}

beforeEach(() => {
	previewGuest.mockReset();
	addMember.mockReset();
	inviteGuest.mockReset();
	reinviteGuest.mockReset();
	updateChannel.mockResolvedValue(undefined);
	setChannelNotif.mockResolvedValue(undefined);
	bindFederationRoom.mockResolvedValue({ roomId: 'room1@hub.test' });
	getFederationRoomRoster.mockResolvedValue(roster());
	previewGuest.mockResolvedValue({ kind: 'inviteRequired' });
	addMember.mockResolvedValue(undefined);
	inviteGuest.mockResolvedValue({ guestUserId: 9, inviteId: '8001', invitedEmail: 'pat@example.com', expiresAt: '2026-08-01T00:00:00Z' });
	reinviteGuest.mockResolvedValue({ guestUserId: 9, inviteId: '8002', expiresAt: '2026-08-01T00:00:00Z' });
});

afterEach(() => {
	vi.clearAllMocks();
	jmapSession.set(null);
});

describe('ChannelSettingsSheet', () => {
	it('shows exact-email member add for enabled members and hides it for guest callers', () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: true } } } as never);
		const props = { open:true,channelId:5,kind:'channel',canManage:true,notifLevel:'all' as const,
			postPermission:'all' as const,broadcastPermission:'admins' as const,onClose:noop,onSaved:noop };
		const member = render(ChannelSettingsSheet,props);
		expect(screen.getByLabelText('Add guest by exact email')).toBeEnabled();
		member.unmount();
		jmapSession.set({ isGuest:true,effectiveCapabilities:{ apps:{chat:true},features:{assist:false,bundles:false,guest_accounts:false,guest_invite:false} } } as never);
		render(ChannelSettingsSheet,props);
		expect(screen.queryByLabelText('Add guest by exact email')).toBeNull();
	});

	it('hides the guest invite entry while guest accounts are disabled', () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: false, guest_invite: false } } } as never);
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: false, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		expect(screen.queryByLabelText('Add guest by exact email')).toBeNull();
	});

	it('previews an active guest, discloses join-time history, then calls the existing member-add route', async () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: false } } } as never);
		previewGuest.mockResolvedValue({ kind: 'activeGuest', userId: 9, displayName: 'Pat', historyFromJoin: true });
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		await fireEvent.input(screen.getByLabelText('Add guest by exact email'), { target: { value: 'PAT@Example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		await waitFor(() => expect(previewGuest).toHaveBeenCalledWith(5, 'pat@example.com'));
		expect(screen.getByText('Pat')).toBeTruthy();
		expect(screen.getByText('This guest will see messages sent after they join.')).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: 'Add to channel' }));
		await waitFor(() => expect(addMember).toHaveBeenCalledWith(5, 9));
	});

	it('ignores a late preview after the exact email changes, so it cannot drive member-add', async () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: false } } } as never);
		const stale = deferred<{ kind: 'activeGuest'; userId: number; displayName: string; historyFromJoin: boolean }>();
		previewGuest.mockReturnValueOnce(stale.promise);
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		const email = screen.getByLabelText('Add guest by exact email');
		await fireEvent.input(email, { target: { value: 'first@example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		await waitFor(() => expect(previewGuest).toHaveBeenCalledWith(5, 'first@example.com'));
		await fireEvent.input(email, { target: { value: 'second@example.com' } });
		stale.resolve({ kind: 'activeGuest', userId: 9, displayName: 'Stale person', historyFromJoin: true });
		await Promise.resolve();

		expect(screen.queryByText('Stale person')).toBeNull();
		expect(screen.queryByRole('button', { name: 'Add to channel' })).toBeNull();
		expect(addMember).not.toHaveBeenCalled();
	});

	it('keeps only the latest preview response and adds the guest bound to that email and channel', async () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: false } } } as never);
		const first = deferred<{ kind: 'activeGuest'; userId: number; displayName: string; historyFromJoin: boolean }>();
		const second = deferred<{ kind: 'activeGuest'; userId: number; displayName: string; historyFromJoin: boolean }>();
		previewGuest.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		const email = screen.getByLabelText('Add guest by exact email');
		await fireEvent.input(email, { target: { value: 'first@example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		await waitFor(() => expect(previewGuest).toHaveBeenCalledTimes(1));
		await fireEvent.input(email, { target: { value: 'SECOND@Example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		await waitFor(() => expect(previewGuest).toHaveBeenCalledTimes(2));

		second.resolve({ kind: 'activeGuest', userId: 22, displayName: 'Latest person', historyFromJoin: false });
		expect(await screen.findByText('Latest person')).toBeTruthy();
		first.resolve({ kind: 'activeGuest', userId: 11, displayName: 'Stale person', historyFromJoin: true });
		await Promise.resolve();
		expect(screen.queryByText('Stale person')).toBeNull();

		await fireEvent.click(screen.getByRole('button', { name: 'Add to channel' }));
		await waitFor(() => expect(addMember).toHaveBeenCalledWith(5, 22));
		expect(addMember).not.toHaveBeenCalledWith(5, 11);
	});

	it('revalidates the accepted preview binding before submit', async () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: false } } } as never);
		previewGuest.mockResolvedValue({ kind: 'activeGuest', userId: 9, displayName: 'Pat', historyFromJoin: true });
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		const email = screen.getByLabelText('Add guest by exact email');
		await fireEvent.input(email, { target: { value: 'pat@example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		const staleAdd = await screen.findByRole('button', { name: 'Add to channel' });
		await fireEvent.input(email, { target: { value: 'other@example.com' } });
		await fireEvent.click(staleAdd);
		expect(addMember).not.toHaveBeenCalled();
	});

	it('routes inviteRequired to the existing approval-backed G1 invite surface', async () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: true } } } as never);
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		await fireEvent.input(screen.getByLabelText('Add guest by exact email'), { target: { value: 'unknown@example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		await waitFor(() => expect(previewGuest).toHaveBeenCalled());
		expect(screen.getByText('Invite this person before adding them to the channel.')).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Invite guest' })).toBeEnabled();
	});

	it('discloses full-history access from the server preview instead of inferring it', async () => {
		jmapSession.set({ effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: false } } } as never);
		previewGuest.mockResolvedValue({ kind: 'activeGuest', userId: 9, displayName: 'Pat', historyFromJoin: false });
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		await fireEvent.input(screen.getByLabelText('Add guest by exact email'), { target: { value: 'pat@example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		expect(await screen.findByText("This guest will see the channel's full history.")).toBeTruthy();
		expect(screen.queryByText('This guest will see messages sent after they join.')).toBeNull();
	});

	it('uses the direct admin invitation route only for guests.manage callers', async () => {
		jmapSession.set({
			capabilities: {
				'urn:setjoin:params:jmap:mail': {
					admin: { consoles: ['access'], permissions: ['guests.manage'] },
				},
			},
			effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: true } },
		} as never);
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		await fireEvent.input(screen.getByLabelText('Add guest by exact email'), { target: { value: 'pat@example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		await fireEvent.input(await screen.findByLabelText('Display name'), { target: { value: 'Pat External' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Invite guest' }));
		await waitFor(() => expect(inviteGuest).toHaveBeenCalledWith({ email: 'pat@example.com', displayName: 'Pat External' }));
		expect(screen.queryByText('Request guest access')).toBeNull();
	});

	it('never repeats an uncertain initial create and uses explicit re-invite for replacement', async () => {
		jmapSession.set({
			capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['access'], permissions: ['guests.manage'] } } },
			effectiveCapabilities: { apps: {}, features: { assist: false, bundles: false, guest_accounts: true, guest_invite: true } },
		} as never);
		inviteGuest.mockRejectedValueOnce(new InviteDeliveryUnconfirmedError('9007199254740993', 9));
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
		});
		await fireEvent.input(screen.getByLabelText('Add guest by exact email'), { target: { value: 'pat@example.com' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview access' }));
		await fireEvent.input(await screen.findByLabelText('Display name'), { target: { value: 'Pat External' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Invite guest' }));

		expect(await screen.findByText('9007199254740993')).toBeTruthy();
		expect(inviteGuest).toHaveBeenCalledTimes(1);
		await fireEvent.click(screen.getByRole('button', { name: 'Create replacement invitation' }));
		await waitFor(() => expect(reinviteGuest).toHaveBeenCalledWith(9));
		expect(inviteGuest).toHaveBeenCalledTimes(1);
	});

	it('renders roster lifecycle badges only from external and removed server fields', () => {
		render(ChannelSettingsSheet, {
			open: true, channelId: 5, kind: 'channel', canManage: true, notifLevel: 'all',
			postPermission: 'all', broadcastPermission: 'admins', onClose: noop, onSaved: noop,
			roster: [
				{ userId: 2, displayName: 'Internal-looking guest', avatarSha256: null, role: 'member', external: true, removed: true },
				{ userId: 3, displayName: 'external@example.com', avatarSha256: null, role: 'member', external: false, removed: false },
			],
		});
		expect(screen.getByText('Internal-looking guest').parentElement?.textContent).toContain('External');
		expect(screen.getByText('Internal-looking guest').parentElement?.textContent).toContain('Removed');
		expect(screen.getByText('external@example.com').parentElement?.textContent).not.toContain('External');
	});
	it('a plain member sees only the notification-level control, not the permission selects', () => {
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'channel',
			canManage: false,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			onClose: noop,
			onSaved: noop,
		});
		expect(screen.getByText('Notifications')).toBeTruthy();
		expect(screen.queryByText('Who can post')).toBeNull();
		expect(screen.queryByText('Who can @channel / @all')).toBeNull();
		expect(screen.getByText('Only channel owners and admins can change posting settings.')).toBeTruthy();
	});

	it('an owner/admin sees the post-permission and broadcast-permission selects too', () => {
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'channel',
			canManage: true,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			onClose: noop,
			onSaved: noop,
		});
		expect(screen.getByText('Who can post')).toBeTruthy();
		expect(screen.getByText('Who can @channel / @all')).toBeTruthy();
	});

	it('a DM (kind !== channel) never shows the permission selects, even for canManage', () => {
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'dm',
			canManage: true,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			onClose: noop,
			onSaved: noop,
		});
		expect(screen.queryByText('Who can post')).toBeNull();
	});

	it('saving sets the notif level for everyone, and the permission fields only for a manager', async () => {
		const onSaved = vi.fn();
		const onClose = vi.fn();
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'channel',
			canManage: true,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			onClose,
			onSaved,
		});
		await fireEvent.change(screen.getByLabelText('Notifications'), { target: { value: 'mentions' } });
		await fireEvent.change(screen.getByLabelText('Who can post'), { target: { value: 'admins' } });
		await fireEvent.click(screen.getByText('Save'));
		await waitFor(() => expect(setChannelNotif).toHaveBeenCalledWith(5, 'mentions'));
		await waitFor(() => expect(updateChannel).toHaveBeenCalledWith(5, { postPermission: 'admins', broadcastPermission: 'admins' }));
		await waitFor(() => expect(onSaved).toHaveBeenCalled());
		await waitFor(() => expect(onClose).toHaveBeenCalled());
	});

	// A4a Task 13 — read-only display; this sheet never edits compliance
	// state (Task 12's admin-only ChannelComplianceSheet owns that).
	it('no Retention row when retentionDays is null (the pre-A4a / no-policy case)', () => {
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'channel',
			canManage: false,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			onClose: noop,
			onSaved: noop,
		});
		expect(screen.queryByText('Retention')).toBeNull();
	});

	it("a 'regular' channel with retentionDays shows the destroy-ceiling wording", () => {
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'channel',
			canManage: false,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			classification: 'regular',
			retentionDays: 30,
			onClose: noop,
			onSaved: noop,
		});
		expect(screen.getByText('Retention')).toBeTruthy();
		expect(screen.getByText('Permanently delete messages older than 30 days')).toBeTruthy();
	});

	it("a 'gxp' channel with retentionDays shows the WORM keep-floor wording, never the ceiling one", () => {
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'channel',
			canManage: false,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			classification: 'gxp',
			retentionDays: 90,
			onClose: noop,
			onSaved: noop,
		});
		expect(screen.getByText('Messages cannot be edited or deleted for 90 days')).toBeTruthy();
		expect(screen.queryByText(/Permanently delete messages older than/)).toBeNull();
	});

	it('a plain member saving only calls setChannelNotif, never updateChannel', async () => {
		render(ChannelSettingsSheet, {
			open: true,
			channelId: 5,
			kind: 'channel',
			canManage: false,
			notifLevel: 'all',
			postPermission: 'all',
			broadcastPermission: 'admins',
			onClose: noop,
			onSaved: noop,
		});
		await fireEvent.change(screen.getByLabelText('Notifications'), { target: { value: 'none' } });
		await fireEvent.click(screen.getByText('Save'));
		await waitFor(() => expect(setChannelNotif).toHaveBeenCalledWith(5, 'none'));
		expect(updateChannel).not.toHaveBeenCalled();
	});
});

describe('ChannelSettingsSheet — Pillar C2 Task 7: bind-to-federation + Q13 archive gating', () => {
	const baseProps = {
		open: true,
		channelId: 5,
		kind: 'channel',
		notifLevel: 'all' as const,
		postPermission: 'all' as const,
		broadcastPermission: 'admins' as const,
		onClose: noop,
		onSaved: noop,
	};

	it('an owner/admin on a not-yet-bound channel sees the bind button; clicking it calls bindFederationRoom + onSaved', async () => {
		const onSaved = vi.fn();
		render(ChannelSettingsSheet, { ...baseProps, canManage: true, onSaved });
		const btn = screen.getByText('Make this a federated room…');
		await fireEvent.click(btn);
		await waitFor(() => expect(bindFederationRoom).toHaveBeenCalledWith(5));
		await waitFor(() => expect(onSaved).toHaveBeenCalled());
	});

	it('a plain member never sees the bind button, even on an unbound channel', () => {
		render(ChannelSettingsSheet, { ...baseProps, canManage: false });
		expect(screen.queryByText('Make this a federated room…')).toBeNull();
	});

	it('a bound channel never shows the bind button (already federated)', () => {
		render(ChannelSettingsSheet, { ...baseProps, canManage: true, federatedRoomId: 'room1@hub.test', isFederatedRoomHub: true });
		expect(screen.queryByText('Make this a federated room…')).toBeNull();
	});

	it('a plain (non-federated) channel shows no archive control at all — Task 7 scopes archive to room-bound channels only', () => {
		render(ChannelSettingsSheet, { ...baseProps, canManage: true });
		expect(screen.queryByText('Archive channel')).toBeNull();
	});

	it('a hub with active member orgs disables Archive with the "remove all member organizations first" message', async () => {
		getFederationRoomRoster.mockResolvedValue(
			roster({ members: [{ domain: 'partner.test', state: 'active', invitedAt: '2026-07-01T00:00:00Z', parkedReason: null, depthWarn: false }] }),
		);
		render(ChannelSettingsSheet, { ...baseProps, canManage: true, federatedRoomId: 'room1@hub.test', isFederatedRoomHub: true });
		await waitFor(() => expect(getFederationRoomRoster).toHaveBeenCalledWith(5));
		await waitFor(() => expect((screen.getByText('Archive channel') as HTMLButtonElement).disabled).toBe(true));
		expect(screen.getByText('Remove all member organizations before archiving this room')).toBeTruthy();
		expect(updateChannel).not.toHaveBeenCalled();
	});

	it('a hub with an EMPTY roster enables Archive; clicking it archives and calls onSaved + onClose', async () => {
		getFederationRoomRoster.mockResolvedValue(roster({ members: [] }));
		const onSaved = vi.fn();
		const onClose = vi.fn();
		render(ChannelSettingsSheet, {
			...baseProps,
			canManage: true,
			federatedRoomId: 'room1@hub.test',
			isFederatedRoomHub: true,
			onSaved,
			onClose,
		});
		await waitFor(() => expect((screen.getByText('Archive channel') as HTMLButtonElement).disabled).toBe(false));
		await fireEvent.click(screen.getByText('Archive channel'));
		await waitFor(() => expect(updateChannel).toHaveBeenCalledWith(5, { archived: true }));
		await waitFor(() => expect(onSaved).toHaveBeenCalled());
		await waitFor(() => expect(onClose).toHaveBeenCalled());
	});

	it('a LIVE spoke mirror disables Archive with the "hub organization controls this room" message', () => {
		render(ChannelSettingsSheet, {
			...baseProps,
			canManage: true,
			federatedRoomId: 'room1@hub.test',
			isFederatedRoomHub: false,
			federatedRoomRemoved: false,
		});
		expect((screen.getByText('Archive channel') as HTMLButtonElement).disabled).toBe(true);
		expect(screen.getByText('The hub organization controls this room — it cannot be archived here')).toBeTruthy();
		// a spoke never fetches the roster for archive-gating — only a hub does.
		expect(getFederationRoomRoster).not.toHaveBeenCalled();
	});

	// Pillar C2 Task 7 review (M3): the fedKey reseed guard never reset on
	// close, so reopening the sheet for the SAME channel served the stale
	// active-member count forever (the documented "remove last org, reopen
	// settings, archive still blocked" flow wedged until a full page
	// reload). Fails before the fix (fedKey stays 'true:5:room1@hub.test:true'
	// across the close).
	it('closing and reopening for the SAME channel re-fetches the roster — a stale "blocked" no longer survives a close/reopen', async () => {
		getFederationRoomRoster.mockResolvedValueOnce(
			roster({ members: [{ domain: 'partner.test', state: 'active', invitedAt: '2026-07-01T00:00:00Z', parkedReason: null, depthWarn: false }] }),
		);
		const { rerender } = render(ChannelSettingsSheet, { ...baseProps, canManage: true, federatedRoomId: 'room1@hub.test', isFederatedRoomHub: true });
		await waitFor(() => expect((screen.getByText('Archive channel') as HTMLButtonElement).disabled).toBe(true));
		expect(getFederationRoomRoster).toHaveBeenCalledTimes(1);

		await rerender({ ...baseProps, open: false, canManage: true, federatedRoomId: 'room1@hub.test', isFederatedRoomHub: true });

		// the hub removed its last member org while the sheet was closed.
		getFederationRoomRoster.mockResolvedValueOnce(roster({ members: [] }));
		await rerender({ ...baseProps, open: true, canManage: true, federatedRoomId: 'room1@hub.test', isFederatedRoomHub: true });

		await waitFor(() => expect(getFederationRoomRoster).toHaveBeenCalledTimes(2));
		await waitFor(() => expect((screen.getByText('Archive channel') as HTMLButtonElement).disabled).toBe(false));
	});

	it('a KICKED/removed spoke mirror enables Archive (a purely local act at that point)', () => {
		render(ChannelSettingsSheet, {
			...baseProps,
			canManage: true,
			federatedRoomId: 'room1@hub.test',
			isFederatedRoomHub: false,
			federatedRoomRemoved: true,
		});
		expect((screen.getByText('Archive channel') as HTMLButtonElement).disabled).toBe(false);
	});
});
