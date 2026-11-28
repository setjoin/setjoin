import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import FederationRosterSheet from './FederationRosterSheet.svelte';
import type { FederationRoomRoster, FederationRoomMember } from '$lib/chat/api';
import { toasts, clearToasts } from '$lib/components/ui';

const getFederationRoomRoster = vi.fn();
const inviteFederationMember = vi.fn();
const removeFederationMember = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		getFederationRoomRoster: (...a: unknown[]) => getFederationRoomRoster(...a),
		inviteFederationMember: (...a: unknown[]) => inviteFederationMember(...a),
		removeFederationMember: (...a: unknown[]) => removeFederationMember(...a),
	};
});

function member(over: Partial<FederationRoomMember> = {}): FederationRoomMember {
	return { domain: 'partner.test', state: 'active', invitedAt: '2026-07-01T00:00:00Z', parkedReason: null, depthWarn: false, ...over };
}

function roster(over: Partial<FederationRoomRoster> = {}): FederationRoomRoster {
	return { roomId: 'room1@hub.test', hubDomain: 'hub.test', isHub: true, removedAt: null, members: [], ...over };
}

const noop = vi.fn();

beforeEach(() => {
	getFederationRoomRoster.mockResolvedValue(roster());
	inviteFederationMember.mockResolvedValue(undefined);
	removeFederationMember.mockResolvedValue(undefined);
});

afterEach(() => {
	vi.clearAllMocks();
	clearToasts();
});

describe('FederationRosterSheet', () => {
	it('an empty roster shows the empty state', async () => {
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop });
		await waitFor(() => expect(getFederationRoomRoster).toHaveBeenCalledWith(5));
		expect(await screen.findByText('No member organizations yet')).toBeTruthy();
	});

	it('renders each member with its state label; a depth-warn member also shows the warn icon', async () => {
		getFederationRoomRoster.mockResolvedValue(
			roster({
				members: [
					member({ domain: 'active.test', state: 'active' }),
					member({ domain: 'warn.test', state: 'active', depthWarn: true }),
					member({ domain: 'parked.test', state: 'parked' }),
					member({ domain: 'revoked.test', state: 'revoked' }),
					member({ domain: 'left.test', state: 'left' }),
				],
			}),
		);
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop });
		await screen.findByText('active.test');
		expect(screen.getByText('warn.test')).toBeTruthy();
		expect(screen.getByText('parked.test')).toBeTruthy();
		expect(screen.getByText('revoked.test')).toBeTruthy();
		expect(screen.getByText('left.test')).toBeTruthy();
		// state labels (Badge) — 4 distinct labels + one extra 'Active' for the warn row.
		expect(screen.getAllByText('Active')).toHaveLength(2);
		expect(screen.getByText('Paused (delivery backlog)')).toBeTruthy();
		expect(screen.getByText('Revoked')).toBeTruthy();
		expect(screen.getByText('Removed')).toBeTruthy();
		expect(screen.getByLabelText('Nearing this organization’s delivery backlog limit')).toBeTruthy();
	});

	it('a spoke (isHub=false) shows the hub-domain note and NEVER shows invite/remove/re-admit, even for canManage', async () => {
		getFederationRoomRoster.mockResolvedValue(
			roster({ isHub: false, hubDomain: 'thehub.example', members: [member({ domain: 'other-member.test' })] }),
		);
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop });
		await screen.findByText('Hub organization: thehub.example');
		expect(screen.queryByText('Invite organization…')).toBeNull();
		expect(screen.queryByText('Remove')).toBeNull();
		expect(screen.queryByText('Re-admit…')).toBeNull();
	});

	it('a hub, canManage=false, sees the roster but no invite/remove affordances', async () => {
		getFederationRoomRoster.mockResolvedValue(roster({ members: [member()] }));
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: false, onClose: noop });
		await screen.findByText('partner.test');
		expect(screen.queryByText('Invite organization…')).toBeNull();
		expect(screen.queryByText('Remove')).toBeNull();
	});

	it('a hub owner/admin sees Remove for active/parked members and Re-admit for revoked/left ones', async () => {
		getFederationRoomRoster.mockResolvedValue(
			roster({
				members: [member({ domain: 'a.test', state: 'active' }), member({ domain: 'r.test', state: 'revoked' })],
			}),
		);
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop });
		await screen.findByText('a.test');
		expect(screen.getByText('Remove')).toBeTruthy();
		expect(screen.getByText('Re-admit…')).toBeTruthy();
	});

	it('clicking Remove calls removeFederationMember and reloads the roster', async () => {
		getFederationRoomRoster.mockResolvedValueOnce(roster({ members: [member({ domain: 'a.test', state: 'active' })] }));
		const onChanged = vi.fn();
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop, onChanged });
		await screen.findByText('a.test');
		getFederationRoomRoster.mockResolvedValueOnce(roster({ members: [member({ domain: 'a.test', state: 'left' })] }));
		await fireEvent.click(screen.getByText('Remove'));
		await waitFor(() => expect(removeFederationMember).toHaveBeenCalledWith(5, 'a.test'));
		await waitFor(() => expect(onChanged).toHaveBeenCalled());
	});

	it('the invite dialog carries the RATIFIED Q1 divergence warning and submits {memberDomain, contactAddr}', async () => {
		const onChanged = vi.fn();
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop, onChanged });
		await waitFor(() => expect(getFederationRoomRoster).toHaveBeenCalled());
		await fireEvent.click(screen.getByText('Invite organization…'));
		expect(
			screen.getByText(
				'Messages in this room are archived independently by each member organization under its own retention rules — copies in other organizations are not governed by yours.',
			),
		).toBeTruthy();
		await fireEvent.input(screen.getByLabelText('Organization domain'), { target: { value: 'newpartner.test' } });
		await fireEvent.input(screen.getByLabelText('Contact address'), { target: { value: 'bob@newpartner.test' } });
		await fireEvent.click(screen.getByText('Invite'));
		await waitFor(() => expect(inviteFederationMember).toHaveBeenCalledWith(5, 'newpartner.test', 'bob@newpartner.test'));
		await waitFor(() => expect(onChanged).toHaveBeenCalled());
	});

	it('a failed roster fetch shows the error text, not a blank sheet', async () => {
		getFederationRoomRoster.mockRejectedValue(new Error('boom'));
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop });
		expect(await screen.findByRole('alert')).toBeTruthy();
	});

	it('a failed remove toasts the error, does not silently swallow it', async () => {
		getFederationRoomRoster.mockResolvedValue(roster({ members: [member({ domain: 'a.test', state: 'active' })] }));
		removeFederationMember.mockRejectedValue(new Error('nope'));
		render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop });
		await screen.findByText('a.test');
		await fireEvent.click(screen.getByText('Remove'));
		await waitFor(() => expect(toasts.length).toBeGreaterThan(0));
	});

	// Pillar C2 Task 7 review (M3): the lastKey reseed guard never reset on
	// close, so reopening for the SAME channel served the stale first
	// roster forever (the documented "remove last org, reopen settings,
	// archive still blocked" flow wedged until a full page reload). This
	// fails before the fix (lastKey stays 'true:5' across the close).
	it('closing and reopening the sheet for the SAME channel re-fetches the roster, not the stale one', async () => {
		getFederationRoomRoster.mockResolvedValueOnce(roster({ members: [member({ domain: 'a.test', state: 'active' })] }));
		const { rerender } = render(FederationRosterSheet, { open: true, channelId: 5, canManage: true, onClose: noop });
		await screen.findByText('a.test');
		expect(getFederationRoomRoster).toHaveBeenCalledTimes(1);

		await rerender({ open: false, channelId: 5, canManage: true, onClose: noop });

		// something changed server-side while the sheet was closed.
		getFederationRoomRoster.mockResolvedValueOnce(roster({ members: [member({ domain: 'a.test', state: 'revoked' })] }));
		await rerender({ open: true, channelId: 5, canManage: true, onClose: noop });

		await waitFor(() => expect(getFederationRoomRoster).toHaveBeenCalledTimes(2));
		await waitFor(() => expect(screen.getByText('Revoked')).toBeTruthy());
	});
});
