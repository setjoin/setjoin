import { adminFetch } from './transport';
import { problemDetail } from '$lib/errors';

export type GuestApp = 'mail' | 'calendar' | 'contacts' | 'tasks' | 'chat' | 'drive' | 'meet';
export type GuestStatus = 'invited' | 'active' | 'disabled' | 'expired';
export type GuestInviteState = 'pending' | 'expired' | 'accepted' | 'superseded' | 'revoked' | 'unknown';

export interface GuestInviteHistoryEntry {
	inviteId: string;
	state: GuestInviteState;
	createdAt: string;
	expiresAt: string;
	terminalAt: string | null;
	createdByEmail: string | null;
}

export interface GuestInviteMutationResult {
	guestUserId: number;
	inviteId: string;
	expiresAt: string;
}

export class InviteDeliveryUnconfirmedError extends Error {
	readonly code = 'invite_delivery_unconfirmed';
	constructor(
		readonly inviteId: string,
		readonly guestUserId: number,
	) {
		super('Invitation created; email delivery could not be confirmed.');
	}
}

export class GuestInviteStateError extends Error {
	constructor(readonly status: 404 | 409, message: string) {
		super(message);
	}
}

export interface GuestProfileInput {
	hostDomainId: number;
	name: string;
	canPost: boolean;
	historyFromJoin: boolean;
	allowDownload: boolean;
	allowMeetCreate: boolean;
	allowMeetHost: boolean;
	canInitiateDm: boolean;
	allowNativeShell: boolean;
	defaultExpiryDays: number | null;
	apps: Array<'chat' | 'drive' | 'meet'>;
}

export interface GuestProfile extends GuestProfileInput {
	id: number;
	assignedCount: number;
	createdAt: string;
	updatedAt: string;
}

export interface GuestSummary {
	id: number;
	displayName: string;
	invitedEmail: string;
	status: GuestStatus;
	effectiveStatus: GuestStatus;
	expiresAt: string | null;
	sponsorUserId: number | null;
	sponsorDisplayName: string | null;
	sponsorNeedsReview: boolean;
	profileId: number | null;
	profileName: string | null;
	pendingInvite: boolean;
	channelGrantCount: number;
	createdAt: string;
	updatedAt: string;
}

export interface GuestChannelGrant {
	channelId: number;
	kind: string;
	name: string | null;
	role: string;
	canPost: boolean | null;
	historyFloorSeq: number | null;
}

export interface GuestProfileDomain {
	id: number;
	name: string;
}

export interface GuestDetail extends Omit<GuestSummary, 'pendingInvite'> {
	invitedBy: number | null;
	invitedByEmail: string | null;
	pendingInvite: { inviteId: string; expiresAt: string; createdAt: string; createdByEmail: string | null } | null;
	inviteHistory: GuestInviteHistoryEntry[];
	inviteHistoryHasMore: boolean;
	channelGrants: GuestChannelGrant[];
	appEntitlements: Record<GuestApp, boolean>;
}

export interface GuestInviteInput {
	email: string;
	displayName: string;
	profileId?: number | null;
	expiresAt?: string;
}

export interface GuestSponsorOption {
	id: number;
	email: string;
	displayName: string;
}

export interface GuestTransferResult {
	guestUserId: number;
	sponsorUserId: number;
	channelOwnersTransferred: number;
	driveSpacesTransferred: number;
}

async function json<T>(path: string, opts?: Parameters<typeof adminFetch>[1]): Promise<T> {
	const response = await adminFetch(path, { ...opts, onError: problemDetail });
	return (await response.json()) as T;
}

export function listGuests(): Promise<GuestSummary[]> {
	return json('/admin/guests');
}

export function getGuest(id: number): Promise<GuestDetail> {
	return json(`/admin/guests/${id}`);
}

export function listGuestProfiles(): Promise<GuestProfile[]> {
	return json('/admin/guest-profiles');
}

export function listGuestProfileDomains(): Promise<GuestProfileDomain[]> {
	return json('/admin/guest-profile-domains');
}

export function createGuestProfile(input: GuestProfileInput): Promise<GuestProfile> {
	return json('/admin/guest-profiles', { method: 'POST', body: JSON.stringify(input) });
}

export function updateGuestProfile(id: number, input: GuestProfileInput): Promise<GuestProfile> {
	return json(`/admin/guest-profiles/${id}`, { method: 'PUT', body: JSON.stringify(input) });
}

export async function deleteGuestProfile(id: number): Promise<void> {
	await adminFetch(`/admin/guest-profiles/${id}`, { method: 'DELETE', onError: problemDetail });
}

export async function assignGuestProfile(guestId: number, profileId: number | null): Promise<void> {
	await adminFetch(`/admin/guests/${guestId}/profile`, {
		method: 'PUT', body: JSON.stringify({ profileId }), onError: problemDetail,
	});
}

async function postGuestAction(id: number, action: 'disable' | 'enable', body?: string): Promise<void> {
	await adminFetch(`/admin/guests/${id}/${action}`, { method: 'POST', body, onError: problemDetail });
}

export function disableGuest(id: number): Promise<void> {
	return postGuestAction(id, 'disable');
}

export function enableGuest(id: number): Promise<void> {
	return postGuestAction(id, 'enable');
}

export async function extendGuest(id: number, expiresAt: string): Promise<void> {
	await adminFetch(`/admin/guests/${id}/extend`, {
		method: 'POST', body: JSON.stringify({ expiresAt }), onError: problemDetail,
	});
}

export function listGuestSponsorOptions(id: number, q = ''): Promise<GuestSponsorOption[]> {
	const params = new URLSearchParams();
	if (q.trim()) params.set('q', q.trim());
	const suffix = params.size ? `?${params.toString()}` : '';
	return json(`/admin/guests/${id}/sponsor-options${suffix}`);
}

export function transferGuest(id: number, sponsorUserId: number): Promise<GuestTransferResult> {
	return json(`/admin/guests/${id}/transfer`, {
		method: 'POST', body: JSON.stringify({ sponsorUserId }),
	});
}

async function inviteMutation(path: string, body: string): Promise<GuestInviteMutationResult & { invitedEmail?: string }> {
	const response = await adminFetch(path, {
		method: 'POST', body, onError: problemDetail, allowStatuses: [503],
	});
	const payload = (await response.json()) as Record<string, unknown>;
	if (response.status === 503 && payload.code === 'invite_delivery_unconfirmed') {
		throw new InviteDeliveryUnconfirmedError(String(payload.inviteId ?? ''), Number(payload.guestUserId));
	}
	if (response.status === 503) {
		throw new Error('Invitation delivery could not be confirmed. Refresh status before trying again.');
	}
	return payload as unknown as GuestInviteMutationResult & { invitedEmail?: string };
}

export function inviteGuest(input: GuestInviteInput): Promise<GuestInviteMutationResult & { invitedEmail?: string }> {
	return inviteMutation('/admin/guests', JSON.stringify(input));
}

export function reinviteGuest(id: number, expiresAt?: string): Promise<GuestInviteMutationResult> {
	return inviteMutation(`/admin/guests/${id}/reinvite`, JSON.stringify(expiresAt ? { expiresAt } : {}));
}

export async function revokeGuestInvite(id: number, expectedInviteId: string): Promise<void> {
	const response = await adminFetch(`/admin/guests/${id}/invite`, {
		method: 'DELETE', body: JSON.stringify({ expectedInviteId }), onError: problemDetail,
		allowStatuses: [404, 409],
	});
	if (response.status === 404 || response.status === 409) {
		throw new GuestInviteStateError(response.status, await problemDetail(response));
	}
}
