import { problemDetail } from '$lib/errors';
import { createEdgeClient, toEdgeProblemError } from '$lib/edge/client';

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

const guestsEdge = createEdgeClient({
	cache: 'no-store',
	loginRedirect: '/login',
	forbiddenMessage: 'Admin access required',
	onError: problemDetail
});

function handleInviteMutationResult(
	data: (GuestInviteMutationResult & { invitedEmail?: string }) | undefined,
	error: unknown,
	response: Response
): GuestInviteMutationResult & { invitedEmail?: string } {
	if (response.status === 503) {
		const payload = (error && typeof error === 'object' ? error : {}) as Record<string, unknown>;
		if (payload.code === 'invite_delivery_unconfirmed') {
			throw new InviteDeliveryUnconfirmedError(String(payload.inviteId ?? ''), Number(payload.guestUserId));
		}
		throw new Error('Invitation delivery could not be confirmed. Refresh status before trying again.');
	}
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data;
}

export async function listGuests(): Promise<GuestSummary[]> {
	const { data, error, response } = await guestsEdge.GET('/api/admin/guests');
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data as GuestSummary[];
}

export async function getGuest(id: number): Promise<GuestDetail> {
	const { data, error, response } = await guestsEdge.GET('/api/admin/guests/{id}', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data as unknown as GuestDetail;
}

export async function listGuestProfiles(): Promise<GuestProfile[]> {
	const { data, error, response } = await guestsEdge.GET('/api/admin/guest-profiles');
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data as GuestProfile[];
}

export async function listGuestProfileDomains(): Promise<GuestProfileDomain[]> {
	const { data, error, response } = await guestsEdge.GET('/api/admin/guest-profile-domains');
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data;
}

export async function createGuestProfile(input: GuestProfileInput): Promise<GuestProfile> {
	const { data, error, response } = await guestsEdge.POST('/api/admin/guest-profiles', {
		body: input
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data as GuestProfile;
}

export async function updateGuestProfile(id: number, input: GuestProfileInput): Promise<GuestProfile> {
	const { data, error, response } = await guestsEdge.PUT('/api/admin/guest-profiles/{id}', {
		params: { path: { id } },
		body: input
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data as GuestProfile;
}

export async function deleteGuestProfile(id: number): Promise<void> {
	const { error, response } = await guestsEdge.DELETE('/api/admin/guest-profiles/{id}', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}

export async function assignGuestProfile(guestId: number, profileId: number | null): Promise<void> {
	const { error, response } = await guestsEdge.PUT('/api/admin/guests/{id}/profile', {
		params: { path: { id: guestId } },
		body: { profileId }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}

export async function disableGuest(id: number): Promise<void> {
	const { error, response } = await guestsEdge.POST('/api/admin/guests/{id}/disable', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}

export async function enableGuest(id: number): Promise<void> {
	const { error, response } = await guestsEdge.POST('/api/admin/guests/{id}/enable', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}

export async function extendGuest(id: number, expiresAt: string): Promise<void> {
	const { error, response } = await guestsEdge.POST('/api/admin/guests/{id}/extend', {
		params: { path: { id } },
		body: { expiresAt }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}

export async function listGuestSponsorOptions(id: number, q = ''): Promise<GuestSponsorOption[]> {
	const trimmed = q.trim();
	const { data, error, response } = await guestsEdge.GET('/api/admin/guests/{id}/sponsor-options', {
		params: {
			path: { id },
			query: trimmed ? { q: trimmed } : undefined
		}
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data;
}

export async function transferGuest(id: number, sponsorUserId: number): Promise<GuestTransferResult> {
	const { data, error, response } = await guestsEdge.POST('/api/admin/guests/{id}/transfer', {
		params: { path: { id } },
		body: { sponsorUserId }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response);
	}
	return data;
}

export async function inviteGuest(input: GuestInviteInput): Promise<GuestInviteMutationResult & { invitedEmail?: string }> {
	const { data, error, response } = await guestsEdge.POST('/api/admin/guests', {
		body: input
	});
	return handleInviteMutationResult(data, error, response);
}

export async function reinviteGuest(id: number, expiresAt?: string): Promise<GuestInviteMutationResult> {
	const { data, error, response } = await guestsEdge.POST('/api/admin/guests/{id}/reinvite', {
		params: { path: { id } },
		body: expiresAt ? { expiresAt } : {}
	});
	return handleInviteMutationResult(data, error, response);
}

export async function revokeGuestInvite(id: number, expectedInviteId: string): Promise<void> {
	const { error, response } = await guestsEdge.DELETE('/api/admin/guests/{userId}/invite', {
		params: { path: { userId: id } },
		body: { expectedInviteId }
	});
	if (response.status === 404 || response.status === 409) {
		throw new GuestInviteStateError(response.status, toEdgeProblemError(error, response).message);
	}
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response);
	}
}
