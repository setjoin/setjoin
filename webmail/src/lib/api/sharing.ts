// End-user sharing/delegation client — the /api/me/sharing* surface (spec
// 2026-06-27-sharing-delegation-design.md §6). Routed through the schema-first
// openapi-fetch edge client ($lib/edge/client) over $lib/http's DPoP seam.
// The gateway forces the caller's own primary mailbox / user id server-side,
// so we never send them.

import { problemDetail } from '$lib/errors';
import { createEdgeClient, toEdgeProblemError } from '$lib/edge/client';

export type DelegatePermission = 'read' | 'send_as' | 'send_on_behalf' | 'full_access' | 'manage_calendar';
export type SharingLevel = 'none' | 'freebusy' | 'read';
export type SharingAudience = 'everyone' | 'ou' | 'group';

export interface SharingDelegate {
	userId: number;
	email: string;
	name: string;
	permission: DelegatePermission;
	grantedAt: string;
}

export interface SharingCalendarGrant {
	calendarId: number;
	calendarName: string;
	userEmail: string;
	userName: string;
	level: string;
}

export interface SharingDefault {
	id: number;
	ownerScope: 'org' | 'ou' | 'group' | 'user';
	audience: SharingAudience;
	audienceRef: number;
	level: SharingLevel;
}

export interface SharingOverview {
	delegates: SharingDelegate[];
	calendarGrants: SharingCalendarGrant[];
	myDefaults: SharingDefault[];
	inheritedDefaults: SharingDefault[];
	/** Server-computed 'sharing.defaults' toggle — the §6-A section hides when false (D11). */
	defaultsEnabled: boolean;
}

// The gateway emits problem+json for this app-JSON surface — surface the
// reducer's actionable .detail (BZ114–BZ117), not statusText.
const sharingError = (r: Response) => problemDetail(r, `Sharing request failed (${r.status})`);
const sharingEdge = createEdgeClient({ onError: sharingError });

export async function getSharingOverview(signal?: AbortSignal): Promise<SharingOverview> {
	const { data, error, response } = await sharingEdge.GET('/api/me/sharing', { signal });
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response, `Sharing request failed (${response.status})`);
	}
	return data as SharingOverview;
}

export async function grantDelegate(granteeEmail: string, permission: DelegatePermission): Promise<void> {
	const { error, response } = await sharingEdge.POST('/api/me/sharing/delegates', {
		body: { granteeEmail, permission }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response, `Sharing request failed (${response.status})`);
	}
}

export async function revokeDelegate(userId: number): Promise<void> {
	const { error, response } = await sharingEdge.DELETE('/api/me/sharing/delegates/{userId}', {
		params: { path: { userId } }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response, `Sharing request failed (${response.status})`);
	}
}

/** Upsert the caller's own user-scope default. audienceRef 0 for audience='everyone' (server resolves the domain, D7). */
export async function setMyDefault(audience: SharingAudience, audienceRef: number, level: SharingLevel): Promise<number> {
	const { data, error, response } = await sharingEdge.PUT('/api/me/sharing/default', {
		body: { audience, audienceRef, level }
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw toEdgeProblemError(error, response, `Sharing request failed (${response.status})`);
	}
	return data.id;
}

export async function clearMyDefault(id: number): Promise<void> {
	const { error, response } = await sharingEdge.DELETE('/api/me/sharing/default/{id}', {
		params: { path: { id } }
	});
	if (!response.ok || error !== undefined) {
		throw toEdgeProblemError(error, response, `Sharing request failed (${response.status})`);
	}
}
