// End-user sharing/delegation client — the /api/me/sharing* surface (spec
// 2026-06-27-sharing-delegation-design.md §6). Mirrors the rules.ts fetch
// style (httpRequest seam; auth cookie automatic). The gateway forces the
// caller's own primary mailbox / user id server-side, so we never send them.

import { httpRequest } from '$lib/http';
import { problemDetail } from '$lib/errors';

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

const JSON_HEADERS = { 'content-type': 'application/json' };

// The gateway emits problem+json for this app-JSON surface — surface the
// reducer's actionable .detail (BZ114–BZ117), not statusText.
const sharingError = (r: Response) => problemDetail(r, `Sharing request failed (${r.status})`);

export async function getSharingOverview(signal?: AbortSignal): Promise<SharingOverview> {
	const res = await httpRequest('/api/me/sharing', { method: 'GET', signal, onError: sharingError });
	return (await res.json()) as SharingOverview;
}

export async function grantDelegate(granteeEmail: string, permission: DelegatePermission): Promise<void> {
	await httpRequest('/api/me/sharing/delegates', {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ granteeEmail, permission }),
		onError: sharingError
	});
}

export async function revokeDelegate(userId: number): Promise<void> {
	await httpRequest(`/api/me/sharing/delegates/${userId}`, { method: 'DELETE', onError: sharingError });
}

/** Upsert the caller's own user-scope default. audienceRef 0 for audience='everyone' (server resolves the domain, D7). */
export async function setMyDefault(audience: SharingAudience, audienceRef: number, level: SharingLevel): Promise<number> {
	const res = await httpRequest('/api/me/sharing/default', {
		method: 'PUT',
		headers: JSON_HEADERS,
		body: JSON.stringify({ audience, audienceRef, level }),
		onError: sharingError
	});
	return ((await res.json()) as { id: number }).id;
}

export async function clearMyDefault(id: number): Promise<void> {
	await httpRequest(`/api/me/sharing/default/${id}`, { method: 'DELETE', onError: sharingError });
}
