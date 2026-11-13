import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	assignGuestProfile,
	createGuestProfile,
	deleteGuestProfile,
	disableGuest,
	enableGuest,
	extendGuest,
	getGuest,
	inviteGuest,
	InviteDeliveryUnconfirmedError,
	listGuestProfileDomains,
	listGuestProfiles,
	listGuestSponsorOptions,
	listGuests,
	reinviteGuest,
	revokeGuestInvite,
	transferGuest,
	updateGuestProfile,
	type GuestProfileInput,
} from './guests';

function response(body: unknown = {}, status = 200) {
	return { ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) };
}

describe('guest admin API', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('uses the frozen guest/profile routes and camelCase bodies', async () => {
		const fetch = vi.fn().mockResolvedValue(response([]));
		vi.stubGlobal('fetch', fetch);
		const profile: GuestProfileInput = {
			hostDomainId: 4,
			name: 'Partner',
			canPost: true,
			historyFromJoin: true,
			allowDownload: false,
			allowMeetCreate: false,
			allowMeetHost: false,
			canInitiateDm: true,
			allowNativeShell: false,
			defaultExpiryDays: 30,
			apps: ['chat'],
		};

		await listGuests();
		await getGuest(7);
		await listGuestProfiles();
		await listGuestProfileDomains();
		await createGuestProfile(profile);
		await updateGuestProfile(3, profile);
		await deleteGuestProfile(3);
		await assignGuestProfile(7, null);
		await disableGuest(7);
		await enableGuest(7);
		await extendGuest(7, '2026-09-01T00:00:00.000Z');
		await reinviteGuest(7, '2026-10-01T00:00:00.000Z');
		await revokeGuestInvite(7, '9007199254740993');
		await listGuestSponsorOptions(7, 'alex@example.com');
		await transferGuest(7, 42);
		await inviteGuest({ email: 'guest@example.net', displayName: 'Guest', profileId: 3 });

		expect(fetch.mock.calls.map(([url, init]) => [url, init?.method ?? 'GET', init?.body])).toEqual([
			['/api/admin/guests', 'GET', undefined],
			['/api/admin/guests/7', 'GET', undefined],
			['/api/admin/guest-profiles', 'GET', undefined],
			['/api/admin/guest-profile-domains', 'GET', undefined],
			['/api/admin/guest-profiles', 'POST', JSON.stringify(profile)],
			['/api/admin/guest-profiles/3', 'PUT', JSON.stringify(profile)],
			['/api/admin/guest-profiles/3', 'DELETE', undefined],
			['/api/admin/guests/7/profile', 'PUT', JSON.stringify({ profileId: null })],
			['/api/admin/guests/7/disable', 'POST', undefined],
			['/api/admin/guests/7/enable', 'POST', undefined],
			['/api/admin/guests/7/extend', 'POST', JSON.stringify({ expiresAt: '2026-09-01T00:00:00.000Z' })],
			['/api/admin/guests/7/reinvite', 'POST', JSON.stringify({ expiresAt: '2026-10-01T00:00:00.000Z' })],
			['/api/admin/guests/7/invite', 'DELETE', JSON.stringify({ expectedInviteId: '9007199254740993' })],
			['/api/admin/guests/7/sponsor-options?q=alex%40example.com', 'GET', undefined],
			['/api/admin/guests/7/transfer', 'POST', JSON.stringify({ sponsorUserId: 42 })],
			['/api/admin/guests', 'POST', JSON.stringify({ email: 'guest@example.net', displayName: 'Guest', profileId: 3 })],
		]);
	});

	it('surfaces a committed invite with unconfirmed delivery as a typed exact-id error', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({
			code: 'invite_delivery_unconfirmed', inviteId: '9007199254740993', guestUserId: 7,
		}, 503)));
		await expect(inviteGuest({ email: 'guest@example.net', displayName: 'Guest' }))
			.rejects.toEqual(expect.objectContaining({
				constructor: InviteDeliveryUnconfirmedError,
				inviteId: '9007199254740993', guestUserId: 7,
			}));
	});
});
