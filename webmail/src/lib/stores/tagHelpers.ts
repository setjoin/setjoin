import type { Mailbox } from '$lib/types/jmap';

/**
 * Canonical list of mail location-group tag roles.
 * Archive = strip location tags; All Mail = exclude Trash/Spam.
 * Single source of truth — do not duplicate this list elsewhere.
 */
export const LOCATION_ROLES = [
	'inbox',
	'sent',
	'drafts',
	'trash',
	'spam',
	'archive',
	'junk',
] as const;

export type LocationRole = (typeof LOCATION_ROLES)[number];

/**
 * Strip all location-group tag entries from a mailboxIds map.
 * Used by archive: result is the All Mail destination (no location tag).
 * Entries whose id is not found in the mailboxes list are kept (unknown = user tag).
 */
export function stripLocationTags(
	mailboxIds: Record<string, boolean>,
	mailboxes: Mailbox[],
): Record<string, boolean> {
	const mailboxMap = new Map(mailboxes.map((m) => [m.id, m]));
	return Object.fromEntries(
		Object.entries(mailboxIds).filter(([id]) => {
			const mb = mailboxMap.get(id);
			if (!mb) return true; // unknown id — keep it
			return !mb.role || !(LOCATION_ROLES as ReadonlyArray<string>).includes(mb.role);
		}),
	);
}

/**
 * Filter mailboxes to only user-created tags (no system location-group tags).
 */
// System tags that must never appear in the user "Tags" list: location group +
// the snooze group (Snoozed/Scheduled) + Templates. User labels carry role=null.
const SYSTEM_TAG_ROLES: ReadonlyArray<string> = [...LOCATION_ROLES, 'snoozed', 'scheduled', 'templates'];

export function userTags(mailboxes: Mailbox[]): Mailbox[] {
	return mailboxes.filter((m) => !m.role || !SYSTEM_TAG_ROLES.includes(m.role));
}

/**
 * Build a flat ordered list with depth for tree rendering from parentId references.
 */
export function buildTagTree(mailboxes: Mailbox[]): (Mailbox & { depth: number })[] {
	const map: Record<string, Mailbox & { depth: number }> = {};
	const result: (Mailbox & { depth: number })[] = [];

	for (const mb of mailboxes) {
		map[mb.id] = { ...mb, depth: 0 };
	}

	function walk(id: string, depth: number) {
		for (const mb of Object.values(map)) {
			const match = (!mb.parentId && !id && depth === 0) || mb.parentId === id;
			if (match && !result.some((r) => r.id === mb.id)) {
				mb.depth = depth;
				result.push(mb);
				walk(mb.id, depth + 1);
			}
		}
	}

	walk('', 0);

	// Include orphaned nodes (parent not found) at depth 0
	for (const mb of Object.values(map)) {
		if (!result.some((r) => r.id === mb.id)) {
			mb.depth = 0;
			result.push(mb);
		}
	}

	return result;
}

/**
 * Generate snooze preset labels and timestamps relative to now.
 *
 * Exactly the four kit §7 presets (in order):
 *   Later today, 18:00 · Tomorrow, 8:00 · This weekend, Sat 9:00 · Next week, Mon 8:00
 * "Later today, 18:00" is dropped once 18:00 has passed (so the list shows the
 * remaining three after the evening). Labels match the kit fixture exactly.
 */
export function snoozePresets(now: Date = new Date()): { label: string; date: Date }[] {
	const weekday = now.getDay();

	const laterToday = new Date(now); laterToday.setHours(18, 0, 0, 0);

	const tomorrow8am = new Date(now); tomorrow8am.setDate(tomorrow8am.getDate() + 1); tomorrow8am.setHours(8, 0, 0, 0);

	// Next Saturday 09:00 (always strictly in the future).
	const saturday = new Date(now); saturday.setDate(saturday.getDate() + (6 - weekday)); saturday.setHours(9, 0, 0, 0);
	if (saturday <= now) saturday.setDate(saturday.getDate() + 7);

	// Next Monday 08:00.
	const nextMonday = new Date(now);
	const daysUntilMonday = weekday === 1 ? 7 : (8 - weekday) % 7 || 7;
	nextMonday.setDate(nextMonday.getDate() + daysUntilMonday); nextMonday.setHours(8, 0, 0, 0);

	const presets: { label: string; date: Date }[] = [];

	if (laterToday > now) {
		presets.push({ label: 'Later today, 18:00', date: laterToday });
	}
	presets.push({ label: 'Tomorrow, 8:00', date: tomorrow8am });
	presets.push({ label: 'This weekend, Sat 9:00', date: saturday });
	presets.push({ label: 'Next week, Mon 8:00', date: nextMonday });

	return presets;
}
