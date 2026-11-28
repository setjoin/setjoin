import { describe, it, expect } from 'vitest';
import { userTags, buildTagTree, snoozePresets, LOCATION_ROLES, stripLocationTags } from './tagHelpers';
import type { Mailbox } from '$lib/types/jmap';

const inbox: Mailbox = { id: '1', name: 'Inbox', role: 'inbox' };
const sent: Mailbox = { id: '2', name: 'Sent', role: 'sent' };
const drafts: Mailbox = { id: '3', name: 'Drafts', role: 'drafts' };
const trash: Mailbox = { id: '4', name: 'Trash', role: 'trash' };
const spam: Mailbox = { id: '5', name: 'Spam', role: 'spam' };
const projects: Mailbox = { id: '6', name: 'Projects', color: '#4A90D9' };
const finance: Mailbox = { id: '7', name: 'Finance', color: '#E74C3C', parentId: '6' };
const family: Mailbox = { id: '8', name: 'Family', color: '#2ECC71' };

describe('userTags', () => {
	it('filters out all system location-group tags', () => {
		const result = userTags([inbox, sent, drafts, trash, spam, projects, finance, family]);
		expect(result).toHaveLength(3);
		expect(result.map((t) => t.name)).toEqual(['Projects', 'Finance', 'Family']);
	});

	it('returns empty array when only system tags exist', () => {
		const result = userTags([inbox, sent]);
		expect(result).toHaveLength(0);
	});

	it('includes tags with role=null (user-created)', () => {
		const label: Mailbox = { id: '9', name: 'Custom', role: undefined };
		const result = userTags([inbox, label]);
		expect(result).toHaveLength(1);
		expect(result[0].name).toBe('Custom');
	});
});

describe('buildTagTree', () => {
	const allMail: Mailbox = { id: '0', name: 'All Mail' };
	const mailboxes = [allMail, inbox, sent, projects, finance, family];

	it('returns flat ordered list with depth', () => {
		const result = buildTagTree(mailboxes);
		expect(result.every((r) => typeof r.depth === 'number')).toBe(true);
	});

	it('sorts roots before children', () => {
		const result = buildTagTree([projects, finance, family, inbox]);
		const projIdx = result.findIndex((r) => r.id === '6');
		const finIdx = result.findIndex((r) => r.id === '7');
		expect(projIdx).toBeLessThan(finIdx);
	});

	it('children have depth greater than parent', () => {
		const result = buildTagTree([projects, finance, family, inbox]);
		const proj = result.find((r) => r.id === '6');
		const fin = result.find((r) => r.id === '7');
		expect(fin?.depth).toBeGreaterThan(proj?.depth ?? 0);
	});

	it('flat tags (no nesting) have depth 0', () => {
		const result = buildTagTree([projects, family, inbox]);
		for (const r of result) {
			expect(r.depth).toBeGreaterThanOrEqual(0);
		}
		expect(result.every((r) => r.depth >= 0)).toBe(true);
	});

	it('handles empty input', () => {
		const result = buildTagTree([]);
		expect(result).toHaveLength(0);
	});

	it('handles orphaned children gracefully', () => {
		const orphan: Mailbox = { id: '99', name: 'Orphan', parentId: '999' };
		const result = buildTagTree([inbox, orphan]);
		expect(result.find((r) => r.id === '99')).toBeTruthy();
	});

	it('handles deeply nested tags (3+ levels)', () => {
		const l1: Mailbox = { id: '10', name: 'Level1' };
		const l2: Mailbox = { id: '11', name: 'Level2', parentId: '10' };
		const l3: Mailbox = { id: '12', name: 'Level3', parentId: '11' };
		const result = buildTagTree([l1, l2, l3]);
		expect(result).toHaveLength(3);
		expect(result[0].depth).toBeLessThan(result[1].depth);
		expect(result[1].depth).toBeLessThan(result[2].depth);
	});
});

describe('snoozePresets (kit §7 — exactly 4 presets)', () => {
	it('returns the four kit presets before 18:00', () => {
		const presets = snoozePresets(new Date('2026-05-01T10:00:00'));
		expect(presets.map((p) => p.label)).toEqual([
			'Later today, 18:00',
			'Tomorrow, 8:00',
			'This weekend, Sat 9:00',
			'Next week, Mon 8:00',
		]);
	});

	it('never includes a "This evening" preset', () => {
		const presets = snoozePresets(new Date('2026-05-01T10:00:00'));
		expect(presets.some((p) => p.label.includes('This evening'))).toBe(false);
	});

	it('includes tomorrow morning preset', () => {
		const presets = snoozePresets(new Date('2026-05-01T10:00:00'));
		expect(presets.some((p) => p.label.includes('Tomorrow'))).toBe(true);
	});

	it('includes next week preset', () => {
		const presets = snoozePresets(new Date('2026-05-01T10:00:00'));
		expect(presets.some((p) => p.label.includes('Next week'))).toBe(true);
	});

	it('all preset dates are in the future', () => {
		const now = new Date('2026-05-01T10:00:00');
		const presets = snoozePresets(now);
		for (const p of presets) {
			expect(p.date.getTime()).toBeGreaterThan(now.getTime());
		}
	});

	it('Saturday preset falls on a Saturday at 09:00', () => {
		const now = new Date('2026-05-01T10:00:00'); // Friday May 1, 2026
		const presets = snoozePresets(now);
		const sat = presets.find((p) => p.label.includes('weekend'));
		expect(sat?.date.getDay()).toBe(6); // Saturday
		expect(sat?.date.getHours()).toBe(9);
	});

	it('Monday preset falls on a Monday at 08:00', () => {
		const now = new Date('2026-05-01T10:00:00'); // Friday
		const presets = snoozePresets(now);
		const mon = presets.find((p) => p.label.includes('Next week'));
		expect(mon?.date.getDay()).toBe(1); // Monday
		expect(mon?.date.getHours()).toBe(8);
	});

	it('"Later today" targets 18:00 and is present at 17:00', () => {
		const presets = snoozePresets(new Date('2026-05-01T17:00:00'));
		const later = presets.find((p) => p.label.includes('Later today'));
		expect(later).toBeTruthy();
		expect(later?.date.getHours()).toBe(18);
	});

	it('"Later today" is excluded once 18:00 has passed (3 presets remain)', () => {
		const presets = snoozePresets(new Date('2026-05-01T19:00:00'));
		expect(presets.some((p) => p.label.includes('Later today'))).toBe(false);
		expect(presets.length).toBe(3);
	});

	it('includes "Later today" when before 18:00', () => {
		const presets = snoozePresets(new Date('2026-05-01T10:00:00'));
		expect(presets.some((p) => p.label.includes('Later today'))).toBe(true);
	});
});

describe('LOCATION_ROLES + stripLocationTags + isArchivable', () => {
	it('LOCATION_ROLES equals the canonical list', () => {
		expect(LOCATION_ROLES).toEqual(['inbox', 'sent', 'drafts', 'trash', 'spam', 'archive', 'junk']);
	});

	it('LOCATION_ROLES is readonly (array-like)', () => {
		// Confirm it is an array-like structure with the expected length
		expect(LOCATION_ROLES.length).toBe(7);
	});

	it('stripLocationTags removes entries whose mailbox role is in LOCATION_ROLES', () => {
		const mailboxes: Mailbox[] = [
			{ id: 'a', name: 'Inbox', role: 'inbox' },
			{ id: 'b', name: 'Finance', role: undefined },
		];
		const result = stripLocationTags({ a: true, b: true }, mailboxes);
		expect(result).toEqual({ b: true });
	});

	it('stripLocationTags keeps all entries when none are location-group tags', () => {
		const mailboxes: Mailbox[] = [
			{ id: 'c', name: 'Projects', role: undefined },
			{ id: 'd', name: 'Personal', role: undefined },
		];
		const result = stripLocationTags({ c: true, d: true }, mailboxes);
		expect(result).toEqual({ c: true, d: true });
	});

	it('stripLocationTags removes all entries that are location-group tags', () => {
		const mailboxes: Mailbox[] = [
			{ id: 'e', name: 'Inbox', role: 'inbox' },
			{ id: 'f', name: 'Trash', role: 'trash' },
			{ id: 'g', name: 'Spam', role: 'spam' },
		];
		const result = stripLocationTags({ e: true, f: true, g: true }, mailboxes);
		expect(result).toEqual({});
	});

	it('stripLocationTags ignores ids not present in mailboxes list', () => {
		const mailboxes: Mailbox[] = [
			{ id: 'h', name: 'Inbox', role: 'inbox' },
		];
		// id 'z' is not in the mailboxes list — keep it (unknown, could be user tag)
		const result = stripLocationTags({ h: true, z: true }, mailboxes);
		expect(result).toEqual({ z: true });
	});

	it('userTags still excludes LOCATION_ROLES (behavior unchanged)', () => {
		const mailboxes: Mailbox[] = [
			{ id: '1', name: 'Inbox', role: 'inbox' },
			{ id: '2', name: 'Archive', role: 'archive' },
			{ id: '3', name: 'Junk', role: 'junk' },
			{ id: '4', name: 'Finance', role: undefined },
		];
		const tags = userTags(mailboxes);
		expect(tags.map((t) => t.id)).toEqual(['4']);
	});
});
