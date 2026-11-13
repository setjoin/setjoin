import { describe, it, expect } from 'vitest';
import {
	computeListFilter,
	computeCounts,
	resolveViewMailbox,
	selectionFromUrl,
	replyAllRecipients,
} from './inboxModel';
import type { Email, Mailbox } from '$lib/types/jmap';
import type { ViewId } from '$lib/components/mail/MailSidebar.svelte';

function makeMailbox(id: string, overrides: Partial<Mailbox> = {}): Mailbox {
	return { id, name: id, ...overrides };
}

const FIXTURE: Mailbox[] = [
	makeMailbox('mb1', { role: 'inbox', name: 'Inbox' }),
	makeMailbox('mb2', { role: 'sent', name: 'Sent' }),
	makeMailbox('mb3', { role: 'drafts', name: 'Drafts' }),
	makeMailbox('mb4', { role: 'trash', name: 'Trash' }),
	makeMailbox('mb5', { role: 'spam', name: 'Spam' }),
	makeMailbox('mb6', { name: 'Snoozed' }),
	makeMailbox('mb7', { name: 'Scheduled' }),
	makeMailbox('mb8', { name: 'Finance', color: 'green' }),
	makeMailbox('mb9', { name: 'Work', parentId: 'mb8', color: 'amber' }),
];

describe('resolveViewMailbox', () => {
	it('maps inbox to role=inbox mailbox', () => {
		const mb = resolveViewMailbox('inbox', FIXTURE);
		expect(mb?.id).toBe('mb1');
	});

	it('maps sent to role=sent mailbox', () => {
		const mb = resolveViewMailbox('sent', FIXTURE);
		expect(mb?.id).toBe('mb2');
	});

	it('maps drafts to role=drafts mailbox', () => {
		const mb = resolveViewMailbox('drafts', FIXTURE);
		expect(mb?.id).toBe('mb3');
	});

	it('maps trash to role=trash mailbox', () => {
		const mb = resolveViewMailbox('trash', FIXTURE);
		expect(mb?.id).toBe('mb4');
	});

	it('maps snoozed to name=Snoozed mailbox', () => {
		const mb = resolveViewMailbox('snoozed', FIXTURE);
		expect(mb?.id).toBe('mb6');
	});

	it('maps scheduled to name=Scheduled mailbox', () => {
		const mb = resolveViewMailbox('scheduled', FIXTURE);
		expect(mb?.id).toBe('mb7');
	});

	it('returns null for all view', () => {
		expect(resolveViewMailbox('all', FIXTURE)).toBeNull();
	});

	it('returns null when mailbox not found', () => {
		expect(resolveViewMailbox('inbox', [])).toBeNull();
	});
});

describe('computeListFilter', () => {
	it('view=inbox with no tagFilter → inMailbox of inbox role', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result).toEqual({ inMailbox: 'mb1' });
	});

	it('view=all with no tagFilter → no inMailbox', () => {
		const result = computeListFilter({
			view: 'all',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result.inMailbox).toBeUndefined();
	});

	it('tagFilter wins over view (inbox)', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: 'mb8',
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result).toEqual({ inMailbox: 'mb8' });
	});

	it('tagFilter does NOT win over trash view', () => {
		const result = computeListFilter({
			view: 'trash',
			tagFilter: 'mb8',
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result).toEqual({ inMailbox: 'mb4' });
	});

	it('snoozed view resolves to Snoozed mailbox', () => {
		const result = computeListFilter({
			view: 'snoozed',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result).toEqual({ inMailbox: 'mb6' });
	});

	it('scheduled view resolves to Scheduled mailbox', () => {
		const result = computeListFilter({
			view: 'scheduled',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result).toEqual({ inMailbox: 'mb7' });
	});

	it('AND-merges text from searchFilter', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: { text: 'quarterly report' },
		});
		expect(result).toEqual({ inMailbox: 'mb1', text: 'quarterly report' });
	});

	it('AND-merges from from searchFilter', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: { from: 'mark' },
		});
		expect(result).toEqual({ inMailbox: 'mb1', from: 'mark' });
	});

	it('searchFilter inMailbox (tag: operator) takes precedence over view', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: { inMailbox: 'mb8', text: 'report' },
		});
		expect(result).toEqual({ inMailbox: 'mb8', text: 'report' });
	});

	it('empty search returns only inMailbox', () => {
		const result = computeListFilter({
			view: 'drafts',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result).toEqual({ inMailbox: 'mb3' });
	});

	it('all view with text search → no inMailbox, only text', () => {
		const result = computeListFilter({
			view: 'all',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: { text: 'hello' },
		});
		expect(result).toEqual({ text: 'hello' });
	});

	// ── Focused/Other split (V078) ──
	it('plain inbox + focusTab=other → adds focus:other', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
			focusTab: 'other',
		});
		expect(result).toEqual({ inMailbox: 'mb1', focus: 'other' });
	});

	it('plain inbox + focusTab=focused → adds focus:focused (default hides Other pile)', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
			focusTab: 'focused',
		});
		expect(result).toEqual({ inMailbox: 'mb1', focus: 'focused' });
	});

	it('inbox with no focusTab → no focus key (backward compatible)', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: {},
		});
		expect(result).toEqual({ inMailbox: 'mb1' });
	});

	it('does NOT add focus to a tag-filtered inbox', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: 'mb8',
			mailboxes: FIXTURE,
			searchFilter: {},
			focusTab: 'other',
		});
		expect(result).toEqual({ inMailbox: 'mb8' });
	});

	it('does NOT add focus to a search (text) within inbox', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: { text: 'report' },
			focusTab: 'other',
		});
		expect(result).toEqual({ inMailbox: 'mb1', text: 'report' });
	});

	it('does NOT add focus to a search tag: operator (inMailbox)', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: { inMailbox: 'mb8' },
			focusTab: 'other',
		});
		expect(result).toEqual({ inMailbox: 'mb8' });
	});

	it('does NOT add focus to archive/trash/sent views', () => {
		expect(
			computeListFilter({ view: 'archive', tagFilter: null, mailboxes: FIXTURE, searchFilter: {}, focusTab: 'other' }),
		).toEqual({ inArchive: true });
		expect(
			computeListFilter({ view: 'trash', tagFilter: null, mailboxes: FIXTURE, searchFilter: {}, focusTab: 'other' }),
		).toEqual({ inMailbox: 'mb4' });
		expect(
			computeListFilter({ view: 'sent', tagFilter: null, mailboxes: FIXTURE, searchFilter: {}, focusTab: 'other' }),
		).toEqual({ inMailbox: 'mb2' });
	});
});

describe('computeCounts', () => {
	it('inboxUnread from Inbox mailbox unreadEmails', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox', unreadEmails: 7 }),
		];
		const result = computeCounts(mailboxes);
		expect(result.inboxUnread).toBe(7);
	});

	it('snoozedTotal from Snoozed mailbox totalEmails (total, not unread)', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-snoozed', { name: 'Snoozed', totalEmails: 4, unreadEmails: 1 }),
		];
		const result = computeCounts(mailboxes);
		// §3: Snoozed badge shows totalEmails, NOT unreadEmails
		expect(result.snoozedTotal).toBe(4);
	});

	it('snoozedTotal is 0 when Snoozed mailbox not found', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox' }),
		];
		const result = computeCounts(mailboxes);
		expect(result.snoozedTotal).toBe(0);
	});

	it('inboxUnread is 0 when Inbox mailbox not found', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-other', { name: 'Other' }),
		];
		const result = computeCounts(mailboxes);
		expect(result.inboxUnread).toBe(0);
	});

	it('tagCounts maps tag mailbox id to totalEmails for non-location mailboxes', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox', totalEmails: 50 }),
			makeMailbox('mb-finance', { name: 'Finance', color: 'green', totalEmails: 12 }),
			makeMailbox('mb-work', { name: 'Work', color: 'amber', totalEmails: 3 }),
			makeMailbox('mb-snoozed', { name: 'Snoozed', totalEmails: 4 }),
		];
		const result = computeCounts(mailboxes);
		expect(result.tagCounts).toEqual({
			'mb-finance': 12,
			'mb-work': 3,
		});
	});

	it('tagCounts excludes location-role mailboxes and system-named mailboxes', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox', totalEmails: 50 }),
			makeMailbox('mb-sent', { role: 'sent', name: 'Sent', totalEmails: 10 }),
			makeMailbox('mb-trash', { role: 'trash', name: 'Trash', totalEmails: 5 }),
			makeMailbox('mb-snoozed', { name: 'Snoozed', totalEmails: 4 }),
			makeMailbox('mb-scheduled', { name: 'Scheduled', totalEmails: 2 }),
			makeMailbox('mb-muted', { name: 'Muted', totalEmails: 1 }),
			makeMailbox('mb-other', { name: 'Other', totalEmails: 9 }),
			makeMailbox('mb-finance', { name: 'Finance', color: 'green', totalEmails: 8 }),
		];
		const result = computeCounts(mailboxes);
		// Only user tags (Finance) should appear in tagCounts — the Other split pile (V078)
		// is surfaced via the list tabs, never as a sidebar count.
		expect(result.tagCounts).toEqual({
			'mb-finance': 8,
		});
	});

	it('returns zeros and empty tagCounts for empty mailboxes', () => {
		const result = computeCounts([]);
		expect(result).toEqual({
			inboxUnread: 0,
			snoozedTotal: 0,
			tagCounts: {},
		});
	});
});

describe('selectionFromUrl', () => {
	it('returns first email of matched thread', () => {
		const threads = [{ id: 't1', emails: [{ id: 'e1' }, { id: 'e2' }], expanded: false, muted: false }];
		expect(selectionFromUrl(threads, 't1')).toEqual({ id: 'e1' });
	});

	it('returns null for unknown threadId', () => {
		const threads = [{ id: 't1', emails: [{ id: 'e1' }], expanded: false, muted: false }];
		expect(selectionFromUrl(threads, 't2')).toBeNull();
	});

	it('returns null for empty thread emails', () => {
		const threads = [{ id: 't1', emails: [], expanded: false, muted: false }];
		expect(selectionFromUrl(threads, 't1')).toBeNull();
	});

	it('resolves a message id inside a thread to that exact email (task linkage deep link)', () => {
		const threads = [
			{ id: 't1', emails: [{ id: 'e1' }, { id: 'e2' }], expanded: false, muted: false },
			{ id: 't2', emails: [{ id: 'e3' }], expanded: false, muted: false },
		];
		expect(selectionFromUrl(threads, 'e2')).toEqual({ id: 'e2' });
		expect(selectionFromUrl(threads, 'e3')).toEqual({ id: 'e3' });
	});

	it('prefers an exact thread-id match over a same-valued email id', () => {
		const threads = [
			{ id: 'x', emails: [{ id: 'e1' }], expanded: false, muted: false },
			{ id: 't9', emails: [{ id: 'x' }], expanded: false, muted: false },
		];
		expect(selectionFromUrl(threads, 'x')).toEqual({ id: 'e1' });
	});
});

describe('replyAllRecipients (A2)', () => {
	const base: Email = {
		id: '1',
		threadId: 't1',
		mailboxIds: {},
		from: [{ email: 'alice@example.com', name: 'Alice' }],
		to: [{ email: 'me@example.com' }, { email: 'bob@example.com' }],
		cc: [{ email: 'carol@example.com' }],
	};

	it('puts the original sender in To', () => {
		const r = replyAllRecipients(base, 'me@example.com');
		expect(r.to).toEqual(['alice@example.com']);
	});

	it('moves other original recipients to Cc and drops self', () => {
		const r = replyAllRecipients(base, 'me@example.com');
		expect(r.cc.sort()).toEqual(['bob@example.com', 'carol@example.com']);
		expect(r.cc).not.toContain('me@example.com');
		expect(r.to).not.toContain('me@example.com');
	});

	it('dedupes and is case-insensitive on self', () => {
		const r = replyAllRecipients(
			{ ...base, cc: [{ email: 'bob@example.com' }, { email: 'ME@example.com' }] },
			'me@example.com',
		);
		expect(r.cc).toEqual(['bob@example.com']);
	});

	it('returns empty To when there is no sender', () => {
		const r = replyAllRecipients({ ...base, from: [] }, 'me@example.com');
		expect(r.to).toEqual([]);
	});
});

describe('computeListFilter — Archive view (A2)', () => {
	it('emits inArchive for the archive view and no inMailbox', () => {
		const f = computeListFilter({ view: 'archive', tagFilter: null, mailboxes: [], searchFilter: {} });
		expect(f.inArchive).toBe(true);
		expect(f.inMailbox).toBeUndefined();
	});

	it('a sidebar tag filter overrides the archive view', () => {
		const f = computeListFilter({ view: 'archive', tagFilter: 'mb8', mailboxes: FIXTURE, searchFilter: {} });
		expect(f.inArchive).toBeUndefined();
		expect(f.inMailbox).toBe('mb8');
	});

	it('a search tag: operator overrides the archive view', () => {
		const f = computeListFilter({ view: 'archive', tagFilter: null, mailboxes: FIXTURE, searchFilter: { inMailbox: 'mb8' } });
		expect(f.inArchive).toBeUndefined();
		expect(f.inMailbox).toBe('mb8');
	});

	it('non-archive views never set inArchive', () => {
		const f = computeListFilter({ view: 'inbox', tagFilter: null, mailboxes: FIXTURE, searchFilter: {} });
		expect(f.inArchive).toBeUndefined();
	});
});

describe('computeListFilter — Starred view', () => {
	it('emits hasKeyword=$flagged and no inMailbox', () => {
		const f = computeListFilter({ view: 'starred', tagFilter: null, mailboxes: FIXTURE, searchFilter: {} });
		expect(f).toEqual({ hasKeyword: '$flagged' });
	});

	it('an explicit search hasKeyword overrides the starred default', () => {
		const f = computeListFilter({
			view: 'starred',
			tagFilter: null,
			mailboxes: FIXTURE,
			searchFilter: { hasKeyword: '$unseen' },
		});
		expect(f).toEqual({ hasKeyword: '$unseen' });
	});

	it('a sidebar tag filter overrides the starred view', () => {
		const f = computeListFilter({ view: 'starred', tagFilter: 'mb8', mailboxes: FIXTURE, searchFilter: {} });
		expect(f.hasKeyword).toBeUndefined();
		expect(f.inMailbox).toBe('mb8');
	});
});

describe('resolveViewMailbox — Archive (A2)', () => {
	it('archive resolves to no backing mailbox', () => {
		expect(resolveViewMailbox('archive', FIXTURE)).toBeNull();
	});
});
