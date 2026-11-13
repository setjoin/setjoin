import { describe, it, expect } from 'vitest';
import { computeListFilter, computeCounts, selectionFromUrl, isMonoBody, resendPrefill } from '$lib/stores/inboxModel';
import { parseSearch } from '$lib/stores/searchQuery';
import type { Mailbox, Email } from '$lib/types/jmap';

// ── Fixtures ──
function makeMailbox(id: string, overrides: Partial<Mailbox> = {}): Mailbox {
	return { id, name: id, ...overrides };
}

const MAILBOXES: Mailbox[] = [
	makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox', unreadEmails: 5 }),
	makeMailbox('mb-sent', { role: 'sent', name: 'Sent' }),
	makeMailbox('mb-drafts', { role: 'drafts', name: 'Drafts' }),
	makeMailbox('mb-trash', { role: 'trash', name: 'Trash' }),
	makeMailbox('mb-spam', { role: 'spam', name: 'Spam' }),
	makeMailbox('mb-snoozed', { name: 'Snoozed', totalEmails: 3 }),
	makeMailbox('mb-scheduled', { name: 'Scheduled' }),
	makeMailbox('mb-finance', { name: 'Finance', color: 'green' }),
];

describe('inbox coordinator — filter precedence', () => {
	it('tag filter wins over view (inbox with Finance tag selected)', () => {
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: 'mb-finance',
			mailboxes: MAILBOXES,
			searchFilter: {},
		});
		expect(result.inMailbox).toBe('mb-finance');
	});

	it('tag filter does NOT override trash view', () => {
		const result = computeListFilter({
			view: 'trash',
			tagFilter: 'mb-finance',
			mailboxes: MAILBOXES,
			searchFilter: {},
		});
		expect(result.inMailbox).toBe('mb-trash');
	});

	it('all view has no inMailbox restriction', () => {
		const result = computeListFilter({
			view: 'all',
			tagFilter: null,
			mailboxes: MAILBOXES,
			searchFilter: {},
		});
		expect(result.inMailbox).toBeUndefined();
	});

	it('snoozed view resolves to Snoozed mailbox', () => {
		const result = computeListFilter({
			view: 'snoozed',
			tagFilter: null,
			mailboxes: MAILBOXES,
			searchFilter: {},
		});
		expect(result.inMailbox).toBe('mb-snoozed');
	});

	it('scheduled view resolves to Scheduled mailbox', () => {
		const result = computeListFilter({
			view: 'scheduled',
			tagFilter: null,
			mailboxes: MAILBOXES,
			searchFilter: {},
		});
		expect(result.inMailbox).toBe('mb-scheduled');
	});

	it('search from: operator AND-merges with view filter', () => {
		const searchFilter = parseSearch('from:alice report', MAILBOXES);
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: MAILBOXES,
			searchFilter,
		});
		expect(result.inMailbox).toBe('mb-inbox');
		expect(result.from).toBe('alice');
		expect(result.text).toBe('report');
	});

	it('search tag: operator takes precedence over view', () => {
		const searchFilter = parseSearch('tag:Finance urgent', MAILBOXES);
		const result = computeListFilter({
			view: 'inbox',
			tagFilter: null,
			mailboxes: MAILBOXES,
			searchFilter,
		});
		expect(result.inMailbox).toBe('mb-finance');
		expect(result.text).toBe('urgent');
	});
});

describe('inbox coordinator — deep links', () => {
	it('selectionFromUrl returns first email of matched thread', () => {
		const threads = [{ id: 't1', emails: [{ id: 'e1' }, { id: 'e2' }], expanded: false, muted: false }];
		expect(selectionFromUrl(threads, 't1')).toEqual({ id: 'e1' });
	});

	it('selectionFromUrl returns null for unknown threadId', () => {
		const threads = [{ id: 't1', emails: [{ id: 'e1' }], expanded: false, muted: false }];
		expect(selectionFromUrl(threads, 't2')).toBeNull();
	});
});

describe('inbox coordinator — count rules (mail-kit §3)', () => {
	it('Snoozed badge shows totalEmails (not unread) from the Snoozed mailbox', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox', unreadEmails: 5 }),
			makeMailbox('mb-snoozed', { name: 'Snoozed', totalEmails: 4, unreadEmails: 1 }),
		];
		const result = computeCounts(mailboxes);
		// §3: Snoozed count must be total (4), not unread (1)
		expect(result.snoozedTotal).toBe(4);
		expect(result.inboxUnread).toBe(5);
	});

	it('Snoozed badge is zero when no Snoozed mailbox exists', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox' }),
		];
		const result = computeCounts(mailboxes);
		expect(result.snoozedTotal).toBe(0);
	});

	it('tagCounts includes only user-tag mailboxes (excludes location roles and system names)', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox('mb-inbox', { role: 'inbox', name: 'Inbox', totalEmails: 50 }),
			makeMailbox('mb-sent', { role: 'sent', name: 'Sent', totalEmails: 10 }),
			makeMailbox('mb-snoozed', { name: 'Snoozed', totalEmails: 4 }),
			makeMailbox('mb-scheduled', { name: 'Scheduled', totalEmails: 2 }),
			makeMailbox('mb-muted', { name: 'Muted', totalEmails: 1 }),
			makeMailbox('mb-finance', { name: 'Finance', color: 'green', totalEmails: 8 }),
		];
		const result = computeCounts(mailboxes);
		expect(result.tagCounts).toEqual({ 'mb-finance': 8 });
	});
});

describe('isMonoBody (machine-mail detection)', () => {
	function makeEmail(overrides: Partial<Email> = {}): Email {
		return { id: 'e1', mailboxIds: { mb1: true }, ...overrides };
	}

	it('returns false for a null email', () => {
		expect(isMonoBody(null)).toBe(false);
	});

	it('returns false for ordinary human mail', () => {
		expect(isMonoBody(makeEmail({ from: [{ email: 'alice@example.com' }] }))).toBe(false);
	});

	it('returns true when the backend flags the email as machine-generated', () => {
		expect(isMonoBody(makeEmail({ mono: true }))).toBe(true);
	});

	it('returns true for a monitoring/no-reply sender heuristic', () => {
		expect(isMonoBody(makeEmail({ from: [{ email: 'alerts@monitoring.example.com' }] }))).toBe(true);
		expect(isMonoBody(makeEmail({ from: [{ email: 'no-reply@ci.example.com' }] }))).toBe(true);
	});
});

describe('parseSearch integration', () => {
	it('tag: operator resolves case-insensitively', () => {
		const result = parseSearch('tag:FINANCE', MAILBOXES);
		expect(result.inMailbox).toBe('mb-finance');
	});

	it('tag: operator returns sentinel for unknown tag', () => {
		const result = parseSearch('tag:Nonexistent', MAILBOXES);
		expect(result.inMailbox).toBe('__no_match__');
	});

	it('empty query returns empty filter', () => {
		const result = parseSearch('', MAILBOXES);
		expect(result).toEqual({});
	});
});

describe('resendPrefill (resend after NDR)', () => {
	const bounced: Email = {
		id: 'bounced-1',
		mailboxIds: { 'mb-sent': true },
		subject: 'Q3 report',
		to: [{ email: 'bob@bigcorp.com' }, { name: 'Carol', email: 'carol@x.com' }],
		cc: [{ email: 'cc@x.com' }],
		bcc: [{ email: 'bcc@x.com' }],
		bodyHTML: '<p>see attached</p>',
		bodyText: 'see attached',
	};

	it('seeds recipients + subject (no prefix) + body, and carries NO id (fresh submission)', () => {
		const opts = resendPrefill(bounced);
		expect(opts.to).toBe('bob@bigcorp.com, carol@x.com');
		expect(opts.cc).toBe('cc@x.com');
		expect(opts.bcc).toBe('bcc@x.com');
		// original subject verbatim — never a Re:/Fwd: prefix
		expect(opts.subject).toBe('Q3 report');
		// HTML body preferred over text
		expect(opts.body).toBe('<p>see attached</p>');
		// must not reuse the bounced queue row's id / Message-ID
		expect(opts).not.toHaveProperty('replyTo');
		expect(opts).not.toHaveProperty('draftId');
		expect(opts).not.toHaveProperty('id');
	});

	it('falls back to bodyText when no HTML, and tolerates missing cc/bcc', () => {
		const opts = resendPrefill({ id: 'x', mailboxIds: {}, subject: 'Hi', to: [{ email: 'a@x.com' }], bodyText: 'plain' });
		expect(opts.body).toBe('plain');
		expect(opts.cc).toBe('');
		expect(opts.bcc).toBe('');
	});
});
