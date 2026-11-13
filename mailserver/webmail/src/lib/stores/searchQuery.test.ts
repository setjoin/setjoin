import { describe, it, expect } from 'vitest';
import { parseSearch } from './searchQuery';
import type { Mailbox } from '$lib/types/jmap';

const mboxes: Mailbox[] = [
	{ id: 'mb1', name: 'Inbox', role: 'inbox' },
	{ id: 'mb2', name: 'Sent', role: 'sent' },
	{ id: 'mb9', name: 'Finance', role: undefined },
	{ id: 'mb10', name: 'Projects', role: undefined },
];

describe('parseSearch', () => {
	it('empty string returns empty filter', () => {
		expect(parseSearch('', mboxes)).toEqual({});
	});

	it('whitespace-only string returns empty filter', () => {
		expect(parseSearch('   ', mboxes)).toEqual({});
	});

	it('bare text becomes text filter', () => {
		expect(parseSearch('quarterly report', mboxes)).toEqual({ text: 'quarterly report' });
	});

	it('from: operator becomes from filter', () => {
		expect(parseSearch('from:mark', mboxes)).toEqual({ from: 'mark' });
	});

	it('tag: operator resolved case-insensitively to inMailbox id', () => {
		expect(parseSearch('tag:finance', mboxes)).toEqual({ inMailbox: 'mb9' });
	});

	it('tag: operator is case-insensitive (uppercase)', () => {
		expect(parseSearch('tag:Finance', mboxes)).toEqual({ inMailbox: 'mb9' });
	});

	it('tag: unknown name uses sentinel __no_match__', () => {
		expect(parseSearch('tag:Nonexistent', mboxes)).toEqual({ inMailbox: '__no_match__' });
	});

	it('from: + bare text: operator extracted, remaining words joined', () => {
		expect(parseSearch('from:mark urgent deploy', mboxes)).toEqual({
			from: 'mark',
			text: 'urgent deploy',
		});
	});

	it('tag: + from: combined', () => {
		expect(parseSearch('tag:finance from:mark', mboxes)).toEqual({
			inMailbox: 'mb9',
			from: 'mark',
		});
	});

	it('bare text with multiple words joined with single space', () => {
		expect(parseSearch('hello   world', mboxes)).toEqual({ text: 'hello world' });
	});

	it('from: operator is case-insensitive', () => {
		expect(parseSearch('FROM:alice', mboxes)).toEqual({ from: 'alice' });
	});

	it('single bare word becomes text filter', () => {
		expect(parseSearch('hello', mboxes)).toEqual({ text: 'hello' });
	});

	it('tag: + from: + bare text together', () => {
		expect(parseSearch('tag:projects from:alice meeting notes', mboxes)).toEqual({
			inMailbox: 'mb10',
			from: 'alice',
			text: 'meeting notes',
		});
	});

	it('tag: operator does not resolve system mailbox names', () => {
		// "Inbox" has a role='inbox', should still resolve by name lookup
		expect(parseSearch('tag:inbox', mboxes)).toEqual({ inMailbox: 'mb1' });
	});

	// ── rich search operators ──────────────────────────────────────────────
	it('has:attachment → hasAttachment true', () => {
		expect(parseSearch('has:attachment', mboxes)).toEqual({ hasAttachment: true });
	});

	it('is:unread maps to $unseen keyword; remaining words are text', () => {
		expect(parseSearch('is:unread report', mboxes)).toEqual({
			hasKeyword: '$unseen',
			text: 'report',
		});
	});

	it('is:starred → $flagged; is:read → $seen', () => {
		expect(parseSearch('is:starred', mboxes)).toEqual({ hasKeyword: '$flagged' });
		expect(parseSearch('is:read', mboxes)).toEqual({ hasKeyword: '$seen' });
	});

	it('to:/cc:/bcc:/subject: pass through as substring filters', () => {
		expect(parseSearch('to:bob cc:carol bcc:dan subject:invoice', mboxes)).toEqual({
			to: 'bob',
			cc: 'carol',
			bcc: 'dan',
			subject: 'invoice',
		});
	});

	it('before: passes an absolute date; larger: parses to 1024-based bytes', () => {
		expect(parseSearch('before:2026-01-01 larger:5M', mboxes)).toEqual({
			before: '2026-01-01',
			minSize: 5 * 1024 * 1024,
		});
	});

	it('smaller: → maxSize; size: → minSize', () => {
		expect(parseSearch('smaller:500K', mboxes)).toEqual({ maxSize: 500 * 1024 });
		expect(parseSearch('size:2G', mboxes)).toEqual({ minSize: 2 * 1024 ** 3 });
	});

	it('in:/label: are aliases of tag:', () => {
		expect(parseSearch('in:finance', mboxes)).toEqual({ inMailbox: 'mb9' });
		expect(parseSearch('label:Projects', mboxes)).toEqual({ inMailbox: 'mb10' });
	});

	it('full stack: tag: + from: + subject: + quoted phrase text', () => {
		expect(parseSearch('tag:finance from:mark subject:invoice "exact phrase"', mboxes)).toEqual({
			inMailbox: 'mb9',
			from: 'mark',
			subject: 'invoice',
			text: '"exact phrase"',
		});
	});

	it('preserves quoted operator values with spaces', () => {
		expect(parseSearch('subject:"quarterly report" in:"Finance"', mboxes)).toEqual({
			subject: 'quarterly report',
			inMailbox: 'mb9',
		});
	});

	it('unknown operator is kept as text, not dropped', () => {
		expect(parseSearch('foo:bar hello', mboxes)).toEqual({ text: 'foo:bar hello' });
	});
});
