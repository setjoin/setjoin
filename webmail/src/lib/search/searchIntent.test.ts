import { describe, expect, it } from 'vitest';
import type { Mailbox } from '$lib/types/jmap';
import {
	buildSearchIntentPreview,
	compileSearchIntent,
	intentFromLocalLanguage,
	intentFromTypedSearch,
	SearchIntentError,
	tokenizeSearch,
	validateAssistIntent,
} from './searchIntent';

const mailboxes: Mailbox[] = [
	{ id: 'inbox', name: 'Inbox', role: 'inbox' },
	{ id: 'finance', name: 'Finance Team', role: undefined },
	{ id: 'projects', name: '项目', role: undefined },
];

describe('SearchIntent', () => {
	it('round-trips quoted typed syntax without dropping a constraint', () => {
		const intent = intentFromTypedSearch('from:alice subject:"quarterly report" in:"Finance Team" has:attachment', mailboxes);
		const raw = compileSearchIntent(intent, mailboxes);
		expect(raw).toBe('from:alice subject:"quarterly report" in:"Finance Team" has:attachment');
		expect(intent.filters).toHaveLength(4);
	});

	it('tokenizes spaces inside quoted operator values', () => {
		expect(tokenizeSearch('subject:"quarterly report" from:alice')).toEqual([
			'subject:"quarterly report"',
			'from:alice',
		]);
	});

	it('recognizes bounded English while preserving unrecognized text', () => {
		const preview = intentFromLocalLanguage('unread from alice with attachments urgent launch', mailboxes, 'en');
		expect(preview.recognizedNaturalLanguage).toBe(true);
		expect(preview.raw).toBe('has:attachment is:unread from:alice "urgent launch"');
	});

	it('recognizes bounded Chinese while preserving unrecognized text', () => {
		const preview = intentFromLocalLanguage('未读 来自 alice 有附件 合同', mailboxes, 'zh-CN');
		expect(preview.recognizedNaturalLanguage).toBe(true);
		expect(preview.raw).toBe('has:attachment is:unread from:alice 合同');
	});

	it('keeps unknown language as full text and never executes it implicitly', () => {
		const preview = buildSearchIntentPreview('something the grammar does not know', mailboxes, 'en');
		expect(preview.recognizedNaturalLanguage).toBe(false);
		expect(preview.intent.filters).toEqual([{ kind: 'text', value: 'something the grammar does not know' }]);
	});

	it('rejects an unknown mailbox rather than broadening the search', () => {
		expect(() => intentFromTypedSearch('in:Secret', mailboxes)).toThrowError(SearchIntentError);
		try { intentFromTypedSearch('in:Secret', mailboxes); } catch (error) {
			expect((error as SearchIntentError).code).toBe('unknown_mailbox');
		}
	});

	it('rejects impossible date ranges', () => {
		const intent = intentFromTypedSearch('after:2026-08-10 before:2026-08-01', mailboxes);
		expect(() => compileSearchIntent(intent, mailboxes)).toThrowError(SearchIntentError);
	});

	it('rejects malformed Assist JSON and locally validates an approved response', () => {
		expect(() => validateAssistIntent({ version: 2, filters: [] }, mailboxes)).toThrowError(SearchIntentError);
		expect(validateAssistIntent({
			version: 1,
			source: 'assist',
			confidence: 'exact',
			filters: [{ kind: 'mailbox', mailboxId: 'projects', label: '项目' }],
		}, mailboxes).confidence).toBe('review');
	});

	it('bounds control characters, filter count, query bytes and size inputs', () => {
		expect(() => intentFromTypedSearch('from:alice\u0000', mailboxes)).toThrowError(SearchIntentError);
		expect(() => compileSearchIntent({
			version: 1, source: 'typed', confidence: 'exact',
			filters: Array.from({ length: 33 }, (_, i) => ({ kind: 'text' as const, value: String(i) })),
		}, mailboxes)).toThrowError(SearchIntentError);
		expect(() => compileSearchIntent({
			version: 1, source: 'typed', confidence: 'exact', filters: [{ kind: 'size', op: 'larger', bytes: Number.MAX_SAFE_INTEGER }],
		}, mailboxes)).toThrowError(SearchIntentError);
	});

	it('property sweep preserves every generated typed constraint after canonicalization', () => {
		for (let i = 1; i <= 250; i += 1) {
			const raw = `from:user${i}@example.test subject:"case ${i}" ${i % 2 ? 'is:unread' : 'has:attachment'} larger:${i}K`;
			const first = intentFromTypedSearch(raw, mailboxes);
			const canonical = compileSearchIntent(first, mailboxes);
			const second = intentFromTypedSearch(canonical, mailboxes);
			expect(second.filters).toEqual(first.filters);
		}
	});

	it('never re-serializes operator-looking free text as an executable constraint', () => {
		// Canonicalization/reparse invariant: unknown `word:` tokens stay literal
		// text after a canonicalize→reparse round trip (narrowing-only).
		const intent = intentFromTypedSearch('older:7d', mailboxes);
		expect(intent.filters).toEqual([{ kind: 'text', value: 'older:7d' }]);
		const canonical = compileSearchIntent(intent, mailboxes);
		expect(canonical).toBe('"older:7d"');
		const reparsed = intentFromTypedSearch(canonical, mailboxes);
		expect(reparsed.filters).toEqual(intent.filters);
		expect(compileSearchIntent(reparsed, mailboxes)).toBe(canonical);
	});

	it('validates every Assist filter entry against the declared union (fail closed)', () => {
		// Unknown kind: rejected, never silently dropped into a broader query.
		expect(() => validateAssistIntent({
			version: 1, source: 'assist',
			filters: [{ kind: 'wat', value: 'x' }, { kind: 'text', value: 'hello' }],
		}, mailboxes)).toThrowError(SearchIntentError);
		// Mistyped field: SearchIntentError, not a raw TypeError.
		expect(() => validateAssistIntent({
			version: 1, source: 'assist',
			filters: [{ kind: 'from', value: 42 }],
		}, mailboxes)).toThrowError(SearchIntentError);
		// Out-of-domain keyword: rejected.
		expect(() => validateAssistIntent({
			version: 1, source: 'assist',
			filters: [{ kind: 'keyword', value: 'pinned' }],
		}, mailboxes)).toThrowError(SearchIntentError);
		// Out-of-range size: rejected.
		expect(() => validateAssistIntent({
			version: 1, source: 'assist',
			filters: [{ kind: 'size', op: 'larger', bytes: -1 }],
		}, mailboxes)).toThrowError(SearchIntentError);
		// Well-formed entries still validate.
		expect(validateAssistIntent({
			version: 1, source: 'assist',
			filters: [
				{ kind: 'text', value: 'hello' },
				{ kind: 'attachment', value: true },
				{ kind: 'size', op: 'larger', bytes: 1048576 },
				{ kind: 'received', op: 'after', value: '2026-01-01' },
			],
		}, mailboxes).filters).toHaveLength(4);
	});

	it('rejects a garbage-only Assist intent instead of canonicalizing to match-all', () => {
		expect(() => validateAssistIntent({ version: 1, source: 'assist', filters: [] }, mailboxes)).toThrowError(SearchIntentError);
		expect(() => validateAssistIntent({ version: 1, source: 'assist', filters: [{ kind: 'wat' }] }, mailboxes)).toThrowError(SearchIntentError);
	});
});
