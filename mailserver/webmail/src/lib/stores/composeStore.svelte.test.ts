import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Mailbox } from '$lib/types/jmap';
import { ComposeStore, MAX_ATTACH_BYTES, INLINE_IMAGE_TYPES, SubmissionMarkerError, type EditorHandle } from './composeStore.svelte';
import { galSearch, loadSession, sha256Hex, putBlob, emailGet } from '$lib/jmap/client';
import { emailSet, emailSubmissionSet } from '$lib/jmap/offline-client';
import { mailDraftOpen, mailDraftReplace } from '$lib/mail/mailDraft';
import { contactGroups, expandGroup } from '$lib/stores/contactGroups';
import { recordSend, removeRecipient, suggestRecipients } from '$lib/utils/contactRanking';

// The store's upload path (WAVE-5 #3) hashes then PUTs through the client seam;
// mock both so the transitions are controllable. Other client exports the store
// touches stay inert stubs.
vi.mock('$lib/jmap/client', () => ({
	galSearch: vi.fn(async () => []),
	loadSession: vi.fn(async () => ({})),
	sha256Hex: vi.fn(async () => 'sha-default'),
	putBlob: vi.fn(async () => undefined),
	emailGet: vi.fn(async () => [])
}));

vi.mock('$lib/mail/mailDraft', () => ({
	mailDraftOpen: vi.fn(),
	mailDraftReplace: vi.fn(),
}));

vi.mock('$lib/jmap/offline-client', () => ({
	emailSet: vi.fn(),
	emailSubmissionSet: vi.fn(),
}));

vi.mock('$lib/stores/contactGroups', async () => {
	const { writable } = await import('svelte/store');
	return { contactGroups: writable([]), expandGroup: vi.fn() };
});

vi.mock('$lib/utils/contactRanking', () => ({
	suggestRecipients: vi.fn(() => []),
	removeRecipient: vi.fn(),
	recordSend: vi.fn(),
}));

const MAILBOXES: Mailbox[] = [
	{ id: 'mb-drafts', name: 'Drafts', role: 'drafts' },
	{ id: 'mb-sent', name: 'Sent', role: 'sent' },
];

/** Minimal editor stand-in — the store reads body content through this seam. */
function editor(html: string, text: string): EditorHandle {
	return { getHTML: () => html, getText: () => text };
}

describe('ComposeStore.parseAddrList', () => {
	it('parses "Name <email>" and bare addresses, trimming and dropping blanks', () => {
		const c = new ComposeStore();
		expect(c.parseAddrList('Alice <a@x.test>, b@y.test , ')).toEqual([
			{ name: 'Alice', email: 'a@x.test' },
			{ email: 'b@y.test' },
		]);
	});
});

describe('ComposeStore mailbox lookups', () => {
	it('resolves the drafts + sent mailbox ids from `mailboxes`', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		expect(c.getDraftsId()).toBe('mb-drafts');
		expect(c.getSentId()).toBe('mb-sent');
	});

	it('does not select a delegated system folder for personal compose', () => {
		const c = new ComposeStore();
		c.mailboxes = [
			{ id: 'delegated-drafts', name: 'Drafts', role: 'drafts', myRights: { maySubmit: true } },
			{ id: 'own-drafts', name: 'Drafts', role: 'drafts', myRights: { maySubmit: null } },
			{ id: 'delegated-sent', name: 'Sent', role: 'sent', myRights: { maySubmit: true } },
			{ id: 'own-sent', name: 'Sent', role: 'sent', myRights: { maySubmit: null } },
		];

		expect(c.getDraftsId()).toBe('own-drafts');
		expect(c.getSentId()).toBe('own-sent');
	});

	it('selects the send-capable delegated system folder in shared compose', () => {
		const c = new ComposeStore();
		c.sharedAccountId = 'shared-account';
		c.mailboxes = [
			{ id: 'own-drafts', name: 'Drafts', role: 'drafts', myRights: { maySubmit: null } },
			{ id: 'shared-drafts', name: 'Drafts', role: 'drafts', myRights: { maySubmit: true } },
			{ id: 'own-sent', name: 'Sent', role: 'sent', myRights: { maySubmit: null } },
			{ id: 'shared-sent', name: 'Sent', role: 'sent', myRights: { maySubmit: true } },
		];

		expect(c.getDraftsId()).toBe('shared-drafts');
		expect(c.getSentId()).toBe('shared-sent');
	});
});

describe('ComposeStore.attachmentBytes', () => {
	it('sums the staged attachment sizes', () => {
		const c = new ComposeStore();
		c.attachments = [
			{ name: 'a', size: 10, blobId: 'b1', type: 't' },
			{ name: 'b', size: 32, blobId: 'b2', type: 't' },
		];
		expect(c.attachmentBytes).toBe(42);
	});
});

describe('ComposeStore.resetOwnedState', () => {
	it('clears only store-owned draft state and preserves identity/signature configuration', () => {
		const c = new ComposeStore();
		c.fromEmail = 'sender@example.test';
		c.signatures = [{ id: 1, alias_email: '', signature_html: '<p>sig</p>', signature_text: 'sig', is_default: true, default_for: 'both' }];
		c.selectedSignatureId = 1;
		c.to = 'recipient@example.test';
		c.subject = 'subject';
		c.bodyHtml = '<p>body</p>';
		c.attachments = [{ name: 'a.txt', size: 1, blobId: 'sha', type: 'text/plain' }];
		c.editingDraftId = 'draft-1';
		c.sharedAccountId = 'shared-1';
		c.scheduledAt = '2026-08-13T12:00:00Z';

		c.resetOwnedState();

		expect(c).toMatchObject({
			to: '', subject: '', bodyHtml: '', attachments: [], editingDraftId: null,
			sharedAccountId: null, scheduledAt: '', priority: 'normal', voteOptions: ['']
		});
		expect(c.fromEmail).toBe('sender@example.test');
		expect(c.selectedSignatureId).toBe(1);
		expect(c.signatures).toHaveLength(1);
	});

	it('drops stale draft hydration after the user edits and isolates store instances', () => {
		const first = new ComposeStore();
		const second = new ComposeStore();
		first.subject = 'before';
		second.subject = 'other window';

		const firstTicket = first.beginHydration();
		const secondTicket = second.beginHydration();
		first.subject = 'typed while loading';

		expect(first.canApplyHydration(firstTicket)).toBe(false);
		expect(second.canApplyHydration(secondTicket)).toBe(true);
	});

	it('allows background From changes but explicitly invalidates for user From intent and delayed view hydration', () => {
		const c = new ComposeStore();
		c.fromEmail = 'first@example.test';
		const staleFromTicket = c.beginHydration();
		c.fromEmail = 'chosen@example.test';
		// Background From initialization/correction is allowed; the view calls the
		// explicit invalidator only for a user selector change.
		expect(c.canApplyHydration(staleFromTicket)).toBe(true);
		c.invalidateHydration();
		expect(c.canApplyHydration(staleFromTicket)).toBe(false);

		const current = c.beginHydration();
		const applied = c.applyHydration(current, () => {
			c.subject = 'loaded draft';
			c.bodyHtml = '<p>loaded</p>';
		});
		expect(applied).not.toBeNull();
		expect(c.canApplyHydration(applied!)).toBe(true);

		c.subject = 'typed before editor tick';
		expect(c.canApplyHydration(applied!)).toBe(false);
	});

	it('invalidates an outstanding hydration when owned state resets', () => {
		const c = new ComposeStore();
		const ticket = c.beginHydration();
		c.resetOwnedState();
		expect(c.canApplyHydration(ticket)).toBe(false);
	});

	it('does not clear draft state on a failed submission', async () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'recipient@example.test';
		c.subject = 'keep me';
		c.bodyText = 'keep body';
		vi.mocked(loadSession).mockResolvedValueOnce({} as never);
		vi.mocked(emailSet).mockResolvedValueOnce({ created: { 'email-1': { id: 'staged-1' } } } as never);
		vi.mocked(emailSubmissionSet).mockRejectedValueOnce(new Error('send failed'));
		vi.mocked(emailSet).mockResolvedValue({} as never);

		await expect(c.createAndSubmit(null, 'sender@example.test', 'now', 10)).rejects.toThrow('send failed');
		expect(c.to).toBe('recipient@example.test');
		expect(c.subject).toBe('keep me');
		expect(c.bodyText).toBe('keep body');
	});
});

// Machine guard (C2): buildMsg's outbound HTML MUST route through the pinned
// sanitizeOutboundHTML profile, not the bare inbound-default sanitizeHTML —
// a source-level check so a future edit that reintroduces the bare call fails
// CI even if it happens to pass the behavioral test above by luck.
describe('ComposeStore source — outbound sanitize profile invariant', () => {
	it('imports sanitizeOutboundHTML, not the bare inbound sanitizeHTML, from $lib/sanitize', () => {
		const path = fileURLToPath(new URL('./composeStore.svelte.ts', String(import.meta.url)));
		const src = readFileSync(path, 'utf-8');
		expect(src).toMatch(/import\s*\{\s*sanitizeOutboundHTML\s*\}\s*from\s*'\$lib\/sanitize'/);
		expect(src).not.toMatch(/\bsanitizeHTML\s*\(/);
	});
});

describe('ComposeStore.buildMsg', () => {
	it('builds a JMAP Email/set create object from the draft fields (representative draft)', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.fromEmail = 'me@corp.test';
		c.to = 'Alice <a@x.test>, b@y.test';
		c.cc = 'c@z.test';
		c.replyTo = 'reply@corp.test';
		c.subject = 'Hi there';
		c.priority = 'high';
		c.readReceipt = true;
		c.bodyText = 'plain body';
		c.bodyHtml = '<p>rich body</p>';

		// A stale editor handle is passed but must be ignored — cached body wins.
		const msg = c.buildMsg(editor('<p>ignored</p>', 'ignored'), 'fallback@corp.test');

		expect(msg.from).toEqual([{ email: 'me@corp.test' }]);
		expect(msg.to).toEqual([{ name: 'Alice', email: 'a@x.test' }, { email: 'b@y.test' }]);
		expect(msg.cc).toEqual([{ email: 'c@z.test' }]);
		expect(msg.replyTo).toEqual([{ email: 'reply@corp.test' }]);
		expect(msg.subject).toBe('Hi there');
		expect(msg.priority).toBe(1);
		expect(msg.readReceiptRequested).toBe(true);
		expect(msg.mailboxIds).toEqual({ 'mb-drafts': true });
		const bv = msg.bodyValues as Record<string, { value: string }>;
		expect(bv.text.value).toBe('plain body');
		expect(bv.html.value).toContain('rich body');
	});

	// C2 regression guard: buildMsg's outbound sanitize pass must NOT reuse the
	// inbound display sanitizer's allowRemoteImages=false default — that silently
	// drops every remote <img> the user inserted into the compose body, while
	// still stripping actual XSS vectors (script/handler).
	it('keeps a user-inserted remote <img> in the outbound HTML (still strips scripts/handlers)', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.subject = 'Hi';
		c.bodyText = 'text';
		c.bodyHtml = '<p>look <img src="https://example.com/photo.png"> <script>alert(1)</script><div onclick="bad()">click</div></p>';

		const bv = c.buildMsg(null).bodyValues as Record<string, { value: string }>;
		expect(bv.html.value).toContain('<img src="https://example.com/photo.png">');
		expect(bv.html.value).not.toContain('<script');
		expect(bv.html.value).not.toContain('onclick');
	});

	it('drops the HTML body part when plainTextOnly is set', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.subject = 'Hi';
		c.bodyText = 'text';
		c.bodyHtml = '<p>rich</p>';
		c.plainTextOnly = true;

		const bv = c.buildMsg(null).bodyValues as Record<string, unknown>;
		expect(bv.text).toBeDefined();
		expect(bv.html).toBeUndefined();
	});

	it('reads body content through the editor handle when the cached body is empty', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.subject = 'Hi';
		// bodyText/bodyHtml empty → falls back to the passed-in editor seam.
		const bv = c.buildMsg(editor('<p>from editor</p>', 'from editor'))
			.bodyValues as Record<string, { value: string }>;
		expect(bv.text.value).toBe('from editor');
		expect(bv.html.value).toContain('from editor');
	});

	it('falls back to `unknown@unknown` when neither fromEmail nor userEmail is set', () => {
		const c = new ComposeStore();
		c.to = 'a@x.test';
		expect(c.buildMsg(null)).toMatchObject({ from: [{ email: 'unknown@unknown' }], mailboxIds: {} });
	});

	// Regression guard (e2e caught it): buildMsg MUST carry staged attachments into the
	// Email/set object or the reducer writes zero message_attachments — silently dropping
	// every outbound attachment.
	it('includes staged attachments in the create object', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.attachments = [{ name: 'report.pdf', size: 1234, blobId: 'sha-abc', type: 'application/pdf' }];
		expect(c.buildMsg(null).attachments).toEqual([
			{ blobId: 'sha-abc', name: 'report.pdf', type: 'application/pdf', size: 1234 }
		]);
	});

	it('omits attachments when none are staged', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		expect(c.buildMsg(null).attachments).toBeUndefined();
	});
});

describe('ComposeStore GAL recipient logic (slice 4)', () => {
	beforeEach(() => {
		vi.mocked(galSearch).mockReset().mockResolvedValue([]);
		vi.mocked(expandGroup).mockReset().mockResolvedValue([]);
		vi.mocked(suggestRecipients).mockReset().mockReturnValue([]);
		vi.mocked(removeRecipient).mockReset();
		contactGroups.set([]);
	});

	afterEach(() => {
		vi.useRealTimers();
		vi.unstubAllGlobals();
	});

	it('appendRecipient targets the field named by galTarget, comma-joining', () => {
		const c = new ComposeStore();
		c.to = 'first@x.test';
		c.galTarget = 'to';
		c.appendRecipient('Second <second@x.test>');
		expect(c.to).toBe('first@x.test, Second <second@x.test>');

		c.galTarget = 'bcc';
		c.appendRecipient('b@x.test');
		expect(c.bcc).toBe('b@x.test');

		c.galTarget = 'replyTo';
		c.appendRecipient('r@x.test');
		expect(c.replyTo).toBe('r@x.test');
	});

	it('suggestionCount sums the groups + cache + GAL result lists', () => {
		const c = new ComposeStore();
		c.groupSuggestions = [{ id: 'g1', name: 'Team' }] as never;
		c.cacheSuggestions = [{ email: 'a@x.test' }, { email: 'b@x.test' }] as never;
		c.galResults = [{ email: 'c@x.test' }] as never;
		expect(c.suggestionCount()).toBe(4);
	});

	it('pickContact appends the contact to the target field and closes the dropdown', () => {
		const c = new ComposeStore();
		c.galTarget = 'to';
		c.galShow = true;
		c.pickContact({ displayName: 'Carol', email: 'carol@x.test' } as never);
		expect(c.to).toBe('Carol <carol@x.test>');
		expect(c.galShow).toBe(false);
	});

	it('debounces GAL search, exposes success and failure, and handles short queries locally', async () => {
		vi.useFakeTimers();
		const c = new ComposeStore();
		contactGroups.set([{ id: 'g1', name: 'Alpha Team' }] as never);
		vi.mocked(suggestRecipients).mockReturnValue([{ email: 'cached@x.test' }] as never);
		vi.mocked(galSearch).mockResolvedValueOnce([{ displayName: 'Alice', email: 'alice@x.test' }] as never);

		c.onGalInput('cc', 'a');
		expect(c.galTarget).toBe('cc');
		expect(c.galShow).toBe(true);
		expect(c.groupSuggestions).toHaveLength(1);
		c.onGalInput('cc', 'alice');
		await vi.advanceTimersByTimeAsync(200);
		expect(galSearch).toHaveBeenCalledWith('alice', 10);
		expect(c.galResults).toHaveLength(1);
		expect(c.galError).toBe(false);

		vi.mocked(galSearch).mockRejectedValueOnce(new Error('directory offline'));
		vi.mocked(suggestRecipients).mockReturnValue([]);
		contactGroups.set([]);
		c.onGalInput('to', 'broken');
		await vi.advanceTimersByTimeAsync(200);
		expect(c.galError).toBe(true);
		expect(c.galShow).toBe(true); // prior result remains usable

		c.onGalInput('to', ' ');
		expect(c.galResults).toEqual([]);
		expect(c.galShow).toBe(false);
	});

	it('picks group, cache, and GAL options by their flat dropdown index', async () => {
		const c = new ComposeStore();
		c.groupSuggestions = [{ id: 'g1', name: 'Team' }] as never;
		c.cacheSuggestions = [{ name: 'Cached', email: 'cached@x.test' }] as never;
		c.galResults = [{ displayName: 'Directory', email: 'dir@x.test' }] as never;
		vi.mocked(expandGroup).mockResolvedValue([{ name: 'Group User', email: 'group@x.test' }] as never);

		await c.pickAt(-1);
		await c.pickAt(0);
		expect(c.to).toBe('Group User <group@x.test>');
		c.galShow = true;
		await c.pickAt(1);
		expect(c.to).toContain('Cached <cached@x.test>');
		c.galShow = true;
		await c.pickAt(2);
		expect(c.to).toContain('Directory <dir@x.test>');
		await c.pickAt(99);
	});

	it('expands groups with named and bare members and leaves recipients intact on failure', async () => {
		const c = new ComposeStore();
		c.galTarget = 'bcc';
		vi.mocked(expandGroup).mockResolvedValueOnce([
			{ name: 'Named', email: 'named@x.test' },
			{ name: '', email: 'bare@x.test' },
		] as never).mockRejectedValueOnce(new Error('forbidden'));
		await c.pickGroup({ id: 'g1', name: 'Team' } as never);
		expect(c.bcc).toBe('Named <named@x.test>, bare@x.test');
		await c.pickGroup({ id: 'g2', name: 'Private' } as never);
		expect(c.bcc).toBe('Named <named@x.test>, bare@x.test');
	});

	it('supports cache selection, forgetting, and every recipient field', () => {
		const c = new ComposeStore();
		for (const target of ['to', 'cc', 'bcc'] as const) {
			c.galTarget = target;
			c.pickCacheSuggestion({ email: `${target}@x.test` } as never);
		}
		c.galTarget = 'replyTo';
		c.pickCacheSuggestion({ name: 'Reply', email: 'reply@x.test' } as never);
		expect(c.to).toBe('to@x.test');
		expect(c.cc).toBe('cc@x.test');
		expect(c.bcc).toBe('bcc@x.test');
		expect(c.replyTo).toBe('reply@x.test');

		vi.mocked(suggestRecipients).mockReturnValue([{ email: 'other@x.test' }] as never);
		c.galQuery = 'other';
		const event = { stopPropagation: vi.fn() } as unknown as Event;
		c.forgetSuggestion('reply@x.test', event);
		expect(removeRecipient).toHaveBeenCalledWith('reply@x.test');
		expect(event.stopPropagation).toHaveBeenCalled();
		expect(c.galShow).toBe(true);
	});

	it('handles keyboard navigation wraparound, selection, escape, and inactive targets', async () => {
		const c = new ComposeStore();
		c.galTarget = 'to';
		c.galShow = true;
		c.galResults = [{ email: 'one@x.test' }, { email: 'two@x.test' }] as never;
		const key = (value: string, shiftKey = false) => ({ key: value, shiftKey, preventDefault: vi.fn() } as unknown as KeyboardEvent);
		c.onGalKeydown('to', key('ArrowUp'));
		expect(c.galActive).toBe(0);
		c.onGalKeydown('to', key('ArrowDown'));
		expect(c.galActive).toBe(1);
		c.onGalKeydown('to', key('Enter'));
		await Promise.resolve();
		expect(c.to).toBe('two@x.test');
		c.galShow = true;
		c.onGalKeydown('to', key('Escape'));
		expect(c.galShow).toBe(false);
		c.galShow = true;
		c.onGalKeydown('cc', key('Escape'));
		expect(c.galShow).toBe(false);
	});

	it('uses fallback contact addresses, ignores addressless cards, and writes all targets', () => {
		const c = new ComposeStore();
		c.pickContact({ displayName: 'Nobody' } as never);
		expect(c.to).toBe('');
		for (const target of ['to', 'cc', 'bcc', 'replyTo'] as const) {
			c.galTarget = target;
			c.pickContact({ emails: [{ address: `${target}@x.test` }] } as never);
		}
		expect(c.to).toBe('to@x.test');
		expect(c.cc).toBe('cc@x.test');
		expect(c.bcc).toBe('bcc@x.test');
		expect(c.replyTo).toBe('replyTo@x.test');
	});

	it('loads mailtips with from/recipient parameters and clears them on network failure', async () => {
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({ ok: true, json: async () => ({ warnings: [{ type: 'ooo' }] }) })
			.mockResolvedValueOnce({ ok: true, json: async () => ({}) })
			.mockRejectedValueOnce(new Error('offline'));
		vi.stubGlobal('fetch', fetchMock);
		const c = new ComposeStore();
		await c.fetchMailTips();
		expect(fetchMock).not.toHaveBeenCalled();
		c.fromEmail = 'me@x.test';
		c.to = 'a@x.test';
		c.cc = 'b@x.test';
		await c.fetchMailTips();
		expect(String(fetchMock.mock.calls[0][0])).toContain('from=me%40x.test');
		expect(c.mailtipsWarnings).toEqual([{ type: 'ooo' }]);
		await c.fetchMailTips();
		expect(c.mailtipsWarnings).toEqual([]);
		c.mailtipsWarnings = [{ type: 'old' }];
		await c.fetchMailTips();
		expect(c.mailtipsWarnings).toEqual([]);
	});
});

describe('ComposeStore.mentionRecipient (@-mention in the body)', () => {
	it('forces galTarget to "to" and appends there, even when Cc had focus', () => {
		const c = new ComposeStore();
		c.galTarget = 'cc'; // a stray Cc focus must NOT leak the mention into Cc
		c.mentionRecipient('Alice', 'alice@x.test');
		expect(c.galTarget).toBe('to');
		expect(c.to).toBe('Alice <alice@x.test>');
		expect(c.cc).toBe('');
	});

	it('comma-joins onto an existing To and uses a bare address when no label', () => {
		const c = new ComposeStore();
		c.to = 'first@x.test';
		c.mentionRecipient('', 'bob@x.test');
		expect(c.to).toBe('first@x.test, bob@x.test');
	});

	it('still forces "to" but touches no field when the person has no address', () => {
		const c = new ComposeStore();
		c.galTarget = 'bcc';
		c.mentionRecipient('Nobody', '');
		expect(c.galTarget).toBe('to');
		expect(c.to).toBe('');
	});
});

describe('ComposeStore.buildSubmission (slice 2b)', () => {
	it('builds the envelope + scheduled-send + tag-on-send + S/MIME intents', () => {
		const c = new ComposeStore();
		c.fromEmail = 'me@corp.test';
		c.to = 'a@x.test, b@y.test';
		c.scheduledAt = '2030-01-01T09:00';
		c.sendTags = ['tag1', 'tag2'];
		c.smimeSign = true;
		c.smimeEncrypt = true;

		const sub = c.buildSubmission('E9', 'fallback@corp.test', 'custom', 42);

		expect(sub.emailId).toBe('E9');
		expect(sub.envelope).toEqual({
			mailFrom: { email: 'me@corp.test' },
			rcptTo: [{ email: 'a@x.test' }, { email: 'b@y.test' }],
		});
		expect(sub.onSendUndoWindowSeconds).toBe(42);
		expect(sub.sendAt).toBe(new Date('2030-01-01T09:00').toISOString());
		expect(sub.onSuccessUpdateEmail).toEqual({ '#E9': { 'keywords/$tag1': true, 'keywords/$tag2': true } });
		expect(sub.signSMIME).toBe(true);
		expect(sub.encryptSMIME).toBe(true);
	});

	it('omits sendAt for scheduleMode=now, and the tag/S-MIME fields when unset; falls back to userEmail', () => {
		const c = new ComposeStore();
		c.to = 'a@x.test';
		c.scheduledAt = '2030-01-01T09:00'; // ignored because scheduleMode is 'now'
		const sub = c.buildSubmission('E1', 'fallback@corp.test', 'now', 30);
		expect((sub.envelope as { mailFrom: { email: string } }).mailFrom.email).toBe('fallback@corp.test');
		expect(sub.sendAt).toBeUndefined();
		expect(sub.onSuccessUpdateEmail).toBeUndefined();
		expect(sub.signSMIME).toBeUndefined();
		expect(sub.encryptSMIME).toBeUndefined();
	});
});

describe('ComposeStore.createAndSubmit orchestration', () => {
	beforeEach(() => {
		vi.mocked(loadSession).mockReset().mockResolvedValue({} as never);
		vi.mocked(emailSet).mockReset();
		vi.mocked(emailGet).mockReset();
		vi.mocked(mailDraftOpen).mockReset();
		vi.mocked(mailDraftReplace).mockReset();
		vi.mocked(emailSubmissionSet).mockReset();
		vi.mocked(recordSend).mockReset();
	});

	it('refuses to send without a drafts mailbox', async () => {
		const c = new ComposeStore();
		await expect(c.createAndSubmit(null, 'me@x.test', 'now', 30)).rejects.toThrow(/Drafts folder/i);
		expect(emailSet).not.toHaveBeenCalled();
	});

	it('rejects offline and failed Email/set creates with bounded errors', async () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		vi.mocked(emailSet).mockResolvedValueOnce({ offline: true } as never);
		await expect(c.createAndSubmit(null, 'me@x.test', 'now', 30)).rejects.toThrow(/offline/i);

		vi.mocked(emailSet).mockResolvedValueOnce({ created: {}, notCreated: { 'email-1': { description: 'mailbox quota' } } } as never);
		await expect(c.createAndSubmit(null, 'me@x.test', 'now', 30)).rejects.toThrow('mailbox quota');
		vi.mocked(emailSet).mockResolvedValueOnce({ created: {}, notCreated: {} } as never);
		await expect(c.createAndSubmit(null, 'me@x.test', 'now', 30)).rejects.toThrow(/Failed to create email/i);
	});

	it('returns held status, cleans the prior draft, and records To/Cc/Bcc recipients', async () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.editingDraftId = 'old-draft';
		c.to = 'Alice <a@x.test>';
		c.cc = 'c@x.test';
		c.bcc = 'b@x.test';
		vi.mocked(emailSet)
			.mockResolvedValueOnce({ created: { 'email-1': { id: 'new-email' } }, notCreated: {} } as never)
			.mockResolvedValueOnce({ updated: {} } as never);
		vi.mocked(emailSubmissionSet).mockResolvedValueOnce({ created: { 'sub-1': { id: 's1', heldForApproval: true } } } as never);

		await expect(c.createAndSubmit(null, 'me@x.test', 'custom', 60)).resolves.toEqual({ emailId: 'new-email', held: true });
		expect(emailSubmissionSet).toHaveBeenCalledWith(expect.objectContaining({ 'sub-1': expect.objectContaining({ emailId: 'new-email' }) }), null);
		expect(emailSet).toHaveBeenLastCalledWith(null, null, ['old-draft'], null);
		expect(c.editingDraftId).toBeNull();
		expect(recordSend).toHaveBeenCalledTimes(3);
	});

	it('treats an offline submission result as queued and tolerates old-draft cleanup failure', async () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.editingDraftId = 'old-draft';
		c.to = 'a@x.test';
		vi.mocked(emailSet)
			.mockResolvedValueOnce({ created: { 'email-1': { id: 'new-email' } } } as never)
			.mockRejectedValueOnce(new Error('cleanup unavailable'));
		vi.mocked(emailSubmissionSet).mockResolvedValueOnce({ offline: true } as never);
		await expect(c.createAndSubmit(null, 'me@x.test', 'now', 30)).resolves.toEqual({ emailId: 'new-email', held: false });
		expect(c.editingDraftId).toBeNull();
	});

	it('turns submission markers into typed errors and purges the staged message twice', async () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		vi.mocked(emailSet)
			.mockResolvedValueOnce({ created: { 'email-1': { id: 'staged' } } } as never)
			.mockResolvedValue({ updated: {} } as never);
		vi.mocked(emailSubmissionSet).mockResolvedValueOnce({
			notCreated: { 'sub-1': { type: 'smime_encrypt_no_cert', addresses: ['a@x.test'] } },
		} as never);
		try {
			await c.createAndSubmit(null, 'me@x.test', 'now', 30);
			throw new Error('expected failure');
		} catch (error) {
			expect(error).toBeInstanceOf(SubmissionMarkerError);
			expect(error).toMatchObject({ code: 'smime_encrypt_no_cert', addresses: ['a@x.test'] });
		}
		expect(emailSet).toHaveBeenNthCalledWith(2, null, null, ['staged'], null);
		expect(emailSet).toHaveBeenNthCalledWith(3, null, null, ['staged'], null);
	});

	it('preserves the submission error when staged-message cleanup also fails', async () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		vi.mocked(emailSet)
			.mockResolvedValueOnce({ created: { 'email-1': { id: 'staged' } } } as never)
			.mockRejectedValue(new Error('cleanup failure'));
		vi.mocked(emailSubmissionSet).mockRejectedValueOnce(new Error('submission offline'));
		await expect(c.createAndSubmit(null, 'me@x.test', 'now', 30)).rejects.toThrow('submission offline');
	});

	it('submits the atomically replaced shared draft tuple without staging a second email', async () => {
		const c = new ComposeStore();
		c.mailboxes = [{ id: 'shared-drafts', name: 'Drafts', role: 'drafts', myRights: { maySubmit: true } }];
		c.sharedAccountId = '42';
		c.sharedDraftsEnabled = true;
		c.to = 'a@x.test';
		c.sharedDraftSession = { id: 'session', messageId: '100', receivedAt: '2030-01-01T00:00:00Z', contentRevision: '1', leaseEpoch: '2', leaseExpiresAt: '2030-01-01T00:02:00Z' };
		vi.mocked(mailDraftReplace).mockResolvedValueOnce({ id: 'session', messageId: '101', receivedAt: '2030-01-01T00:01:00Z', contentRevision: '2', leaseEpoch: '2', leaseExpiresAt: '2030-01-01T00:03:00Z' });
		vi.mocked(emailSubmissionSet).mockResolvedValueOnce({ created: { 'sub-1': { id: 'submission' } } } as never);
		await expect(c.createAndSubmit(null, 'me@x.test', 'now', 30)).resolves.toEqual({ emailId: '101', held: false });
		expect(emailSet).not.toHaveBeenCalled();
		expect(emailSubmissionSet).toHaveBeenCalledWith({ 'sub-1': expect.objectContaining({
			emailId: '101', draftSessionId: 'session', draftLeaseEpoch: '2', draftRevision: '2',
		}) }, '42');
	});
});

describe('ComposeStore.saveDraft (slice 2a)', () => {
	beforeEach(() => {
		vi.mocked(loadSession).mockReset().mockResolvedValue({} as never);
		vi.mocked(emailSet).mockReset();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('no-ops when the draft is empty (no subject/body/recipients) — no network call', async () => {
		const c = new ComposeStore();
		// Empty draft → returns before loadSession/emailSet, so nothing is mocked.
		await c.saveDraft(null);
		expect(c.draftSaving).toBe(false);
		expect(c.draftSaved).toBe(false);
	});

	it('skips a concurrent save and a non-empty draft without a drafts mailbox', async () => {
		const c = new ComposeStore();
		c.subject = 'Subject';
		c.draftSaving = true;
		await c.saveDraft(null);
		expect(loadSession).not.toHaveBeenCalled();
		c.draftSaving = false;
		await c.saveDraft(null);
		expect(emailSet).not.toHaveBeenCalled();
		expect(c.draftSaving).toBe(false);
	});

	it('creates a draft, replaces an old draft id, and clears the saved flash', async () => {
		vi.useFakeTimers();
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.subject = 'Subject';
		c.editingDraftId = 'old';
		vi.mocked(emailSet).mockResolvedValueOnce({ created: { 'draft-1': { id: 'new' } } } as never);
		await c.saveDraft(null, 'me@x.test');
		expect(emailSet).toHaveBeenCalledWith(expect.any(Object), null, ['old'], null);
		expect(c.editingDraftId).toBe('new');
		expect(c.draftSaved).toBe(true);
		await vi.advanceTimersByTimeAsync(2000);
		expect(c.draftSaved).toBe(false);
	});

	it('accepts an offline draft result and exposes then clears a save failure', async () => {
		vi.useFakeTimers();
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		vi.mocked(emailSet).mockResolvedValueOnce({ offline: true } as never);
		await c.saveDraft(null);
		expect(c.draftSaved).toBe(true);

		vi.mocked(emailSet).mockRejectedValueOnce(new Error('db offline'));
		await c.saveDraft(null);
		expect(c.draftSaveError).toBe(true);
		await vi.advanceTimersByTimeAsync(3000);
		expect(c.draftSaveError).toBe(false);
	});

	it('opens one stable shared session and atomically retargets later saves', async () => {
		const c = new ComposeStore();
		c.mailboxes = [{ id: 'shared-drafts', name: 'Drafts', role: 'drafts', myRights: { maySubmit: true } }];
		c.sharedAccountId = '42';
		c.sharedDraftsEnabled = true;
		c.fromEmail = 'team@example.test';
		c.subject = 'Shared';
		vi.mocked(emailSet).mockResolvedValueOnce({ created: { 'draft-1': { id: '100' } } } as never);
		vi.mocked(emailGet).mockResolvedValueOnce([{ id: '100', mailboxIds: {}, receivedAt: '2030-01-01T00:00:00Z' }]);
		vi.mocked(mailDraftOpen).mockResolvedValueOnce({ id: 'session', messageId: '100', receivedAt: '2030-01-01T00:00:00Z', contentRevision: '1', leaseEpoch: '1', leaseExpiresAt: '2030-01-01T00:02:00Z' });
		await c.saveDraft(null, 'me@example.test');
		expect(mailDraftOpen).toHaveBeenCalledWith(expect.objectContaining({ accountId: '42', messageId: '100', finalSenderAddress: 'team@example.test' }));

		vi.mocked(mailDraftReplace).mockResolvedValueOnce({ id: 'session', messageId: '101', receivedAt: '2030-01-01T00:01:00Z', contentRevision: '2', leaseEpoch: '1', leaseExpiresAt: '2030-01-01T00:03:00Z' });
		await c.saveDraft(null, 'me@example.test');
		expect(mailDraftReplace).toHaveBeenCalled();
		expect(emailSet).toHaveBeenCalledTimes(1);
		expect(c.editingDraftId).toBe('101');
	});

	it('preserves content and becomes read-only after a stale shared save', async () => {
		const c = new ComposeStore();
		c.mailboxes = [{ id: 'shared-drafts', name: 'Drafts', role: 'drafts', myRights: { maySubmit: true } }];
		c.sharedAccountId = '42';
		c.sharedDraftsEnabled = true;
		c.subject = 'Keep me';
		c.sharedDraftSession = { id: 'session', messageId: '100', receivedAt: '2030-01-01T00:00:00Z', contentRevision: '1', leaseEpoch: '1', leaseExpiresAt: '2030-01-01T00:02:00Z' };
		vi.mocked(mailDraftReplace).mockRejectedValueOnce(new Error('shared draft revision or lease is stale'));
		await c.saveDraft(null, 'me@example.test');
		expect(c.subject).toBe('Keep me');
		expect(c.sharedDraftReadOnly).toBe(true);
		expect(c.sharedDraftConflict).toBe(true);
	});
});

describe('ComposeStore.handleFiles (slice 3)', () => {
	it('returns over-cap file names skipped, without uploading them', async () => {
		const c = new ComposeStore();
		// Pre-fill to just under the cap so the next file overflows it.
		c.attachments = [{ name: 'existing', size: MAX_ATTACH_BYTES - 100, blobId: 'b0', type: 't' }];
		const bigFile = { name: 'huge.bin', size: 200 } as File;
		const files = { 0: bigFile, length: 1 } as unknown as FileList;

		// The over-cap file is skipped (never calls uploadBlob), so it is returned
		// for the view to toast and the attachment list is unchanged.
		const skipped = await c.handleFiles(files);
		expect(skipped).toEqual(['huge.bin']);
		expect(c.attachments).toHaveLength(1);
	});
});

// ── WAVE-5 #3: per-chip upload transitions + send gating ──
describe('ComposeStore upload lifecycle (WAVE-5 #3)', () => {
	const file = (name: string, size = 10, type = 't') => ({ name, size, type }) as File;
	const fileList = (...fs: File[]) =>
		Object.assign({ length: fs.length }, fs) as unknown as FileList;

	beforeEach(() => {
		vi.mocked(sha256Hex).mockReset().mockResolvedValue('sha-default');
		vi.mocked(putBlob).mockReset().mockResolvedValue(undefined);
	});

	it('uploading → done: chip walks preparing → uploading (real progress) → done at 100', async () => {
		const c = new ComposeStore();
		vi.mocked(sha256Hex).mockResolvedValue('sha-1');
		vi.mocked(putBlob).mockImplementation(async (blobId, _file, opts) => {
			// Mid-PUT: the chip is 'uploading' under the hashed blob id, Send gated.
			expect(blobId).toBe('sha-1');
			expect(c.attachments[0].status).toBe('uploading');
			expect(c.uploading).toBe(true);
			opts?.onProgress?.(0.5);
			expect(c.attachments[0].progress).toBe(50);
		});

		await c.handleFiles(fileList(file('a.txt')));

		expect(c.attachments).toHaveLength(1);
		expect(c.attachments[0]).toMatchObject({ blobId: 'sha-1', status: 'done', progress: 100 });
		expect(c.uploading).toBe(false);
		expect(c.batchTotal).toBe(0); // batch drained → N-of-M copy reset
	});

	it('uploading → failed: chip gets a per-chip failed state; retryUpload re-runs it', async () => {
		const c = new ComposeStore();
		vi.mocked(putBlob).mockRejectedValueOnce(new Error('boom'));

		await c.handleFiles(fileList(file('b.txt')));
		expect(c.attachments[0].status).toBe('failed');
		expect(c.failedUploads).toEqual(['b.txt']);
		expect(c.uploading).toBe(false);

		// Retry from the retained File → done.
		await c.retryUpload(c.attachments[0].uploadId!);
		expect(c.attachments[0].status).toBe('done');
		expect(c.failedUploads).toEqual([]);
	});

	it('uploading → cancelled: cancelUpload aborts the XHR, removes the chip, un-gates Send', async () => {
		const c = new ComposeStore();
		let seenSignal: AbortSignal | undefined;
		vi.mocked(putBlob).mockImplementation(
			(_blobId, _file, opts) =>
				new Promise<void>((_resolve, reject) => {
					seenSignal = opts?.signal;
					opts?.signal?.addEventListener('abort', () =>
						reject(new DOMException('Aborted', 'AbortError'))
					);
				})
		);

		const done = c.handleFiles(fileList(file('c.txt')));
		await vi.waitFor(() => expect(c.attachments[0]?.status).toBe('uploading'));
		expect(c.uploading).toBe(true);

		c.cancelUpload(c.attachments[0].uploadId!);
		expect(seenSignal?.aborted).toBe(true); // the XHR was really aborted
		expect(c.attachments).toHaveLength(0); // chip removed
		expect(c.uploading).toBe(false); // Send un-gated
		await done;
		expect(c.batchTotal).toBe(0);
	});

	it('dedupe fast-path: an already-staged blob skips the PUT and jumps to 100', async () => {
		const c = new ComposeStore();
		c.attachments = [{ name: 'orig', size: 10, blobId: 'sha-dupe', type: 't' }]; // status absent = done
		vi.mocked(sha256Hex).mockResolvedValue('sha-dupe');

		await c.handleFiles(fileList(file('copy.txt')));

		expect(putBlob).not.toHaveBeenCalled();
		expect(c.attachments[1]).toMatchObject({ blobId: 'sha-dupe', status: 'done', progress: 100 });
	});

	it('gating copy counters: a 2-file batch counts N of M, then resets when drained', async () => {
		const c = new ComposeStore();
		const seen: Array<{ done: number; total: number }> = [];
		// Distinct hashes per file — identical hashes would take the dedupe fast-path.
		vi.mocked(sha256Hex).mockImplementation(async (f) => `sha-${f.name}`);
		vi.mocked(putBlob).mockImplementation(async () => {
			seen.push({ done: c.batchDone, total: c.batchTotal });
		});

		await c.handleFiles(fileList(file('one.txt'), file('two.txt')));

		// During chip 1: 0 done of 2 ("Uploading 1 of 2…"); during chip 2: 1 of 2.
		expect(seen).toEqual([
			{ done: 0, total: 2 },
			{ done: 1, total: 2 }
		]);
		expect(c.batchDone).toBe(0);
		expect(c.batchTotal).toBe(0);
	});

	it('buildMsg carries only fully-uploaded chips (in-flight/failed never ride along)', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.attachments = [
			{ name: 'done.txt', size: 5, blobId: 'sha-d', type: 't' }, // absent status = done
			{ name: 'up.txt', size: 5, blobId: 'sha-u', type: 't', status: 'uploading', uploadId: 'u1' },
			{ name: 'bad.txt', size: 5, blobId: '', type: 't', status: 'failed', uploadId: 'u2' }
		];
		const msg = c.buildMsg(null);
		expect(msg.attachments).toEqual([{ blobId: 'sha-d', name: 'done.txt', type: 't', size: 5 }]);
	});
});

// ── WAVE-5 #2: inline body images ──
describe('ComposeStore.stageInlineImage', () => {
	beforeEach(() => {
		// Real URL.createObjectURL requires an actual Blob; these tests use plain
		// duck-typed { name, size, type } File stand-ins (matching this file's
		// existing convention), so the browser API is stubbed rather than fed a
		// value it would reject.
		vi.stubGlobal('URL', { ...URL, createObjectURL: vi.fn(() => `blob:mock-${Math.random()}`), revokeObjectURL: vi.fn() });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('rejects a non-whitelisted mime type (e.g. SVG) — caller falls back to a normal attachment', () => {
		const c = new ComposeStore();
		const svg = { name: 'evil.svg', size: 10, type: 'image/svg+xml' } as File;
		expect(c.stageInlineImage(svg)).toBeNull();
		expect(c.attachments).toHaveLength(0);
	});

	it('accepts every whitelisted type', () => {
		for (const type of INLINE_IMAGE_TYPES) {
			const c = new ComposeStore();
			const file = { name: 'pic', size: 10, type } as File;
			expect(c.stageInlineImage(file)).not.toBeNull();
		}
	});

	it('rejects when staging would exceed the shared 25 MiB budget', () => {
		const c = new ComposeStore();
		c.attachments = [{ name: 'existing', size: MAX_ATTACH_BYTES - 100, blobId: 'b0', type: 't' }];
		const big = { name: 'big.png', size: 200, type: 'image/png' } as File;
		expect(c.stageInlineImage(big)).toBeNull();
		expect(c.attachments).toHaveLength(1); // no row added
	});

	it('stages a row synchronously (preparing) and kicks off the upload in the background', () => {
		const c = new ComposeStore();
		const file = { name: 'shot.png', size: 100, type: 'image/png' } as File;
		const staged = c.stageInlineImage(file);
		expect(staged).toMatchObject({ uploadId: expect.stringContaining('up-') });
		expect(staged?.cid).toContain(staged?.uploadId);
		expect(c.attachments).toHaveLength(1);
		expect(c.attachments[0]).toMatchObject({
			inline: true,
			status: 'preparing',
			previewUrl: staged?.previewUrl,
			cid: staged?.cid,
		});
		expect(c.uploading).toBe(true); // shares the Send gate with file attachments
	});
});

describe('ComposeStore.pruneOrphanedInlineImages', () => {
	it('drops an inline row whose previewUrl no longer appears in the body (the <img> was deleted)', () => {
		const c = new ComposeStore();
		c.attachments = [
			{ name: 'a.png', size: 5, blobId: 'sha-a', type: 'image/png', inline: true, previewUrl: 'blob:a', cid: 'a@x' },
			{ name: 'b.png', size: 5, blobId: 'sha-b', type: 'image/png', inline: true, previewUrl: 'blob:b', cid: 'b@x' },
			{ name: 'file.pdf', size: 5, blobId: 'sha-f', type: 'application/pdf' }, // never inline — untouched
		];
		c.pruneOrphanedInlineImages('<p>only <img src="blob:a"> remains</p>');
		expect(c.attachments.map((a) => a.name)).toEqual(['a.png', 'file.pdf']);
	});

	it('cancels (aborts) an orphaned inline image still mid-upload rather than leaving Send stuck', () => {
		const c = new ComposeStore();
		c.attachments = [
			{ name: 'a.png', size: 5, blobId: '', type: 'image/png', inline: true, previewUrl: 'blob:a',
			  cid: 'a@x', status: 'uploading', uploadId: 'up-9' },
		];
		c.pruneOrphanedInlineImages('<p>body has no image anymore</p>');
		expect(c.attachments).toHaveLength(0);
		expect(c.uploading).toBe(false);
	});
});

describe('ComposeStore.buildMsg — inline image blob:→cid: rewrite', () => {
	it('rewrites multiple inline images to cid: refs, in stable order, and adds their attachment entries', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.bodyHtml = '<p><img src="blob:one" data-upload-id="up-1"> and <img src="blob:two" data-upload-id="up-2"></p>';
		c.attachments = [
			{ name: 'one.png', size: 5, blobId: 'sha-1', type: 'image/png', inline: true, previewUrl: 'blob:one', cid: 'up-1@setjoin.inline' },
			{ name: 'two.png', size: 5, blobId: 'sha-2', type: 'image/png', inline: true, previewUrl: 'blob:two', cid: 'up-2@setjoin.inline' },
		];

		const msg = c.buildMsg(null);

		const html = (msg.bodyValues as Record<string, { value: string }>).html.value;
		expect(html).toContain('cid:up-1@setjoin.inline');
		expect(html).toContain('cid:up-2@setjoin.inline');
		expect(html).not.toContain('blob:');
		// Order stable: attachments follow the order they were staged in.
		expect(msg.attachments).toEqual([
			{ blobId: 'sha-1', name: 'one.png', type: 'image/png', size: 5, cid: 'up-1@setjoin.inline', disposition: 'inline' },
			{ blobId: 'sha-2', name: 'two.png', type: 'image/png', size: 5, cid: 'up-2@setjoin.inline', disposition: 'inline' },
		]);
	});

	it('excludes an inline image still uploading (no blobId yet) and one whose <img> was deleted from the body', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.bodyHtml = '<p>text only, no images left</p>';
		c.attachments = [
			{ name: 'uploading.png', size: 5, blobId: '', type: 'image/png', inline: true,
			  previewUrl: 'blob:uploading', cid: 'up-1@setjoin.inline', status: 'uploading', uploadId: 'up-1' },
			{ name: 'deleted.png', size: 5, blobId: 'sha-d', type: 'image/png', inline: true,
			  previewUrl: 'blob:deleted', cid: 'up-2@setjoin.inline' }, // status done, but no longer in the body
		];

		const msg = c.buildMsg(null);
		expect(msg.attachments).toBeUndefined();
	});

	it('a non-whitelisted-type image pasted as a plain attachment (never staged inline) sends as a regular attachment', () => {
		const c = new ComposeStore();
		c.mailboxes = MAILBOXES;
		c.to = 'a@x.test';
		c.attachments = [{ name: 'evil.svg', size: 5, blobId: 'sha-svg', type: 'image/svg+xml' }]; // inline undefined
		const msg = c.buildMsg(null);
		expect(msg.attachments).toEqual([{ blobId: 'sha-svg', name: 'evil.svg', type: 'image/svg+xml', size: 5 }]);
	});
});

// ── DLP compose-tip: fetchDlpCheck / debounceDlpCheck (mirrors mailtips, 1s debounce) ──
describe('ComposeStore.fetchDlpCheck / debounceDlpCheck', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	it('does not fetch when subject and body are both empty', async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		const c = new ComposeStore();
		await c.fetchDlpCheck();
		expect(fetchMock).not.toHaveBeenCalled();
		expect(c.dlpTip).toEqual({ violated: false });
	});

	it('POSTs recipients/subject/bodyText/bodyHtml and sets dlpTip from the response', async () => {
		const fetchMock = vi.fn(async (_url: string, _init: RequestInit) => ({
			ok: true,
			json: async () => ({ violated: true, policyId: 3, policyName: 'ssn-block', action: 'block', reasonKind: 'content' })
		}));
		vi.stubGlobal('fetch', fetchMock);
		const c = new ComposeStore();
		c.to = 'bob@x.test';
		c.cc = 'carol@x.test';
		c.subject = 'subj';
		c.bodyText = 'my ssn is 123-45-6789';
		c.bodyHtml = '<p>my ssn is 123-45-6789</p>';

		await c.fetchDlpCheck();

		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe('/auth/me/dlp-check');
		expect(init!.method).toBe('POST');
		expect(JSON.parse(init!.body as string)).toEqual({
			recipients: ['bob@x.test', 'carol@x.test'],
			subject: 'subj',
			bodyText: 'my ssn is 123-45-6789',
			bodyHtml: '<p>my ssn is 123-45-6789</p>'
		});
		expect(c.dlpTip).toEqual({ violated: true, policyId: 3, policyName: 'ssn-block', action: 'block', reasonKind: 'content' });
	});

	it('a network failure keeps the last tip rather than throwing', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline'); }));
		const c = new ComposeStore();
		c.subject = 'subj';
		c.dlpTip = { violated: true, action: 'warn' };
		await expect(c.fetchDlpCheck()).resolves.toBeUndefined();
		expect(c.dlpTip).toEqual({ violated: true, action: 'warn' });
	});

	it('debounceDlpCheck coalesces rapid calls into exactly one fetch after 1s', () => {
		vi.useFakeTimers();
		const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ violated: false }) }));
		vi.stubGlobal('fetch', fetchMock);
		const c = new ComposeStore();
		c.subject = 'a';
		c.debounceDlpCheck();
		c.subject = 'ab';
		c.debounceDlpCheck();
		c.subject = 'abc';
		c.debounceDlpCheck();

		vi.advanceTimersByTime(999);
		expect(fetchMock).not.toHaveBeenCalled();
		vi.advanceTimersByTime(1);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('a stale in-flight response is dropped when a newer request has since resolved (#dlpSeq guard)', async () => {
		// First call resolves LATE with a stale "clean" verdict; second call
		// resolves FIRST with "block". The stale clean must never overwrite it.
		let resolveFirst!: (v: unknown) => void;
		const firstPromise = new Promise((resolve) => { resolveFirst = resolve; });
		const fetchMock = vi.fn()
			.mockImplementationOnce(async () => { await firstPromise; return { ok: true, json: async () => ({ violated: false }) }; })
			.mockImplementationOnce(async () => ({ ok: true, json: async () => ({ violated: true, action: 'block', policyName: 'p' }) }));
		vi.stubGlobal('fetch', fetchMock);
		const c = new ComposeStore();
		c.subject = 'first';

		const firstCall = c.fetchDlpCheck();
		c.subject = 'second';
		const secondCall = c.fetchDlpCheck();
		await secondCall;
		expect(c.dlpTip).toEqual({ violated: true, action: 'block', policyName: 'p' });

		resolveFirst(undefined);
		await firstCall;
		expect(c.dlpTip).toEqual({ violated: true, action: 'block', policyName: 'p' }); // NOT overwritten by the stale clean
	});

	it('teardown clears the debounce timer so it never fires after unmount', () => {
		vi.useFakeTimers();
		const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ violated: false }) }));
		vi.stubGlobal('fetch', fetchMock);
		const c = new ComposeStore();
		c.subject = 'a';
		c.debounceDlpCheck();
		c.teardown();
		vi.advanceTimersByTime(5000);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
