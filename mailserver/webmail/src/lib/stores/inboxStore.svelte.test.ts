import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { flushSync } from 'svelte';
import type { Email, Mailbox } from '$lib/types/jmap';
import type { ViewId } from '$lib/components/mail/MailSidebar.svelte';

// ── JMAP client / websocket mocks ──
const loadSession = vi.fn();
const mailboxGet = vi.fn();
const emailQuery = vi.fn();
const emailGet = vi.fn();
const emailSubmissionQuery = vi.fn();
const emailSubmissionGet = vi.fn();
const emailBundles = vi.fn();
const searchSnippetGet = vi.fn();
const threadGet = vi.fn();
const loadList = vi.fn();
const searchList = vi.fn();
const offlineState = vi.hoisted(() => ({ effectiveOffline: false }));

vi.mock('$lib/jmap/client', () => ({
	loadSession: (...a: unknown[]) => loadSession(...a),
	mailboxGet: (...a: unknown[]) => mailboxGet(...a),
	emailQuery: (...a: unknown[]) => emailQuery(...a),
	emailGet: (...a: unknown[]) => emailGet(...a),
	emailGetWithState: async (...a: unknown[]) => ({ list: await emailGet(...a), state: '1' }),
	emailChanges: vi.fn(),
	mailboxState: vi.fn().mockResolvedValue('1'),
	isJmapMethodError: () => false,
	emailSubmissionQuery: (...a: unknown[]) => emailSubmissionQuery(...a),
	emailSubmissionGet: (...a: unknown[]) => emailSubmissionGet(...a),
	emailBundles: (...a: unknown[]) => emailBundles(...a),
	searchSnippetGet: (...a: unknown[]) => searchSnippetGet(...a),
	threadGet: (...a: unknown[]) => threadGet(...a),
	FULL_EMAIL_PROPS: [],
}));

vi.mock('$lib/offline/readpath', () => ({
	loadList: (...a: unknown[]) => loadList(...a),
	searchList: (...a: unknown[]) => searchList(...a),
}));

vi.mock('$lib/offline/state.svelte', () => ({ offline: offlineState }));

const subscribe = vi.fn();
vi.mock('$lib/jmap/websocket', () => ({
	subscribe: (...a: unknown[]) => subscribe(...a),
}));

// ── Saved-search client mock ──
const savedSearchList = vi.fn();
const savedSearchSet = vi.fn();
const savedSearchDelete = vi.fn();
vi.mock('$lib/jmap/savedsearches', () => ({
	savedSearchList: (...a: unknown[]) => savedSearchList(...a),
	savedSearchSet: (...a: unknown[]) => savedSearchSet(...a),
	savedSearchDelete: (...a: unknown[]) => savedSearchDelete(...a),
}));

import { InboxStore } from './inboxStore.svelte';

// ── Fixtures ──
function mb(id: string, overrides: Partial<Mailbox> = {}): Mailbox {
	return { id, name: id, ...overrides };
}
function em(id: string, overrides: Partial<Email> = {}): Email {
	return { id, mailboxIds: {}, threadId: id, ...overrides };
}

const MAILBOXES: Mailbox[] = [
	mb('mb-inbox', { role: 'inbox', name: 'Inbox', unreadEmails: 5, totalEmails: 10 }),
	mb('mb-sent', { role: 'sent', name: 'Sent' }),
	mb('mb-trash', { role: 'trash', name: 'Trash' }),
	mb('mb-snoozed', { name: 'Snoozed', totalEmails: 3 }),
	mb('mb-scheduled', { name: 'Scheduled' }),
	mb('mb-finance', { name: 'Finance', color: 'green', totalEmails: 7 }),
];

beforeEach(() => {
	loadSession.mockReset().mockResolvedValue(undefined);
	mailboxGet.mockReset().mockResolvedValue(MAILBOXES);
	emailQuery.mockReset().mockResolvedValue({ ids: [], total: 0, position: 0 });
	emailGet.mockReset().mockResolvedValue([]);
	emailSubmissionQuery.mockReset().mockResolvedValue({ ids: [], total: 0, position: 0 });
	emailSubmissionGet.mockReset().mockResolvedValue([]);
	emailBundles.mockReset().mockResolvedValue({ bundles: [] });
	searchSnippetGet.mockReset().mockResolvedValue([]);
	threadGet.mockReset().mockResolvedValue([]);
	loadList.mockReset().mockResolvedValue([]);
	searchList.mockReset().mockResolvedValue([]);
	offlineState.effectiveOffline = false;
	subscribe.mockReset().mockReturnValue(() => {});
	savedSearchList.mockReset().mockResolvedValue([]);
	savedSearchSet.mockReset().mockResolvedValue({ id: '1', name: 'x', query: 'q', position: 0 });
	savedSearchDelete.mockReset().mockResolvedValue(undefined);
});

afterEach(() => {
	vi.useRealTimers();
});

describe('InboxStore.loadEmails — standard Email/query path', () => {
	it('queries with the computed filter for the current view and fills emails + pagination', async () => {
		// position omitted → currentPosition advances by ids.length (the gateway window
		// semantics the page relies on); 2 of 2 consumed ⇒ no further pages.
		emailQuery.mockResolvedValue({ ids: ['e1', 'e2'], total: 2 });
		emailGet.mockResolvedValue([em('e1'), em('e2')]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'inbox';

		await s.loadEmails();

		expect(emailQuery).toHaveBeenCalledOnce();
		const filterArg = emailQuery.mock.calls[0][0] as Record<string, unknown>;
		expect(filterArg.inMailbox).toBe('mb-inbox');
		expect(s.emails.map((e) => e.id)).toEqual(['e1', 'e2']);
		expect(s.totalEmails).toBe(2);
		expect(s.hasMore).toBe(false);
		expect(s.loading).toBe(false);
	});

	it('AND-merges a from: search fragment into the query filter', async () => {
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'inbox';
		s.rawSearch = 'from:alice report';

		await s.loadEmails();

		const filterArg = emailQuery.mock.calls[0][0] as Record<string, unknown>;
		expect(filterArg.inMailbox).toBe('mb-inbox');
		expect(filterArg.from).toBe('alice');
		expect(filterArg.text).toBe('report');
	});

	it('sets hasMore when the result is paginated', async () => {
		emailQuery.mockResolvedValue({ ids: ['e1'], total: 50, position: 0 });
		emailGet.mockResolvedValue([em('e1')]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		await s.loadEmails();
		expect(s.hasMore).toBe(true);
	});

	it('advances the offset on load-more (regression: the gateway echoes position=0)', async () => {
		// The reducer returns the REQUESTED offset as `position` (0 on a reset load),
		// so the store must advance by the page size — pinning currentPosition at the
		// echoed 0 re-fetched page 1 and crashed the keyed list with duplicate ids.
		emailQuery
			.mockResolvedValueOnce({ ids: ['e1', 'e2'], total: 50, position: 0 })
			.mockResolvedValueOnce({ ids: ['e3', 'e4'], total: 50, position: 2 });
		emailGet
			.mockResolvedValueOnce([em('e1'), em('e2')])
			.mockResolvedValueOnce([em('e3'), em('e4')]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;

		await s.loadEmails(); // reset
		expect(s.currentPosition).toBe(2);

		await s.loadEmails(false); // load more
		// the 2nd query requested offset 2 (the page size), NOT 0
		expect(emailQuery.mock.calls[1][3]).toBe(2);
		// ...and appended without re-fetching/duplicating page 1
		expect(s.emails.map((e) => e.id)).toEqual(['e1', 'e2', 'e3', 'e4']);
		expect(s.currentPosition).toBe(4);
	});

	it('attaches SearchSnippet/get highlights to matching emails on a text search', async () => {
		emailQuery.mockResolvedValue({ ids: ['e1', 'e2'], total: 2, position: 0 });
		emailGet.mockResolvedValue([em('e1'), em('e2')]);
		searchSnippetGet.mockResolvedValue([
			{ emailId: 'e1', subject: 'hi <mark>report</mark>', preview: 'body <mark>report</mark>' },
		]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'inbox';
		s.rawSearch = 'report';

		await s.loadEmails();

		expect(searchSnippetGet).toHaveBeenCalledOnce();
		// filter passed carries the parsed text query; ids are the query result ids
		expect((searchSnippetGet.mock.calls[0][0] as { text?: string }).text).toBe('report');
		expect(searchSnippetGet.mock.calls[0][1]).toEqual(['e1', 'e2']);
		// e1 got its snippet; e2 (no match) is left untouched
		expect(s.emails.find((e) => e.id === 'e1')?.searchSubject).toBe('hi <mark>report</mark>');
		expect(s.emails.find((e) => e.id === 'e1')?.searchPreview).toBe('body <mark>report</mark>');
		expect(s.emails.find((e) => e.id === 'e2')?.searchPreview).toBeUndefined();
	});

	it('does NOT call SearchSnippet/get when there is no text query (plain inbox / from:-only)', async () => {
		emailQuery.mockResolvedValue({ ids: ['e1'], total: 1, position: 0 });
		emailGet.mockResolvedValue([em('e1')]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'inbox';
		s.rawSearch = 'from:alice'; // from-only → parseSearch sets no `text`

		await s.loadEmails();

		expect(searchSnippetGet).not.toHaveBeenCalled();
		expect(s.emails[0].searchPreview).toBeUndefined();
	});

	it('falls back to plain emails when the snippet fetch fails (best-effort)', async () => {
		emailQuery.mockResolvedValue({ ids: ['e1'], total: 1, position: 0 });
		emailGet.mockResolvedValue([em('e1')]);
		searchSnippetGet.mockRejectedValue(new Error('boom'));
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'inbox';
		s.rawSearch = 'report';

		await s.loadEmails();

		expect(s.emails.map((e) => e.id)).toEqual(['e1']);
		expect(s.emails[0].searchPreview).toBeUndefined();
	});
});

describe('InboxStore.loadEmails — Scheduled view (B2 EmailSubmission path)', () => {
	it('loads via EmailSubmission APIs and records sendAt in scheduledMap', async () => {
		emailSubmissionQuery.mockResolvedValue({ ids: ['sub1'], total: 1, position: 0 });
		emailSubmissionGet.mockResolvedValue([{ id: 'sub1', emailId: 'e9', sendAt: '2026-07-01T10:00:00Z' }]);
		emailGet.mockResolvedValue([em('e9')]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'scheduled';

		await s.loadEmails();

		expect(emailSubmissionQuery).toHaveBeenCalledOnce();
		expect(emailQuery).not.toHaveBeenCalled();
		expect(s.emails.map((e) => e.id)).toEqual(['e9']);
		expect(s.scheduledMap['e9']).toBe('2026-07-01T10:00:00Z');
	});

	it('handles empty reset and appends a later scheduled page without sendAt', async () => {
		const s = new InboxStore();
		s.view = 'scheduled';
		s.emails = [em('stale')];
		await s.loadEmails();
		expect(s.emails).toEqual([]);
		emailSubmissionQuery.mockResolvedValueOnce({ ids: ['sub2'], total: 2, position: 1 });
		emailSubmissionGet.mockResolvedValueOnce([{ id: 'sub2', emailId: 'e2' }]);
		emailGet.mockResolvedValueOnce([em('e2')]);
		await s.loadEmails(false);
		expect(s.emails.map((e) => e.id)).toEqual(['e2']);
		expect(s.scheduledMap.e2).toBeUndefined();
		expect(s.currentPosition).toBe(2);
	});
});

describe('InboxStore.loadEmails — offline and failure paths', () => {
	it('maps cached inbox rows and appends an offline page without offering load-more', async () => {
		offlineState.effectiveOffline = true;
		loadList
			.mockResolvedValueOnce([{ id: 'c1', receivedAt: 1_700_000_000_000, subject: 'Cached', from: 'a@x.test' }])
			.mockResolvedValueOnce([{ id: 'c2', receivedAt: 1_700_000_001_000, subject: 'Next', from: '' }]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		await s.loadEmails();
		expect(loadList).toHaveBeenCalledWith({ limit: 50, offset: 0 });
		expect(s.emails[0]).toMatchObject({ id: 'c1', subject: 'Cached', from: [{ email: 'a@x.test', name: 'a@x.test' }] });
		await s.loadEmails(false);
		expect(loadList).toHaveBeenLastCalledWith({ limit: 50, offset: 1 });
		expect(s.emails.map((e) => e.id)).toEqual(['c1', 'c2']);
		expect(s.emails[1].from).toBeUndefined();
		expect(s.hasMore).toBe(false);
	});

	it('uses the bounded cache search path for an offline text query', async () => {
		offlineState.effectiveOffline = true;
		searchList.mockResolvedValueOnce([{ id: 's1', receivedAt: 1_700_000_000_000, subject: 'Hit', from: null }]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.rawSearch = '  quarterly  ';
		await s.loadEmails();
		expect(searchList).toHaveBeenCalledWith('quarterly', 50);
		expect(loadList).not.toHaveBeenCalled();
	});

	it('swallows superseded aborts, flags shared access loss, and rethrows own-mail failures', async () => {
		const abort = Object.assign(new Error('superseded'), { name: 'AbortError' });
		emailQuery.mockRejectedValueOnce(abort);
		const s = new InboxStore();
		await expect(s.loadEmails()).resolves.toBeUndefined();
		expect(s.loading).toBe(false);

		emailQuery.mockRejectedValueOnce(new Error('forbidden'));
		s.accountOverride = 'shared-1';
		await expect(s.loadEmails()).resolves.toBeUndefined();
		expect(s.accessRevoked).toBe(true);

		emailQuery.mockRejectedValueOnce(new Error('database offline'));
		s.accountOverride = null;
		await expect(s.loadEmails()).rejects.toThrow('database offline');
		expect(s.loading).toBe(false);
	});
});

describe('InboxStore.selectView', () => {
	it('sets the view, clears tagFilter + selectedEmail, and reloads', async () => {
		emailQuery.mockResolvedValue({ ids: ['e1'], total: 1, position: 0 });
		emailGet.mockResolvedValue([em('e1')]);
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.tagFilter = 'mb-finance';
		s.selectedEmail = em('old');

		s.selectView('sent' as ViewId);
		await Promise.resolve();
		await Promise.resolve();

		expect(s.view).toBe('sent');
		expect(s.tagFilter).toBeNull();
		expect(s.selectedEmail).toBeNull();
		expect(emailQuery).toHaveBeenCalled();
		const filterArg = emailQuery.mock.calls[0][0] as Record<string, unknown>;
		expect(filterArg.inMailbox).toBe('mb-sent');
	});
});

describe('InboxStore.selectTag', () => {
	it('sets the tag filter, clears selection, and reloads scoped to the tag', async () => {
		emailQuery.mockResolvedValue({ ids: [], total: 0, position: 0 });
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'inbox';
		s.selectedEmail = em('old');

		s.selectTag('mb-finance');
		await Promise.resolve();
		await Promise.resolve();

		expect(s.tagFilter).toBe('mb-finance');
		expect(s.selectedEmail).toBeNull();
		const filterArg = emailQuery.mock.calls[0][0] as Record<string, unknown>;
		expect(filterArg.inMailbox).toBe('mb-finance');
	});
});

describe('InboxStore — derived reactivity', () => {
	it('counts, flatForView, effectiveViewMode, selectedRole, and threadList recompute on state change', () => {
		const cleanup = $effect.root(() => {
			const s = new InboxStore();
			s.mailboxes = MAILBOXES;
			s.view = 'inbox';
			s.emails = [em('e1', { mailboxIds: { 'mb-inbox': true } })];
			s.viewMode = 'threaded';
			flushSync();

			// counts derived from mailboxes
			expect(s.counts.inboxUnread).toBe(5);
			expect(s.counts.snoozedTotal).toBe(3);
			expect(s.counts.tagCounts).toEqual({ 'mb-finance': 7 });

			// inbox view + threaded mode → not forced flat
			expect(s.flatForView).toBe(false);
			expect(s.effectiveViewMode).toBe('threaded');
			expect(s.selectedRole).toBe('inbox');

			// switching to the All Mail view forces flat
			s.view = 'all';
			flushSync();
			expect(s.flatForView).toBe(true);
			expect(s.effectiveViewMode).toBe('flat');

			// a sidebar tag filter forces flat; a non-location tag has no role of its
			// own, so selectedRole falls back to the underlying view's role (frozen
			// behavior from the page: tag-role ?? view-role ?? null).
			s.tagFilter = 'mb-finance';
			s.view = 'inbox';
			flushSync();
			expect(s.flatForView).toBe(true);
			expect(s.selectedRole).toBe('inbox');
		});
		cleanup();
	});

	it('threadList reflects flat vs threaded mode', () => {
		const cleanup = $effect.root(() => {
			const s = new InboxStore();
			s.mailboxes = MAILBOXES;
			s.view = 'inbox';
			s.emails = [em('e1', { threadId: 't1' }), em('e2', { threadId: 't1' })];
			s.buildThreads();
			s.viewMode = 'threaded';
			flushSync();
			// threaded → one thread holding both emails
			expect(s.threadList).toHaveLength(1);
			expect(s.threadList[0].emails).toHaveLength(2);

			// flat → one entry per email
			s.viewMode = 'flat';
			flushSync();
			expect(s.threadList).toHaveLength(2);
		});
		cleanup();
	});
});

describe('InboxStore.subscribeToChanges', () => {
	it('registers an Email/Mailbox listener and debounces a reload on an Email change', async () => {
		vi.useFakeTimers();
		emailQuery.mockResolvedValue({ ids: [], total: 0, position: 0 });
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;

		s.subscribeToChanges();
		expect(subscribe).toHaveBeenCalledOnce();
		const [types, handler] = subscribe.mock.calls[0] as [string[], (c: Record<string, unknown>) => void];
		expect(types).toEqual(['Email', 'Mailbox']);

		const before = emailQuery.mock.calls.length;
		handler({ Email: '1' });
		handler({ Email: '2' });
		// debounced — not yet called
		expect(emailQuery.mock.calls.length).toBe(before);
		await vi.advanceTimersByTimeAsync(300);
		// exactly one reload despite two events
		expect(emailQuery.mock.calls.length).toBe(before + 1);
	});

	it('ignores own-mail pushes in shared context and runs the post-reload hook otherwise', async () => {
		vi.useFakeTimers();
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.accountOverride = 'shared-1';
		s.onAfterPushReload = vi.fn();
		s.subscribeToChanges();
		const handler = subscribe.mock.calls[0][1] as (changes: Record<string, unknown>) => void;
		handler({ Email: '1' });
		await vi.advanceTimersByTimeAsync(300);
		expect(emailQuery).not.toHaveBeenCalled();
		s.accountOverride = null;
		handler({ Mailbox: '2' });
		await vi.advanceTimersByTimeAsync(300);
		await Promise.resolve();
		expect(emailQuery).toHaveBeenCalledOnce();
		expect(s.onAfterPushReload).toHaveBeenCalledOnce();
	});

	it('teardown() clears the debounce timer and calls the unsubscribe', () => {
		const unsub = vi.fn();
		subscribe.mockReturnValue(unsub);
		const s = new InboxStore();
		s.subscribeToChanges();
		s.teardown();
		expect(unsub).toHaveBeenCalledOnce();
	});
});

describe('InboxStore ancillary data and controls', () => {
	it('builds sorted muted and unmuted thread buckets with id fallback', () => {
		const s = new InboxStore();
		s.mutedTagId = 'muted';
		s.emails = [
			em('new', { threadId: 't1', receivedAt: '2026-01-02T00:00:00Z' }),
			em('old', { threadId: 't1', receivedAt: '2026-01-01T00:00:00Z' }),
			{ id: 'solo', mailboxIds: { muted: true }, receivedAt: '2026-01-03T00:00:00Z' } as Email,
		];
		s.buildThreads();
		expect(s.threads.get('t1')?.emails.map((e) => e.id)).toEqual(['new', 'old']);
		expect(s.threads.get('solo')?.muted).toBe(true);
	});

	it('loads, disables, and clears newsletter bundles on failure', async () => {
		const s = new InboxStore();
		s.bundles = [{ id: 'old' }] as never;
		await s.loadBundles(false);
		expect(s.bundles).toEqual([]);
		emailBundles.mockResolvedValueOnce({ bundles: [{ id: 'b1' }] });
		await s.loadBundles(true);
		expect(loadSession).toHaveBeenCalled();
		expect(s.bundles).toEqual([{ id: 'b1' }]);
		emailBundles.mockRejectedValueOnce(new Error('offline'));
		await s.loadBundles(true);
		expect(s.bundles).toEqual([]);
	});

	it('refreshes own and shared mailboxes with fail-closed shared access handling', async () => {
		const s = new InboxStore();
		await s.refreshMailboxes();
		expect(s.mailboxes).toEqual(MAILBOXES);
		mailboxGet.mockRejectedValueOnce(new Error('forbidden'));
		s.accountOverride = 'shared-1';
		await expect(s.refreshMailboxes()).resolves.toBeUndefined();
		expect(s.accessRevoked).toBe(true);
		mailboxGet.mockRejectedValueOnce(new Error('own failure'));
		s.accountOverride = null;
		await expect(s.refreshMailboxes()).rejects.toThrow('own failure');
	});

	it('persists sort, tolerates storage denial, and only reloads on a changed focus tab', async () => {
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		const setItem = vi.fn();
		vi.stubGlobal('localStorage', { getItem: vi.fn(), setItem });
		s.selectedEmail = em('selected');
		s.setSort('subject', true);
		await Promise.resolve();
		expect(setItem).toHaveBeenCalledWith('sj-inbox-sort', JSON.stringify({ property: 'subject', ascending: true }));
		expect(s.selectedEmail).toBeNull();
		const calls = emailQuery.mock.calls.length;
		s.setFocusTab('focused');
		expect(emailQuery).toHaveBeenCalledTimes(calls);
		s.setFocusTab('other');
		await Promise.resolve();
		expect(s.focusTab).toBe('other');
		expect(emailQuery.mock.calls.length).toBeGreaterThan(calls);
		setItem.mockImplementationOnce(() => { throw new Error('quota'); });
		expect(() => s.setSort('size', false)).not.toThrow();
		vi.unstubAllGlobals();
	});
});

describe('InboxStore — saved-search folders', () => {
	it('selectSavedSearch sets rawSearch + view=all and clears the tag filter', () => {
		const s = new InboxStore();
		s.mailboxes = MAILBOXES;
		s.view = 'inbox';
		s.tagFilter = 'mb-finance';

		s.selectSavedSearch({ id: '7', name: 'Big', query: 'larger:5M has:attachment', position: 0 });

		expect(s.rawSearch).toBe('larger:5M has:attachment');
		expect(s.view).toBe('all');
		expect(s.tagFilter).toBeNull();
	});

	it('loadSavedSearches fills the list from the client', async () => {
		savedSearchList.mockResolvedValue([{ id: '1', name: 'Unread', query: 'is:unread', position: 0 }]);
		const s = new InboxStore();
		await s.loadSavedSearches();
		expect(savedSearchList).toHaveBeenCalledOnce();
		expect(s.savedSearches.map((x) => x.name)).toEqual(['Unread']);
	});

	it('loadSavedSearches clears the list on error (optional chrome)', async () => {
		savedSearchList.mockRejectedValue(new Error('boom'));
		const s = new InboxStore();
		s.savedSearches = [{ id: '1', name: 'stale', query: 'q', position: 0 }];
		await s.loadSavedSearches();
		expect(s.savedSearches).toEqual([]);
	});

	it('saveSearch persists the current rawSearch, then reloads the list', async () => {
		savedSearchList.mockResolvedValue([{ id: '9', name: 'Finance mail', query: 'tag:finance', position: 0 }]);
		const s = new InboxStore();
		s.rawSearch = 'tag:finance';

		await s.saveSearch('Finance mail');

		expect(savedSearchSet).toHaveBeenCalledWith('Finance mail', 'tag:finance');
		expect(savedSearchList).toHaveBeenCalledOnce();
		expect(s.savedSearches.map((x) => x.name)).toEqual(['Finance mail']);
	});

	it('deleteSavedSearch deletes by id, then reloads the list', async () => {
		const s = new InboxStore();
		await s.deleteSavedSearch('9');
		expect(savedSearchDelete).toHaveBeenCalledWith('9');
		expect(savedSearchList).toHaveBeenCalledOnce();
	});
});

describe('InboxStore.loadThread — conversation-view depth', () => {
	it('fetches the thread and sorts messages oldest→newest into threadEmails', async () => {
		threadGet.mockResolvedValue([{ id: 't1', emailIds: ['a', 'b', 'c'] }]);
		emailGet.mockResolvedValue([
			em('c', { threadId: 't1', receivedAt: '2026-06-14T12:00:00Z' }),
			em('a', { threadId: 't1', receivedAt: '2026-06-14T10:00:00Z' }),
			em('b', { threadId: 't1', receivedAt: '2026-06-14T11:00:00Z' }),
		]);
		const s = new InboxStore();
		const opened = em('a', { threadId: 't1', receivedAt: '2026-06-14T10:00:00Z' });
		s.selectedEmail = opened;

		await s.loadThread(opened);

		expect(threadGet).toHaveBeenCalledWith(['t1'], null);
		expect(s.threadEmails.map((e) => e.id)).toEqual(['a', 'b', 'c']);
	});

	it('falls back to the opened id when Thread/get has no email ids', async () => {
		threadGet.mockResolvedValue([{ id: 't1', emailIds: [] }]);
		emailGet.mockResolvedValue([em('opened', { threadId: 't1' })]);
		const s = new InboxStore();
		const opened = em('opened', { threadId: 't1' });
		s.selectedEmail = opened;
		await s.loadThread(opened);
		expect(emailGet.mock.calls[0][0]).toEqual(['opened']);
	});

	it('drops Email/get results when selection changes after Thread/get', async () => {
		let resolveEmails!: (value: Email[]) => void;
		threadGet.mockResolvedValue([{ id: 't1', emailIds: ['a'] }]);
		emailGet.mockImplementationOnce(() => new Promise((resolve) => { resolveEmails = resolve; }));
		const s = new InboxStore();
		const opened = em('a', { threadId: 't1' });
		s.selectedEmail = opened;
		const pending = s.loadThread(opened);
		await vi.waitFor(() => expect(emailGet).toHaveBeenCalled());
		s.selectedEmail = em('z', { threadId: 'tz' });
		resolveEmails([em('a', { threadId: 't1' })]);
		await pending;
		expect(s.threadEmails).toEqual([]);
	});

	it('uses email.id as the thread id when threadId is absent (single-message thread)', async () => {
		threadGet.mockResolvedValue([{ id: 'solo', emailIds: ['solo'] }]);
		emailGet.mockResolvedValue([em('solo', { receivedAt: '2026-06-14T10:00:00Z' })]);
		const s = new InboxStore();
		const opened = em('solo');
		s.selectedEmail = opened;

		await s.loadThread(opened);

		expect(threadGet).toHaveBeenCalledWith(['solo'], null);
		expect(s.threadEmails.map((e) => e.id)).toEqual(['solo']);
	});

	it('falls back to the single email when the thread fetch fails', async () => {
		threadGet.mockRejectedValue(new Error('boom'));
		const s = new InboxStore();
		const opened = em('x', { threadId: 'tx' });
		s.selectedEmail = opened;

		await s.loadThread(opened);

		expect(s.threadEmails.map((e) => e.id)).toEqual(['x']);
	});

	it('drops the result when a newer open has superseded the thread (race guard)', async () => {
		threadGet.mockResolvedValue([{ id: 't1', emailIds: ['a'] }]);
		emailGet.mockResolvedValue([em('a', { threadId: 't1' })]);
		const s = new InboxStore();
		s.selectedEmail = em('a', { threadId: 't1' });
		const p = s.loadThread(em('a', { threadId: 't1' }));
		// A newer open switches the selection to a different thread before the fetch lands.
		s.selectedEmail = em('z', { threadId: 'tz' });
		await p;
		expect(s.threadEmails).toEqual([]);
	});
});
