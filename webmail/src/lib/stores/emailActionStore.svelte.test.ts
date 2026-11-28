import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Email, Mailbox } from '$lib/types/jmap';

// ── JMAP client / offline-client mocks ──
const loadSession = vi.fn();
const emailSubmissionCancel = vi.fn();
const setMessageFocus = vi.fn();
const emailSet = vi.fn();
const emailSubmissionSet = vi.fn();
const applyQuickStep = vi.fn();

vi.mock('$lib/jmap/client', () => ({
	loadSession: (...a: unknown[]) => loadSession(...a),
	emailSubmissionCancel: (...a: unknown[]) => emailSubmissionCancel(...a),
	setMessageFocus: (...a: unknown[]) => setMessageFocus(...a),
}));
vi.mock('$lib/jmap/offline-client', () => ({
	emailSet: (...a: unknown[]) => emailSet(...a),
	emailSubmissionSet: (...a: unknown[]) => emailSubmissionSet(...a),
}));
vi.mock('$lib/jmap/quicksteps', () => ({
	applyQuickStep: (...a: unknown[]) => applyQuickStep(...a),
}));

import { EmailActionStore, type Snapshot, type DispatchResult } from './emailActionStore.svelte';

/** Narrow a dispatch result to a Snapshot (or null) for the undoable-mutation tests. */
function asSnap(r: DispatchResult): Snapshot | null {
	return r as Snapshot | null;
}

// ── Fixtures ──
function mb(id: string, overrides: Partial<Mailbox> = {}): Mailbox {
	return { id, name: id, ...overrides };
}
function em(id: string, overrides: Partial<Email> = {}): Email {
	return { id, mailboxIds: {}, threadId: id, keywords: {}, ...overrides };
}

const MAILBOXES: Mailbox[] = [
	mb('mb-inbox', { role: 'inbox', name: 'Inbox' }),
	mb('mb-sent', { role: 'sent', name: 'Sent' }),
	mb('mb-trash', { role: 'trash', name: 'Trash' }),
	mb('mb-spam', { role: 'spam', name: 'Spam' }),
	mb('mb-drafts', { role: 'drafts', name: 'Drafts' }),
	mb('mb-finance', { name: 'Finance', color: 'green' }),
	mb('mb-muted', { name: 'Muted' }),
	mb('mb-other', { name: 'Other' }),
];

/**
 * A minimal InboxStore-like host. EmailActionStore reads/writes through this seam
 * so the page binds the real InboxStore and the test binds a plain object.
 */
function makeHost(over: Partial<Record<string, unknown>> = {}) {
	return {
		mailboxes: MAILBOXES,
		selectedEmail: null as Email | null,
		emails: [] as Email[],
		threads: new Map(),
		mutating: new Set<string>(),
		mutedTagId: 'mb-muted' as string | null,
		otherTagId: 'mb-other',
		accountOverride: null as string | null,
		accessRevoked: false,
		loadEmails: vi.fn().mockResolvedValue(undefined),
		refreshMailboxes: vi.fn().mockResolvedValue(undefined),
		...over,
	};
}

beforeEach(() => {
	loadSession.mockReset().mockResolvedValue(undefined);
	emailSubmissionCancel.mockReset().mockResolvedValue(undefined);
	emailSet.mockReset().mockResolvedValue({ created: {} });
	emailSubmissionSet.mockReset().mockResolvedValue({ created: {} });
	applyQuickStep.mockReset().mockResolvedValue(undefined);
	setMessageFocus.mockReset().mockResolvedValue(undefined);
});

describe('EmailActionStore.dispatch — focus (Focused/Other split, V078)', () => {
	it('move to Other: adds the Other tag optimistically, POSTs focused=false, reloads', async () => {
		const target = em('e1', { mailboxIds: { 'mb-inbox': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const res = await store.dispatch({ type: 'focus', email: target, focused: false });

		expect(res).toBeNull();
		expect(target.mailboxIds).toEqual({ 'mb-inbox': true, 'mb-other': true });
		expect(setMessageFocus).toHaveBeenCalledWith('e1', false);
		expect(host.loadEmails).toHaveBeenCalled();
	});

	it('move to Focused: removes the Other tag optimistically and POSTs focused=true', async () => {
		const target = em('e2', { mailboxIds: { 'mb-inbox': true, 'mb-other': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		await store.dispatch({ type: 'focus', email: target, focused: true });

		expect(target.mailboxIds).toEqual({ 'mb-inbox': true });
		expect(setMessageFocus).toHaveBeenCalledWith('e2', true);
	});

	it('reverts the optimistic tag change when the POST fails', async () => {
		setMessageFocus.mockRejectedValueOnce(new Error('boom'));
		const target = em('e3', { mailboxIds: { 'mb-inbox': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		await expect(store.dispatch({ type: 'focus', email: target, focused: false })).rejects.toThrow('boom');
		expect(target.mailboxIds).toEqual({ 'mb-inbox': true });
		expect(host.loadEmails).not.toHaveBeenCalled();
	});
});

describe('EmailActionStore.dispatch — archive', () => {
	it('strips the location tag, clears the selection, reloads, and returns an undo snapshot', async () => {
		const target = em('e1', { mailboxIds: { 'mb-inbox': true, 'mb-finance': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const snap = asSnap(await store.dispatch({ type: 'archive', email: target }));

		expect(loadSession).toHaveBeenCalled();
		// archive = strip location tags (mb-inbox removed, mb-finance kept).
		const patch = emailSet.mock.calls[0][1] as Record<string, { mailboxIds: Record<string, boolean> }>;
		expect(patch['e1'].mailboxIds).toEqual({ 'mb-finance': true });
		expect(host.selectedEmail).toBeNull();
		expect(host.loadEmails).toHaveBeenCalled();
		// snapshot carries the prior mailboxIds for undo.
		expect(snap).not.toBeNull();
		expect(snap!.prevMailboxIds).toEqual({ 'mb-inbox': true, 'mb-finance': true });
	});

	it('undo restores the prior mailboxIds and reloads', async () => {
		const target = em('e1', { mailboxIds: { 'mb-inbox': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);
		const snap = asSnap(await store.dispatch({ type: 'archive', email: target }));
		emailSet.mockClear();
		host.loadEmails.mockClear();

		await store.undo(snap!);

		const patch = emailSet.mock.calls[0][1] as Record<string, { mailboxIds: Record<string, boolean> }>;
		expect(patch['e1'].mailboxIds).toEqual({ 'mb-inbox': true });
		expect(host.loadEmails).toHaveBeenCalled();
	});
});

describe('EmailActionStore.dispatch — trash', () => {
	it('moves the email into Trash and snapshots the prior location for undo', async () => {
		const target = em('e1', { mailboxIds: { 'mb-inbox': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const snap = asSnap(await store.dispatch({ type: 'trash', email: target }));

		const patch = emailSet.mock.calls[0][1] as Record<string, { mailboxIds: Record<string, boolean> }>;
		expect(patch['e1'].mailboxIds).toEqual({ 'mb-trash': true });
		expect(host.selectedEmail).toBeNull();
		expect(snap!.prevMailboxIds).toEqual({ 'mb-inbox': true });
	});
});

describe('EmailActionStore.dispatch — snooze', () => {
	it('sets snoozeUntil, clears the selection, and returns a snapshot keyed by id', async () => {
		const when = new Date('2026-07-01T09:00:00Z');
		const target = em('e1', { mailboxIds: { 'mb-inbox': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const snap = asSnap(await store.dispatch({ type: 'snooze', email: target, date: when }));

		const patch = emailSet.mock.calls[0][1] as Record<string, { snoozeUntil: string }>;
		expect(patch['e1'].snoozeUntil).toBe(when.toISOString());
		expect(host.selectedEmail).toBeNull();
		expect(snap!.emailId).toBe('e1');
	});
});

describe('EmailActionStore.dispatch — star', () => {
	it('toggles $flagged optimistically and persists, returning no undo snapshot', async () => {
		const target = em('e1', { keywords: {} });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const snap = await store.dispatch({ type: 'star', email: target });

		const patch = emailSet.mock.calls[0][1] as Record<string, { keywords: Record<string, boolean> }>;
		expect(patch['e1'].keywords.$flagged).toBe(true);
		expect(target.keywords?.$flagged).toBe(true);
		expect(snap).toBeNull();
	});

	it('rolls back the optimistic flag and rethrows so the page owns the error banner', async () => {
		emailSet.mockRejectedValueOnce(new Error('boom'));
		const target = em('e1', { keywords: { $flagged: true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		// The store rethrows; the page's dispatch wrapper catches it into store.error.
		await expect(store.dispatch({ type: 'star', email: target })).rejects.toThrow('boom');
		expect(target.keywords?.$flagged).toBe(true); // rolled back to prior value
	});
});

describe('EmailActionStore.dispatch — toggleTag', () => {
	it('adds a tag when absent and removes when present (snapshot only on removal)', async () => {
		const target = em('e1', { mailboxIds: {} });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		// add → no undo snapshot
		const addSnap = asSnap(await store.dispatch({ type: 'toggleTag', email: target, tagId: 'mb-finance' }));
		expect(target.mailboxIds?.['mb-finance']).toBe(true);
		expect(addSnap).toBeNull();

		// remove → returns a snapshot so the page can offer Undo
		const removeSnap = asSnap(await store.dispatch({ type: 'toggleTag', email: target, tagId: 'mb-finance' }));
		expect(target.mailboxIds?.['mb-finance']).toBeUndefined();
		expect(removeSnap).not.toBeNull();
		expect(removeSnap!.prevMailboxIds?.['mb-finance']).toBe(true);
	});

	it('serializes overlapping toggles on one email so the second write carries the first tag', async () => {
		// Email/set replaces the WHOLE mailboxIds map server-side, so if toggle B
		// computed its map before toggle A committed, B's write would drop A
		// (last-writer-wins). The store must queue B behind A.
		const target = em('e1', { mailboxIds: {} });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		// Hold A's emailSet open until B has been dispatched.
		let releaseA!: () => void;
		emailSet.mockImplementationOnce(
			() => new Promise((resolve) => { releaseA = () => resolve({} as never); }),
		);

		const a = store.dispatch({ type: 'toggleTag', email: target, tagId: 'tag-a' });
		const b = store.dispatch({ type: 'toggleTag', email: target, tagId: 'tag-b' });
		await vi.waitFor(() => expect(emailSet).toHaveBeenCalledTimes(1)); // A in flight, B queued
		releaseA();
		await Promise.all([a, b]);

		const patchB = emailSet.mock.calls[1][1] as Record<string, { mailboxIds: Record<string, boolean> }>;
		expect(patchB['e1'].mailboxIds).toEqual({ 'tag-a': true, 'tag-b': true });
		expect(target.mailboxIds).toEqual({ 'tag-a': true, 'tag-b': true });
	});
});

describe('EmailActionStore.dispatch — setRead', () => {
	it('patches $seen and refreshes mailbox counts; no-ops when already in the desired state', async () => {
		const target = em('e1', { keywords: { $seen: false } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		await store.dispatch({ type: 'setRead', email: target, read: true });
		const patch = emailSet.mock.calls[0][1] as Record<string, { keywords: Record<string, boolean> }>;
		expect(patch['e1'].keywords.$seen).toBe(true);
		expect(host.refreshMailboxes).toHaveBeenCalled();

		emailSet.mockClear();
		await store.dispatch({ type: 'setRead', email: target, read: true });
		expect(emailSet).not.toHaveBeenCalled(); // already read → no-op
	});
});

describe('EmailActionStore.dispatch — blockSender', () => {
	it('moves the email to Spam and returns an undo snapshot', async () => {
		const target = em('e1', { mailboxIds: { 'mb-inbox': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const snap = asSnap(await store.dispatch({ type: 'blockSender', email: target }));

		const patch = emailSet.mock.calls[0][1] as Record<string, { mailboxIds: Record<string, boolean> }>;
		expect(patch['e1'].mailboxIds).toEqual({ 'mb-spam': true });
		expect(host.selectedEmail).toBeNull();
		expect(snap!.prevMailboxIds).toEqual({ 'mb-inbox': true });
	});
});

describe('EmailActionStore.dispatch — notSpam', () => {
	it('moves the email back to Inbox and reloads', async () => {
		const target = em('e1', { mailboxIds: { 'mb-spam': true } });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		await store.dispatch({ type: 'notSpam', email: target });

		const patch = emailSet.mock.calls[0][1] as Record<string, { mailboxIds: Record<string, boolean> }>;
		expect(patch['e1'].mailboxIds).toEqual({ 'mb-inbox': true });
		expect(host.loadEmails).toHaveBeenCalled();
	});
});

describe('EmailActionStore.dispatch — applyQuickStep', () => {
	it('runs the macro, reloads, and refreshes counts (guards re-entry)', async () => {
		const target = em('e1');
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		await store.dispatch({ type: 'applyQuickStep', email: target, id: 'qs1' });

		expect(applyQuickStep).toHaveBeenCalledWith('qs1', 'e1');
		expect(host.loadEmails).toHaveBeenCalled();
		expect(host.refreshMailboxes).toHaveBeenCalled();
	});
});

describe('EmailActionStore.dispatch — recall', () => {
	it('POSTs the recall endpoint and returns the parsed result', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ recalled_count: 3 }),
		});
		vi.stubGlobal('fetch', fetchMock);
		const target = em('e1');
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const res = await store.dispatch({ type: 'recall', email: target });

		expect(fetchMock).toHaveBeenCalledWith('/api/messages/e1/recall', expect.objectContaining({ method: 'POST' }));
		expect(res).toEqual({ recall: { ok: true, status: 200, recalledCount: 3 } });
		vi.unstubAllGlobals();
	});
});

describe('EmailActionStore.dispatch — sendReply', () => {
	it('creates a reply draft and submits it with a 5s undo window, returning the submission id', async () => {
		emailSet.mockResolvedValueOnce({ created: { 'reply-1': { id: 'eReply' } } });
		const target = em('e1', { subject: 'Hi', from: [{ email: 'alice@example.com' }] });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const res = await store.dispatch({
			type: 'sendReply',
			email: target,
			text: 'thanks',
			selfEmail: 'me@setjoin.local',
		});

		const created = emailSet.mock.calls[0][0] as Record<string, { subject: string; inReplyTo: string }>;
		expect(created['reply-1'].subject).toBe('Re: Hi');
		expect(created['reply-1'].inReplyTo).toBe('e1');
		const sub = emailSubmissionSet.mock.calls[0][0] as Record<string, { emailId: string; onSendUndoWindowSeconds: number }>;
		expect(sub['sub-1'].emailId).toBe('eReply');
		expect(sub['sub-1'].onSendUndoWindowSeconds).toBe(5);
		expect(res).toEqual({ reply: { submissionId: 'eReply', offline: false } });
	});

	it('reports an offline queue without submitting', async () => {
		emailSet.mockResolvedValueOnce({ offline: true });
		const target = em('e1', { from: [{ email: 'alice@example.com' }] });
		const host = makeHost({ selectedEmail: target });
		const store = new EmailActionStore(host as never);

		const res = await store.dispatch({ type: 'sendReply', email: target, text: 'hi', selfEmail: 'me@x' });
		expect(emailSubmissionSet).not.toHaveBeenCalled();
		expect(res).toEqual({ reply: { submissionId: null, offline: true } });
	});
});

describe('EmailActionStore.cancelReply', () => {
	it('cancels a previously submitted reply', async () => {
		const host = makeHost();
		const store = new EmailActionStore(host as never);
		await store.cancelReply('eReply');
		expect(emailSubmissionCancel).toHaveBeenCalledWith('eReply', null);
	});

	it('treats cancellation failure as best effort', async () => {
		emailSubmissionCancel.mockRejectedValueOnce(new Error('already sent'));
		const store = new EmailActionStore(makeHost() as never);
		await expect(store.cancelReply('gone')).resolves.toBeUndefined();
	});
});

describe('EmailActionStore uncovered mutation and recovery paths', () => {
	it('mutes an entire thread, strips location tags, and returns a per-email inverse', async () => {
		const first = em('e1', { threadId: 't1', mailboxIds: { 'mb-inbox': true, 'mb-finance': true } });
		const second = em('e2', { threadId: 't1', mailboxIds: { 'mb-inbox': true } });
		const thread = { emails: [first, second], expanded: true, muted: false };
		const host = makeHost({ threads: new Map([['t1', thread]]) });
		const store = new EmailActionStore(host as never);
		const result = asSnap(await store.dispatch({ type: 'mute', email: first }));

		const update = emailSet.mock.calls[0][1];
		expect(update.e1.mailboxIds).toEqual({ 'mb-finance': true, 'mb-muted': true });
		expect(update.e2.mailboxIds).toEqual({ 'mb-muted': true });
		expect(result?.threadPatch).toEqual({
			e1: { 'mb-inbox': true, 'mb-finance': true },
			e2: { 'mb-inbox': true },
		});
		expect(thread.muted).toBe(true);
		expect(host.mutating.size).toBe(0);
	});

	it('unmutes without an undo snapshot and guards missing or busy threads', async () => {
		const target = em('e1', { threadId: 't1', mailboxIds: { 'mb-muted': true, 'mb-finance': true } });
		const thread = { emails: [target], expanded: false, muted: true };
		const host = makeHost({ threads: new Map([['t1', thread]]) });
		const store = new EmailActionStore(host as never);
		expect(await store.dispatch({ type: 'mute', email: target })).toBeNull();
		expect(emailSet.mock.calls[0][1].e1.mailboxIds).toEqual({ 'mb-finance': true });

		host.mutedTagId = null;
		expect(await store.dispatch({ type: 'mute', email: target })).toBeNull();
		host.mutedTagId = 'mb-muted';
		host.threads.clear();
		expect(await store.dispatch({ type: 'mute', email: target })).toBeNull();
		host.threads.set('t1', thread);
		host.mutating.add('t1');
		expect(await store.dispatch({ type: 'mute', email: target })).toBeNull();
	});

	it('undoes a thread patch, ignores empty snapshots, and tolerates replay failure', async () => {
		const host = makeHost({ accountOverride: 'shared-1' });
		const store = new EmailActionStore(host as never);
		await store.undo({ emailId: 'e1', threadPatch: { e1: { inbox: true }, e2: { archive: true } } });
		expect(emailSet).toHaveBeenCalledWith(null, {
			e1: { mailboxIds: { inbox: true } },
			e2: { mailboxIds: { archive: true } },
		}, null, 'shared-1');
		await store.undo({ emailId: 'empty' });
		emailSet.mockRejectedValueOnce(new Error('offline'));
		await expect(store.undo({ emailId: 'e3', prevMailboxIds: { inbox: true } })).resolves.toBeUndefined();
	});

	it('uses prior snooze locations when Inbox is absent and tolerates Trash/Spam/Inbox absence', async () => {
		const target = em('e1', { mailboxIds: { archive: true } });
		const host = makeHost({ mailboxes: [] });
		const store = new EmailActionStore(host as never);
		const snooze = asSnap(await store.dispatch({ type: 'snooze', email: target, date: new Date('2026-08-01T00:00:00Z') }));
		expect(snooze?.prevMailboxIds).toEqual({ archive: true });
		emailSet.mockClear();
		expect(await store.dispatch({ type: 'trash', email: target })).toMatchObject({ prevMailboxIds: { archive: true } });
		expect(emailSet).not.toHaveBeenCalled();
		expect(await store.dispatch({ type: 'blockSender', email: target })).toBeNull();
		expect(await store.dispatch({ type: 'notSpam', email: target })).toBeNull();
	});

	it('persists follow-up deadlines with and without reminders', async () => {
		const target = em('e1');
		const store = new EmailActionStore(makeHost() as never);
		const due = new Date('2026-09-01T12:00:00Z');
		const reminder = new Date('2026-09-01T11:00:00Z');
		await store.dispatch({ type: 'followUp', email: target, dueAt: due, reminderAt: reminder });
		expect(target).toMatchObject({ flagDueAt: due.toISOString(), flagReminderAt: reminder.toISOString() });
		await store.dispatch({ type: 'followUp', email: target, dueAt: due, reminderAt: null });
		expect(target.flagReminderAt).toBeUndefined();
	});

	it('rolls back failed read and tag mutations and releases their guards', async () => {
		const target = em('e1', { keywords: { $seen: false }, mailboxIds: { old: true } });
		const host = makeHost();
		const store = new EmailActionStore(host as never);
		emailSet.mockRejectedValueOnce(new Error('read failed'));
		await expect(store.dispatch({ type: 'setRead', email: target, read: true })).rejects.toThrow('read failed');
		expect(target.keywords?.$seen).toBe(false);

		emailSet.mockRejectedValueOnce(new Error('tag failed'));
		await expect(store.dispatch({ type: 'toggleTag', email: target, tagId: 'new' })).rejects.toThrow('tag failed');
		expect(target.mailboxIds).toEqual({ old: true });
		expect(host.mutating.has('new')).toBe(false);
		host.mutating.add('busy');
		expect(await store.dispatch({ type: 'toggleTag', email: target, tagId: 'busy' })).toBeNull();
	});

	it('marks shared access revoked when a shared-context mutation fails', async () => {
		const host = makeHost({ accountOverride: 'shared-1' });
		const store = new EmailActionStore(host as never);
		emailSet.mockRejectedValueOnce(new Error('forbidden'));
		await expect(store.dispatch({ type: 'archive', email: em('e1') })).rejects.toThrow('forbidden');
		expect(host.accessRevoked).toBe(true);
	});

	it('returns recall verdicts for non-ok, malformed, and empty responses', async () => {
		const store = new EmailActionStore(makeHost() as never);
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({ ok: false, status: 409, text: async () => 'conflict', json: async () => ({}) })
			.mockResolvedValueOnce({ ok: true, status: 200, json: async () => { throw new Error('empty'); } });
		vi.stubGlobal('fetch', fetchMock);
		expect(await store.dispatch({ type: 'recall', email: em('e1') })).toEqual({ recall: { ok: false, status: 409, recalledCount: 0 } });
		expect(await store.dispatch({ type: 'recall', email: em('e2') })).toEqual({ recall: { ok: true, status: 200, recalledCount: 0 } });
		vi.unstubAllGlobals();
	});

	it('builds reply fallbacks and rejects an Email/set response without an id', async () => {
		const host = makeHost({ mailboxes: [] });
		const store = new EmailActionStore(host as never);
		emailSet.mockResolvedValueOnce({ created: { 'reply-1': { id: 'r1' } } });
		await store.dispatch({ type: 'sendReply', email: em('e1', { subject: 'Re: Existing' }), text: 'ok', selfEmail: '' });
		const msg = emailSet.mock.calls[0][0]['reply-1'];
		expect(msg).toMatchObject({ mailboxIds: {}, from: undefined, to: [], subject: 'Re: Existing' });
		expect(emailSubmissionSet.mock.calls[0][0]['sub-1'].envelope).toEqual({
			mailFrom: { email: 'unknown@unknown' }, rcptTo: [],
		});

		emailSet.mockResolvedValueOnce({ created: {} });
		await expect(store.dispatch({ type: 'sendReply', email: em('e2'), text: 'x', selfEmail: 'me@x.test' })).rejects.toThrow(/create reply/i);
	});

	it('serializes scheduled cancellation and always releases the mutation guard', async () => {
		const host = makeHost({ accountOverride: 'shared-1' });
		const store = new EmailActionStore(host as never);
		host.mutating.add('busy');
		expect(await store.dispatch({ type: 'cancelScheduled', emailId: 'busy' })).toBeNull();
		emailSubmissionCancel.mockRejectedValueOnce(new Error('cannot cancel'));
		await expect(store.dispatch({ type: 'cancelScheduled', emailId: 'e1' })).rejects.toThrow('cannot cancel');
		expect(host.mutating.has('e1')).toBe(false);
		emailSubmissionCancel.mockResolvedValueOnce(undefined);
		await store.dispatch({ type: 'cancelScheduled', emailId: 'e2' });
		expect(emailSubmissionCancel).toHaveBeenLastCalledWith('e2', 'shared-1');
		expect(host.loadEmails).toHaveBeenCalled();
	});
});
