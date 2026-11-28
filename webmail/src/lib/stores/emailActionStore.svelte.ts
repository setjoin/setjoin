// EmailActionStore — the inbox's mutation/intent seam (Svelte 5 $state rune class).
//
// Owns the ~13 reading-pane / message-list mutations as a typed `EmailAction`
// union behind a single async `dispatch(action) → DispatchResult`. The page no
// longer wires 23 individual JMAP callbacks into ReadingPane / MessageList — it
// passes one `actions` facade backed by this store. Toast + undo copy STAYS in
// `+page.svelte`: a mutation returns a `Snapshot`, the page shows the toast and,
// on Undo, calls `store.undo(snapshot)` to replay the inverse JMAP patch.
//
// State lives in the InboxStore (the list/view seam, candidate 6). This store
// reaches it through the small `ActionHost` interface so the two stores stay
// decoupled and the action store is unit-testable against a plain host object.

import type { Email, Mailbox } from '$lib/types/jmap';
import { httpRequest } from '$lib/http';
import { loadSession, emailSubmissionCancel, setMessageFocus } from '$lib/jmap/client';
import { emailSet, emailSubmissionSet } from '$lib/jmap/offline-client';
import { applyQuickStep } from '$lib/jmap/quicksteps';
import { stripLocationTags } from '$lib/stores/tagHelpers';

/** Reactive thread bucket shape the host exposes (mirrors InboxStore.InboxThread). */
interface HostThread {
	emails: Email[];
	expanded: boolean;
	muted: boolean;
}

/**
 * The slice of InboxStore this store mutates. The page binds the real InboxStore;
 * tests bind a plain object. Keeping it an interface (not the concrete class)
 * keeps the action seam independently testable and the two stores decoupled.
 */
export interface ActionHost {
	mailboxes: Mailbox[];
	selectedEmail: Email | null;
	emails: Email[];
	threads: Map<string, HostThread>;
	mutating: Set<string>;
	mutedTagId: string | null;
	/** The `Other` pile tag id (Focused/Other split, V078) — used by the focus move. */
	otherTagId: string | null;
	/** #13 shared-mailbox use-surface: non-null while browsing a delegated
	 *  mailbox's workspace — threaded into every JMAP call this store makes. */
	accountOverride: string | null;
	/** #13: set by `dispatch()` when a shared-context call is denied
	 *  (accountNotFound/forbidden) — the page renders the "access removed"
	 *  full-pane state instead of a toast. */
	accessRevoked: boolean;
	loadEmails(reset?: boolean): Promise<void>;
	refreshMailboxes(): Promise<void>;
}

/** The typed reading-pane / message-list mutation union. */
export type EmailAction =
	| { type: 'archive'; email: Email }
	| { type: 'trash'; email: Email }
	| { type: 'snooze'; email: Email; date: Date }
	| { type: 'mute'; email: Email }
	| { type: 'focus'; email: Email; focused: boolean }
	| { type: 'star'; email: Email }
	| { type: 'toggleTag'; email: Email; tagId: string }
	| { type: 'setRead'; email: Email; read: boolean }
	| { type: 'followUp'; email: Email; dueAt: Date; reminderAt: Date | null }
	| { type: 'blockSender'; email: Email }
	| { type: 'notSpam'; email: Email }
	| { type: 'applyQuickStep'; email: Email; id: string }
	| { type: 'recall'; email: Email }
	| { type: 'sendReply'; email: Email; text: string; selfEmail: string }
	| { type: 'cancelScheduled'; emailId: string };

/**
 * Inverse-patch record returned by undoable mutations. The page captures it and,
 * on the toast's Undo, calls `store.undo(snapshot)`.
 *
 * - `prevMailboxIds` set → undo restores the email's prior location set.
 * - For thread-wide mutes, `threadPatch` carries the per-email inverse.
 */
export interface Snapshot {
	emailId: string;
	prevMailboxIds?: Record<string, boolean>;
	/** Per-email inverse mailboxId patch for thread-wide actions (mute). */
	threadPatch?: Record<string, Record<string, boolean>>;
}

/** Result of a recall POST. */
export interface RecallResult {
	ok: boolean;
	status: number;
	recalledCount: number;
}

/** Result of an inline reply submission. */
export interface ReplyResult {
	submissionId: string | null;
	offline: boolean;
}

/**
 * What `dispatch` returns. Undoable mutations yield a `Snapshot`; recall and
 * sendReply yield their own typed result; non-undoable mutations yield `null`.
 */
export type DispatchResult =
	| Snapshot
	| { recall: RecallResult }
	| { reply: ReplyResult }
	| null;

export class EmailActionStore {
	#host: ActionHost;

	/** Per-email tail of in-flight tag writes (see toggleTag). */
	#tagChains = new Map<string, Promise<unknown>>();

	constructor(host: ActionHost) {
		this.#host = host;
	}

	private get host(): ActionHost {
		return this.#host;
	}

	/** Clear the host selection when the dispatched email is the open one. */
	private clearIfSelected(emailId: string): void {
		if (this.host.selectedEmail?.id === emailId) this.host.selectedEmail = null;
	}

	/**
	 * Perform a reading-pane / message-list mutation. Returns a `Snapshot` for
	 * undoable mutations (the page wires the toast), a typed result for recall /
	 * sendReply, or `null`. Errors are rethrown so the page owns the error banner.
	 */
	async dispatch(action: EmailAction): Promise<DispatchResult> {
		try {
			switch (action.type) {
				case 'archive':
					return await this.archive(action.email);
				case 'trash':
					return await this.trash(action.email);
				case 'snooze':
					return await this.snooze(action.email, action.date);
				case 'mute':
					return await this.mute(action.email);
				case 'focus':
					return await this.focus(action.email, action.focused);
				case 'star':
					return await this.star(action.email);
				case 'toggleTag':
					return await this.toggleTag(action.email, action.tagId);
				case 'setRead':
					return await this.setRead(action.email, action.read);
				case 'followUp':
					return await this.followUp(action.email, action.dueAt, action.reminderAt);
				case 'blockSender':
					return await this.blockSender(action.email);
				case 'notSpam':
					return await this.notSpam(action.email);
				case 'applyQuickStep':
					return await this.applyQuickStepAction(action.email, action.id);
				case 'recall':
					return { recall: await this.recall(action.email) };
				case 'sendReply':
					return { reply: await this.sendReply(action.email, action.text, action.selfEmail) };
				case 'cancelScheduled':
					return await this.cancelScheduled(action.emailId);
			}
		} catch (e) {
			// #13: a denied shared-context call (accountNotFound/forbidden — grant
			// revoked mid-session) renders the full-pane "access removed" state
			// instead of a toast loop. Each mutation keeps its own optimistic
			// rollback (this only flags the host state); the error still
			// propagates so the page's undo-toast wiring never fires on a failure.
			if (this.host.accountOverride) this.host.accessRevoked = true;
			throw e;
		}
	}

	/** Replay the inverse JMAP patch for a captured snapshot (the toast's Undo). */
	async undo(snap: Snapshot): Promise<void> {
		try {
			if (snap.threadPatch) {
				const update: Record<string, { mailboxIds: Record<string, boolean> }> = {};
				for (const [id, ids] of Object.entries(snap.threadPatch)) {
					update[id] = { mailboxIds: ids };
				}
				await emailSet(null, update, null, this.host.accountOverride);
			} else if (snap.prevMailboxIds) {
				await emailSet(null, { [snap.emailId]: { mailboxIds: snap.prevMailboxIds } }, null, this.host.accountOverride);
			}
			await this.host.loadEmails();
		} catch {
			/* best effort — the next reload reconciles */
		}
	}

	/** Cancel a previously submitted inline reply (the "Cancel" toast action). */
	async cancelReply(submissionId: string): Promise<void> {
		try {
			await emailSubmissionCancel(submissionId, this.host.accountOverride);
		} catch {
			/* best effort */
		}
	}

	// ── Individual mutations ──

	private async archive(email: Email): Promise<Snapshot> {
		const prevMailboxIds = { ...(email.mailboxIds ?? {}) };
		const filtered = stripLocationTags(prevMailboxIds, this.host.mailboxes);
		await loadSession();
		await emailSet(null, { [email.id]: { mailboxIds: filtered } }, null, this.host.accountOverride);
		this.clearIfSelected(email.id);
		await this.host.loadEmails();
		return { emailId: email.id, prevMailboxIds };
	}

	private async trash(email: Email): Promise<Snapshot> {
		const trashMb = this.host.mailboxes.find((m) => m.role === 'trash');
		const prevMailboxIds = { ...(email.mailboxIds ?? {}) };
		await loadSession();
		if (trashMb) {
			await emailSet(null, { [email.id]: { mailboxIds: { [trashMb.id]: true } } }, null, this.host.accountOverride);
		}
		this.clearIfSelected(email.id);
		await this.host.loadEmails();
		return { emailId: email.id, prevMailboxIds };
	}

	private async snooze(email: Email, date: Date): Promise<Snapshot> {
		const prevMailboxIds = { ...(email.mailboxIds ?? {}) };
		await loadSession();
		await emailSet(null, { [email.id]: { snoozeUntil: date.toISOString() } }, null, this.host.accountOverride);
		this.clearIfSelected(email.id);
		await this.host.loadEmails();
		// Snooze undo moves the email back to Inbox (mirrors the prior page behavior).
		const inboxMb = this.host.mailboxes.find((m) => m.role === 'inbox');
		return {
			emailId: email.id,
			prevMailboxIds: inboxMb ? { [inboxMb.id]: true } : prevMailboxIds,
		};
	}

	private async mute(email: Email): Promise<Snapshot | null> {
		const mutedTagId = this.host.mutedTagId;
		if (!mutedTagId) return null;
		const tid = email.threadId || email.id;
		const thread = this.host.threads.get(tid);
		if (!thread) return null;
		if (this.host.mutating.has(tid)) return null;
		this.host.mutating.add(tid);
		const wasMuted = thread.muted;
		try {
			await loadSession();
			const update: Record<string, { mailboxIds: Record<string, boolean> }> = {};
			const threadPatch: Record<string, Record<string, boolean>> = {};
			for (const e of thread.emails) {
				const current = { ...(e.mailboxIds ?? {}) };
				// inverse patch (for undo) is the pre-mutation set.
				threadPatch[e.id] = { ...current };
				let next: Record<string, boolean>;
				if (wasMuted) {
					// Unmute: drop the Muted tag; leave the thread archived (Gmail parity —
					// Undo restores the full prior set via threadPatch).
					next = { ...current };
					delete next[mutedTagId];
				} else {
					// Mute: archive (strip the Inbox/location tag) AND add Muted, so the
					// thread leaves the Inbox for every client, not just this view. Future
					// replies auto-archive via the deliver() muted-thread check.
					next = stripLocationTags(current, this.host.mailboxes);
					next[mutedTagId] = true;
				}
				update[e.id] = { mailboxIds: next };
			}
			await emailSet(null, update, null, this.host.accountOverride);
			thread.muted = !wasMuted;
			this.host.threads = new Map(this.host.threads);
			// Only muting (not un-muting) offers an Undo.
			return wasMuted ? null : { emailId: email.id, threadPatch };
		} finally {
			this.host.mutating.delete(tid);
		}
	}

	/**
	 * Move a message to Focused (focused=true) or Other (focused=false) in the
	 * Focused/Other split (V078). Optimistically toggles the Other tag on the row's
	 * mailboxIds (so the row flips its label / drops out of the current tab instantly),
	 * POSTs to /messages/{id}/focus (which also learns a per-sender override), then
	 * reloads. Reverts the optimistic patch if the POST fails.
	 */
	private async focus(email: Email, focused: boolean): Promise<null> {
		const otherTagId = this.host.otherTagId;
		if (!otherTagId) return null;
		const prev = { ...(email.mailboxIds ?? {}) };
		const next = { ...prev };
		if (focused) delete next[otherTagId];
		else next[otherTagId] = true;
		email.mailboxIds = next;
		try {
			await setMessageFocus(email.id, focused);
		} catch (e) {
			email.mailboxIds = prev;
			throw e;
		}
		await this.host.loadEmails();
		return null;
	}

	private async star(email: Email): Promise<null> {
		const wasFlagged = email.keywords?.['$flagged'] || false;
		email.keywords = { ...email.keywords, $flagged: !wasFlagged };
		try {
			await loadSession();
			await emailSet(null, { [email.id]: { keywords: { $flagged: !wasFlagged } } }, null, this.host.accountOverride);
		} catch (e) {
			email.keywords = { ...email.keywords, $flagged: wasFlagged };
			throw e;
		}
		return null;
	}

	private toggleTag(email: Email, tagId: string): Promise<Snapshot | null> {
		// Serialize tag writes PER EMAIL: Email/set replaces the WHOLE mailboxIds
		// map (jmap_email_set_update deletes all tags then re-inserts the map), so
		// two overlapping read-modify-write toggles are last-writer-wins — the
		// first request to commit last silently drops the other tag. Queue each
		// toggle behind the previous one so `prev` is read post-commit.
		// ponytail: single-client serialization; cross-tab/device rapid tagging
		// still races — upgrade path is RFC 8620 patch paths (mailboxIds/<id>).
		const tail = this.#tagChains.get(email.id) ?? Promise.resolve();
		const run = tail.then(
			() => this.doToggleTag(email, tagId),
			() => this.doToggleTag(email, tagId),
		);
		this.#tagChains.set(email.id, run.catch(() => undefined));
		return run;
	}

	private async doToggleTag(email: Email, tagId: string): Promise<Snapshot | null> {
		if (this.host.mutating.has(tagId)) return null;
		const prev = { ...(email.mailboxIds ?? {}) };
		const next = { ...prev };
		const wasRemoved = !!next[tagId];
		if (next[tagId]) delete next[tagId];
		else next[tagId] = true;
		email.mailboxIds = next;
		this.host.mutating.add(tagId);
		try {
			await loadSession();
			await emailSet(null, { [email.id]: { mailboxIds: next } }, null, this.host.accountOverride);
			// Only removal offers an Undo (adding a tag is trivially reversible by the user).
			return wasRemoved ? { emailId: email.id, prevMailboxIds: prev } : null;
		} catch (e) {
			email.mailboxIds = prev;
			throw e;
		} finally {
			this.host.mutating.delete(tagId);
		}
	}

	private async setRead(email: Email, read: boolean): Promise<null> {
		const prev = email.keywords?.['$seen'] ?? false;
		if (prev === read) return null;
		email.keywords = { ...email.keywords, $seen: read };
		try {
			await loadSession();
			await emailSet(null, { [email.id]: { keywords: { ...email.keywords, $seen: read } } }, null, this.host.accountOverride);
			await this.host.refreshMailboxes();
		} catch (e) {
			email.keywords = { ...email.keywords, $seen: prev };
			throw e;
		}
		return null;
	}

	private async followUp(email: Email, dueAt: Date, reminderAt: Date | null): Promise<null> {
		await loadSession();
		await emailSet(
			null,
			{
				[email.id]: {
					keywords: { ...email.keywords, $flagged: true },
					flagDueAt: dueAt.toISOString(),
					flagReminderAt: reminderAt ? reminderAt.toISOString() : null,
				},
			},
			null,
			this.host.accountOverride,
		);
		email.keywords = { ...email.keywords, $flagged: true };
		email.flagDueAt = dueAt.toISOString();
		email.flagReminderAt = reminderAt ? reminderAt.toISOString() : undefined;
		return null;
	}

	private async blockSender(email: Email): Promise<Snapshot | null> {
		const spamMb = this.host.mailboxes.find((m) => m.role === 'spam' || m.role === 'junk');
		if (!spamMb) return null;
		const prevMailboxIds = { ...(email.mailboxIds ?? {}) };
		await loadSession();
		await emailSet(null, { [email.id]: { mailboxIds: { [spamMb.id]: true } } }, null, this.host.accountOverride);
		this.clearIfSelected(email.id);
		await this.host.loadEmails();
		await this.host.refreshMailboxes();
		return { emailId: email.id, prevMailboxIds };
	}

	private async notSpam(email: Email): Promise<null> {
		const inboxMb = this.host.mailboxes.find((m) => m.role === 'inbox');
		if (!inboxMb) return null;
		await emailSet(null, { [email.id]: { mailboxIds: { [inboxMb.id]: true } } }, null, this.host.accountOverride);
		await this.host.loadEmails();
		return null;
	}

	private async applyQuickStepAction(email: Email, id: string): Promise<null> {
		await applyQuickStep(id, email.id);
		await this.host.loadEmails();
		await this.host.refreshMailboxes();
		return null;
	}

	private async recall(email: Email): Promise<RecallResult> {
		// Routes through httpRequest for the shared timeout/abort, but recall NEVER
		// throws on non-ok — it returns {ok,status,recalledCount} for every status
		// (the page maps verdict→status). httpRequest throws on non-ok, so onError
		// captures the Response and we recover it instead of propagating the throw.
		let nonOk: Response | null = null;
		const res = await httpRequest(`/api/messages/${email.id}/recall`, {
			method: 'POST',
			loginRedirect: null,
			onError: (r) => {
				nonOk = r;
				return '';
			},
		}).catch((err) => {
			if (nonOk) return nonOk;
			throw err;
		});
		let recalledCount = 0;
		if (res.ok) {
			try {
				const data = await res.json();
				recalledCount = data.recalled_count ?? 0;
			} catch {
				/* tolerate empty body */
			}
		}
		return { ok: res.ok, status: res.status, recalledCount };
	}

	private async sendReply(email: Email, text: string, selfEmail: string): Promise<ReplyResult> {
		const toAddr = email.from?.[0]?.email || '';
		const draftsMb = this.host.mailboxes.find((m) => m.role === 'drafts');
		const subject = email.subject?.startsWith('Re:')
			? email.subject
			: 'Re: ' + (email.subject || '');

		await loadSession();
		const msg: Partial<Email> & Record<string, unknown> = {
			mailboxIds: draftsMb ? { [draftsMb.id]: true } : {},
			from: selfEmail ? [{ email: selfEmail }] : undefined,
			to: toAddr ? [{ email: toAddr }] : [],
			subject,
			inReplyTo: email.id,
			bodyValues: { text: { value: text, partId: 'text' } },
			textBody: [{ partId: 'text', type: 'text/plain' }],
		};
		const created = await emailSet({ 'reply-1': msg }, null, null, this.host.accountOverride);
		if ('offline' in created) {
			return { submissionId: null, offline: true };
		}
		const replyId = created.created?.['reply-1']?.id;
		if (!replyId) throw new Error('Failed to create reply');

		await emailSubmissionSet({
			'sub-1': {
				emailId: replyId,
				envelope: {
					mailFrom: { email: selfEmail || 'unknown@unknown' },
					rcptTo: toAddr ? [{ email: toAddr }] : [],
				},
				onSendUndoWindowSeconds: 5,
			},
		}, this.host.accountOverride);
		return { submissionId: replyId, offline: false };
	}

	private async cancelScheduled(emailId: string): Promise<null> {
		if (this.host.mutating.has(emailId)) return null;
		this.host.mutating.add(emailId);
		try {
			await loadSession();
			await emailSubmissionCancel(emailId, this.host.accountOverride);
			await this.host.loadEmails();
		} finally {
			this.host.mutating.delete(emailId);
		}
		return null;
	}
}
