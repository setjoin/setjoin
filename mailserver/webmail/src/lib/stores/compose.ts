import { writable } from 'svelte/store';

export interface ComposeAttachment {
	name: string;
	size: number;
	blobId: string;
	type: string;
}

export interface ComposeOpts {
	to?: string;
	cc?: string;
	bcc?: string;
	from?: string;
	/** #13 shared-mailbox use-surface: the delegated mailbox's accountId when
	 *  composing FROM a shared-mailbox workspace — threads through ComposeStore
	 *  to mailboxGet/Email-set/EmailSubmission-set so the draft/send/Sent-copy
	 *  all land in the SHARED mailbox, not the caller's own. Absent = personal. */
	accountId?: string;
	replyToAddr?: string;
	subject?: string;
	body?: string;
	replyTo?: string;
	expanded?: boolean;
	priority?: 'high' | 'normal' | 'low';
	sensitivity?: 'normal' | 'personal' | 'private' | 'confidential';
	categories?: string[];
	attachments?: ComposeAttachment[];
	scheduledAt?: string;
	readReceipt?: boolean;
	flagFollowUp?: boolean;
	voteOptions?: string[];
	voteResponse?: string;
	draftId?: string;
	/** True when the draft is being silently restored (undo-send / reopen),
	 * not opened for intentional editing — drives the "restored" toast. */
	restored?: boolean;
}

/** Gmail-style multi-compose cap. A 4th concurrent compose is refused — the caller
 *  toasts and asks the user to close one (design fix, binding). */
export const MAX_COMPOSE_SESSIONS = 3;

/** One live compose window. Each session drives its OWN mounted ComposeScreen /
 *  ComposeStore (NEVER unmounted while minimized — that would lose in-flight
 *  uploads + editor content; the panel is only CSS-hidden). Exactly one session is
 *  maximized at a time (the one-maximized invariant), enforced by open()/restore(). */
export interface ComposeSession {
	id: number;
	opts: ComposeOpts;
	minimized: boolean;
	/** Dock-bar display metadata, pushed by the mounted ComposeScreen so the
	 *  minimized dock can render subject/recipient + an autosave-error badge
	 *  without reaching into the per-session ComposeStore instance. */
	subject: string;
	recipient: string;
	saveError: boolean;
}

interface ComposeState {
	sessions: ComposeSession[];
}

let nextId = 1;

function createComposeStore() {
	const { subscribe, set, update } = writable<ComposeState>({ sessions: [] });

	return {
		subscribe,
		/**
		 * Open a new maximized compose, minimizing any current maximized one (swap).
		 * Returns the new session id, or `null` when the concurrent-session cap
		 * (MAX_COMPOSE_SESSIONS) is already reached — the caller toasts and asks the
		 * user to close one.
		 */
		open(opts: ComposeOpts = {}): number | null {
			let newId: number | null = null;
			update((s) => {
				if (s.sessions.length >= MAX_COMPOSE_SESSIONS) return s; // capped — no-op
				newId = nextId++;
				const sessions = s.sessions.map((x) => ({ ...x, minimized: true }));
				sessions.push({ id: newId, opts, minimized: false, subject: '', recipient: '', saveError: false });
				return { sessions };
			});
			return newId;
		},
		/** Close a session. No id → close the current maximized one (single-window
		 *  back-compat for the Escape / close-button call sites). */
		close(id?: number) {
			update((s) => {
				const target = id ?? s.sessions.find((x) => !x.minimized)?.id;
				return { sessions: s.sessions.filter((x) => x.id !== target) };
			});
		},
		/** Minimize a session to the dock. No id → minimize the current maximized one. */
		minimize(id?: number) {
			update((s) => {
				const target = id ?? s.sessions.find((x) => !x.minimized)?.id;
				return { sessions: s.sessions.map((x) => (x.id === target ? { ...x, minimized: true } : x)) };
			});
		},
		/** Restore a minimized session, minimizing the current maximized one
		 *  (symmetric swap — the one-maximized invariant holds). */
		restore(id: number) {
			update((s) => ({ sessions: s.sessions.map((x) => ({ ...x, minimized: x.id !== id })) }));
		},
		/** Merge dock-bar display metadata pushed by a mounted ComposeScreen. Returns
		 *  the SAME array reference when nothing changed, so a no-op push does not
		 *  churn subscribers (prevents the meta-effect ↔ store-update feedback loop). */
		setMeta(id: number, patch: Partial<Pick<ComposeSession, 'subject' | 'recipient' | 'saveError'>>) {
			update((s) => {
				const cur = s.sessions.find((x) => x.id === id);
				if (!cur) return s;
				const changed =
					(patch.subject !== undefined && patch.subject !== cur.subject) ||
					(patch.recipient !== undefined && patch.recipient !== cur.recipient) ||
					(patch.saveError !== undefined && patch.saveError !== cur.saveError);
				if (!changed) return s;
				return { sessions: s.sessions.map((x) => (x.id === id ? { ...x, ...patch } : x)) };
			});
		},
		/** Close every session (test teardown / hard reset). */
		reset() {
			set({ sessions: [] });
		}
	};
}

export const composeStore = createComposeStore();

export function reset() {
	composeStore.reset();
}
