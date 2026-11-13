// InboxStore — the inbox surface's state owner (Svelte 5 $state rune class).
//
// Promotes the former `inboxModel.ts` page-local let-declarations into a single
// reactive seam: the ~23 inbox state vars + the $derived projections (counts,
// selectedRole, flatForView, effectiveViewMode, threadList) + the Email/query
// data flow + the Email/Mailbox WebSocket push subscription (with its 300ms
// debounce). `routes/inbox/+page.svelte` instantiates this once and binds the
// template to its fields; the page keeps the JMAP *mutations* (archive/trash/
// snooze/tag/reply, undo toasts) and the DOM glue.
//
// Pure helpers stay in `inboxModel.ts` (computeCounts, computeListFilter,
// resolveViewMailbox, selectionFromUrl, replyAllRecipients, isMonoBody) — they
// remain independently unit-tested there.

import type { Email, EmailBundle, Mailbox } from '$lib/types/jmap';
import type { ViewId } from '$lib/components/mail/MailSidebar.svelte';
import type { ReceiptPolicy } from '$lib/mail/readReceipt';
import type { QuickStep, SavedSearch } from '$lib/types/jmap';
import { savedSearchList, savedSearchSet, savedSearchDelete } from '$lib/jmap/savedsearches';
import {
	loadSession,
	mailboxGet,
	emailQuery,
	emailGet,
	emailGetWithState,
	emailChanges,
	mailboxState,
	isJmapMethodError,
	emailSubmissionQuery,
	emailSubmissionGet,
	emailBundles,
	searchSnippetGet,
	threadGet,
	FULL_EMAIL_PROPS,
} from '$lib/jmap/client';
import { loadList, searchList } from '$lib/offline/readpath';
import { offline } from '$lib/offline/state.svelte';
import { PushHandlerStore, type PushChanges } from '$lib/stores/pushHandler.svelte';
import { parseSearch } from '$lib/stores/searchQuery';
import {
	computeCounts,
	computeListFilter,
	resolveViewMailbox,
	type MailCounts,
} from '$lib/stores/inboxModel';

/** Reactive thread bucket: the emails of a thread plus its UI flags. */
export interface InboxThread {
	emails: Email[];
	expanded: boolean;
	muted: boolean;
}

/** Flattened thread shape consumed by `MessageList`. */
export interface InboxThreadItem extends InboxThread {
	id: string;
}

const WS_DEBOUNCE_MS = 300;
/** The JMAP data types the inbox list depends on (push subscription + skip rule). */
const INBOX_PUSH_TYPES = ['Email', 'Mailbox'] as const;
/** One bounded Email/changes page is enough to answer "did anything change". */
const RESYNC_MAX_CHANGES = 64;

/** Email/query sort whitelist — must match jmap_email.sql's ORDER BY CASE
 *  (receivedAt/sentAt/size/subject/from; asc/desc + pinned-first applied server-side). */
const SORT_PROPERTIES = ['receivedAt', 'sentAt', 'size', 'subject', 'from'] as const;
const SORT_STORAGE_KEY = 'sj-inbox-sort';

/** Read the persisted list-sort preference; falls back to receivedAt/desc. */
function loadSortPref(): { property: string; ascending: boolean } {
	const fallback = { property: 'receivedAt', ascending: false };
	if (typeof localStorage === 'undefined') return fallback;
	try {
		const raw = localStorage.getItem(SORT_STORAGE_KEY);
		if (!raw) return fallback;
		const p = JSON.parse(raw) as { property?: unknown; ascending?: unknown };
		if (
			typeof p.property === 'string' &&
			(SORT_PROPERTIES as readonly string[]).includes(p.property) &&
			typeof p.ascending === 'boolean'
		) {
			return { property: p.property, ascending: p.ascending };
		}
	} catch {
		/* ignore malformed pref */
	}
	return fallback;
}

export class InboxStore {
	// ── $state (the ~23 inbox vars formerly in +page.svelte) ──
	mailboxes = $state<Mailbox[]>([]);
	emails = $state<Email[]>([]);
	threads = $state<Map<string, InboxThread>>(new Map());
	selectedEmail = $state<Email | null>(null);
	/**
	 * Conversation-view depth: the full thread of `selectedEmail`, oldest→newest,
	 * with bodies, for the stacked message cards in the reading pane. Fetched fresh
	 * via loadThread (Thread/get + Email/get) — NOT reused from `threads`, which only
	 * holds the current page/view (missing older + cross-folder Sent messages).
	 */
	threadEmails = $state<Email[]>([]);
	view = $state<ViewId>('inbox');
	tagFilter = $state<string | null>(null);
	rawSearch = $state('');
	/** Flat vs threaded list mode — driven by the topbar Tabs (user intent). */
	viewMode = $state<'flat' | 'threaded'>('threaded');
	loading = $state(false);
	loadingMore = $state(false);
	error = $state('');
	currentPosition = $state(0);
	totalEmails = $state(0);
	hasMore = $state(false);
	online = $state(true);
	quarantineCount = $state(0);
	mutedTagId = $state<string | null>(null);
	/** Focused/Other inbox-split tab (V078). Only meaningful on the plain Inbox view. */
	focusTab = $state<'focused' | 'other'>('focused');
	mutating = $state<Set<string>>(new Set());
	/** Maps emailId → sendAt (ISO) for the Scheduled view. Populated by loadEmails. */
	scheduledMap = $state<Record<string, string>>({});
	/** Newsletter bundles from Email/bundles (B5). */
	bundles = $state<EmailBundle[]>([]);
	/** Effective read-receipt policy (Track A privacy). Default 'ask'. */
	readReceiptPolicy = $state<ReceiptPolicy>('ask');
	/** User-defined Quick Steps (A2). */
	quickSteps = $state<QuickStep[]>([]);
	/** Id of the quick step currently running (disables its button). */
	applyingQuickStep = $state<string | null>(null);
	/** User-defined saved-search folders (named re-runnable queries). */
	savedSearches = $state<SavedSearch[]>([]);
	/** List-sort property + direction passed to Email/query (backend whitelist:
	 *  receivedAt/sentAt/size/subject/from). Seeded from localStorage; default date-desc. */
	sortProperty = $state<string>(loadSortPref().property);
	sortAsc = $state<boolean>(loadSortPref().ascending);

	// ── #13 shared-mailbox use-surface ──
	/** Non-null while browsing a delegated (shared) mailbox's workspace
	 *  (/inbox?mbx=<id>) — threaded into every MAIL-family JMAP call as the
	 *  per-call accountId override. Null = the caller's own mail. */
	accountOverride = $state<string | null>(null);
	/** True once a shared-context call comes back accountNotFound/forbidden
	 *  (grant revoked mid-session, or the caller never had one). The page
	 *  renders the full-pane "access removed" state instead of retrying —
	 *  never a toast loop. Manual refresh (loadEmails) is the only way to
	 *  re-check; there is no push subscription in shared context (v1 pin). */
	accessRevoked = $state(false);

	// ── $derived projections ──
	counts: MailCounts = $derived(computeCounts(this.mailboxes));

	/** The `Other` pile tag's mailbox id (Focused/Other split, V078), or null when the
	 *  account has no Other tag. Derived from mailboxes the same way the page derives
	 *  mutedTagId (by system-tag name). */
	otherTagId = $derived(this.mailboxes.find((m) => m.name === 'Other')?.id ?? null);

	/** Unread count of the Other pile — drives the Other tab badge. Synced to the
	 *  client via the mailbox list, like every sidebar tag count. */
	otherUnread = $derived(this.mailboxes.find((m) => m.name === 'Other')?.unreadEmails ?? 0);

	selectedRole = $derived(
		this.mailboxes.find((m) => m.id === this.tagFilter)?.role ??
			resolveViewMailbox(this.view, this.mailboxes)?.role ??
			null,
	);

	/** Some views are intrinsically flat (tag filter, All Mail, Scheduled). */
	flatForView = $derived(
		this.tagFilter !== null || this.view === 'all' || this.view === 'scheduled',
	);

	/** Effective list mode: flat when the view forces it OR the user chose Flat. */
	effectiveViewMode: 'flat' | 'threaded' = $derived(
		this.flatForView || this.viewMode === 'flat' ? 'flat' : 'threaded',
	);

	threadList: InboxThreadItem[] = $derived(
		this.effectiveViewMode === 'flat'
			? this.emails.map((e) => ({ id: e.id, emails: [e], expanded: true, muted: false }))
			: [...this.threads.entries()].map(([id, t]) => ({ id, ...t })).filter((t) => !t.muted),
	);

	// ── Push subscription / debounce internals ──
	// The 300ms Email debounce + hub subscription bookkeeping live in the
	// PushHandlerStore seam; the InboxStore owns its own instance so teardown()
	// stays self-contained.
	#push = new PushHandlerStore();
	#abortController: AbortController | null = null;
	/** Optional hook the page wires so a WS reload can restore a deep link. */
	onAfterPushReload: (() => void) | null = null;
	/**
	 * #222: the primary account's Email state the displayed list reflects (the
	 * `state` of the list's own Email/get). null = unknown (offline/scheduled/
	 * shared views, an empty result, or nothing fetched yet). Reconnect resyncs
	 * from it. #225: it is taken ONLY from a reset (first-page / full) load,
	 * which re-reads the whole visible list; a load-more page never advances it,
	 * because the earlier pages were read at the older state and a change between
	 * the two reads would otherwise be marked as already reflected.
	 */
	#emailState: string | null = null;
	/**
	 * #225: the Mailbox state read at the start of the last reset load (null =
	 * unknown). Read before the list so it can only be older than what the list
	 * shows, never newer.
	 */
	#mailboxState: string | null = null;
	/** Bumped by every loadEmails() so an in-flight resync can tell it was superseded. */
	#loadGen = 0;

	/**
	 * #225: true only when EVERY inbox data type the push names carries exactly
	 * the token the list already reflects. Any unknown or moved state (e.g. a
	 * Mailbox-only change) means the push is not yet reflected.
	 */
	#reflects(changes: PushChanges): boolean {
		const known: Record<(typeof INBOX_PUSH_TYPES)[number], string | null> = {
			Email: this.#emailState,
			Mailbox: this.#mailboxState,
		};
		let named = 0;
		for (const type of INBOX_PUSH_TYPES) {
			const token = changes[type];
			if (token === undefined) continue;
			named++;
			if (known[type] === null || known[type] !== token) return false;
		}
		return named > 0;
	}

	/** Mailbox state for the anchor; a failed read leaves it unknown (never fatal). */
	async #readMailboxState(signal?: AbortSignal): Promise<string | null> {
		try {
			return (await mailboxState(undefined, signal)) || null;
		} catch {
			return null;
		}
	}

	// ── JMAP data flow ──
	async loadEmails(reset = true): Promise<void> {
		const gen = ++this.#loadGen;
		this.#abortController?.abort();
		this.#abortController = new AbortController();
		const signal = this.#abortController.signal;
		this.error = '';
		if (reset) {
			this.loading = true;
			this.currentPosition = 0;
			this.emails = [];
		} else {
			this.loadingMore = true;
		}

		try {
			// Scheduled view: load via EmailSubmission APIs (B2)
			if (this.view === 'scheduled' && !this.tagFilter) {
				this.#emailState = null;
				this.#mailboxState = null;
				const subResult = await emailSubmissionQuery(
					{},
					reset ? undefined : this.currentPosition,
					50,
				);
				const subIds = subResult.ids;
				if (subIds.length > 0) {
					const submissions = await emailSubmissionGet(subIds);
					const emailIds = submissions.map((s) => s.emailId);
					const fetched = await emailGet(emailIds, undefined, signal);
					this.emails = reset ? fetched : [...this.emails, ...fetched];
					const next = { ...this.scheduledMap };
					for (const sub of submissions) {
						if (sub.sendAt) next[sub.emailId] = sub.sendAt;
					}
					this.scheduledMap = next;
				} else if (reset) {
					this.emails = [];
				}
				this.currentPosition = (subResult.position ?? this.currentPosition) + subIds.length;
				this.totalEmails = subResult.total ?? 0;
				this.hasMore = this.currentPosition < this.totalEmails;
			} else if (offline.effectiveOffline && !this.tagFilter && this.view === 'inbox' && !this.accountOverride) {
				// ponytail: shared-mailbox browsing is online-only (no native offline
				// cache for a delegated mailbox) — falls through to the standard
				// Email/query path below, which threads accountOverride.
				// ponytail: offline read-path — routes through the offline selector (loadList/
				// searchList) which returns from SQLCipher cache. Only inbox+no-tag-filter is
				// supported offline (Scheduled/Snoozed views require JMAP state). Ceiling: add
				// per-view offline slices in #1b when offline cache coverage expands.
				this.#emailState = null;
				this.#mailboxState = null;
				const offset = reset ? 0 : this.currentPosition;
				let fetched: Email[];
				if (this.rawSearch.trim()) {
					// searchList returns ListRow[] from the cache — no network call.
					const rows = await searchList(this.rawSearch.trim(), 50);
					fetched = rows.map((r) => ({
						id: r.id,
						mailboxIds: {},
						receivedAt: new Date(r.receivedAt).toISOString(),
						subject: r.subject,
						from: r.from ? [{ email: r.from, name: r.from }] : undefined,
					} satisfies Email));
				} else {
					const rows = await loadList({ limit: 50, offset });
					// Map ListRow → minimal Email for the list view. Full body fetch on open.
					fetched = rows.map((r) => ({
						id: r.id,
						mailboxIds: {},
						receivedAt: new Date(r.receivedAt).toISOString(),
						subject: r.subject,
						from: r.from ? [{ email: r.from, name: r.from }] : undefined,
					} satisfies Email));
				}
				this.emails = reset ? fetched : [...this.emails, ...fetched];
				this.currentPosition = (reset ? 0 : this.currentPosition) + fetched.length;
				this.totalEmails = this.currentPosition; // unknown offline; disable "load more"
				this.hasMore = false;
			} else {
				// Standard Email/query path (online)
				const searchFilter = parseSearch(this.rawSearch, this.mailboxes);
				const filter = computeListFilter({
					view: this.view,
					tagFilter: this.tagFilter,
					mailboxes: this.mailboxes,
					searchFilter,
					focusTab: this.focusTab,
				});
				const sort = [{ property: this.sortProperty, isAscending: this.sortAsc }];
				// #225: anchors come only from a reset load of the primary account.
				// The Mailbox state is requested before the list so the anchor can
				// only lag what the list shows (a lag costs one extra reload; a lead
				// would hide a change).
				const anchor = reset && !this.accountOverride;
				const mailboxStateRead = anchor ? this.#readMailboxState(signal) : null;
				const result = await emailQuery(
					filter,
					sort,
					50,
					reset ? undefined : this.currentPosition,
					signal,
					this.accountOverride,
				);
				if (result.ids.length > 0) {
					const got = await emailGetWithState(result.ids, undefined, signal, this.accountOverride);
					// The state token is per account: only the primary account's anchors
					// the push/reconnect resync (shared context is manual-refresh-only).
					// A load-more page leaves the anchor at the first page's state.
					if (this.accountOverride) this.#emailState = null;
					else if (anchor) this.#emailState = got.state || null;
					let fetched = got.list;
					// A text query gets highlighted subject/preview snippets (SearchSnippet/
					// get, BM25 <mark> highlights) attached per email. Best-effort: fall back
					// to the plain preview if the snippet fetch fails. Only when `text` is set
					// (the reducer rejects a from:/tag:-only filter with no text/subject/body).
					if (searchFilter.text) {
						try {
							const snippets = await searchSnippetGet(filter, result.ids, this.accountOverride);
							const byId = new Map(snippets.map((s) => [s.emailId, s]));
							fetched = fetched.map((e) => {
								const snip = byId.get(e.id);
								return snip
									? { ...e, searchSubject: snip.subject, searchPreview: snip.preview }
									: e;
							});
						} catch {
							// leave `fetched` as-is; MailRow renders the plain preview
						}
					}
					this.emails = reset ? fetched : [...this.emails, ...fetched];
				} else if (reset) {
					this.emails = [];
					// #225: no Email/get ran, so no state describes this (empty) list.
					this.#emailState = null;
				}
				if (mailboxStateRead) {
					const mb = await mailboxStateRead;
					if (gen === this.#loadGen) this.#mailboxState = mb;
				}
				// The reducer echoes the REQUESTED offset (RFC 8620 'position'), so on a
				// reset load result.position is 0 — `0 ?? x` is 0, which used to pin
				// currentPosition at 0 forever (load-more re-fetched page 1, appending
				// duplicate ids that crashed the keyed list). Advance by the page size,
				// matching the offline branch above.
				this.currentPosition = (result.position ?? this.currentPosition) + result.ids.length;
				this.totalEmails = result.total ?? 0;
				this.hasMore = this.currentPosition < this.totalEmails;
			}
			this.buildThreads();
		} catch (e) {
			if ((e as Error).name === 'AbortError') {
				// swallow — a newer load superseded this one
			} else if (this.accountOverride) {
				// Shared-mailbox context: a denied call (accountNotFound/forbidden —
				// grant revoked mid-session, or never granted) renders the full-pane
				// "access removed" state, never a toast-loop retry.
				this.accessRevoked = true;
			} else {
				throw e;
			}
		} finally {
			this.loading = false;
			this.loadingMore = false;
		}
	}

	buildThreads(): void {
		const map = new Map<string, InboxThread>();
		for (const email of this.emails) {
			const tid = email.threadId || email.id;
			if (!map.has(tid)) {
				const isMuted = this.mutedTagId ? email.mailboxIds?.[this.mutedTagId] || false : false;
				map.set(tid, { emails: [], expanded: false, muted: isMuted });
			}
			map.get(tid)!.emails.push(email);
		}
		for (const t of map.values()) {
			t.emails.sort(
				(a, b) => new Date(b.receivedAt!).getTime() - new Date(a.receivedAt!).getTime(),
			);
		}
		this.threads = map;
	}

	/**
	 * Load the full conversation of `email` into `threadEmails` (oldest→newest, with
	 * bodies) for the stacked message cards. Cross-folder + full-history via Thread/get.
	 * Guards against a race (a newer open supersedes this one) and falls back to the
	 * single message on any fetch error so the pane never breaks.
	 */
	async loadThread(email: Email): Promise<void> {
		const threadId = email.threadId || email.id;
		const stillCurrent = () => (this.selectedEmail?.threadId || this.selectedEmail?.id) === threadId;
		try {
			const [thread] = await threadGet([threadId], this.accountOverride);
			if (!stillCurrent()) return;
			const ids = thread?.emailIds?.length ? thread.emailIds : [email.id];
			const msgs = await emailGet(ids, FULL_EMAIL_PROPS, undefined, this.accountOverride);
			if (!stillCurrent()) return;
			this.threadEmails = msgs
				.slice()
				.sort((a, b) => new Date(a.receivedAt ?? 0).getTime() - new Date(b.receivedAt ?? 0).getTime());
		} catch {
			if (stillCurrent()) this.threadEmails = [email];
		}
	}

	/** Load the newsletter bundles (B5) when bundling is enabled for the user. */
	async loadBundles(bundlingEnabled: boolean): Promise<void> {
		if (!bundlingEnabled) {
			this.bundles = [];
			return;
		}
		try {
			await loadSession();
			const result = await emailBundles(50, 0);
			this.bundles = result.bundles;
		} catch {
			this.bundles = [];
		}
	}

	/** Refresh the mailbox list (e.g. after a count-affecting mutation). */
	async refreshMailboxes(): Promise<void> {
		try {
			this.mailboxes = await mailboxGet(undefined, this.accountOverride);
		} catch (e) {
			if (this.accountOverride) {
				this.accessRevoked = true;
				return;
			}
			throw e;
		}
	}

	// ── View / tag selection ──
	selectView(v: ViewId): void {
		this.view = v;
		this.tagFilter = null;
		this.selectedEmail = null;
		void this.loadEmails();
	}

	selectTag(tagId: string): void {
		this.tagFilter = tagId;
		this.selectedEmail = null;
		void this.loadEmails();
	}

	// ── Saved-search folders ──
	/** Load the account's saved searches. Optional chrome — a failure clears the list. */
	async loadSavedSearches(): Promise<void> {
		try {
			this.savedSearches = await savedSearchList();
		} catch {
			this.savedSearches = [];
		}
	}

	/**
	 * Re-run a saved search: point the inbox at its raw query (searched across All
	 * Mail, no sidebar tag filter). The page then calls handleSearch()/loadEmails to
	 * re-run the whole parseSearch→loadEmails pipeline against the live index.
	 */
	selectSavedSearch(s: SavedSearch): void {
		this.view = 'all';
		this.tagFilter = null;
		this.rawSearch = s.query;
	}

	/** Save the current raw search under `name`, then reload the saved-search list. */
	async saveSearch(name: string): Promise<void> {
		await savedSearchSet(name, this.rawSearch);
		await this.loadSavedSearches();
	}

	/** Delete a saved search, then reload the list. */
	async deleteSavedSearch(id: string): Promise<void> {
		await savedSearchDelete(id);
		await this.loadSavedSearches();
	}

	/** Change the list sort property/direction, persist it, and re-query. The property
	 *  is bounded by the Select's options + the reducer's ORDER BY whitelist (ELSE default). */
	setSort(property: string, ascending: boolean): void {
		this.sortProperty = property;
		this.sortAsc = ascending;
		if (typeof localStorage !== 'undefined') {
			try {
				localStorage.setItem(SORT_STORAGE_KEY, JSON.stringify({ property, ascending }));
			} catch {
				/* ignore quota / private-mode write failures */
			}
		}
		this.selectedEmail = null;
		void this.loadEmails();
	}

	/** Switch the Focused/Other tab and re-query (V078). No-op when already on `tab`. */
	setFocusTab(tab: 'focused' | 'other'): void {
		if (this.focusTab === tab) return;
		this.focusTab = tab;
		this.selectedEmail = null;
		void this.loadEmails();
	}

	// ── WebSocket push subscription (Email + Mailbox) ──
	/**
	 * Open the always-on Email/Mailbox listener. An Email change schedules a
	 * single debounced reload (300ms); coalesces bursts. The optional
	 * `onAfterPushReload` hook (wired by the page) runs after each reload so a
	 * deep link can be restored. Idempotent — re-subscribing tears the old one
	 * down first.
	 */
	subscribeToChanges(): void {
		this.#push.teardown();
		// Every gateway StateChange carries the Email/Mailbox/Thread tokens, so an
		// Email/Mailbox listener fires on each mail-affecting push. The 300ms window
		// coalesces a burst into one reload; the post-reload hook restores a deep
		// link (wired by the page).
		this.#push.register(
			[...INBOX_PUSH_TYPES],
			(changes) => {
				// #13 pin: shared-mailbox context is manual-refresh-only — no live
				// push-driven reload (a push for the caller's OWN mail must not
				// silently re-fetch whatever shared workspace happens to be open).
				if (this.accountOverride) return;
				// #222/#225: a push whose every inbox token (Email AND Mailbox) is
				// the state the list already reflects (e.g. the change a reconnect
				// resync just loaded) adds nothing — skip the duplicate fetch. Any
				// moved or unknown token, such as a Mailbox-only change, reloads.
				if (this.#reflects(changes)) return;
				void this.#pushReload();
			},
			{ debounceMs: WS_DEBOUNCE_MS, onReconnect: () => void this.#resyncAfterReconnect() },
		);
	}

	async #pushReload(): Promise<void> {
		await this.loadEmails();
		this.onAfterPushReload?.();
	}

	/**
	 * #222: StateChanges pushed while the socket was down are lost, so after a
	 * reconnect ask the server what changed since the list's last known Email
	 * state. Nothing changed → no fetch. Something changed → reload the list (a
	 * filtered/sorted view can gain or lose rows on any change, so the list is
	 * re-queried rather than patched). cannotCalculateChanges (pruned or unknown
	 * state) → the same reload as the fallback. Other errors are left to the next
	 * push rather than turned into a blanket reload. #225: the Mailbox state is
	 * re-read alongside, so a Mailbox-only change made while disconnected (or an
	 * unknown Mailbox anchor) also reloads.
	 */
	async #resyncAfterReconnect(): Promise<void> {
		if (this.accountOverride) return;
		const since = this.#emailState;
		const mailboxSince = this.#mailboxState;
		const gen = this.#loadGen;
		if (since === null) {
			// No anchor to diff from is the client-side cannotCalculateChanges.
			await this.#pushReload();
			return;
		}
		const mailboxNow = this.#readMailboxState();
		let changed: boolean;
		try {
			const r = await emailChanges(since, RESYNC_MAX_CHANGES);
			changed =
				r.newState !== since ||
				r.hasMoreChanges ||
				r.created.length + r.updated.length + r.destroyed.length > 0;
		} catch (e) {
			if (!isJmapMethodError(e, 'cannotCalculateChanges')) {
				console.error('InboxStore reconnect resync failed', e);
				return;
			}
			changed = true;
		}
		const mb = await mailboxNow;
		if (mailboxSince === null || mb === null || mb !== mailboxSince) changed = true;
		// A load that started meanwhile (push, navigation) already re-read the list.
		if (!changed || gen !== this.#loadGen || this.accountOverride) return;
		await this.#pushReload();
	}

	/** Tear down the push subscription + any pending debounce (onDestroy). */
	teardown(): void {
		this.#push.teardown();
		this.#abortController?.abort();
	}
}
