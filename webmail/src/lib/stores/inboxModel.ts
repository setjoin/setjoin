import type { Email, EmailAddress, Mailbox } from '$lib/types/jmap';
import type { SearchFilter } from '$lib/stores/searchQuery';
import type { ViewId } from '$lib/components/mail/MailSidebar.svelte';
import { LOCATION_ROLES } from '$lib/stores/tagHelpers';

/** The Archive view id (A2). Archived mail = no location-group tag, not deleted. */
export const ARCHIVE_VIEW: ViewId = 'archive';

/**
 * Compute Reply-All recipients (A2): the original sender goes to To; every other
 * original to+cc recipient goes to Cc; the caller's own address is removed from
 * both. Case-insensitive on the self address and deduplicated.
 */
export function replyAllRecipients(
	email: Email,
	selfEmail: string,
): { to: string[]; cc: string[] } {
	const self = (selfEmail ?? '').toLowerCase();
	const sender = email.from?.[0]?.email ?? '';
	const to = sender ? [sender] : [];
	const seen = new Set<string>([...to.map((a) => a.toLowerCase()), self]);
	const cc: string[] = [];
	for (const addr of [...(email.to ?? []), ...(email.cc ?? [])]) {
		const e = addr.email;
		if (!e) continue;
		const key = e.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		cc.push(e);
	}
	return { to, cc };
}

/**
 * Prefill for "Resend after NDR/bounce": a FRESH compose seeded with the
 * original message's recipients, subject (verbatim — NO Re:/Fwd: prefix), and
 * body (HTML preferred, else text). Deliberately carries NO original id: a
 * resend is a brand-new submission, never an un-bounce of the immutable (BZ012)
 * bounced queue row — reusing the Message-ID would collide dedup_key. Original
 * attachments are not re-attached (forward skips these too — out of scope).
 */
export function resendPrefill(email: Email): {
	to: string;
	cc: string;
	bcc: string;
	subject: string;
	body: string;
} {
	const addrs = (list: EmailAddress[] | undefined): string =>
		(list ?? []).map((a) => a.email).filter(Boolean).join(', ');
	return {
		to: addrs(email.to),
		cc: addrs(email.cc),
		bcc: addrs(email.bcc),
		subject: email.subject ?? '',
		body: email.bodyHTML ?? email.bodyText ?? '',
	};
}

/**
 * Sender-domain/local-part markers for machine-generated mail (monitoring
 * alerts, CI, delivery reports). Used as a fallback when the backend has not
 * set the explicit `mono` flag on the email.
 */
const MONO_SENDER_MARKERS = ['monitoring', 'alerts@', 'alert@', 'no-reply@', 'noreply@', '@ci.', 'mailer-daemon'];

/**
 * Whether the reading-pane body should render in mono (machine-generated mail
 * per mail-kit §6). Prefers the backend `mono` flag; falls back to a
 * sender-address heuristic for monitoring/CI/no-reply senders.
 */
export function isMonoBody(email: Email | null | undefined): boolean {
	if (!email) return false;
	if (email.mono === true) return true;
	const fromEmail = email.from?.[0]?.email?.toLowerCase();
	if (!fromEmail) return false;
	return MONO_SENDER_MARKERS.some((m) => fromEmail.includes(m));
}

/**
 * Input for computeListFilter — bundles all state needed to produce
 * the JMAP Email/query filter object for the current view + tag + search state.
 */
export interface ListFilterInput {
	view: ViewId;
	tagFilter: string | null;
	mailboxes: Mailbox[];
	searchFilter: SearchFilter;
	/**
	 * Focused/Other inbox-split tab (V078). Optional: when omitted the split is not
	 * applied (keeps the plain-view tests unchanged). Applied ONLY to the plain
	 * Inbox view — see the focus block in computeListFilter.
	 */
	focusTab?: 'focused' | 'other';
}

/** Counts computed from mailboxes for the MailSidebar (mail-kit §3). */
export interface MailCounts {
	inboxUnread: number;
	snoozedTotal: number;
	tagCounts: Record<string, number>;
}

/** System mailbox names that should not appear in tagCounts. `Other` is the
 *  Focused/Other split pile (V078) — surfaced via the list tabs, not a sidebar count. */
const SYSTEM_NAMES = new Set(['Snoozed', 'Scheduled', 'Muted', 'Other']);

/**
 * Compute sidebar counts from the mailbox list.
 *
 * Rules (mail-kit §3):
 * - inboxUnread = Inbox (role=inbox) unreadEmails count
 * - snoozedTotal = Snoozed (name='Snoozed') totalEmails (total, not unread)
 * - tagCounts[id] = totalEmails for each user-tag mailbox (no location role,
 *   not a system-named mailbox like Snoozed/Scheduled/Muted)
 */
export function computeCounts(mailboxes: Mailbox[]): MailCounts {
	const inboxUnread = mailboxes.find((m) => m.role === 'inbox')?.unreadEmails ?? 0;
	const snoozedTotal = mailboxes.find((m) => m.name === 'Snoozed')?.totalEmails ?? 0;
	const tagCounts: Record<string, number> = {};

	for (const mb of mailboxes) {
		if (mb.role && (LOCATION_ROLES as ReadonlyArray<string>).includes(mb.role)) continue;
		if (SYSTEM_NAMES.has(mb.name)) continue;
		if (mb.totalEmails != null && mb.totalEmails > 0) {
			tagCounts[mb.id] = mb.totalEmails;
		}
	}

	return { inboxUnread, snoozedTotal, tagCounts };
}

/** Minimal thread shape for selectionFromUrl. */
export interface ThreadItem {
	id: string;
	emails: Array<{ id: string }>;
	expanded: boolean;
	muted: boolean;
}

/**
 * Map a ViewId to its corresponding mailbox.
 *
 * Rules (mail-kit reference *3, *4):
 * - inbox / sent / drafts / trash  lookup by role
 * - snoozed / scheduled            lookup by name
 * - archive / all                  no mailbox (filtered server-side: archive =
 *                                   no location-group tag; All Mail = unfiltered)
 */
export function resolveViewMailbox(view: ViewId, mailboxes: Mailbox[]): Mailbox | null {
	switch (view) {
		case 'inbox':
			return mailboxes.find((m) => m.role === 'inbox') ?? null;
		case 'sent':
			return mailboxes.find((m) => m.role === 'sent') ?? null;
		case 'drafts':
			return mailboxes.find((m) => m.role === 'drafts') ?? null;
		case 'trash':
			return mailboxes.find((m) => m.role === 'trash') ?? null;
		case 'snoozed':
			return mailboxes.find((m) => m.name === 'Snoozed') ?? null;
		case 'scheduled':
			return mailboxes.find((m) => m.name === 'Scheduled') ?? null;
		case 'starred':
		case 'archive':
		case 'all':
			return null;
	}
}

/**
 * Compute the JMAP Email/query filter implementing mail-kit *4 precedence:
 *
 * 1. Search-operator `tag:<name>` (`searchFilter.inMailbox`) wins over everything.
 * 2. Sidebar tag filter (`tagFilter`) wins over the view, **except** that it
 *    does **not** override the Trash view (Trash always shows its own mailbox).
 * 3. Otherwise, resolve the view to a mailbox via `resolveViewMailbox`.
 * 4. All Mail view (`all`) emits **no** `inMailbox` — the coordinator’s
 *    `loadEmails` path treats a missing `inMailbox` as an unfiltered query
 *    (the server-side Trash/Spam exclusion is handled by the reducer).
 * 5. Bare text and `from:` search fragments are AND-merged into the filter.
 */
export function computeListFilter(input: ListFilterInput): Record<string, unknown> {
	const { view, tagFilter, mailboxes, searchFilter, focusTab } = input;

	let inMailbox: string | undefined;
	// Archive (A2) is filtered by tag-absence, not a backing mailbox, so it cannot
	// set inMailbox. It applies only when neither a search tag: nor a sidebar tag
	// filter overrides the view (both take precedence, like every other view).
	let inArchive = false;
	// Starred: an always-on flag view, backed by the `$flagged` keyword (not a
	// location mailbox). Like archive, it applies only when neither search nor a
	// sidebar tag filter overrides the view.
	let starred = false;

	if (searchFilter.inMailbox) {
		// search `tag:` operator always wins
		inMailbox = searchFilter.inMailbox;
	} else if (tagFilter && view !== 'trash') {
		// sidebar tag selection wins over view, but never over Trash
		inMailbox = tagFilter;
	} else if (view === 'archive') {
		inArchive = true;
	} else if (view === 'starred') {
		starred = true;
	} else {
		const viewMb = resolveViewMailbox(view, mailboxes);
		inMailbox = viewMb?.id;
	}

	const filter: Record<string, unknown> = {};

	if (inMailbox) {
		filter.inMailbox = inMailbox;
	}

	if (inArchive) {
		filter.inArchive = true;
	}

	// Starred view → `$flagged` keyword. Set BEFORE the SEARCH_KEYS loop so an
	// explicit `is:flagged`/`is:unread` search operator (searchFilter.hasKeyword)
	// still wins (precedence: search > sidebar tag > view).
	if (starred) {
		filter.hasKeyword = '$flagged';
	}

	// Forward every search-operator key the reducer understands. inMailbox/inArchive
	// are handled above (view/tag precedence); the rest pass straight through.
	const SEARCH_KEYS = [
		'text', 'from', 'to', 'cc', 'bcc', 'subject',
		'hasAttachment', 'hasKeyword', 'before', 'after', 'minSize', 'maxSize',
	] as const;
	for (const key of SEARCH_KEYS) {
		const v = searchFilter[key];
		if (v !== undefined) filter[key] = v;
	}

	// Focused/Other split (V078): applies ONLY to the plain Inbox view — the resolved
	// query is the Inbox mailbox with no tag override (search `tag:` or sidebar) and no
	// search operator. Any search, tag view, archive/trash/sent/etc. is left un-split
	// (so `Other` mail is still findable via search and the tabs never leak elsewhere).
	// focus='focused' (the default tab) hides the Other pile; 'other' shows only it.
	if (
		focusTab &&
		view === 'inbox' &&
		!searchFilter.inMailbox &&
		!tagFilter &&
		!SEARCH_KEYS.some((k) => searchFilter[k] !== undefined)
	) {
		filter.focus = focusTab;
	}

	return filter;
}

/**
 * Find the thread matching a deep-linked id and return the email to open.
 * The id is a threadId (in-app navigation writes ?t=<threadId>), but a message
 * id is also accepted — task linkage (tasks.linkedMessageId) deep-links by
 * message id — resolving to that message's thread, preferring the exact email.
 * Returns null when nothing in the loaded thread list matches.
 */
export function selectionFromUrl(
	threadList: ThreadItem[],
	threadId: string,
): { id: string } | null {
	const thread =
		threadList.find((t) => t.id === threadId) ??
		threadList.find((t) => t.emails.some((e) => e.id === threadId));
	if (!thread || thread.emails.length === 0) return null;
	return thread.emails.find((e) => e.id === threadId) ?? thread.emails[0];
}
