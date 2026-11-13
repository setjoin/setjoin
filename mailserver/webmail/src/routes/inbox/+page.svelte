<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy, getContext } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { user } from '$lib/stores/auth';
	import { composeStore, MAX_COMPOSE_SESSIONS } from '$lib/stores/compose';
	import {
		loadSession,
		emailGet,
		FULL_EMAIL_PROPS,
		getAccountId,
		getDelegatedAccounts,
	} from '$lib/jmap/client';
	import type { DelegatedAccount } from '$lib/jmap/client';
	import type { ComposeOpts } from '$lib/stores/compose';
	import { emailSet } from '$lib/jmap/offline-client';
	import { createTask } from '$lib/stores/tasks';
	import { isOnline, onNetworkChange } from '$lib/db/offline';
	import { logger } from '$lib/logger';
	import { stripLocationTags } from '$lib/stores/tagHelpers';
	import { selectionFromUrl, replyAllRecipients, resendPrefill } from '$lib/stores/inboxModel';
	import { InboxStore } from '$lib/stores/inboxStore.svelte';
	import { vipSenders } from '$lib/stores/vipSenders.svelte';
	import { EmailActionStore, type Snapshot } from '$lib/stores/emailActionStore.svelte';
	import { listQuickSteps } from '$lib/jmap/quicksteps';
	import { effectiveCaps } from '$lib/stores/session';
	import { parseError } from '$lib/errors';
	import { registerShortcut, EMAIL_SHORTCUTS } from '$lib/hooks/useKeyboard.svelte';
	import { consumePendingPushAction } from '$lib/native/pushAction.svelte';
	import { markProductInteractive, markProductReady } from '$lib/performance/marks';
	import { Input, IconButton, Button, Tabs, Badge, Select, Toast, showToast, EmptyState } from '$lib/components/ui';
	import { t, locale } from '$lib/i18n';
	import Icon from '$lib/components/Icon.svelte';
	import SearchIntentRail from '$lib/components/mail/SearchIntentRail.svelte';
	import { buildSearchIntentPreview } from '$lib/search/searchIntent';
	import OfflineStatus from '$lib/components/OfflineStatus.svelte';
	import BiometricUnlock from '$lib/components/BiometricUnlock.svelte';
	import { offline } from '$lib/offline/state.svelte';
	import { installIdleRelock, lockMail } from '$lib/offline/biometric';
	import MailSidebar, { VIEWS } from '$lib/components/mail/MailSidebar.svelte';
	import ResponsiveComposeAction from '$lib/components/mail/ResponsiveComposeAction.svelte';
	import type { ViewId } from '$lib/components/mail/MailSidebar.svelte';
	import MessageList, { type MessageListActions } from '$lib/components/mail/MessageList.svelte';
	import ReadingPane, { type ReadingPaneActions } from '$lib/components/mail/ReadingPane.svelte';
	import NewsletterBundle from '$lib/components/NewsletterBundle.svelte';
	import NudgeBanner from '$lib/components/NudgeBanner.svelte';
	import type { EmailNudge } from '$lib/types/jmap';
	import type { FollowUpSelection } from '$lib/components/FollowUpPicker.svelte';
	import type { Email, SavedSearch } from '$lib/types/jmap';
	import { mailWorkGet, mailWorkMatchesFilter, type MailWorkFilter, type MailWorkItem } from '$lib/mail/mailWork';
	import {
		TOUR_HOST_CONTEXT,
		type TourHostContext,
	} from '$lib/onboarding/host';

	// ── Stores ──
	// InboxStore owns the inbox's ~23 reactive vars + the list/view/push
	// coordination (loadEmails, selectView/selectTag, buildThreads, the
	// Email/Mailbox WS subscription + debounce).
	// EmailActionStore owns the ~13 reading-pane / message-list JMAP mutations
	// behind a typed dispatch()→Snapshot seam. The page keeps only the toast/undo
	// copy + the compose hand-offs + the DOM glue.
	const store = new InboxStore();
	const actionStore = new EmailActionStore(store);
	const tourHost = getContext<TourHostContext>(TOUR_HOST_CONTEXT);
	tourHost?.setInboxReadiness('loading');

	// ── #13 shared-mailbox use-surface ──────────────────────────────────────
	// Workspace = /inbox?mbx=<delegated mailbox id>. sharedAccounts is the ONE
	// identity enumeration (session accounts, from getDelegatedAccounts) that
	// backs the sidebar's SHARED MAILBOXES section, the context-guard header/
	// info-strip, and (in ComposeScreen) the From Select.
	let sharedAccounts = $state<DelegatedAccount[]>([]);
	let mbxParam = $derived($page?.url?.searchParams?.get('mbx') ?? null);
	let currentShared = $derived(mbxParam ? sharedAccounts.find((a) => a.id === mbxParam) ?? null : null);
	/** True whenever the URL carries ?mbx=, even before sharedAccounts resolves
	 *  (the read path must not wait — accountOverride is set immediately). */
	let inSharedContext = $derived(!!mbxParam);
	let sharedGrants = $derived(currentShared?.grants ?? []);
	/** DANGER STATE: no send capability at all — compose/reply/forward disable. */
	let sharedReadOnly = $derived(
		inSharedContext && !sharedGrants.some((g) => g === 'send_as' || g === 'send_on_behalf' || g === 'full_access'),
	);
	let sharedPermissionLabel = $derived.by(() => {
		if (!inSharedContext) return '';
		if (sharedGrants.includes('full_access')) return t('inbox.shared.perm_full');
		if (sharedGrants.includes('send_as')) return t('inbox.shared.perm_send_as');
		if (sharedGrants.includes('send_on_behalf')) return t('inbox.shared.perm_send_on_behalf');
		return t('inbox.shared.perm_read');
	});
	/**
	 * True when the caller may MUTATE messages in the current context (the
	 * server's gateMutate class — Email/set, incl. the auto mark-$seen below —
	 * requires full_access specifically). Personal mail always allows it.
	 * NOT the same predicate as `sharedReadOnly` (which asks "can send" —
	 * send_as/send_on_behalf grant sending but NOT the mutate gate): a
	 * send_as-only or send_on_behalf-only delegate has `sharedReadOnly=false`
	 * yet still can't Email/set. Bug found finishing #13: without this, simply
	 * OPENING a message under any non-full_access grant fired the read-on-
	 * expand auto-mark-$seen mutation, which the server correctly 403s — and
	 * EmailActionStore.dispatch's catch (any denied call in shared context ⇒
	 * "access removed") read that as a revoked grant, breaking the read-only
	 * reading flow the design explicitly requires to keep working.
	 */
	let sharedCanMutate = $derived(!inSharedContext || sharedGrants.includes('full_access'));

	// ── Shared-context mutate gate (S20 hardening) ──
	// The server's gateMutate class 403s every Email/set under a delegate
	// without full_access, and EmailActionStore maps ANY denied shared-context
	// call to the full-pane "access removed" state — so a healthy send-grant
	// delegate firing a one-click mutation got a false "access removed". Gate
	// at the source instead: every Email/set-class page mutation is refused
	// (with the context's permission label as feedback) unless the current
	// context can mutate. Personal contexts always pass.
	function guardMutate(): boolean {
		if (sharedCanMutate) return true;
		store.error = t('inbox.shared.perm_read');
		return false;
	}
	let mailWorkFilter = $state<MailWorkFilter>('all');
	let mailWorkByThread = $state<Record<string, MailWorkItem>>({});
	let mailWorkLoadEpoch = 0;
	let visibleThreadList = $derived.by(() => {
		if (!inSharedContext || !$effectiveCaps.sharedMailWork || mailWorkFilter === 'all') return store.threadList;
		const selfId = $user?.userId == null ? null : String($user.userId);
		return store.threadList.filter((thread) => mailWorkMatchesFilter(mailWorkByThread[thread.id], mailWorkFilter, selfId));
	});
	const SHARED_VIEW_IDS: ViewId[] = ['inbox', 'drafts', 'sent', 'trash'];

	async function loadMailWorkList(): Promise<void> {
		const epoch = ++mailWorkLoadEpoch;
		const accountId = mbxParam;
		if (!inSharedContext || !$effectiveCaps.sharedMailWork || !accountId) {
			mailWorkByThread = {};
			mailWorkFilter = 'all';
			return;
		}
		const ids = store.threadList.map((thread) => thread.id).slice(0, 256);
		if (ids.length === 0) {
			mailWorkByThread = {};
			return;
		}
		try {
			const projection = await mailWorkGet(accountId, ids);
			if (epoch !== mailWorkLoadEpoch || accountId !== mbxParam) return;
			mailWorkByThread = Object.fromEntries(projection.list.map((item) => [item.threadId, item]));
		} catch {
			if (epoch === mailWorkLoadEpoch && accountId === mbxParam) mailWorkByThread = {};
		}
	}

	/** Build an `/inbox` URL carrying `t` (a deep-linked thread) when given, and
	 *  ALWAYS re-attaching the current `?mbx=` (bug found finishing #13: `goto`
	 *  replaces the whole query string, not just `t` — a bare `goto('/inbox?t=…')`
	 *  from inside the shared-mailbox workspace silently dropped `mbx`, which the
	 *  `$effect` below reads as "back to my mail" and kicked the reading pane's
	 *  own fetches onto the caller's personal account mid-open). Only the
	 *  explicit `backToMyMail()` action may drop `mbx` on purpose. */
	function inboxUrl(t?: string): string {
		const params = new URLSearchParams();
		if (t) params.set('t', t);
		if (mbxParam) params.set('mbx', mbxParam);
		const qs = params.toString();
		return qs ? `/inbox?${qs}` : '/inbox';
	}

	/** Load the delegated-account list (sidebar + context guard + From Select). */
	async function loadSharedAccounts() {
		try {
			sharedAccounts = await getDelegatedAccounts();
		} catch {
			sharedAccounts = [];
		}
	}

	/** Switch the store's accountOverride + reload for a context change (initial
	 *  mount, a sidebar shared-mailbox click, or "back to my mail"). Views outside
	 *  the shared 4 (Inbox/Drafts/Sent/Trash) collapse to Inbox — the personal-only
	 *  views (Tags/Saved searches/Snoozed/Scheduled/Archive/All Mail) don't exist
	 *  in shared context. */
	async function switchContext(mbx: string | null) {
		store.accountOverride = mbx;
		store.accessRevoked = false;
		store.selectedEmail = null;
		store.threadEmails = [];
		store.tagFilter = null;
		if (mbx && !SHARED_VIEW_IDS.includes(store.view)) store.view = 'inbox';
		// MUST resolve before loadEmails(): computeListFilter maps the view (e.g.
		// 'inbox') to a mailbox id via store.mailboxes — racing the two left
		// loadEmails reading the STALE (pre-switch) mailbox list, so the very
		// first shared-context load filtered by the caller's OWN inbox mailbox
		// id (invalid under the new accountId) and read as a denied/empty load.
		await store.refreshMailboxes();
		store.mutedTagId = store.mailboxes.find((m) => m.name === 'Muted')?.id || null;
		await loadEmails();
	}

	// React to URL ?mbx= changes AFTER the initial mount (a sidebar click, the
	// back-to-my-mail X, or a direct deep link navigation) — the first run is a
	// no-op (onMount's own load handles the initial context) so context isn't
	// loaded twice on page load.
	let mbxInitialized = false;
	$effect(() => {
		const mbx = mbxParam;
		if (!mbxInitialized) {
			mbxInitialized = true;
			return;
		}
		switchContext(mbx);
	});

	// The SINGLE compose-open gate: every compose entry point (Compose button,
	// reply/reply-all/forward/resend/schedule-reply/vote, the 'c'/'r'/'a'/'f'
	// keyboard shortcuts) routes through this function, so the read-only DANGER
	// STATE (compose/reply/forward disabled) is enforced once here rather than
	// re-checked at every call site (and covers the keyboard shortcuts, which
	// bypass a merely-disabled toolbar button).
	function openComposeInContext(opts: ComposeOpts = {}) {
		if (sharedReadOnly) return;
		// Multi-compose cap (QoL #18): open() returns null when 3 windows are already
		// open — toast and ask the user to close one rather than silently no-op.
		const id =
			inSharedContext && currentShared
				? composeStore.open({ accountId: currentShared.id, from: currentShared.name, ...opts })
				: composeStore.open(opts);
		if (id === null) {
			showToast(t('compose.cap_reached', { n: String(MAX_COMPOSE_SESSIONS) }));
		}
	}

	function backToMyMail() {
		goto('/inbox', { replaceState: false, keepFocus: true, noScroll: true });
	}

	interface NewsletterSender {
		id: string;
		fromName: string;
		fromAddr: string;
		subject: string;
		count: number;
	}

	// ── Page-local derived (bundles) ──
	// Per-message body render (sanitization + remote-image blocking + mono) now lives
	// in MessageCard — each card of the conversation-view stack owns its own state.

	// loadEmails surfaces store errors onto the page error banner (the store
	// rethrows non-abort failures so the page owns the user-facing message).
	async function loadEmails(reset = true) {
		if (reset) tourHost?.setInboxReadiness('loading');
		try {
			await store.loadEmails(reset);
			await loadMailWorkList();
			if (reset) {
				tourHost?.setInboxReadiness(store.emails.length > 0 ? 'loaded-populated' : 'loaded-empty');
				markProductReady('inbox-list-visible');
				markProductInteractive('inbox-interactive');
			}
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	async function loadQuarantineCount() {
		try {
			const res = await fetch('/api/quarantine/count');
			if (res.ok) { const data = await res.json(); store.quarantineCount = data.count || 0; }
		} catch { /* quarantine endpoint may not be available */ }
	}

	// Load the effective read-receipt policy (the global notification-prefs row).
	async function loadReadReceiptPolicy() {
		try {
			const res = await fetch('/api/user/notification-preferences', { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				const global = (data.preferences ?? []).find(
					(p: { device_fingerprint?: string }) => !p.device_fingerprint,
				);
				const p = global?.read_receipt_policy;
				if (p === 'ask' || p === 'always' || p === 'never') store.readReceiptPolicy = p;
			}
		} catch { /* prefs endpoint may not be available — default 'ask' (privacy-safe) */ }
	}

	// Relay the recipient's read-receipt consent to the server. The reducer is the hard
	// privacy gate: 'never' suppresses regardless of consent, 'ask' needs consent=true.
	async function sendReadReceipt(consent: boolean) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail) return;
		try {
			await fetch('/auth/me/read-receipt', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({ messageId: store.selectedEmail.id, consent }),
			});
		} catch (e) {
			logger.error('inbox: read-receipt send failed', e);
		}
	}

	// ── View / tag selection ──
	function selectView(v: ViewId) {
		store.selectView(v);
		if (v === 'inbox') loadBundles();
	}

	function selectTag(tagId: string) {
		store.selectTag(tagId);
	}

	// ── Email selection + deep links ──
	// ── B5 Newsletter bundles ──
	// #13: bundles/Focused-Other are personal-only features — hidden in shared context.
	let showBundles = $derived(
		!inSharedContext && $effectiveCaps.bundling && store.view === 'inbox' && !store.tagFilter && !store.rawSearch,
	);

	// #13 nudges: personal Inbox only (no tag/search). The banner self-fetches and
	// renders nothing when feature.stale_nudges is OFF (gateway returns empty), so
	// no capability flag is needed here — the same personal-context gate as bundles.
	let showNudges = $derived(
		!inSharedContext && store.view === 'inbox' && !store.tagFilter && !store.rawSearch,
	);

	// Focused/Other split tabs (V078): plain Inbox view only (no tag/search), and only
	// once the account actually has an Other tag (absent on e.g. journal mailboxes).
	let showFocusTabs = $derived(
		!inSharedContext && store.view === 'inbox' && !store.tagFilter && !store.rawSearch && !!store.otherTagId,
	);

	let newsletterSenders = $derived(
		store.bundles.map(
			(b): NewsletterSender => ({
				id: b.latestEmailId,
				fromName: b.listId,
				fromAddr: b.listId,
				subject: b.latestSubject ?? '',
				count: b.count,
			}),
		),
	);

	function loadBundles() {
		return store.loadBundles($effectiveCaps.bundling);
	}

	async function handleUnsubscribe(detail: { senderAddr: string }) {
		const bundle = store.bundles.find((b) => b.listId === detail.senderAddr);
		if (!bundle) return;
		try {
			const res = await fetch(`/api/messages/${bundle.latestEmailId}/unsubscribe`, {
				method: 'POST',
				credentials: 'include',
			});
			if (res.ok) {
				showToast(`Unsubscribed from ${detail.senderAddr}`);
				await loadBundles();
			}
		} catch {
			showToast('Failed to unsubscribe. Try again from the email detail.');
		}
	}

	async function handleBundleSelect(messageId: string) {
		// Try the in-memory emails first (fast path).
		let email = store.emails.find((e) => e.id === messageId);
		if (!email) {
			// The bundle's latestEmailId may not be in the current page;
			// fetch it explicitly so the click does not silently fail.
			try {
				const fetched = await emailGet([messageId]);
				email = fetched[0] ?? null;
			} catch {
				// If the fetch fails, show a toast instead of silent no-op.
				showToast('Could not open this newsletter email.');
				return;
			}
		}
		if (email) openEmail(email);
	}

	async function openEmail(email: Email) {
		store.selectedEmail = email; // instant: list item carries metadata + preview
		store.threadEmails = []; // clear the previous conversation; pane falls back to [selectedEmail] until loadThread
		try {
			const threadId = email.threadId || email.id;
			goto(inboxUrl(threadId), { replaceState: false, keepFocus: true, noScroll: true });
		} catch { /* navigation may not be available in test */ }
		// The list projection omits bodyHTML/bodyText/inlineImages, so fetch the full
		// message on open — otherwise the reading pane falls back to the 256-char preview
		// and HTML mail never renders. Merge so the pane doesn't flash empty.
		try {
			const [full] = await emailGet([email.id], FULL_EMAIL_PROPS, undefined, store.accountOverride);
			if (full && store.selectedEmail?.id === email.id) store.selectedEmail = full;
		} catch { /* keep the list item on fetch failure */ }
		// Conversation-view depth: stack the whole thread as collapsible cards.
		store.loadThread(email);
	}

	function closeReadingPane() {
		store.selectedEmail = null;
		store.threadEmails = [];
		try {
			goto(inboxUrl(), { replaceState: false, keepFocus: true, noScroll: true });
		} catch { /* navigation may not be available in test */ }
	}

	// Consume a ?folder=<view> deep link (CommandPalette G S / G D / G T
	// shortcuts navigate to /inbox?folder=sent|drafts|starred). Select the view,
	// then strip the param — mirroring the ?t= deep-link cleanup — so a refresh
	// doesn't re-trigger it. Only known sidebar views are honoured.
	function consumeFolderParam() {
		try {
			const folder = $page?.url?.searchParams?.get('folder');
			if (!folder || !VIEWS.some((v) => v.id === folder)) return;
			store.view = folder as ViewId;
			const url = new URL($page.url);
			url.searchParams.delete('folder');
			goto(url.pathname + url.search, { replaceState: true, keepFocus: true, noScroll: true });
		} catch { /* $page/navigation may not be available in test */ }
	}

	function restoreDeepLink() {
		try {
			const t = $page?.url?.searchParams?.get('t');
			if (!t) return;
			const match = selectionFromUrl(
				store.threadList.map((th) => ({ id: th.id, emails: th.emails, expanded: th.expanded, muted: th.muted })),
				t,
			);
			if (match) {
				const found = store.emails.find((e) => e.id === match.id);
				if (found) {
					store.selectedEmail = found;
					store.loadThread(found); // rebuild the conversation-view stack for the deep-linked thread

					// Push-action bridge (QoL #9): a native-shell "Archive" notification tap
					// stashed the intent (installPushActionHandler in +layout.svelte); apply
					// it now that the deep-linked message has actually loaded. Guarded by id
					// so an unrelated later deep link never replays a stale archive.
					const pushAction = consumePendingPushAction();
					if (pushAction?.actionId === 'archive' && pushAction.messageId === found.id) {
						void archiveEmail(found);
					}
				}
			}
		} catch { /* $page may not be available */ }
	}

	// ── Mutations (thin wrappers over the EmailActionStore + page toast/undo) ──
	// dispatch() performs the JMAP mutation and returns a Snapshot; the page owns
	// the toast copy and, on Undo, replays the inverse patch via actionStore.undo.
	function showUndoToast(message: string, snap: Snapshot) {
		showToast(message, {
			actionLabel: 'Undo',
			onAction: () => actionStore.undo(snap),
		});
	}

	async function archiveEmail(email?: Email) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		const target = email ?? store.selectedEmail;
		if (!target) return;
		try {
			const snap = (await actionStore.dispatch({ type: 'archive', email: target })) as Snapshot;
			showUndoToast('Conversation archived', snap);
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	async function trashEmail(email?: Email) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		const target = email ?? store.selectedEmail;
		if (!target) return;
		try {
			const snap = (await actionStore.dispatch({ type: 'trash', email: target })) as Snapshot;
			showUndoToast('Conversation moved to Trash', snap);
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	async function starEmail(email?: Email) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		const target = email ?? store.selectedEmail;
		if (!target) return;
		try {
			await actionStore.dispatch({ type: 'star', email: target });
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// `email` defaults to the open (reading-pane) message — the reading-pane
	// Snooze button calls this with just a date. Swipe-snooze (MailRow tray)
	// passes its own row's email, since that row need not be selected/open.
	async function snoozeEmail(date: Date, email?: Email) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		const target = email ?? store.selectedEmail;
		if (!target) return;
		const presetLabel = date.toLocaleString();
		try {
			const snap = (await actionStore.dispatch({
				type: 'snooze',
				email: target,
				date,
			})) as Snapshot;
			showUndoToast(`Snoozed until ${presetLabel}`, snap);
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	async function muteEmail() {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail) return;
		try {
			const snap = (await actionStore.dispatch({ type: 'mute', email: store.selectedEmail })) as Snapshot | null;
			if (snap) showUndoToast('Conversation muted — replies skip your inbox', snap);
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	async function toggleTag(tagId: string) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail) return;
		try {
			const snap = (await actionStore.dispatch({
				type: 'toggleTag',
				email: store.selectedEmail,
				tagId,
			})) as Snapshot | null;
			if (snap) showUndoToast('Tag removed', snap);
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	async function createTag(name: string, color?: string) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!name.trim()) return;
		const create: { name: string; color?: string } = { name: name.trim() };
		if (color) create.color = color;
		await mailboxSet({ create: { newTag: create } });
	}

	// Rename / recolor a user tag (Mailbox/set update); patch carries name and/or color.
	async function updateTag(id: string, patch: { name?: string; color?: string }) {
		await mailboxSet({ update: { [id]: patch } });
	}

	// Delete a user tag (Mailbox/set destroy). The reducer refuses system tags +
	// non-empty tags (mailboxHasEmail), so a live-labelled tag is left intact.
	async function deleteTag(id: string) {
		await mailboxSet({ destroy: [id] });
	}

	// Shared Mailbox/set caller (create/update/destroy of user tags), then reload.
	async function mailboxSet(args: Record<string, unknown>) {
		try {
			await loadSession();
			const res = await fetch('/jmap', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				credentials: 'include',
				body: JSON.stringify({
					using: ['urn:ietf:params:jmap:mail'],
					methodCalls: [['Mailbox/set', { accountId: await getAccountId(), ...args }, 't1']],
				}),
			});
			if (res.ok) {
				await store.refreshMailboxes();
			}
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// ── Scheduled-send cancel (B2) ──
	async function cancelScheduledEmail(emailId: string) {
		try {
			await actionStore.dispatch({ type: 'cancelScheduled', emailId });
			showToast('Scheduled send cancelled', {
				actionLabel: 'Undo',
				// Undo is not possible for cancellation (submission is gone); reload only.
				onAction: () => loadEmails(),
			});
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// ── Compose actions ──
	function replyTo() {
		if (!store.selectedEmail) return;
		const from = store.selectedEmail.from?.[0]?.email || '';
		openComposeInContext({
			to: from,
			subject: 'Re: ' + (store.selectedEmail.subject || ''),
			replyTo: store.selectedEmail.id,
		});
	}

	function forwardEmail() {
		if (!store.selectedEmail) return;
		openComposeInContext({
			subject: 'Fwd: ' + (store.selectedEmail.subject || ''),
			body: store.selectedEmail.preview || '',
		});
	}

	// Resend after NDR/bounce: a FRESH compose seeded with the original
	// recipients/subject/body (resendPrefill carries no id — brand-new submission,
	// never a reuse of the immutable bounced queue row / its Message-ID).
	function resendEmail() {
		if (!store.selectedEmail) return;
		openComposeInContext(resendPrefill(store.selectedEmail));
	}

	// Reply All (A2): original sender → To; all other to+cc → Cc; self removed.
	function replyAllTo() {
		if (!store.selectedEmail) return;
		const { to, cc } = replyAllRecipients(store.selectedEmail, $user?.email ?? '');
		openComposeInContext({
			to: to.join(', '),
			cc: cc.join(', '),
			subject: 'Re: ' + (store.selectedEmail.subject || ''),
			replyTo: store.selectedEmail.id,
		});
	}

	// Mark read / unread (A2). Optimistic via the action store; refreshes counts.
	async function setRead(read: boolean, email?: Email) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		const target = email ?? store.selectedEmail;
		if (!target) return;
		const isSelected = store.selectedEmail?.id === target.id;
		try {
			await actionStore.dispatch({ type: 'setRead', email: target, read });
			if (isSelected && store.selectedEmail) store.selectedEmail = { ...store.selectedEmail };
		} catch (e) {
			if (isSelected && store.selectedEmail) store.selectedEmail = { ...store.selectedEmail };
			store.error = parseError(e).message;
		}
	}

	// Flag for follow-up with due + reminder (A2). A6's scan fires the reminder.
	async function setFollowUp(sel: FollowUpSelection) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail) return;
		try {
			await actionStore.dispatch({
				type: 'followUp',
				email: store.selectedEmail,
				dueAt: sel.dueAt,
				reminderAt: sel.reminderAt,
			});
			store.selectedEmail = { ...store.selectedEmail };
			showToast(t('triage.followup.flagged_due', { date: sel.dueAt.toLocaleString() }));
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// Email → task: create a task titled with the subject, linked back to the message.
	// The FK is MATCH SIMPLE, so BOTH the id AND its received-at partition key must be
	// passed or the link is unenforced.
	async function createTaskFromEmail() {
		const em = store.selectedEmail;
		if (!em) return;
		try {
			await createTask({
				title: em.subject || '(no subject)',
				linkedMessageId: em.id,
				linkedMessageReceivedAt: em.receivedAt,
			});
			showToast(t('triage.task_created'));
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// Apply a Quick Step macro to the selected message (A2). Plain confirmation
	// toast (no undo) — a macro runs multiple actions, so a partial revert misleads.
	async function applyQuickStepTo(id: string) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail || store.applyingQuickStep) return;
		store.applyingQuickStep = id;
		try {
			await actionStore.dispatch({ type: 'applyQuickStep', email: store.selectedEmail, id });
			showToast(t('triage.quick_step_applied'));
		} catch (e) {
			store.error = parseError(e).message;
		} finally {
			store.applyingQuickStep = null;
		}
	}

	// One-click block sender (A2): move the current message to Spam so the sender's
	// future mail is also trained as junk, with an Undo. The hard server-side spam
	// learning happens in the move reducer; this is a single triage action (not a rule).
	async function blockSender(email?: Email) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		const target = email ?? store.selectedEmail;
		if (!target) return;
		try {
			const snap = (await actionStore.dispatch({ type: 'blockSender', email: target })) as Snapshot | null;
			if (snap) showUndoToast(t('triage.sender_blocked'), snap);
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// One-click "Create rule from this message" (#4): deep-link into the rules
	// editor with the sender + subject pre-filled. The rules page consumes the
	// prefill* query params and seeds a new draft rule.
	// Reply / follow-up from a stale-thread nudge (#13): open compose to the
	// thread counterpart, seeded as a reply to the nudge's latest message.
	function nudgeReply(nudge: EmailNudge) {
		openComposeInContext({
			to: nudge.counterpart,
			subject: 'Re: ' + (nudge.subject || ''),
			replyTo: nudge.emailId,
		});
	}

	function createRuleFromMessage(email?: Email) {
		const target = email ?? store.selectedEmail;
		if (!target) return;
		const from = target.from?.[0]?.email ?? '';
		const subject = target.subject ?? '';
		const domain = from.includes('@') ? from.slice(from.indexOf('@') + 1) : '';
		const params = new URLSearchParams();
		if (from) params.set('prefillFrom', from);
		if (subject) params.set('prefillSubject', subject);
		if (domain) params.set('prefillDomain', domain);
		goto('/settings/rules?' + params.toString());
	}

	async function loadQuickSteps() {
		try {
			store.quickSteps = await listQuickSteps();
		} catch {
			// Quick Steps are optional chrome; a load failure must not block the inbox.
			store.quickSteps = [];
		}
	}

	// Recall a sent message from local recipients' mailboxes (within the recall window).
	// Backed by the existing POST /messages/{id}/recall handler (5-minute window).
	async function recallEmail() {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail) return;
		try {
			const res = (await actionStore.dispatch({ type: 'recall', email: store.selectedEmail })) as {
				recall: { ok: boolean; status: number; recalledCount: number };
			} | null;
			const r = res?.recall;
			if (r?.ok) {
				showToast(t('compose.recallDone', { n: String(r.recalledCount) }));
			} else if (r?.status === 410) {
				showToast(t('compose.recallExpired'));
			} else {
				showToast(t('compose.recallFailed'));
			}
		} catch {
			showToast(t('compose.recallFailed'));
		}
	}

	// ── Thread actions ──
	function toggleThread(threadId: string) {
		const t = store.threads.get(threadId);
		if (t) { t.expanded = !t.expanded; store.threads = new Map(store.threads); }
	}

	async function muteThread(threadId: string) {
		// Delegate to the single mute implementation in the action store (archives +
		// adds the Muted tag + offers Undo). Any email of the thread identifies it.
		const t = store.threads.get(threadId);
		if (!t || !t.emails.length) return;
		try {
			const snap = (await actionStore.dispatch({ type: 'mute', email: t.emails[0] })) as Snapshot | null;
			if (snap) showUndoToast('Conversation muted — replies skip your inbox', snap);
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	async function archiveThread(threadId: string) {
		const t = store.threads.get(threadId);
		if (!t || store.mutating.has(threadId)) return;
		store.mutating.add(threadId);
		try {
			await loadSession();
			const update: Record<string, { mailboxIds: Record<string, boolean> }> = {};
			for (const e of t.emails) {
				update[e.id] = { mailboxIds: stripLocationTags(e.mailboxIds || {}, store.mailboxes) };
			}
			await emailSet(null, update, null);
			if (store.selectedEmail && update[store.selectedEmail.id]) store.selectedEmail = null;
			await loadEmails();

			showToast('Conversation archived', {
				actionLabel: 'Undo',
				onAction: async () => {
					try {
						const revert: Record<string, { mailboxIds: Record<string, boolean> }> = {};
						for (const e of t.emails) {
							revert[e.id] = { mailboxIds: e.mailboxIds || {} };
						}
						await emailSet(null, revert, null);
						await loadEmails();
					} catch { /* best effort */ }
				},
			});
		} catch (e) {
			store.error = parseError(e).message;
		} finally {
			store.mutating.delete(threadId);
		}
	}

	/** Quick inline reply send (kit §8): submit directly with a 5s Cancel window. */
	async function sendReply(text: string) {
		if (!store.selectedEmail || !text.trim()) return;
		try {
			const res = (await actionStore.dispatch({
				type: 'sendReply',
				email: store.selectedEmail,
				text,
				selfEmail: $user?.email || '',
			})) as { reply: { submissionId: string | null; offline: boolean } } | null;
			const reply = res?.reply;
			if (reply?.offline) {
				showToast('Reply queued — will send when back online');
				return;
			}
			if (reply?.submissionId) {
				const submissionId = reply.submissionId;
				showToast('Sending in 5s…', {
					actionLabel: 'Cancel',
					onAction: () => actionStore.cancelReply(submissionId),
				});
			}
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	function scheduleReply(text: string) {
		if (!store.selectedEmail) return;
		const from = store.selectedEmail.from?.[0]?.email || '';
		// Open the full composer prefilled as a reply; the Delivery section lets
		// the user pick the schedule (the inline footer cannot host a date picker).
		openComposeInContext({
			to: from,
			subject: 'Re: ' + (store.selectedEmail.subject || ''),
			replyTo: store.selectedEmail.id,
			body: text,
			expanded: true,
		});
	}

	// Move a row between the Focused and Other piles (V078). Optimistic + reload lives
	// in the action store; the gateway also learns a per-sender override.
	async function moveFocus(email: Email, focused: boolean) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		try {
			await actionStore.dispatch({ type: 'focus', email, focused });
			showToast(focused ? 'Moved to Focused' : 'Moved to Other');
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// Not-Spam (reading pane, Spam/Junk view): move the open message back to Inbox.
	async function notSpam() {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail) return;
		try {
			await actionStore.dispatch({ type: 'notSpam', email: store.selectedEmail });
		} catch (e) {
			store.error = parseError(e).message;
		}
	}

	// Cast a vote (X-Mailserver-Voting): a vote is just a reply to the sender carrying
	// the chosen option as the vote-response header. composeStore.opts.voteResponse →
	// ComposeScreen → send reducer's X-Mailserver-Vote-Response (CR/LF-sanitized Go-side).
	// The tally/results side is a deferred backend concern.
	function castVote(option: string) {
		// Shared-context mutate gate (S20): no Email/set without the mutate grant.
		if (!guardMutate()) return;

		if (!store.selectedEmail) return;
		const from = store.selectedEmail.from?.[0]?.email || '';
		openComposeInContext({
			to: from,
			subject: 'Re: ' + (store.selectedEmail.subject || ''),
			replyTo: store.selectedEmail.id,
			voteResponse: option,
		});
	}

	// ── MessageList action facade (candidate 7) ──
	// One object instead of the per-row / per-thread callbacks. Row mutations route
	// through the EmailActionStore wrappers; thread + list coordination stay page-local.
	let messageListActions = $derived<MessageListActions>({
		onOpen: openEmail,
		onArchive: archiveEmail,
		onStar: starEmail,
		onTrash: trashEmail,
		onToggleRead: (email, read) => setRead(read, email),
		onToggleThread: toggleThread,
		onMuteThread: muteThread,
		onArchiveThread: archiveThread,
		onLoadMore: () => loadEmails(false),
		onCancelScheduled: store.view === 'scheduled' ? cancelScheduledEmail : undefined,
		// Move-to-Focused/Other is an Inbox-view action (covers both tabs); other views
		// (sent/trash/archive/search) have no focus split, so it's omitted there.
		onMoveFocus: store.view === 'inbox' ? moveFocus : undefined,
		// Swipe-tray Snooze (QoL #2) — same snoozeEmail the reading pane uses,
		// just given the swiped row's own email instead of the selected one.
		onSnooze: (email, date) => snoozeEmail(date, email),
	});

	// ── ReadingPane action facade (candidate 7) ──
	// One object instead of 23 callbacks. Each member dispatches through the
	// EmailActionStore (with the page's toast/undo glue) or hands off to compose.
	let readingActions = $derived<ReadingPaneActions>({
		onArchive: () => archiveEmail(),
		onSnooze: snoozeEmail,
		onTrash: () => trashEmail(),
		onMute: muteEmail,
		onStar: () => starEmail(),
		onReply: replyTo,
		onReplyAll: replyAllTo,
		onForward: forwardEmail,
		onResend: resendEmail,
		onToggleRead: (read) => setRead(read),
		onFollowUp: setFollowUp,
		onCreateTask: createTaskFromEmail,
		onBlockSender:
			store.selectedRole !== 'spam' && store.selectedRole !== 'junk'
				? () => blockSender()
				: undefined,
		onCreateRule: inSharedContext ? undefined : () => createRuleFromMessage(),
		onApplyQuickStep: applyQuickStepTo,
		onRemoveTag: (tagId) => toggleTag(tagId),
		onAddTag: (tagId) => toggleTag(tagId),
		onCreateTag: createTag,
		onSendReply: sendReply,
		onScheduleReply: scheduleReply,
		onRecall: recallEmail,
		onNotSpam: notSpam,
		onVoteResponse: castVote,
		onReadReceipt: sendReadReceipt,
		// Read-on-expand (WAVE-5 #6): the pane fires this for an UNREAD message
		// whose card becomes visible (auto-expanded newest on open, or a collapsed
		// card the user expands). Collapsed older messages stay unread.
		// #13: omitted entirely (never wired, never attempted) without the
		// mutate grant — see sharedCanMutate's comment.
		onMarkSeen: sharedCanMutate ? (email) => setRead(true, email) : undefined,
		onSenderControlChanged: () => loadEmails(),
	});

	// ── Search ──
	function handleSearch() {
		store.selectedEmail = null;
		loadEmails();
	}

	let searchIntentState = $derived.by(() => {
		if (!$effectiveCaps.mailSearchBuilder || !store.rawSearch.trim()) return { preview: null, error: '' };
		try {
			return { preview: buildSearchIntentPreview(store.rawSearch, store.mailboxes, $locale), error: '' };
		} catch {
			return { preview: null, error: t('inbox.search_intent.invalid') };
		}
	});

	function applySearchIntent(raw: string) {
		store.rawSearch = raw;
		handleSearch();
	}

	function handleSearchEnter() {
		if (!$effectiveCaps.mailSearchBuilder) { handleSearch(); return; }
		if (!searchIntentState.preview) return;
		applySearchIntent(searchIntentState.preview.raw);
	}

	// ── Quick-filter chips (#15) ──
	// A no-typing toolbar for the handful of filters people reach for constantly.
	// Each chip toggles an exact search-operator token in/out of the raw query and
	// re-runs the existing parseSearch→loadEmails pipeline. Active state is DERIVED
	// from rawSearch (single source of truth), so hand-typing the same operator
	// lights the chip too. `to:me` resolves to the caller's own address.
	let searchTokens = $derived(store.rawSearch.trim().split(/\s+/).filter(Boolean));
	let quickChips = $derived([
		{ token: 'is:unread', label: t('inbox.filter_chip.unread') },
		{ token: 'is:flagged', label: t('inbox.filter_chip.flagged') },
		{ token: 'has:attachment', label: t('inbox.filter_chip.attachments') },
		...($user?.email ? [{ token: `to:${$user.email}`, label: t('inbox.filter_chip.to_me') }] : []),
	]);
	function toggleChip(token: string) {
		const toks = store.rawSearch.trim().split(/\s+/).filter(Boolean);
		const i = toks.indexOf(token);
		if (i >= 0) toks.splice(i, 1);
		else toks.push(token);
		store.rawSearch = toks.join(' ');
		handleSearch();
	}

	// ── VIP filter chip ──
	// ponytail: v1 composes a single `from:` search term (the parser AND-merges
	// fragments, no OR-of-senders support yet) — with >1 VIP this filters to the
	// first VIP sender only. Upgrade when the search grammar grows an OR-of-from
	// or the reducer takes a sender list directly.
	const vipQuery = $derived(vipSenders.senders.length ? `from:${vipSenders.senders[0]}` : '');
	const vipFilterActive = $derived(!!vipQuery && store.rawSearch.trim() === vipQuery);
	function toggleVipFilter() {
		store.rawSearch = vipFilterActive ? '' : vipQuery;
		handleSearch();
	}

	// ── Saved-search folders ──
	// Re-run a saved search: the store points the inbox at its raw query, then we
	// re-run the whole parseSearch→loadEmails pipeline via handleSearch().
	function selectSaved(s: SavedSearch) {
		store.selectSavedSearch(s);
		handleSearch();
	}

	// Inline "Save search" affordance in the topbar (mirrors MailSidebar's new-tag input).
	let showSaveSearch = $state(false);
	let saveSearchName = $state('');

	function saveCurrentSearch() {
		const name = saveSearchName.trim();
		if (!name) return;
		store.saveSearch(name).catch((e) => { store.error = parseError(e).message; });
		saveSearchName = '';
		showSaveSearch = false;
	}

	function deleteSaved(id: string) {
		store.deleteSavedSearch(id).catch((e) => { store.error = parseError(e).message; });
	}

	// JMAP account id for attachment download URLs (loaded once; reading pane uses it).
	let accountIdVal = $state('');

	// ── Lifecycle ──
	onMount(async () => {
		logger.log('inbox: onMount start');
		getAccountId().then((id) => { accountIdVal = id ?? ''; }).catch(() => {});
		if (!$user?.hasMailbox) {
			logger.log('inbox: no mailbox, redirecting to /apps');
			goto('/apps');
			return;
		}
		try {
			store.online = isOnline();
			onNetworkChange((status) => { store.online = status; });
			vipSenders.load().catch(() => {});

			await loadSession();
			loadSharedAccounts();
			// #13: the initial load goes through switchContext so a deep link
			// straight into a shared workspace (/inbox?mbx=<id>) threads
			// accountOverride from the very first Mailbox/get — mbxInitialized
			// is set true here so the reactive $effect above only fires on
			// LATER ?mbx= changes (sidebar clicks, back-to-my-mail), never twice.
			mbxInitialized = true;
			store.accountOverride = mbxParam;
			if (mbxParam && !SHARED_VIEW_IDS.includes(store.view)) store.view = 'inbox';
			await store.refreshMailboxes();
			store.mutedTagId = store.mailboxes.find((m) => m.name === 'Muted')?.id || null;
			loadQuarantineCount();
			loadReadReceiptPolicy();
			loadBundles();
			loadQuickSteps();
			store.loadSavedSearches();

			consumeFolderParam();

			await loadEmails();

			// Deep link restore on initial load
			restoreDeepLink();

			// The store owns the Email/Mailbox push subscription + 300ms debounce;
			// the page wires its deep-link restore as the post-reload hook.
			store.onAfterPushReload = restoreDeepLink;
			store.subscribeToChanges();
		} catch (e) {
			store.error = parseError(e).message;
		}
	});

	onDestroy(() => {
		tourHost?.setInboxReadiness('inactive');
		store.teardown();
	});

	// ── Offline: idle re-lock (T19) ──
	// Installs a 15-minute idle re-lock while offline controls are active.
	// ponytail: $effect + disposer; no external cleanup boilerplate needed.
	$effect(() => {
		if (!offline.controlsActive) return;
		const dispose = installIdleRelock(15, () => {
			lockMail();
			offline.setLockState('locked');
			offline.announce('offline.live.relocked');
		});
		return dispose;
	});

	// ── Keyboard shortcuts ──
	onMount(() => {
		const cleanups: Array<() => void> = [];
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.nextMessage, () => {
			if (!store.selectedEmail) {
				if (store.threadList.length > 0) openEmail(store.threadList[0].emails[0]);
				return;
			}
			const idx = store.threadList.findIndex((t) => t.emails.some((e) => e.id === store.selectedEmail?.id));
			if (idx >= 0 && idx < store.threadList.length - 1) {
				openEmail(store.threadList[idx + 1].emails[0]);
			}
		}));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.prevMessage, () => {
			if (!store.selectedEmail) return;
			const idx = store.threadList.findIndex((t) => t.emails.some((e) => e.id === store.selectedEmail?.id));
			if (idx > 0) openEmail(store.threadList[idx - 1].emails[0]);
		}));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.reply, () => { if (store.selectedEmail) replyTo(); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.replyAll, () => { if (store.selectedEmail) replyAllTo(); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.forward, () => { if (store.selectedEmail) forwardEmail(); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.archive, () => { if (store.selectedEmail) archiveEmail(); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.delete, () => { if (store.selectedEmail) trashEmail(); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.markRead, () => { if (store.selectedEmail) setRead(true); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.markUnread, () => { if (store.selectedEmail) setRead(false); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.compose, () => { openComposeInContext(); }));
		// Previously defined-but-unregistered (the shortcut help advertised them):
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.star, () => { if (store.selectedEmail) starEmail(); }));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.snooze, () => {
			if (!store.selectedEmail) return;
			const d = new Date(); d.setDate(d.getDate() + 1); d.setHours(8, 0, 0, 0); // tomorrow 8:00 (quick snooze)
			snoozeEmail(d);
		}));
		cleanups.push(registerShortcut(EMAIL_SHORTCUTS.search, () => {
			const el = document.querySelector<HTMLInputElement>('input[aria-label="Search mail"]');
			if (el) { el.focus(); el.select(); }
		}));
		return () => cleanups.forEach((c) => c());
	});
</script>

{#if store.error && !store.accessRevoked}
	<div class="sj-inbox-error" role="alert">
		<span class="sj-inbox-error__icon" aria-hidden="true">
			<Icon name="AlertTriangle" size={16} strokeWidth={1.75} />
		</span>
		<span class="sj-inbox-error__msg">{store.error}</span>
		<Button variant="ghost" size="sm" onclick={() => loadEmails()}>{t('common.retry')}</Button>
		<IconButton label={t('common.dismiss')} size="sm" onclick={() => (store.error = '')}>
			<Icon name="X" size={14} strokeWidth={1.75} />
		</IconButton>
	</div>
{/if}

<div class="sj-inbox">
	<!-- Topbar (52px) -->
	<div class="sj-inbox__topbar">
		<div class="sj-inbox__search-wrap" data-tour="search">
			<span class="sj-inbox__search-icon" aria-hidden="true">
				<Icon name="Search" size={15} strokeWidth={1.75} />
			</span>
			<Input
				class="sj-inbox__search-input"
				size="md"
				aria-label="Search mail"
				placeholder="Search mail — try tag:finance or from:mark"
				bind:value={store.rawSearch}
				onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') handleSearchEnter(); }}
			/>
		</div>
		<ResponsiveComposeAction
			onCompose={() => openComposeInContext()}
			disabled={sharedReadOnly}
			disabledReason={t('inbox.shared.read_only_tooltip')}
		/>
		{#if vipSenders.senders.length > 0}
			<button
				type="button"
				class="sj-inbox__vip-chip"
				class:sj-inbox__vip-chip--active={vipFilterActive}
				aria-pressed={vipFilterActive}
				onclick={toggleVipFilter}
			>
				{t('inbox.vip_filter')}
			</button>
		{/if}
		<div class="sj-inbox__topbar-actions">
			{#if store.rawSearch.trim()}
				{#if showSaveSearch}
					<Input
						class="sj-inbox__save-input"
						size="md"
						aria-label="Name this saved search"
						placeholder="Name this search"
						bind:value={saveSearchName}
						onkeydown={(e: KeyboardEvent) => {
							if (e.key === 'Enter') saveCurrentSearch();
							else if (e.key === 'Escape') { showSaveSearch = false; saveSearchName = ''; }
						}}
					/>
				{:else}
					<IconButton label="Save search" size="md" onclick={() => (showSaveSearch = true)}>
						<Icon name="FileSearch" size={16} strokeWidth={1.75} />
					</IconButton>
				{/if}
			{/if}
			<Select
				class="sj-inbox__sort"
				aria-label={t('inbox.sort_by')}
				value={store.sortProperty}
				options={[
					{ value: 'receivedAt', label: t('inbox.sort_date_received') },
					{ value: 'sentAt', label: t('inbox.sort_date_sent') },
					{ value: 'size', label: t('inbox.sort_size') },
					{ value: 'subject', label: t('inbox.sort_subject') },
					{ value: 'from', label: t('inbox.sort_from') },
				]}
				onchange={(e: Event & { currentTarget: HTMLSelectElement }) =>
					store.setSort(e.currentTarget.value, store.sortAsc)}
			/>
			<IconButton
				class="sj-inbox__sort-direction"
				label={store.sortAsc ? t('inbox.sort_ascending') : t('inbox.sort_descending')}
				size="md"
				onclick={() => store.setSort(store.sortProperty, !store.sortAsc)}
			>
				<Icon name={store.sortAsc ? 'ChevronUp' : 'ChevronDown'} size={16} strokeWidth={1.75} />
			</IconButton>
			<div class="sj-inbox__view-tabs">
				<Tabs
					items={[
						{ id: 'flat', label: 'Flat' },
						{ id: 'threaded', label: 'Threaded' },
					]}
					active={store.effectiveViewMode}
					onChange={(id: string) => {
						store.viewMode = id === 'flat' ? 'flat' : 'threaded';
						store.selectedEmail = null;
					}}
				/>
			</div>
			{#if !store.online}
				<Badge variant="warning" label="Offline" />
			{/if}
			<OfflineStatus />
		</div>
	</div>

	{#if $effectiveCaps.mailSearchBuilder && searchIntentState.preview}
		<SearchIntentRail
			intent={searchIntentState.preview.intent}
			mailboxes={store.mailboxes}
			zeroResults={!store.loading && store.totalEmails === 0}
			onEdit={(raw) => (store.rawSearch = raw)}
			onApply={applySearchIntent}
		/>
	{:else if searchIntentState.error}
		<div class="sj-search-intent-error" role="alert">{searchIntentState.error}</div>
	{/if}

	<!-- Quick-filter chips (#15): persistent no-typing filter toggles. Personal
	     context only (to:me resolves the caller's own address). -->
	{#if !inSharedContext}
		<div class="sj-inbox__chips" role="group" aria-label={t('inbox.filter_chip.group')}>
			{#each quickChips as chip (chip.token)}
				<button
					type="button"
					class="sj-inbox__chip"
					class:is-active={searchTokens.includes(chip.token)}
					aria-pressed={searchTokens.includes(chip.token)}
					onclick={() => toggleChip(chip.token)}
				>
					{chip.label}
				</button>
			{/each}
		</div>
	{/if}

	<!-- Body: sidebar + list + reading pane (or locked-inbox gate, or the
	     #13 shared-mailbox "access removed" danger state) -->
	<div class="sj-inbox__body">
		{#if offline.needsUnlock}
			<div class="sj-inbox__locked">
				<BiometricUnlock />
			</div>
		{:else if store.accessRevoked}
			<!-- #13 DANGER STATE: any denied call in shared context (grant revoked
			     mid-session, or never granted) renders this full-pane state instead
			     of a toast loop. Back returns to the caller's own mail. -->
			<div class="sj-inbox__access-removed">
				<EmptyState title={t('inbox.shared.access_removed')}>
					{#snippet action()}
						<Button variant="primary" onclick={backToMyMail}>{t('inbox.shared.back_to_mail')}</Button>
					{/snippet}
				</EmptyState>
			</div>
		{:else}
		<MailSidebar
			view={store.view}
			tagFilter={store.tagFilter}
			mailboxes={store.mailboxes}
			counts={store.counts}
			onCompose={() => openComposeInContext()}
			onSelectView={selectView}
			onSelectTag={selectTag}
			onNewTag={createTag}
			onUpdateTag={updateTag}
			onDeleteTag={deleteTag}
			savedSearches={store.savedSearches}
			onSelectSaved={selectSaved}
			onDeleteSaved={deleteSaved}
			sharedMailboxes={sharedAccounts}
			onSelectShared={(id) => goto('/inbox?mbx=' + id)}
			sharedContext={inSharedContext}
			activeSharedId={mbxParam}
			sharedName={currentShared?.name ?? ''}
			sharedPermissionLabel={sharedPermissionLabel}
			onBackToMyMail={backToMyMail}
			composeDisabled={sharedReadOnly}
			composeDisabledReason={t('inbox.shared.read_only_tooltip')}
		/>

		<section class="sj-inbox__list">
			{#if inSharedContext}
				<!-- #13 context-guard SIGNAL 2: persistent info strip naming the
				     mailbox AND the permission level + the manual-refresh control
				     (no push in shared context — v1 pin). -->
				<div class="sj-inbox__shared-strip" role="status">
					<Icon name="Users" size={14} strokeWidth={1.75} />
					<span class="sj-inbox__shared-strip-text">
						{t('inbox.shared.strip', { name: currentShared?.name ?? mbxParam ?? '', level: sharedPermissionLabel })}
					</span>
					<IconButton label={t('inbox.shared.refresh')} size="sm" onclick={() => loadEmails()}>
						<Icon name="RefreshCw" size={14} strokeWidth={1.75} />
					</IconButton>
				</div>
				{#if $effectiveCaps.sharedMailWork}
					<div class="sj-inbox__work-filters" role="group" aria-label={t('inbox.work.filter')}>
						{#each (['all', 'unassigned', 'mine', 'owned', 'waiting', 'due_soon', 'breached', 'done'] as MailWorkFilter[]) as filter}
							<button type="button" class:active={mailWorkFilter === filter} aria-pressed={mailWorkFilter === filter}
								onclick={() => (mailWorkFilter = filter)}>{t(`inbox.work.filter_${filter}`)}</button>
						{/each}
					</div>
				{/if}
			{/if}
			{#if showBundles && newsletterSenders.length > 0}
				<NewsletterBundle
					senders={newsletterSenders}
					onselect={(d) => handleBundleSelect(d.messageId)}
					onunsubscribe={handleUnsubscribe}
				/>
			{/if}
			{#if showNudges}
				<NudgeBanner onreply={nudgeReply} />
			{/if}
			<MessageList
				threads={visibleThreadList}
				viewMode={store.effectiveViewMode}
				selectedId={store.selectedEmail?.id ?? null}
				tags={store.mailboxes}
				loading={store.loading}
				loadingMore={store.loadingMore}
				hasMore={store.hasMore}
				remaining={store.totalEmails - store.currentPosition}
				scheduledTimes={store.view === 'scheduled' ? store.scheduledMap : undefined}
				otherTagId={store.otherTagId}
				focusTab={store.focusTab}
				otherUnread={store.otherUnread}
				onFocusTab={showFocusTabs ? (tab) => store.setFocusTab(tab) : undefined}
				actions={messageListActions}
				workByThread={inSharedContext && $effectiveCaps.sharedMailWork ? mailWorkByThread : undefined}
			/>
		</section>

		<section class="sj-inbox__reading" class:sj-inbox__reading--active={!!store.selectedEmail}>
			{#if store.selectedEmail}
				<ReadingPane
					email={store.selectedEmail}
					emails={store.threadEmails.length ? store.threadEmails : [store.selectedEmail]}
					mailboxes={store.mailboxes}
					currentRole={store.selectedRole}
					quickSteps={inSharedContext ? [] : store.quickSteps}
					applyingQuickStep={store.applyingQuickStep}
					readReceiptPolicy={store.readReceiptPolicy}
					onBack={closeReadingPane}
					actions={readingActions}
					accountId={mbxParam ?? accountIdVal}
					senderControlEnabled={!inSharedContext}
					mailWorkEnabled={inSharedContext}
					mailWorkCanCollaborate={!sharedReadOnly}
					composeDisabled={sharedReadOnly}
					composeDisabledReason={t('inbox.shared.read_only_tooltip')}
				/>
			{:else}
				<div class="sj-inbox__empty-reading">
					<EmptyState title="Select a conversation" watermark={true} />
				</div>
			{/if}
		</section>
		{/if}
	</div>
</div>

<!-- Toast stack -->
<Toast />

<style>
	.sj-inbox {
		height: 100%;
		display: flex;
		flex-direction: column;
		background: var(--surface-card);
		position: relative;
		overflow: hidden;
	}

	.sj-inbox-error {
		display: flex;
		align-items: center;
		gap: 8px;
		color: var(--danger-fg);
		padding: 8px 16px;
		font-size: var(--text-sm);
		background: var(--danger-bg);
		border-bottom: 1px solid var(--danger-solid);
	}
	.sj-inbox-error__icon {
		display: inline-flex;
		align-items: center;
		flex: none;
	}
	.sj-inbox-error__msg {
		flex: 1;
		min-width: 0;
	}

	/* ── Topbar (52px) ── */
	.sj-inbox__topbar {
		height: 52px;
		flex: none;
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 0 12px;
		border-bottom: 1px solid var(--border-default);
		background: var(--surface-card);
	}

	.sj-inbox__search-wrap {
		flex: 1 1 auto;
		min-width: 0;
		max-width: 560px;
		position: relative;
	}

	.sj-inbox__search-icon {
		position: absolute;
		left: 9px;
		top: 50%;
		transform: translateY(-50%);
		color: var(--text-tertiary);
		pointer-events: none;
		z-index: 1;
	}

	:global(.sj-inbox__search-input) {
		width: 100%;
	}

	:global(.sj-inbox__search-input input) {
		padding-left: 30px !important;
	}

	.sj-inbox__vip-chip {
		flex: none;
		display: inline-flex;
		align-items: center;
		height: 28px;
		padding: 0 10px;
		margin-left: 8px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-full);
		background: var(--surface-card);
		color: var(--text-secondary);
		font-size: var(--text-xs);
		font-weight: 600;
		cursor: pointer;
	}

	.sj-inbox__vip-chip:hover {
		background: var(--surface-hover);
	}

	.sj-inbox__vip-chip--active {
		background: var(--tag-amber-bg);
		border-color: var(--tag-amber-dot);
		color: var(--tag-amber-fg);
	}

	.sj-inbox__topbar-actions {
		display: flex;
		align-items: center;
		gap: 8px;
		flex: none;
	}

	:global(.sj-inbox__sort) {
		max-width: 168px;
	}

	:global(.sj-inbox__save-input) {
		width: 180px;
	}

	/* ── Quick-filter chips (#15) ── */
	.sj-search-intent-error { padding:var(--space-2) var(--space-3); color:var(--text-danger); background:var(--surface-danger-subtle); border-bottom:1px solid var(--border-default); font-size:var(--text-sm); }
	.sj-inbox__chips {
		flex: none;
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 6px 12px;
		border-bottom: 1px solid var(--border-default);
		background: var(--surface-card);
		overflow-x: auto;
	}

	.sj-inbox__chip {
		flex: none;
		font: inherit;
		font-size: var(--text-xs);
		line-height: 1.4;
		padding: 3px 10px;
		border-radius: var(--radius-full);
		border: 1px solid var(--border-default);
		background: var(--surface-sunken);
		color: var(--text-secondary);
		cursor: pointer;
		white-space: nowrap;
	}

	.sj-inbox__chip:hover {
		background: var(--accent-subtle);
	}

	.sj-inbox__chip.is-active {
		background: var(--accent-subtle);
		border-color: var(--accent);
		color: var(--accent-fg-on-subtle);
	}

	.sj-inbox__chip:focus-visible {
		outline: 2px solid var(--focus-ring);
		outline-offset: 1px;
	}

	/* ── Body ── */
	.sj-inbox__body {
		flex: 1;
		display: flex;
		overflow: hidden;
	}

	/* Locked-inbox full-body placeholder: BiometricUnlock fills the whole body. */
	.sj-inbox__locked {
		flex: 1;
		position: relative;
		overflow: hidden;
	}

	/* #13 shared-mailbox DANGER STATE: full-pane "access removed" (revoked grant
	   or a never-granted mbx id) — replaces the whole sidebar+list+reading body. */
	.sj-inbox__access-removed {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	/* #13 context-guard SIGNAL 2: persistent info strip above the message list. */
	.sj-inbox__shared-strip {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		border-bottom: 1px solid var(--border-default);
		background: var(--surface-sunken);
		color: var(--text-caption);
		font-size: var(--text-xs);
		flex: none;
	}
	.sj-inbox__shared-strip-text {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.sj-inbox__work-filters {
		display: flex;
		gap: var(--space-1);
		overflow-x: auto;
		padding: var(--space-2);
		border-bottom: 1px solid var(--border-subtle);
		background: var(--surface-card);
		flex: none;
	}
	.sj-inbox__work-filters button {
		min-height: 30px;
		padding: 0 var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-caption);
		font: inherit;
		font-size: var(--text-xs);
		white-space: nowrap;
		cursor: pointer;
	}
	.sj-inbox__work-filters button.active {
		border-color: var(--border-accent);
		background: var(--surface-selected);
		color: var(--text-primary);
	}
	.sj-inbox__work-filters button:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	/* ── List pane ── */
	.sj-inbox__list {
		flex: 0 0 auto;
		width: clamp(280px, 40vw, 390px);
		border-right: 1px solid var(--border-default);
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}

	/* ── Reading pane ── */
	.sj-inbox__reading {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	.sj-inbox__empty-reading {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	/* ── Responsive ── */
	@media (max-width: 767px) {
		.sj-inbox__topbar {
			padding-inline: 8px;
		}
		:global(.sj-inbox__sort),
		:global(.sj-inbox__sort-direction),
		.sj-inbox__view-tabs {
			display: none;
		}
		.sj-inbox__list {
			width: 100%;
			border-right: none;
		}
		.sj-inbox__reading {
			display: none;
		}
		.sj-inbox__reading--active {
			display: flex;
			position: fixed;
			inset: 0;
			z-index: 20;
			background: var(--surface-card);
		}
	}
</style>
