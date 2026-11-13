<svelte:options runes={true} />

<script lang="ts">
	import { onDestroy, tick } from 'svelte';
	import type { Editor } from '@tiptap/core';
	import RichTextEditor from './RichTextEditor.svelte';
	import RichTextEditorToolbar from './RichTextEditorToolbar.svelte';
	import { composeStore } from '$lib/stores/compose';
	import type { ComposeSession } from '$lib/stores/compose';
	import { user } from '$lib/stores/auth';
	import { loadSession, mailboxGet, emailGet, FULL_EMAIL_PROPS, emailSubmissionCancel, assistComplete, calendarEventResourceList, getDelegatedAccounts } from '$lib/jmap/client';
	import type { DelegatedAccount } from '$lib/jmap/client';
	import { emailTemplateList } from '$lib/jmap/emailTemplates';
	import type { EmailTemplate } from '$lib/types/jmap';
	import { sanitizeHTML, escapeHTML } from '$lib/sanitize';
	import { validate, required, maxLength } from '$lib/validation';
	import { formatBytes } from '$lib/utils/display';
	import { removeRecipient } from '$lib/utils/contactRanking';
	import { loadGroups } from '$lib/stores/contactGroups';
	import { mentionsAttachment } from '$lib/utils/attachmentReminder';
	import type { EmailAddress } from '$lib/types/jmap';
	import { t, formatDate, formatDateTime } from '$lib/i18n';
	import Icon from './Icon.svelte';
	import IconButton from './ui/IconButton.svelte';
	import Button from './ui/Button.svelte';
	import Switch from './ui/Switch.svelte';
	import Select from './ui/Select.svelte';
	import Tag from './ui/Tag.svelte';
	import Spinner from './ui/Spinner.svelte';
	import Progress from './ui/Progress.svelte';
	import { showToast } from './ui';
	import Input from './ui/Input.svelte';
	import { effectiveCaps } from '$lib/stores/session';
	import { buildTimeSlots } from './ui/datetime';
	import DateTimePicker from './ui/DateTimePicker.svelte';
	import { userTags } from '$lib/stores/tagHelpers';
	import { locale } from '$lib/i18n';
	import AvailabilityGrid from './AvailabilityGrid.svelte';
	import { SchedulingStore } from '$lib/stores/scheduling.svelte';
	import type { BusyInterval, MutualFreeSlot } from '$lib/types/scheduling';
	import { ComposeStore, MAX_ATTACH_BYTES, SubmissionMarkerError } from '$lib/stores/composeStore.svelte';
	import { mailDraftLease } from '$lib/mail/mailDraft';
	import { directorySearch, setDirectoryAccountId, type DirectoryMember } from '$lib/stores/directory';

	// Multi-compose (QoL #18): each open compose window is a ComposeSession in the
	// composeStore, and each session mounts its OWN ComposeScreen (keyed by id in
	// +layout) — so every window keeps its own live ComposeStore + editor. When
	// minimized the panel is CSS-hidden (display:none), NEVER unmounted, so in-flight
	// uploads and unsaved edits survive. `session` is the window this instance drives;
	// it falls back to the sole/first session when rendered standalone (unit tests,
	// single-compose).
	let { session: sessionProp }: { session?: ComposeSession } = $props();
	let session = $derived(sessionProp ?? $composeStore.sessions[0] ?? null);
	// Per-window id prefix so the field ids (cmp-to/cmp-from/…) stay UNIQUE across
	// concurrently-mounted compose windows — a bare `cmp-to` would collide and make
	// getElementById()/label-for target the wrong (possibly hidden) window's field.
	let uid = $derived(`cmp-${session?.id ?? 'x'}`);

	// Draft-content state (from/to/cc/bcc/replyTo/subject/body/categories/attachments/
	// signatures/schedule/priority/sensitivity/vote/S-MIME/plainText/sendTags + mailboxes)
	// lives in ComposeStore — a per-mount runes instance. Everything else on this
	// component (send/draft/GAL/mailtips/upload/UI-toggle logic + all $effects) stays
	// here; later A6 slices continue the extraction.
	const compose = new ComposeStore();
	$effect(() => { compose.sharedDraftsEnabled = $effectiveCaps.sharedMailDrafts; });

	// -- Core fields --
	let sending = $state(false);
	let error = $state('');
	let formErrors = $state<Record<string, string>>({});
	let sent = $state(false);
	let undoSendEmailId = $state<string | null>(null);
	let undoCountdown = $state(30);
	let undoInterval = $state<ReturnType<typeof setInterval> | null>(null);
	let draftTimer = $state<ReturnType<typeof setTimeout> | null>(null);

	let mailboxError = $state('');
	let replyContextFailed = $state(false);
	let draftLoadError = $state('');
	let showDraftHandoff = $state(false);
	let draftHandoffQuery = $state('');
	let draftHandoffResults = $state<DirectoryMember[]>([]);
	let draftHandoffTarget = $state<DirectoryMember | null>(null);
	let draftHandoffBusy = $state(false);
	let draftHandoffError = $state('');

	let editorRef = $state<RichTextEditor | null>(null);
	let tipTapEditor = $state<Editor | null>(null);

	async function searchDraftHandoff() {
		if (draftHandoffQuery.trim().length < 2) { draftHandoffResults = []; return; }
		draftHandoffBusy = true; draftHandoffError = '';
		try {
			setDirectoryAccountId('-1');
			draftHandoffResults = await directorySearch(draftHandoffQuery.trim(), 8);
		} catch { draftHandoffResults = []; draftHandoffError = t('compose.sharedDraftHandoffSearchError'); }
		finally { draftHandoffBusy = false; }
	}

	async function handoffSharedDraft() {
		if (!compose.sharedAccountId || !compose.sharedDraftSession || !draftHandoffTarget || draftHandoffBusy) return;
		draftHandoffBusy = true; draftHandoffError = '';
		try {
			compose.sharedDraftSession = await mailDraftLease({ accountId: compose.sharedAccountId,
				session: compose.sharedDraftSession, action: 'handoff', targetUserId: draftHandoffTarget.id,
				reason: 'Explicit compose handoff' });
			compose.sharedDraftReadOnly = true;
			showDraftHandoff = false;
			showToast(t('compose.sharedDraftHandoffDone', { name: draftHandoffTarget.displayName || draftHandoffTarget.email }), { variant: 'success' });
		} catch { draftHandoffError = t('compose.sharedDraftHandoffError'); }
		finally { draftHandoffBusy = false; }
	}

	let delegates = $state<EmailAddress[]>([]);
	let aliases = $state<EmailAddress[]>([]);

	// #13 shared-mailbox use-surface: every MAIL-delegated mailbox with a send
	// grant (send_as|send_on_behalf|full_access) — the identity enumeration the
	// From Select consumes for the "send as / on behalf of a shared mailbox"
	// rows. sendAsShared gets a plain "send as {address}" row (send_as|full_access
	// — either may set From=shared); onBehalfShared gets a "{me} on behalf of
	// {name}" row (send_on_behalf keeps From=own — send.sql:74 rejects
	// From=shared on an on-behalf-only grant, BZ003). An account with send_as/
	// full_access renders ONLY the send-as row even if it also carries
	// send_on_behalf (redundant otherwise).
	let sharedAccounts = $state<DelegatedAccount[]>([]);
	let sendAsShared = $derived(
		sharedAccounts.filter((a) => a.grants.includes('send_as') || a.grants.includes('full_access')),
	);
	let onBehalfShared = $derived(
		sharedAccounts.filter(
			(a) => a.grants.includes('send_on_behalf') && !a.grants.includes('send_as') && !a.grants.includes('full_access'),
		),
	);
	// The native <select> is keyed by an opaque token (own/d:<email>/a:<email>/
	// s:<id>:as/s:<id>:onbehalf) rather than bound directly to compose.fromEmail —
	// "on behalf of" rows must be selectable as DISTINCT options even though their
	// From address (the caller's own) is identical to the plain "own" row's.
	let fromSelectValue = $state('own');
	const sharedAliasToken = (accountId: string, email: string) =>
		`s:${accountId}:alias:${encodeURIComponent(email)}`;

	function handleFromSelectChange() {
		compose.invalidateHydration();
		const v = fromSelectValue;
		if (v === 'own') {
			compose.fromEmail = userEmail;
			compose.sharedAccountId = null;
		} else if (v.startsWith('d:') || v.startsWith('a:')) {
			compose.fromEmail = v.slice(2);
			compose.sharedAccountId = null;
		} else if (v.startsWith('s:')) {
			const [, id, mode] = v.split(':');
			const acct = sharedAccounts.find((a) => a.id === id);
			compose.sharedAccountId = id;
			if (mode === 'alias') {
				let selected = '';
				try {
					selected = decodeURIComponent(v.slice(`s:${id}:alias:`.length));
				} catch {
					// Malformed opaque state fails closed to the caller's address;
					// the reducer independently rejects any unauthorized From.
				}
				compose.fromEmail = acct?.sendAsAliases.includes(selected) ? selected : userEmail;
			} else {
				compose.fromEmail = mode === 'as' ? (acct?.name ?? userEmail) : userEmail;
			}
		}
		pickSignatureForAlias(compose.fromEmail);
	}

	// Caption under the From row when the resolved From address differs from the
	// caller's own — names the shared mailbox / on-behalf relationship rather
	// than leaving the address unexplained (#13 design pin).
	let fromCaption = $derived.by(() => {
		if (!fromSelectValue.startsWith('s:')) return '';
		const [, id, mode] = fromSelectValue.split(':');
		const acct = sharedAccounts.find((a) => a.id === id);
		if (!acct) return '';
		return mode === 'as'
			? t('compose.sendingAsShared', { name: acct.name })
			: t('compose.sendingOnBehalf', { name: acct.name });
	});

	let showCc = $state(false);
	let showBcc = $state(false);

	// The attachment cap + upload state (compose.uploading/compose.uploadErrors) + handleFiles live
	// in ComposeStore now; MAX_ATTACH_BYTES is imported for the over-cap indicator.
	let dragActive = $state(false); // dashed scrim over the compose main while a file is dragged over it
	let hasDefaultCert = $state(false);
	// P4-5: recipients that can't receive encrypted mail (no usable cert on file),
	// surfaced as a toggle-time hint when Encrypt is on. Populated by the recipient
	// cert-presence API (Phase 2/P6 lane); stays [] until that endpoint lands, so
	// the hint simply doesn't show. The send-time fail-closed check is the
	// authoritative gate that blocks the send and names every gap.
	let encryptNoCertRecipients = $state<string[]>([]);
	let showSignatureMenu = $state(false);
	let showTemplateMenu = $state(false);
	let templates = $state<EmailTemplate[]>([]);
	let attachmentWarningShown = $state(false);

	// -- Focus management (a11y: focus trap + return on close) --
	let composeRootEl = $state<HTMLDivElement | null>(null);
	let previousFocus: HTMLElement | null = null;
	let wasOpen = false;

	// -- Options sidebar state --
	let showMore = $state(false);
	let scheduleMode = $state<'now' | 'mon8' | 'fri17' | 'custom'>('now');
	let includeMeeting = $state(false);
	let meetingDate = $state(new Date().toISOString().slice(0, 10));
	let meetingTime = $state('10:00');
	let meetingDuration = $state(30);

	// -- Assist state --
	let assistBusy = $state(false);
	let assistHint = $state('');

	// -- OOO advisory (QoL #7) -- split the mailtips stream into the consolidated
	// out-of-office banner and the rest (inline badges). oooDismissed is per compose
	// session: once dismissed it STAYS dismissed for this window, so the mailtips
	// refetch on refocus never re-nags.
	let oooExpanded = $state(false);
	let oooDismissed = $state(false);
	let oooWarnings = $derived(
		compose.mailtipsWarnings.filter((w) => w.type === 'ooo') as Array<{ recipient: string; until: string | null }>
	);
	let externalLabelsEnabled = $derived($effectiveCaps.externalLabels);
	let otherWarnings = $derived(
		compose.mailtipsWarnings.filter(
			(w) => w.type !== 'ooo' && (w.type !== 'external_recipient' || externalLabelsEnabled),
		),
	);

	// -- DLP compose-time policy tip (dry-run of send-time DLP) -- dismissible
	// per policy hit: dismissing a warn tip suppresses THIS policyId only — a
	// NEW policy hit (different policyId) re-surfaces. Block is never
	// dismissible (it's a hard send-gate, not an advisory).
	let dlpDismissed = $state(false);
	let lastDlpPolicyId: number | undefined;
	$effect(() => {
		// Compare the PRIMITIVE id, not just re-run on every response: dlpTip is
		// replaced wholesale on each fetch (new object identity every time), so
		// gating on identity alone would re-surface a dismissed SAME-policy tip
		// on the very next debounce tick.
		const pid = compose.dlpTip.policyId;
		if (pid !== lastDlpPolicyId) {
			dlpDismissed = false;
			lastDlpPolicyId = pid;
		}
	});
	// quarantine/notify_admin still deliver (with a consequence) — only 'block'
	// refuses Send, so both render at the warn tier.
	let dlpTier = $derived(compose.dlpTip.action === 'block' ? 'block' : 'warn');
	let dlpShown = $derived(compose.dlpTip.violated && !(dlpDismissed && dlpTier !== 'block'));

	// `until` is a bare YYYY-MM-DD date from the reducer; anchor it at local midday so
	// a timezone offset never shifts it a day, then render it in the active locale.
	function formatOooDate(until: string): string {
		const d = new Date(`${until}T12:00:00`);
		return isNaN(d.getTime()) ? until : formatDate(d, 'medium');
	}

	let userEmail = $derived($user?.email ?? '');
	let featureAssist = $derived($effectiveCaps?.assist ?? false);

	// -- Meeting / AvailabilityGrid state --
	const meetingStore = new SchedulingStore();
	let meetingRoomsLoading = $state(false);
	let meetingRoomsError = $state('');
	let meetingRooms = $state<{ id: string; name: string; email: string }[]>([]);
	let meetingAttendeeText = $derived([compose.to, compose.cc].filter(Boolean).join(', '));

	// Build a Map<email, BusyInterval[]> from the To/Cc fields so AvailabilityGrid
	// can render attendee rows. Busy intervals start empty and are filled by the
	// free/busy API once available.
	let meetingAttendees = $derived.by(() => {
		const map = new Map<string, BusyInterval[]>();
		for (const addr of compose.parseAddrList(meetingAttendeeText)) {
			if (addr.email) map.set(addr.email, []);
		}
		return map;
	});

	// -- Undo window from user preference --
	let onSendUndoWindowSeconds = $state(30);

	function loadUndoWindowPref() {
		try {
			if (typeof localStorage !== 'undefined') {
				const v = localStorage.getItem('sj-undo-window');
				if (v) { const n = parseInt(v, 10); if (n >= 5 && n <= 300) onSendUndoWindowSeconds = n; }
			}
		} catch { /* ignore */ }
	}

	async function loadMeetingRooms(signal?: AbortSignal) {
		meetingRoomsLoading = true; meetingRoomsError = '';
		void signal;
		try {
			// CalendarEvent/resourceList is the real bookable-rooms seam; the old
			// fetch hit /api/calendar/rooms — a route that never existed — and
			// discarded its body even on the success path (silently masked by the
			// always-ok test stub until the stub failed loudly).
			const res = await calendarEventResourceList();
			meetingRooms = ((res.list as { id: string; name: string; email: string; resourceType?: string }[]) ?? [])
				.filter((r) => (r.resourceType ?? 'room') === 'room');
			{
				// Populate store with room info but no busy data yet — grid can still show times
				meetingStore.setTimeRange(
					`${meetingDate}T${meetingTime}:00Z`,
					new Date(new Date(`${meetingDate}T${meetingTime}:00Z`).getTime() + meetingDuration * 60 * 1000).toISOString()
				);
			}
		} catch (e) {
			if ((e as Error).name === 'AbortError') return;
			meetingRoomsError = 'Could not load rooms';
		}
		finally { if (!signal?.aborted) meetingRoomsLoading = false; }
	}

	function onMeetingSlotSelect(slot: MutualFreeSlot) {
		// Adopt the chosen mutual-free slot as the meeting time so the send path
		// (iTIP/iMIP) and toast reflect the user's selection.
		meetingDate = slot.start.slice(0, 10);
		meetingTime = slot.start.slice(11, 16);
	}

	let scheduledAtDate = $derived(compose.scheduledAt ? new Date(compose.scheduledAt) : undefined);

	function setScheduledAt(d: Date) {
		compose.scheduledAt = d.toISOString().slice(0, 16);
	}

	let scheduleOptions = $derived([
		{ value: 'now', label: t('compose.sendNow') },
		{ value: 'mon8', label: t('compose.mon8') },
		{ value: 'fri17', label: t('compose.fri17') },
		{ value: 'custom', label: t('compose.custom') },
	]);

	let meetingDurationOptions = $derived([
		{ value: '30', label: '30 min' },
		{ value: '60', label: '60 min' },
		{ value: '90', label: '90 min' },
	]);

	let meetingTimeSlots = $derived(
		buildTimeSlots().map((s) => ({ value: s.value, label: s.label }))
	);

	// One-time initialization from this session's opts. Under the sessions model a
	// ComposeScreen is mounted once per window (opts are fixed at open()), so this
	// runs exactly once — not on every store change as the old open-gated effect did.
	let initialized = false;
	$effect(() => {
		if (initialized || !session) return;
		initialized = true;
		const opts = session.opts;
		// #13 shared-mailbox use-surface: opts.accountId (set when Compose is
		// opened from a shared-mailbox workspace, or from a reply/forward on a
		// shared message) presets the From Select to that mailbox's identity —
		// send_as/full_access preset "send as {shared}", else (send_on_behalf
		// only) preset "on behalf of" (From stays own). Resolved once
		// sharedAccounts loads (loadMailboxes, called below); until then this
		// falls back to opts.from/userEmail like the personal path.
		const sharedId = opts.accountId ?? null;
		compose.sharedAccountId = sharedId;
		if (sharedId) {
			fromSelectValue = 's:' + sharedId + ':as'; // corrected below once sharedAccounts loads, if onbehalf-only
		} else {
			fromSelectValue = 'own';
		}
		compose.fromEmail = opts.from || userEmail || '';
		compose.to = opts.to ?? '';
		compose.cc = opts.cc ?? '';
		compose.bcc = opts.bcc ?? '';
		compose.replyTo = opts.replyToAddr ?? '';
		compose.subject = opts.subject ?? '';
		compose.priority = opts.priority ?? 'normal';
		compose.sensitivity = opts.sensitivity ?? 'normal';
		compose.categories = opts.categories ?? [];
		compose.attachments = opts.attachments ?? [];
		compose.scheduledAt = opts.scheduledAt ?? '';
		compose.readReceipt = opts.readReceipt ?? false;
		compose.useVoting = (opts.voteOptions?.length ?? 0) > 0;
		compose.voteOptions = opts.voteOptions?.length ? opts.voteOptions : [''];
		compose.voteResponse = opts.voteResponse ?? '';
		error = '';
		mailboxError = '';
		replyContextFailed = false;
		draftLoadError = '';
		compose.draftSaveError = false;
		compose.galError = false;
		sent = false;
		compose.editingDraftId = opts.draftId ?? null;
		showMore = false;
		scheduleMode = 'now';
		compose.sendTags = [];
		assistBusy = false;
		assistHint = '';
		hasDefaultCert = false;

		if (opts.body) {
			const prefill = opts.body;
			compose.bodyHtml = prefill;
			// The RichTextEditor snapshots its `content` prop only at mount, so assigning
			// bodyHtml alone leaves the editor empty (the forward body is sent but
			// invisible, and lost the moment the user types). Push it in imperatively
			// once the editor is ready, mirroring the reply-quote path.
			tick().then(() => editorRef?.setContent(prefill));
		}

		loadUndoWindowPref();
		loadMailboxes();
		loadSignatures();
		loadTemplates();
		// F2: load S/MIME cert state so we can warn at toggle-time (not just at Send).
		// Non-critical — a failure simply leaves hasDefaultCert false (no hint shown).
		fetch('/auth/me/smime/certs', { credentials: 'include' })
			.then((r) => r.json())
			.then((data: { certs?: Array<{ isDefault: boolean }> }) => {
				hasDefaultCert = (data.certs ?? []).some((c) => c.isDefault);
			})
			.catch(() => {});
		// Load personal contact groups so "send to group" is searchable in the
		// recipient autocomplete. Non-critical — a failure just omits groups.
		loadGroups().catch(() => {});
		if (opts.replyTo) {
			loadReplyContext(opts.replyTo);
		}
		if (opts.draftId) {
			loadDraft(opts.draftId);
			// Silent restore (undo-send / reopen) — tell the user their work
			// came back, matching the undo-send toast vocabulary.
			if (opts.restored) {
				showToast(t('compose.draftRestored'));
			}
		}
	});

	// Push dock-bar display metadata to this session so the minimized dock can render
	// subject/recipient + the autosave-error badge (design fix, binding). setMeta
	// dedupes (returns the same array when unchanged) so this never loops.
	$effect(() => {
		if (!session) return;
		composeStore.setMeta(session.id, {
			subject: compose.subject,
			recipient: compose.to,
			saveError: compose.draftSaveError
		});
	});

	// #13: `loadMailboxes()` fetches sharedAccounts ASYNCHRONOUSLY, so the preset
	// above (a synchronous guess of ':as') self-corrects here once the real grant
	// set is in — an onbehalf-only account (no send_as/full_access) never gets a
	// sendAsShared row, so its guessed ':as' selection wouldn't match any
	// rendered <option>; this flips it to ':onbehalf' (From=own) instead.
	$effect(() => {
		const id = compose.sharedAccountId;
		if (!id) return;
		if (onBehalfShared.some((a) => a.id === id) && !sendAsShared.some((a) => a.id === id)) {
			fromSelectValue = 's:' + id + ':onbehalf';
			compose.fromEmail = userEmail;
		} else {
			const acct = sendAsShared.find((a) => a.id === id);
			if (!acct) return;
			const presetAlias = acct.sendAsAliases.find(
				(alias) => alias.toLowerCase() === compose.fromEmail.toLowerCase(),
			);
			if (presetAlias) {
				fromSelectValue = sharedAliasToken(id, presetAlias);
				compose.fromEmail = presetAlias;
			} else {
				fromSelectValue = 's:' + id + ':as';
				compose.fromEmail = acct.name;
			}
		}
	});

	$effect(() => {
		if (!session || session.minimized || !includeMeeting || !meetingDate || !meetingTime) return;
		const start = `${meetingDate}T${meetingTime}:00Z`;
		const end = new Date(new Date(start).getTime() + meetingDuration * 60 * 1000).toISOString();
		meetingStore.setTimeRange(start, end);
		const controller = new AbortController();
		loadMeetingRooms(controller.signal);
		return () => controller.abort();
	});

	// Focus management: when this window becomes the maximized one (initial open OR
	// a restore-swap, incl. the auto-minimize path where opening a NEW compose
	// minimizes this one and maximizes the new — the new instance's own effect fires
	// here), capture the trigger and move focus into the To field (binding: "move
	// focus into the new maximized compose"). Focus is RETURNED to the trigger on
	// CLOSE only (onDestroy) — NOT on minimize, so a swap hands focus to the newly
	// maximized window rather than yanking it back.
	$effect(() => {
		const isMax = !!session && !session.minimized;
		if (isMax && !wasOpen) {
			previousFocus = (typeof document !== 'undefined' ? (document.activeElement as HTMLElement) : null);
			tick().then(() => { document.getElementById(`${uid}-to`)?.focus(); });
		}
		wasOpen = isMax;
	});

	function focusableEls(): HTMLElement[] {
		if (!composeRootEl) return [];
		return Array.from(
			composeRootEl.querySelectorAll<HTMLElement>(
				'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
			)
		).filter((el) => el.offsetParent !== null || el === document.activeElement);
	}

	function handleDialogKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			e.preventDefault();
			if (session) composeStore.close(session.id);
			return;
		}
		if (e.key === 'Tab') {
			const els = focusableEls();
			if (els.length === 0) return;
			const first = els[0];
			const last = els[els.length - 1];
			const active = document.activeElement as HTMLElement;
			if (e.shiftKey && active === first) {
				e.preventDefault();
				last.focus();
			} else if (!e.shiftKey && active === last) {
				e.preventDefault();
				first.focus();
			}
		}
	}

	onDestroy(() => {
		if (draftTimer) clearTimeout(draftTimer);
		compose.teardown(); // clears the store-owned GAL + mailtips debounce timers
		if (undoInterval) clearInterval(undoInterval); // else the undo-send countdown ticks on after unmount
		// Return focus to the trigger only on real close (window unmount) — minimize
		// keeps the instance mounted, so this never fires on a minimize/swap.
		if (wasOpen) previousFocus?.focus?.();
	});

	// --- All async functions (loadMailboxes, loadSignatures, pickSignatureForAlias,
	//      loadReplyContext, loadDraft, handleSend, clearUndoInterval,
	//      undoSend, saveDraft, resetForm, handleEditorReady, handleUpdate,
	//      onFiles, triggerFilePicker, discard, addCategory,
	//      removeCategory, addVoteOption, updateVoteOption, removeVoteOption) ---
	// (GAL/mailtips autocomplete moved to ComposeStore — compose.onGalInput etc.)

	async function loadMailboxes() {
		try {
			await loadSession();
			compose.mailboxes = await mailboxGet(undefined, compose.sharedAccountId);
			const res = await fetch('/auth/me', { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				delegates = data.delegates || [];
				aliases = data.aliases || [];
				if (!compose.fromEmail && data.email) compose.fromEmail = data.email;
			}
			if (!compose.signature) {
				compose.signature = '--\n' + (userEmail || '') + '\n';
			}
		} catch (e) {
			console.error('Failed to load mailboxes', e);
			mailboxError = t('compose.mailboxLoadError');
		}
		// #13: the sendable-shared-account list (the From Select's shared rows) is
		// independent of the personal mailboxGet load above — a failure here must
		// not block the rest of compose (the select just omits the shared rows).
		try {
			const all = await getDelegatedAccounts();
			sharedAccounts = all.filter(
				(a) => a.grants.includes('send_as') || a.grants.includes('send_on_behalf') || a.grants.includes('full_access'),
			);
		} catch {
			sharedAccounts = [];
		}
	}

	async function loadSignatures() {
		try {
			const res = await fetch('/api/settings/signatures-list', { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				compose.signatures = Array.isArray(data) ? data : [];
			}
		} catch { /* unavailable */ }
		// A1: auto-select the new-vs-reply default for the current From alias on a
		// fresh compose. Skip when restoring a draft (the body is authoritative) —
		// pickSignatureForAlias is otherwise re-run on From-select change.
		if (!session?.opts.draftId) {
			pickSignatureForAlias(compose.fromEmail);
		}
	}

	function pickSignatureForAlias(email: string) {
		if (compose.signatures.length === 0) {
			compose.signature = '--\n' + (userEmail || '') + '\n';
			compose.selectedSignatureId = null;
			return;
		}
		// An empty email never matches an alias, so it falls through to the
		// role-based default below (A1: the new/reply default still applies before
		// the From address has resolved).
		const match = email ? compose.signatures.find((s) => s.alias_email === email) : undefined;
		if (match) {
			compose.signature = match.signature_text || '';
			compose.selectedSignatureId = match.id;
		} else {
			// A1: pick the signature whose default_for matches the compose mode.
			// A reply/forward (composeStore opts.replyTo set) prefers 'reply' (or
			// 'both'); a fresh compose prefers 'new' (or 'both'). Fall back to the
			// legacy is_default flag, then to the auto-generated stub.
			const isReply = !!session?.opts.replyTo;
			const def = isReply
				? compose.signatures.find((s) => s.default_for === 'reply' || s.default_for === 'both')
				: compose.signatures.find((s) => s.default_for === 'new' || s.default_for === 'both');
			const chosen = def ?? compose.signatures.find((s) => s.is_default);
			if (chosen) {
				compose.signature = chosen.signature_text || '';
				compose.selectedSignatureId = chosen.id;
			} else {
				compose.signature = '--\n' + (userEmail || '') + '\n';
				compose.selectedSignatureId = null;
			}
		}
		if (compose.useSignature && editorRef && compose.signature) {
			const text = editorRef.getText();
			if (!text.includes(compose.signature.trim())) {
				editorRef.setContent(editorRef.getHTML() + '<p><br></p>' + compose.signature.replace(/\n/g, '<br>'));
			}
		}
	}

	// Insert→Signature: append the chosen signature to the current body. HTML is
	// sanitized (mirrors the reply-context path) before it enters the editor.
	function insertSignature(sig: { signature_html: string; signature_text: string }) {
		const html = sig.signature_html || sig.signature_text.replace(/\n/g, '<br>');
		if (editorRef) {
			editorRef.setContent(editorRef.getHTML() + '<p><br></p>' + sanitizeHTML(html));
		}
		showSignatureMenu = false;
	}

	// Compose templates / Quick Parts. Loaded on open; a failure leaves the list
	// empty (menu shows the empty state).
	async function loadTemplates() {
		try {
			templates = await emailTemplateList();
		} catch { /* unavailable */ }
	}

	// Insert→Template: drop the template body at the cursor. The body is user-authored
	// HTML that flows into the editor + outbound mail, so it MUST pass through
	// sanitizeHTML before it enters the editor (never insert raw). Subject fills in
	// only when the compose subject is still empty (never clobbers a typed subject).
	function insertTemplate(tpl: EmailTemplate) {
		editorRef?.getEditor()?.commands.insertContent(sanitizeHTML(tpl.bodyHtml));
		if (tpl.subject && !compose.subject.trim()) compose.subject = tpl.subject;
		showTemplateMenu = false;
	}

	async function loadReplyContext(replyToId: string) {
		try {
			await loadSession();
			const [email] = await emailGet([replyToId], FULL_EMAIL_PROPS, undefined, compose.sharedAccountId);
			if (email) {
				if (!compose.to) compose.to = email.from?.[0]?.email || '';
				const replyBodyHTML = email.bodyHTML || '';
				const replyBodyText = email.bodyText || email.preview || '';
				if (editorRef) {
					if (replyBodyHTML) {
						const safeHTML = sanitizeHTML(replyBodyHTML);
						editorRef.setContent(editorRef.getHTML() + '<p><br></p><blockquote>' + safeHTML + '</blockquote>');
					} else {
						// Plain-text boundary (occ_b60bbe1192d7e36f597f1d56): the text
						// body is attacker-controlled plain TEXT — entity-encode it
						// BEFORE the newline→<br> pass, or embedded markup
						// (`<img src="https://…">`) becomes real HTML in the editor
						// and bypasses the remote-image gate sanitizeHTML enforces on
						// the HTML branch above.
						editorRef.setContent(editorRef.getHTML() + '<p></p><p>--- Original message ---</p><p>' + escapeHTML(replyBodyText).replace(/\n/g, '<br>') + '</p>');
					}
				}
			}
		} catch (e) {
			console.error('Failed to load reply context', e);
			replyContextFailed = true;
		}
	}

	async function loadDraft(draftId: string) {
		const hydration = compose.beginHydration();
		try {
			await loadSession();
			const [email] = await emailGet([draftId], FULL_EMAIL_PROPS, undefined, compose.sharedAccountId);
			if (!email) return;
			const editorHydration = compose.applyHydration(hydration, () => {
				compose.fromEmail = email.from?.[0]?.email || userEmail || '';
				compose.to = email.to?.map((a: { name?: string; email: string }) => a.name ? `${a.name} <${a.email}>` : a.email).join(', ') || '';
				compose.cc = email.cc?.map((a: { name?: string; email: string }) => a.name ? `${a.name} <${a.email}>` : a.email).join(', ') || '';
				compose.bcc = email.bcc?.map((a: { name?: string; email: string }) => a.name ? `${a.name} <${a.email}>` : a.email).join(', ') || '';
				compose.replyTo = email.replyTo?.[0]?.email || '';
				compose.subject = email.subject || '';
				compose.priority = email.priority === 1 ? 'high' : email.priority === -1 ? 'low' : 'normal';
				compose.sensitivity = (email.sensitivity as typeof compose.sensitivity) || 'normal';
				compose.readReceipt = email.readReceiptRequested || false;
				compose.scheduledAt = email.scheduledAt ? new Date(email.scheduledAt).toISOString().slice(0, 16) : '';
				if (email.voteOptions?.length) { compose.useVoting = true; compose.voteOptions = email.voteOptions; }
				// Same plain-text boundary as the reply quote (occ_b60bbe1192d7e36f597f1d56):
				// a draft's text/plain part is TEXT, never markup to re-parse.
				if (email.bodyText) compose.bodyHtml = escapeHTML(email.bodyText).replace(/\n/g, '<br>');
			});
			if (email.bodyText && editorHydration) {
				// The editor snapshots content only at mount and stays mounted across
				// opens. Re-check after tick so reset/user edits cannot be overwritten
				// by a response whose store portion was current one microtask earlier.
				tick().then(() => {
					if (compose.canApplyHydration(editorHydration)) editorRef?.setContent(compose.bodyHtml);
				});
			}
		} catch (e) {
			console.error('Failed to load draft', e);
			if (compose.canApplyHydration(hydration)) draftLoadError = t('compose.draftLoadError');
		}
	}

	// parseAddrList / getDraftsId / getSentId / getBodyHTML / getBodyText / buildMsg
	// moved to ComposeStore (A6 slice 1). Body-reading methods take the editor handle
	// as a parameter — the store never owns the `bind:this` editor ref.

	async function handleSend() {
		error = '';
		formErrors = {};
		const validationResult = validate({
			to: [required('At least one recipient is required')],
			subject: [required('Subject is required'), maxLength(998, 'Subject is too long (maximum 998 characters)')],
		}, { to: compose.to.trim(), subject: compose.subject.trim() });
		if (!validationResult.valid) { formErrors = validationResult.errors; return; }

		// Don't silently drop an attachment that failed to upload. (The Send button is
		// already disabled while compose.uploading; this covers the failed-upload case.)
		if (compose.failedUploads.length > 0) {
			error = t('compose.uploadFailedBlocking', { count: String(compose.failedUploads.length) });
			return;
		}

		// Attachment reminder: the body/subject mentions an attachment but none is
		// attached. Warn once; a second Send (warning already shown) goes through.
		if (compose.attachments.length === 0 && !attachmentWarningShown &&
			mentionsAttachment(compose.subject, compose.getBodyText(editorRef), $locale)) {
			attachmentWarningShown = true;
			error = t('compose.attachmentReminder');
			return;
		}

		sending = true;
		try {
			// The JMAP orchestration (create the email, submit it, record recipients,
			// clear the edited-draft id) lives in the store; this handler keeps the
			// view concerns around it — validation (above), and the toast/undo-timer/
			// close (below). A submission S/MIME marker surfaces as a
			// SubmissionMarkerError the catch localizes (never the raw description).
			const { emailId, held } = await compose.createAndSubmit(editorRef, userEmail, scheduleMode, onSendUndoWindowSeconds);

			// Held for external-send approval: the message is parked as an approval_request,
			// not queued/sent — so there is nothing to undo. Show a distinct "held" toast,
			// do NOT arm the undo-send timer (undoSend → message_cancel would no-op against a
			// non-existent scheduled/undo row), then close.
			if (held) {
				resetForm();
				showToast(t('compose.messageHeld'), { durationMs: 6000 });
				if (session) composeStore.close(session.id);
				return;
			}

			// Capture toast inputs before resetForm() clears them.
			const wasScheduled = !!compose.scheduledAt && scheduleMode !== 'now';
			const scheduledLabel = compose.scheduledAt ? formatDateTime(new Date(compose.scheduledAt)) : '';
			const bookedRoom = includeMeeting ? meetingStore.selectedRoom?.name : undefined;

			resetForm();

			// Toast composition (Task 10)
			const parts: string[] = [];
			if (wasScheduled) {
				parts.push(t('compose.scheduledFor', { time: scheduledLabel }));
			}
			if (bookedRoom) {
				parts.push(t('compose.roomBooked', { name: bookedRoom }));
			}
			const base = wasScheduled
				? t('compose.messageScheduled')
				: t('compose.sendingIn', { n: String(onSendUndoWindowSeconds) });
			const toastMsg = parts.length ? `${base} · ${parts.join(' · ')}` : base;
			const actionLabel = wasScheduled ? t('compose.undo') : t('compose.cancel');

			undoSendEmailId = emailId;
			undoCountdown = onSendUndoWindowSeconds;
			undoInterval = setInterval(() => {
				undoCountdown--;
				if (undoCountdown <= 0) {
					clearUndoInterval();
					undoSendEmailId = null;
					sent = true;
					setTimeout(() => { sent = false; if (session) composeStore.close(session.id); }, 1500);
				}
			}, 1000);

			showToast(toastMsg, { actionLabel, onAction: undoSend, durationMs: onSendUndoWindowSeconds * 1000 });
		} catch (e) {
			// A submission S/MIME marker is localized here (never the raw description);
			// a flow error (drafts-missing / offline / create-failed) shows its message.
			error = e instanceof SubmissionMarkerError ? mapSubmissionMarker(e) : (e as Error).message;
		} finally {
			sending = false;
		}
	}

	// F1/F4: map a submission notCreated marker to localized copy. The encrypt-no-cert
	// case NAMES every offending recipient; unknown markers fall to a generic message.
	function mapSubmissionMarker(e: SubmissionMarkerError): string {
		switch (e.code) {
			case 'overQuota':
				// RFC 8621 SetError from the submission reducer (BZ004: daily
				// sending quota). Generic "try again" copy is actively wrong here —
				// the quota resets tomorrow.
				return t('compose.quota_exceeded');
			case 'smime_no_cert':
				return t('compose.smime_no_cert');
			case 'smime_no_matching_cert':
				return t('compose.smime_no_matching_cert', { from: compose.fromEmail });
			case 'smime_sign_failed':
				return t('compose.smime_sign_failed');
			case 'smime_encrypt_no_cert': {
				const addrs = (e.addresses ?? []).join(', ');
				return t('compose.smime_encrypt_no_cert', { addresses: addrs || t('compose.smime_encrypt_some_recipients') });
			}
			case 'smime_encrypt_no_sender_cert':
				return t('compose.smime_encrypt_no_sender_cert');
			case 'smime_encrypt_no_journal_cert':
				return t('compose.smime_encrypt_no_journal_cert');
			default:
				return t('compose.send_failed');
		}
	}

	function clearUndoInterval() {
		if (undoInterval) { clearInterval(undoInterval); undoInterval = null; }
	}

	async function undoSend() {
		if (!undoSendEmailId) return;
		clearUndoInterval();
		const emailId = undoSendEmailId;
		const sharedAccountId = compose.sharedAccountId;
		const fromEmail = compose.fromEmail;
		undoSendEmailId = null;
		try {
			await emailSubmissionCancel(emailId, sharedAccountId);
			compose.editingDraftId = emailId;
			// #13: preserve the shared-mailbox context the cancelled send was sent
			// from, so the restored draft reopens as the same identity.
			composeStore.open(
				sharedAccountId
					? { draftId: emailId, restored: true, accountId: sharedAccountId, from: fromEmail }
					: { draftId: emailId, restored: true },
			);
		} catch (e) {
			error = 'Failed to cancel send: ' + (e as Error).message;
		}
	}

	// saveDraft moved to ComposeStore (slice 2a) — it takes the editor handle +
	// userEmail as params. Callers: handleUpdate's debounce + the retry button.

	function resetForm() {
		compose.resetOwnedState();
		mailboxError = ''; draftLoadError = ''; replyContextFailed = false;
		showMore = false; scheduleMode = 'now';
		showSignatureMenu = false; showTemplateMenu = false; attachmentWarningShown = false;
		fromSelectValue = 'own';
		editorRef?.clearContent();
	}

	function handleEditorReady(ed: Editor) { tipTapEditor = ed; }

	function handleUpdate(html: string, text: string) {
		compose.bodyHtml = html; compose.bodyText = text;
		// WAVE-5 #2: drop any inline-image row whose <img> the user deleted from the
		// body directly (backspace) — otherwise it would survive invisibly, still
		// eating the shared attachment budget (and, if still uploading, the gate).
		compose.pruneOrphanedInlineImages(html);
		if (draftTimer) clearTimeout(draftTimer);
		draftTimer = setTimeout(() => compose.saveDraft(editorRef, userEmail), 5000);
	}

	// WAVE-5 #2: bridges RichTextEditor's (store-agnostic) inline-image props to
	// the store — same shape as onFiles/handleUpdate above.
	function stageInlineImage(file: File) {
		return compose.stageInlineImage(file);
	}

	// A file RichTextEditor did NOT inline (a non-whitelisted type, or one over
	// the shared budget) is forwarded here rather than silently dropped — it
	// rides the ordinary file-attachment path (same toast copy either way).
	function onNonInlineFiles(files: File[]) {
		void onFiles(files);
	}

	// The live status/progress RichTextEditor's upload overlay tracks. Only the
	// still-in-flight rows: 'done' needs no overlay, and 'failed' strips its own
	// placeholder from the body (the $effect below) rather than showing one.
	let inlineUploads = $derived(
		compose.attachments
			.filter((a) => a.inline && a.uploadId && (a.status === 'preparing' || a.status === 'uploading'))
			.map((a) => ({ uploadId: a.uploadId as string, status: a.status, progress: a.progress ?? 0 }))
	);

	// A failed inline image's placeholder is stripped from the body — the row
	// survives as an ordinary failed file-attachment chip (retry/remove already
	// built for that list below) rather than a separate in-body error state.
	// removeInlineImage no-ops once the node is gone, so re-running this while
	// the row is still 'failed' (any later attachments change re-triggers it)
	// costs nothing.
	$effect(() => {
		for (const a of compose.attachments) {
			if (a.inline && a.status === 'failed' && a.uploadId) editorRef?.removeInlineImage(a.uploadId);
		}
	});


	$effect(() => {
		// Read recipient fields so this effect re-runs when any of them change.
		void compose.to; void compose.cc; void compose.bcc; void compose.fromEmail;
		compose.debounceMailTips();
		// The debounce timer is owned + torn down by the store (compose.teardown()
		// in onDestroy); compose.debounceMailTips clears the prior timer on each call.
	});

	// DLP dry-run: the recipient seam above PLUS subject/body — a DLP hit is
	// content-driven, not recipient-driven. #dlpTimer is owned + torn down by
	// the store the same way #mailtipsTimer is.
	$effect(() => {
		void compose.to; void compose.cc; void compose.bcc;
		void compose.subject; void compose.bodyText;
		compose.debounceDlpCheck();
	});

	// Upload the given files through the store, then surface any over-cap skips as a
	// toast — the store returns the skipped names and stays UI-agnostic (no toast/
	// i18n import). Upload feedback (compose.uploading / compose.failedUploads) lives on the store.
	async function onFiles(files: FileList | File[] | null) {
		const skipped = await compose.handleFiles(files);
		for (const name of skipped) {
			showToast(t('compose.attachmentTooLarge', { name }), { durationMs: 5000 });
		}
	}

	// Paste-to-attach (Gmail parity): when the clipboard carries files (e.g. a
	// screenshot), route them through onFiles instead of the default text paste.
	function handlePaste(e: ClipboardEvent) {
		const files = e.clipboardData?.files;
		if (files && files.length > 0) {
			e.preventDefault();
			void onFiles(files);
		}
	}

	// Clear the drag scrim only when the pointer actually leaves the compose main —
	// dragleave bubbles from every descendant, so ignore moves between children.
	function handleMainDragLeave(e: DragEvent) {
		const related = e.relatedTarget as Node | null;
		if (!related || !(e.currentTarget as HTMLElement).contains(related)) dragActive = false;
	}

	// Re-arm the attachment reminder whenever the attachment set changes (adding a
	// file after the warning should not skip a fresh check on the next Send).
	$effect(() => { void compose.attachments.length; attachmentWarningShown = false; });

	function triggerFilePicker() { document.getElementById(`${uid}-file`)?.click(); }

	function discard() { resetForm(); error = ''; if (session) composeStore.close(session.id); }

	function addCategory() {
		const cat = compose.newCategory.trim();
		if (cat && !compose.categories.includes(cat)) { compose.categories = [...compose.categories, cat]; compose.newCategory = ''; }
	}

	function removeCategory(cat: string) { compose.categories = compose.categories.filter((c) => c !== cat); }

	function addVoteOption() { compose.voteOptions = [...compose.voteOptions, '']; }
	function updateVoteOption(i: number, val: string) { compose.voteOptions = compose.voteOptions.map((v, idx) => (idx === i ? val : v)); }
	function removeVoteOption(i: number) { compose.voteOptions = compose.voteOptions.filter((_, idx) => idx !== i); }

	// -- Tag on send helpers --
	function toggleSendTag(id: string) {
		if (compose.sendTags.includes(id)) {
			compose.sendTags = compose.sendTags.filter((t) => t !== id);
		} else {
			compose.sendTags = [...compose.sendTags, id];
		}
	}

	// -- Assist (Task 9) --
	async function runAssist(action: string) {
		assistBusy = true;
		assistHint = t('compose.assistThinking');
		try {
			const body = compose.getBodyText(editorRef) || compose.subject;
			const replyLang = $locale === 'zh' ? '用中文回复。' : 'Reply in English.';
			let prompt = '';
			if (action === 'draft') {
				prompt = `You are the writing assistant in setjoin Mail. Draft a concise, plain, professional email body (no subject line, plain text only, no markdown) for the subject: "${compose.subject}". ${replyLang}`;
			} else if (action === 'polish') {
				prompt = `Polish this email body, keep the meaning and tone calm and plain. Reply with the body only, plain text, no markdown:\n\n${body}`;
			} else if (action === 'translate') {
				const targetLang = $locale === 'zh' ? 'English' : 'Simplified Chinese';
				prompt = `Translate this email body to ${targetLang}, body only, plain text:\n\n${body}`;
			} else if (action === 'shorten') {
				prompt = `Shorten this email body to its essentials. Body only, plain text, no markdown:\n\n${body}`;
			}
			const content = await assistComplete([{ role: 'user', content: prompt }], $locale);
			if (content && editorRef) {
				// Assist output is a semi-untrusted channel (LLM output influenced by
				// quoted attacker email text); sanitize before writing into the editor,
				// mirroring the reply-context path.
				editorRef.setContent(sanitizeHTML(content));
			}
		} catch (e) {
			showToast(t('compose.assistUnavailable'), { durationMs: 5000 });
		} finally {
			assistBusy = false;
			assistHint = '';
		}
	}
</script>

<!-- Multi-compose (QoL #18): the window is CSS-hidden (display:none) when minimized —
     NEVER unmounted — so the editor + in-flight uploads survive. The minimized dock
     bar is rendered by ComposeDock. -->
{#if session}
	<div
		bind:this={composeRootEl}
		style="position: absolute; inset: 0; z-index: 100; display: {session.minimized ? 'none' : 'flex'}; flex-direction: column; background: var(--surface-card)"
		class="sj-compose-screen"
		data-testid="compose-screen"
		role="dialog"
		aria-modal="true"
		aria-label={t('compose.title')}
		tabindex="-1"
		onkeydown={handleDialogKeydown}
		onpaste={handlePaste}
	>
		<div class="sj-compose-header">
			<Icon name="Pencil" size={16} style="color: var(--accent)" />
			<span class="sj-compose-title">{t('compose.title')}</span>
			<span class="sj-compose-spacer"></span>
			<IconButton label={t('compose.minimize')} variant="ghost" size="sm" onclick={() => session && composeStore.minimize(session.id)}>
				<Icon name="Minus" size={16} />
			</IconButton>
			<IconButton label={t('compose.close')} variant="ghost" size="sm" onclick={() => session && composeStore.close(session.id)}>
				<Icon name="X" size={16} />
			</IconButton>
		</div>

		<div class="sj-compose-body">
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<!-- Drag over the whole column is a supplementary visual affordance; the
			     accessible attach path is the role="button" drop-zone + file input below. -->
			<div class="sj-compose-main"
				ondragenter={(e) => { e.preventDefault(); dragActive = true; }}
				ondragover={(e) => { e.preventDefault(); dragActive = true; }}
				ondragleave={handleMainDragLeave}
				ondrop={async (e) => { e.preventDefault(); dragActive = false; await onFiles(e.dataTransfer?.files ?? null); }}>
				{#if dragActive}
					<div class="compose-drop-overlay" aria-hidden="true">
						<span class="drop-zone-label"><Icon name="Paperclip" size={18} />{t('compose.dropFiles')}</span>
					</div>
				{/if}
				{#if sent}<div class="compose-banner compose-banner--success">{t('compose.sent')}</div>{/if}
				{#if compose.draftSaved}<div class="compose-banner compose-banner--draft">{t('compose.draftSaved')}</div>{/if}
				{#if compose.sharedDraftConflict}<div class="compose-banner compose-banner--error" role="alert">{t('compose.sharedDraftConflict')}</div>{/if}
				{#if compose.sharedDraftSession}
					<div class="compose-banner compose-banner--draft compose-shared-lease" role="status">
						<span>{t('compose.sharedDraftLease', {
							holder: compose.sharedDraftSession.leaseHolderUserId ?? t('compose.sharedDraftYou'),
							expires: formatDateTime(compose.sharedDraftSession.leaseExpiresAt),
							sender: compose.sharedDraftSession.finalSenderAddress ?? compose.fromEmail,
						})}</span>
						{#if !compose.sharedDraftReadOnly}
							<Button size="sm" variant="ghost" onclick={() => (showDraftHandoff = !showDraftHandoff)}>
								{t('compose.sharedDraftHandoff')}
							</Button>
						{/if}
					</div>
					{#if showDraftHandoff && !compose.sharedDraftReadOnly}
						<div class="compose-draft-handoff" aria-label={t('compose.sharedDraftHandoff')}>
							<label for={`${uid}-draft-handoff`}>{t('compose.sharedDraftHandoffTo')}</label>
							<input id={`${uid}-draft-handoff`} type="search" bind:value={draftHandoffQuery}
								placeholder={t('compose.sharedDraftHandoffSearch')} oninput={() => void searchDraftHandoff()} />
							{#if draftHandoffBusy}<Spinner size={16} />{/if}
							{#each draftHandoffResults as member (member.id)}
								<button type="button" class:selected={draftHandoffTarget?.id === member.id}
									onclick={() => (draftHandoffTarget = member)}>
									<strong>{member.displayName || member.email}</strong><span>{member.email}</span>
								</button>
							{/each}
							<Button size="sm" variant="primary" disabled={!draftHandoffTarget || draftHandoffBusy} onclick={handoffSharedDraft}>
								{t('compose.sharedDraftHandoffConfirm')}
							</Button>
							{#if draftHandoffError}<p class="compose-draft-handoff__error" role="alert">{draftHandoffError}</p>{/if}
						</div>
					{/if}
				{/if}
				{#if mailboxError}<div class="compose-banner compose-banner--error">{mailboxError}</div>{/if}
				{#if draftLoadError}<div class="compose-banner compose-banner--error">{draftLoadError}</div>{/if}

				<div class="cp-field">
					<label class="cp-label" for={`${uid}-from`}>{t('compose.from_label')}</label>
					<select id={`${uid}-from`} class="cp-input cp-input--select" bind:value={fromSelectValue} onchange={handleFromSelectChange}>
						<option value="own">{userEmail}</option>
						{#each delegates as d}
							<option value={'d:' + d.email}>{d.name ? `${d.name} <${d.email}>` : d.email}</option>
						{/each}
						{#each aliases as a}
							<option value={'a:' + a.email}>{a.email}</option>
						{/each}
						<!-- #13 shared-mailbox use-surface: send-as / on-behalf-of rows for
						     every MAIL-delegated mailbox with a send grant. -->
						{#each sendAsShared as acct (acct.id)}
							<option value={'s:' + acct.id + ':as'}>{acct.name}</option>
							{#each acct.sendAsAliases as alias}
								<option value={sharedAliasToken(acct.id, alias)}>{alias}</option>
							{/each}
						{/each}
						{#each onBehalfShared as acct (acct.id)}
							<option value={'s:' + acct.id + ':onbehalf'}>{t('compose.on_behalf_of', { name: acct.name })}</option>
						{/each}
					</select>
					<svg class="cp-select-caret" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m6 9 6 6 6-6"></path></svg>
				</div>
				{#if fromCaption}<p class="cp-from-caption">{fromCaption}</p>{/if}

				{#snippet galDropdown(target: 'to' | 'cc' | 'bcc')}
					{#if compose.galShow && compose.galTarget === target}
						<div class="gal-dropdown" id={`cmp-gal-${target}`} role="listbox">
							<!-- Personal contact groups (flat index 0..G) -->
							{#each compose.groupSuggestions as g, gi}
								<button type="button" class="gal-item gal-item--group" id={`cmp-gal-${target}-${gi}`} role="option" aria-selected={compose.galActive === gi} class:gal-item--active={compose.galActive === gi} onclick={() => compose.pickGroup(g)}>
									<span class="gal-group-mark"><Icon name="Users" size={14} /></span>
									<strong>{g.name}</strong>
									<span>{t('contacts.group.member_count', { count: String(g.memberCount) })}</span>
								</button>
							{/each}
							<!-- Cached past recipients (flat index G..G+C), each with a remove (X) -->
							{#each compose.cacheSuggestions as s, ci}
								{@const idx = compose.groupSuggestions.length + ci}
								<div class="gal-item gal-item--cache" id={`cmp-gal-${target}-${idx}`} role="option" aria-selected={compose.galActive === idx} class:gal-item--active={compose.galActive === idx}>
									<button type="button" class="gal-cache-pick" onclick={() => compose.pickCacheSuggestion(s)}>
										<strong>{s.name || s.email}</strong>
										{#if s.name}<span>{s.email}</span>{/if}
									</button>
									<button type="button" class="gal-cache-x" aria-label={t('compose.removeRecipient', { email: s.email })} onclick={(e) => compose.forgetSuggestion(s.email, e)}>
										<Icon name="X" size={13} />
									</button>
								</div>
							{/each}
							<!-- GAL results (flat index G+C..end) -->
							{#if compose.galError}
								<div class="gal-item gal-item-error">{t('compose.searchUnavailable')}</div>
							{:else}
								{#each compose.galResults as c, ri}
									{@const idx = compose.groupSuggestions.length + compose.cacheSuggestions.length + ri}
									<button type="button" class="gal-item" id={`cmp-gal-${target}-${idx}`} role="option" aria-selected={compose.galActive === idx} class:gal-item--active={compose.galActive === idx} onclick={() => compose.pickContact(c)}>
										<strong>{c.displayName || c.firstName + ' ' + c.lastName}</strong>
										<span>{c.email || c.emails?.[0]?.address}</span>
									</button>
								{/each}
							{/if}
						</div>
					{/if}
				{/snippet}

				<div class="cp-field gal-wrap">
					<label class="cp-label" for={`${uid}-to`}>{t('compose.to')}</label>
					<input id={`${uid}-to`} class="cp-input" class:cp-input--error={formErrors.to} type="text" bind:value={compose.to} maxlength="254" placeholder={t('compose.to_placeholder')}
						role="combobox" aria-autocomplete="list" aria-expanded={compose.galShow && compose.galTarget === 'to'} aria-controls="cmp-gal-to" aria-activedescendant={compose.galShow && compose.galTarget === 'to' && compose.galActive >= 0 ? `cmp-gal-to-${compose.galActive}` : undefined}
						oninput={(e) => compose.onGalInput('to', (e.target as HTMLInputElement).value)} onfocus={() => (compose.galTarget = 'to')} onkeydown={(e) => compose.onGalKeydown('to', e)} />
					{#if formErrors.to}<span class="cp-field-error">{formErrors.to}</span>{/if}
					{#if !showCc && !showBcc}
						<span class="cp-reveal-btns">
							<button class="cp-reveal-btn" onclick={() => (showCc = true)}>{t('compose.cc')}</button>
							<button class="cp-reveal-btn" onclick={() => (showBcc = true)}>{t('compose.bcc')}</button>
						</span>
					{/if}
					{@render galDropdown('to')}
				</div>

				{#if showCc}
					<div class="cp-field gal-wrap">
						<label class="cp-label" for={`${uid}-cc`}>{t('compose.cc')}</label>
						<input id={`${uid}-cc`} class="cp-input" type="text" bind:value={compose.cc}
							role="combobox" aria-autocomplete="list" aria-expanded={compose.galShow && compose.galTarget === 'cc'} aria-controls="cmp-gal-cc" aria-activedescendant={compose.galShow && compose.galTarget === 'cc' && compose.galActive >= 0 ? `cmp-gal-cc-${compose.galActive}` : undefined}
							oninput={(e) => compose.onGalInput('cc', (e.target as HTMLInputElement).value)} onfocus={() => (compose.galTarget = 'cc')} onkeydown={(e) => compose.onGalKeydown('cc', e)} />
						{@render galDropdown('cc')}
					</div>
				{/if}

				{#if showBcc}
					<div class="cp-field gal-wrap">
						<label class="cp-label" for={`${uid}-bcc`}>{t('compose.bcc')}</label>
						<input id={`${uid}-bcc`} class="cp-input" type="text" bind:value={compose.bcc}
							role="combobox" aria-autocomplete="list" aria-expanded={compose.galShow && compose.galTarget === 'bcc'} aria-controls="cmp-gal-bcc" aria-activedescendant={compose.galShow && compose.galTarget === 'bcc' && compose.galActive >= 0 ? `cmp-gal-bcc-${compose.galActive}` : undefined}
							oninput={(e) => compose.onGalInput('bcc', (e.target as HTMLInputElement).value)} onfocus={() => (compose.galTarget = 'bcc')} onkeydown={(e) => compose.onGalKeydown('bcc', e)} />
						{@render galDropdown('bcc')}
					</div>
				{/if}

				{#if otherWarnings.length > 0}
					<div class="mailtips">
						{#each otherWarnings as w}
							<div class="mailtip-badge" class:mailtip-warn={w.type === 'large_audience'} class:mailtip-ext={w.type === 'external_recipient'} class:mailtip-err={w.type === 'no_send_as'}>
								{#if w.type === 'large_audience'}{w.message}
								{:else if w.type === 'external_recipient'}{t('compose.mailtip.external', { recipient: w.recipient })}
								{:else if w.type === 'no_send_as'}{w.message}
								{/if}
							</div>
						{/each}
					</div>
				{/if}

				<!-- QoL #7: ONE consolidated out-of-office advisory. Expandable per-person,
				     polite live region, dismissible per compose session (no re-nag on
				     refocus), never blocks Send. -->
				{#if oooWarnings.length > 0 && !oooDismissed}
					<div class="ooo-advisory" role="status" aria-live="polite">
						<button class="ooo-advisory__head" aria-expanded={oooExpanded} onclick={() => (oooExpanded = !oooExpanded)}>
							<Icon name={oooExpanded ? 'ChevronDown' : 'ChevronRight'} size={14} />
							<span>{t('compose.ooo_summary', { count: String(oooWarnings.length) })}</span>
						</button>
						<IconButton label={t('compose.ooo_dismiss')} variant="ghost" size="sm" onclick={() => (oooDismissed = true)}>
							<Icon name="X" size={13} />
						</IconButton>
						{#if oooExpanded}
							<ul class="ooo-advisory__list">
								{#each oooWarnings as w}
									<li>
										{#if w.until}
											{t('compose.ooo_person_until', { recipient: w.recipient, date: formatOooDate(w.until) })}
										{:else}
											{t('compose.ooo_person_indefinite', { recipient: w.recipient })}
										{/if}
									</li>
								{/each}
							</ul>
						{/if}
					</div>
				{/if}

				<!-- DLP compose-time policy tip: dry-run of the SAME dlp_check seam
				     send() enforces (dlp_evaluate_draft), so this can never disagree
				     with the send-time verdict. warn/quarantine/notify_admin render
				     as an advisory (dismissible per policy hit); only 'block' disables
				     Send below and is never dismissible. -->
				{#if dlpShown}
					<div class="dlp-tip" class:dlp-tip--block={dlpTier === 'block'}
						role={dlpTier === 'block' ? 'alert' : 'status'}
						aria-live={dlpTier === 'block' ? 'assertive' : 'polite'}>
						<Icon name={dlpTier === 'block' ? 'ShieldAlert' : 'Shield'} size={14} />
						<span>
							{dlpTier === 'block'
								? t('compose.dlp_blocked', { policy: compose.dlpTip.policyName ?? '' })
								: t('compose.dlp_warn', { policy: compose.dlpTip.policyName ?? '' })}
						</span>
						{#if dlpTier !== 'block'}
							<IconButton label={t('compose.dlp_dismiss')} variant="ghost" size="sm" onclick={() => (dlpDismissed = true)}>
								<Icon name="X" size={13} />
							</IconButton>
						{/if}
					</div>
				{/if}

				<div class="cp-field">
					<label class="cp-label" for={`${uid}-subject`}>{t('compose.subject')}</label>
					<input id={`${uid}-subject`} class="cp-input cp-input--subject" class:cp-input--error={formErrors.subject} type="text" bind:value={compose.subject} maxlength="998"
						oninput={() => handleUpdate(compose.bodyHtml, compose.bodyText)} />
					{#if formErrors.subject}<span class="cp-field-error">{formErrors.subject}</span>{/if}
				</div>

				<!-- WAVE-5 #2: a DONE inline image renders in the body itself (no chip —
				     it would be a confusing duplicate); a FAILED one strips its body
				     placeholder (ComposeScreen's $effect above) and lands here instead,
				     reusing this list's retry/remove UI unchanged. -->
				{#if compose.attachments.some((a) => !a.inline || a.status === 'failed')}
					<div class="attachments-list">
						{#each compose.attachments.filter((a) => !a.inline || a.status === 'failed') as att (att.uploadId ?? `${att.blobId}-${att.name}`)}
							{@const status = att.status ?? 'done'}
							{@const i = compose.attachments.indexOf(att)}
							<div class="att-item" class:att-item--failed={status === 'failed'}>
								<div class="att-item__row">
									<span class="att-name">{att.name}</span>
									<span class="att-size">{formatBytes(att.size)}</span>
									{#if status === 'failed'}
										<span class="att-failed-label">{t('compose.uploadChipFailed')}</span>
										<button type="button" class="att-retry"
											onclick={() => att.uploadId && compose.retryUpload(att.uploadId)}>
											{t('compose.uploadRetry')}
										</button>
									{/if}
									<!-- Cancel-X while in flight (aborts the XHR + removes the chip,
									     un-gating Send); plain remove once done/failed. -->
									<button type="button" class="att-remove"
										aria-label={status === 'preparing' || status === 'uploading'
											? t('compose.uploadCancel', { name: att.name })
											: t('compose.removeAttachment', { name: att.name })}
										onclick={() => compose.removeAttachment(i)}>×</button>
								</div>
								{#if status === 'preparing'}
									<!-- Whole-file SHA-256 digest blocks before progress can start. -->
									<Progress value={0} indeterminate label={t('compose.uploadPreparing', { name: att.name })} />
								{:else if status === 'uploading'}
									<Progress value={att.progress ?? 0} label={t('compose.uploadProgressOf', { name: att.name })} />
								{/if}
							</div>
						{/each}
					</div>
					<span class="attach-total" class:attach-total--over={compose.attachmentBytes > MAX_ATTACH_BYTES}>{t('compose.attachmentTotal', { used: formatBytes(compose.attachmentBytes) })}</span>
				{/if}

				<div class="drop-zone" role="button" tabindex="0"
					onclick={() => document.getElementById(`${uid}-file`)?.click()}
					onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); document.getElementById(`${uid}-file`)?.click(); } }}
					ondragover={(e) => e.preventDefault()}
					ondrop={async (e) => { e.preventDefault(); e.stopPropagation(); dragActive = false; await onFiles(e.dataTransfer?.files ?? null); }}>
					{#if compose.uploading}
						<span class="drop-zone-label"><Spinner size={16} />{t('compose.uploading')}</span>
					{:else}
						<span class="drop-zone-label"><Icon name="Paperclip" size={14} />{t('compose.dropFiles')}</span>
					{/if}
					<input id={`${uid}-file`} type="file" multiple hidden disabled={compose.uploading}
						onchange={async (e) => await onFiles((e.target as HTMLInputElement).files)} />
				</div>

				{#if compose.failedUploads.length > 0}<p class="compose-error-text">{t('compose.uploadFailed', { names: compose.failedUploads.join(', ') })}</p>{/if}

				<div class="editor-container">
					<RichTextEditorToolbar editor={tipTapEditor} onInlineImageFile={stageInlineImage} />
					<RichTextEditor bind:this={editorRef} content={compose.bodyHtml} placeholder={t('compose.body_placeholder')}
						onUpdate={handleUpdate} onEditorReady={handleEditorReady}
						onMentionPick={(label, email) => compose.mentionRecipient(label, email)}
						onInlineImageFile={stageInlineImage} onNonInlineFiles={onNonInlineFiles} inlineUploads={inlineUploads} />
				</div>

				{#if replyContextFailed}<span class="reply-context-indicator">{t('compose.replyContextUnavailable')}</span>{/if}
				{#if error}<p class="compose-error-text" role="alert">{error}</p>{/if}

				<div class="sj-send-bar">
					<Button variant="primary" size="sm"
						disabled={!compose.to.trim() || sending || compose.uploading || compose.sharedDraftReadOnly || (compose.dlpTip.violated && compose.dlpTip.action === 'block')}
						onclick={handleSend}>

						<Icon name="Send" size={14} />
						{sending ? t('compose.sending') : compose.scheduledAt ? t('compose.scheduleSend') : t('compose.send')}
					</Button>
					{#if compose.uploading && compose.batchTotal > 0}
						<span class="send-upload-gate" role="status">
							{t('compose.uploadingOf', {
								n: String(Math.min(compose.batchDone + 1, compose.batchTotal)),
								m: String(compose.batchTotal)
							})}
						</span>
					{:else if compose.dlpTip.violated && compose.dlpTip.action === 'block'}
						<span class="send-upload-gate" role="status">{t('compose.dlp_send_gate')}</span>
					{/if}
					<IconButton label={t('compose.attach')} onclick={triggerFilePicker} variant="ghost" size="sm">
						<Icon name="Paperclip" size={16} />
					</IconButton>
					<span class="cp-sig-anchor">
						<IconButton label={t('compose.insertSignature')} data-testid="insert-signature-btn" variant="ghost" size="sm"
							onclick={() => (showSignatureMenu = !showSignatureMenu)}>
							<Icon name="PenTool" size={16} />
						</IconButton>
						{#if showSignatureMenu}
							<div class="cp-sig-menu" role="menu">
								{#if compose.signatures.length === 0}
									<span class="cp-sig-empty">{t('compose.noSignatures')}</span>
								{:else}
									{#each compose.signatures as sig (sig.id)}
										<button type="button" class="cp-sig-item" role="menuitem"
											data-testid="sig-item-{sig.id}"
											aria-current={compose.selectedSignatureId === sig.id ? 'true' : undefined}
											onclick={() => insertSignature(sig)}>{sig.alias_email}</button>
									{/each}
								{/if}
							</div>
						{/if}
					</span>
					<span class="cp-sig-anchor">
						<IconButton label={t('templates.insert')} data-testid="insert-template-btn" variant="ghost" size="sm"
							onclick={() => (showTemplateMenu = !showTemplateMenu)}>
							<Icon name="FileText" size={16} />
						</IconButton>
						{#if showTemplateMenu}
							<div class="cp-sig-menu" role="menu">
								{#if templates.length === 0}
									<span class="cp-sig-empty">{t('templates.none')}</span>
								{:else}
									{#each templates as tpl (tpl.id)}
										<button type="button" class="cp-sig-item" role="menuitem"
											data-testid="tpl-item-{tpl.id}"
											onclick={() => insertTemplate(tpl)}>{tpl.name}</button>
									{/each}
								{/if}
							</div>
						{/if}
					</span>
					<span class="send-bar-spacer"></span>
					<span class="cp-undo-hint">{t('compose.undoHint', { n: String(onSendUndoWindowSeconds) })}</span>
					{#if compose.draftSaveError}
						<span class="draft-save-error" role="button" tabindex="0" onclick={() => compose.saveDraft(editorRef, userEmail)} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); compose.saveDraft(editorRef, userEmail); } }}>
							{t('compose.draftNotSaved')}</span>
					{/if}
					<IconButton label={t('compose.discard')} onclick={discard} variant="ghost" size="sm">
						<Icon name="Trash2" size={16} />
					</IconButton>
				</div>

				{#if undoSendEmailId}
					<div class="undo-toast">
						<span>{t('compose.willSendIn', { n: String(undoCountdown) })}</span>
						<button class="undo-btn" onclick={undoSend}>{t('compose.undo')}</button>
					</div>
				{/if}
			</div>

			<!-- ─── Options Sidebar ─── -->
			<div class="sj-compose-options" data-testid="compose-options">

				<!-- Task 5: Delivery -->
				<h3 class="cp-section-head">{t('compose.delivery')}</h3>
				<label class="cp-opt-row">
					<span class="cp-opt-cap">{t('compose.when')}</span>
					<Select options={scheduleOptions} value={scheduleMode} onchange={(e) => {
						const v = (e.target as HTMLSelectElement).value; scheduleMode = v as 'now' | 'mon8' | 'fri17' | 'custom'; if (v === 'mon8') { const d = new Date(); d.setDate(d.getDate() + ((8 - d.getDay() + 7) % 7 || 7)); d.setHours(8, 0, 0, 0); compose.scheduledAt = d.toISOString().slice(0, 16); } else if (v === 'fri17') { const d = new Date(); d.setDate(d.getDate() + ((5 - d.getDay() + 7) % 7 || 7)); d.setHours(17, 0, 0, 0); compose.scheduledAt = d.toISOString().slice(0, 16); }
					}} />
				</label>
				{#if scheduleMode === 'custom'}
					<div class="cp-custom-picker">
						<DateTimePicker value={scheduledAtDate} onConfirm={setScheduledAt} confirmLabel={t('compose.setSchedule')} />
					</div>
				{/if}
				<Switch label={t('compose.read_receipt')} checked={compose.readReceipt} onchange={() => (compose.readReceipt = !compose.readReceipt)} />

				<!-- Task 6: Meeting -->
				<h3 class="cp-section-head">{t('compose.meeting')}</h3>
				<Switch label={t('compose.includeMeeting')} checked={includeMeeting} onchange={() => (includeMeeting = !includeMeeting)} />
				{#if includeMeeting}
					<div class="cp-meeting-fields">
						<input type="date" class="sel-style" aria-label={t('compose.meetingDate')} bind:value={meetingDate} />
						<Select options={meetingTimeSlots} value={meetingTime} onchange={(e) => {
							meetingTime = (e.target as HTMLSelectElement).value;
						}} />
						<Select options={meetingDurationOptions} value={String(meetingDuration)} onchange={(e) => {
							meetingDuration = parseInt((e.target as HTMLSelectElement).value);
						}} />
					</div>
						<h3 class="cp-section-head" style="margin-top:10px">{t('compose.roomsFree')}</h3>
						{#if meetingRooms.length > 0}
							<Select label={t('compose.meetingRoom')} value={meetingStore.selectedRoom?.id ?? ''}
								options={[{ value: '', label: '—' }, ...meetingRooms.map((r) => ({ value: r.id, label: r.name }))]}
								onchange={(e) => {
									const id = (e.target as HTMLSelectElement).value;
									const room = meetingRooms.find((r) => r.id === id);
									meetingStore.selectedRoom = room ? { id: room.id, name: room.name, busyIntervals: [] } : null;
								}} />
						{/if}
						<AvailabilityGrid
							attendees={meetingAttendees}
							timeRange={meetingStore.timeRange}
							selectedRoom={meetingStore.selectedRoom}
							durationMinutes={meetingDuration}
							mutualFreeSlots={meetingStore.mutualFreeSlots}
							loading={meetingRoomsLoading}
							error={meetingRoomsError}
							onSlotSelect={onMeetingSlotSelect}
						/>
				{/if}

				<!-- Task 7: Tag on send -->
				<h3 class="cp-section-head">{t('compose.tagOnSend')}</h3>
				<div class="cp-tag-chips">
						{#each userTags(compose.mailboxes).filter(t => !t.parentId) as t (t.id)}
							<button type="button" class="cp-tag-chip-btn" style="outline: {compose.sendTags.includes(t.id) ? '1.5px solid var(--border-accent)' : 'none'}" onclick={() => toggleSendTag(t.id)}>
								<Tag label={t.name} color={t.color as any} dot={false} size="sm" />
							</button>
						{/each}
				</div>

				<!-- Task 8: More disclosure -->
				<button class="cp-disclosure" onclick={() => (showMore = !showMore)} aria-expanded={showMore}>
					{t('compose.moreOptions')}
					<Icon name={showMore ? 'ChevronUp' : 'ChevronDown'} size={14} />
				</button>
				{#if showMore}
					<div class="cp-more-panel">
						<Select label={t('compose.priority')}
							options={[{ value: 'high', label: 'High' }, { value: 'normal', label: 'Normal' }, { value: 'low', label: 'Low' }]}
							value={compose.priority}
							onchange={(e) => { compose.priority = (e.target as HTMLSelectElement).value as 'high' | 'normal' | 'low'; }} />
						<Select label={t('compose.sensitivity')}
							options={[{ value: 'normal', label: 'Normal' }, { value: 'personal', label: 'Personal' }, { value: 'private', label: 'Private' }, { value: 'confidential', label: 'Confidential' }]}
							value={compose.sensitivity}
							onchange={(e) => { compose.sensitivity = (e.target as HTMLSelectElement).value as 'normal' | 'personal' | 'private' | 'confidential'; }} />
						<Switch label={t('compose.votingButtons')} checked={compose.useVoting} onchange={() => (compose.useVoting = !compose.useVoting)} />
	{#if compose.useVoting}
		<div class="cp-voting">
			<label class="cp-cat-label" for={`${uid}-vote-0`}>{t('compose.votingButtons')}</label>
			{#each compose.voteOptions as opt, i}
				<div class="cp-vote-row">
					<Input id={i === 0 ? `${uid}-vote-0` : undefined} aria-label={t('compose.votingOption', { n: String(i + 1) })} value={opt} onchange={(e) => updateVoteOption(i, (e.target as HTMLInputElement).value)} placeholder={t('compose.voting_option_placeholder', { n: String(i + 1) })} />
					{#if compose.voteOptions.length > 1}
						<IconButton label={t('compose.removeOption')} variant="ghost" size="sm" onclick={() => removeVoteOption(i)}>
							<Icon name="X" size={13} />
						</IconButton>
					{/if}
					{#if i === compose.voteOptions.length - 1}
						<IconButton label={t('compose.voting_add')} variant="ghost" size="sm" onclick={addVoteOption}>
							<Icon name="PlusCircle" size={13} />
						</IconButton>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
						<Switch label={t('compose.smime_encrypt')} checked={compose.smimeEncrypt} onchange={() => (compose.smimeEncrypt = !compose.smimeEncrypt)} />
						<Switch label={t('compose.smime_sign')} checked={compose.smimeSign} onchange={() => (compose.smimeSign = !compose.smimeSign)} />
						{#if compose.smimeSign && !hasDefaultCert}
							<p class="cp-smime-hint">{t('compose.smime_no_cert_hint')}</p>
						{/if}
						{#if compose.smimeEncrypt && encryptNoCertRecipients.length > 0}
							<p class="cp-smime-hint">{t('compose.smime_encrypt_no_cert_hint', { addresses: encryptNoCertRecipients.join(', ') })}</p>
						{/if}
						<Switch label={t('compose.plainTextOnly')} checked={compose.plainTextOnly} onchange={() => (compose.plainTextOnly = !compose.plainTextOnly)} />
						<div class="cp-categories">
							<label class="cp-cat-label" for={`${uid}-categories`}>{t('compose.categories')}</label>
							<div class="cp-cat-list">
								{#each compose.categories as cat}
									<span class="cp-cat-pill">{cat} <button type="button" aria-label={t('compose.removeCategory', { cat })} onclick={() => removeCategory(cat)}>×</button></span>
								{/each}
								<input id={`${uid}-categories`} type="text" placeholder={t('compose.addCategory')} bind:value={compose.newCategory}
									onkeydown={(e) => e.key === 'Enter' && (e.preventDefault(), addCategory())} />
							</div>
						</div>
					</div>
				{/if}

				<!-- Task 9: Assist panel -->
				{#if featureAssist}
					<div class="cp-assist-section">
						<h3 class="cp-section-head">
							<Icon name="Sparkles" size={11} style="vertical-align:-1px;margin-right:4px;color:var(--accent)" />
							{t('compose.assist')}
						</h3>
						<div class="cp-assist-btns">
							<Button variant="secondary" size="sm" disabled={assistBusy} onclick={() => runAssist('draft')}>
								<Icon name="PenLine" size={13} />{t('compose.draftIt')}
							</Button>
							<Button variant="secondary" size="sm" disabled={assistBusy} onclick={() => runAssist('polish')}>
								<Icon name="Wand2" size={13} />{t('compose.polish')}
							</Button>
							<Button variant="secondary" size="sm" disabled={assistBusy} onclick={() => runAssist('translate')}>
								<Icon name="Languages" size={13} />{t('compose.translate')}
							</Button>
							<Button variant="secondary" size="sm" disabled={assistBusy} onclick={() => runAssist('shorten')}>
								<Icon name="AlignVerticalSpaceAround" size={13} />{t('compose.shorten')}
							</Button>
						</div>
						<p class="cp-assist-hint">{assistHint || t('compose.assistHint')}</p>
					</div>
				{/if}
			</div>
		</div>
	</div>
{/if}

<!-- The minimized dock (bars for every minimized window, roving tabindex) is rendered
     ONCE by ComposeDock in +layout — not per compose instance. -->

<style>
	.sj-compose-header { height: var(--topbar-height); flex: none; display: flex; align-items: center; gap: 10px; padding: 0 16px; border-bottom: 1px solid var(--border-default); }
	.sj-compose-title { font-size: var(--text-md); font-weight: 600; color: var(--text-primary); }
	.sj-compose-spacer { flex: 1; }
	.sj-compose-body { flex: 1; min-height: 0; display: flex; flex-direction: column; overflow-y: auto; }
	.sj-compose-main { position: relative; display: flex; flex-direction: column; padding: 8px clamp(12px, 3vw, 24px) 16px; }
	.sj-compose-options { width: 100%; border-top: 1px solid var(--border-default); background: var(--surface-sidebar); padding: 16px 16px 24px; display: flex; flex-direction: column; gap: 20px; }

	.compose-drop-overlay { position: absolute; inset: 8px; z-index: 20; display: flex; align-items: center; justify-content: center; border: 2px dashed var(--border-accent); background: var(--accent-subtle); border-radius: var(--radius-md); color: var(--text-accent); font-size: var(--text-md); font-weight: 500; pointer-events: none; }

	@media (min-width: 1024px) {
		.sj-compose-body { flex-direction: row; overflow: hidden; }
		.sj-compose-main { flex: 1; min-width: 0; overflow-y: auto; }
		.sj-compose-options { width: 312px; flex: none; border-top: none; border-left: 1px solid var(--border-default); overflow-y: auto; }
	}

	.cp-field { display: flex; align-items: center; gap: 10px; min-height: 38px; border-bottom: 1px solid var(--border-subtle); padding: 0 2px; position: relative; }
	.cp-label { width: 64px; flex: none; font-size: var(--text-sm); color: var(--text-caption); }
	.cp-input { flex: 1; border: none; outline: none; background: transparent; font-family: var(--font-sans); font-size: var(--text-sm); color: var(--text-primary); padding: 8px 0; border-radius: var(--radius-sm); }
	.cp-input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.cp-input--select { cursor: pointer; appearance: none; font-family: var(--font-mono); font-size: var(--text-xs); padding-right: 22px; }
	.cp-input--select:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.cp-select-caret { position: absolute; right: 4px; top: 50%; transform: translateY(-50%); pointer-events: none; color: var(--text-tertiary); }
	.cp-input--subject { font-weight: 500; }
	.cp-input--error { border-color: var(--danger-solid) !important; }
	.cp-field-error { color: var(--danger-solid); font-size: var(--text-xs); display: block; margin-top: 2px; }
	/* #13: informational caption under the From row when From ≠ own (sending as
	   or on behalf of a shared mailbox). */
	.cp-from-caption { color: var(--text-caption); font-size: var(--text-xs); margin: -6px 0 4px 74px; }
	.cp-reveal-btns { position: absolute; right: 0; display: flex; gap: 8px; }
	.cp-reveal-btn { border: none; background: none; color: var(--text-accent); font-size: var(--text-xs); cursor: pointer; border-radius: var(--radius-sm); }
	.cp-reveal-btn:hover { text-decoration: underline; }
	.cp-reveal-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.compose-banner { padding: 6px 12px; border-radius: var(--radius-md); font-size: var(--text-sm); font-weight: 500; margin-bottom: 4px; }
	.compose-banner--success { background: var(--success-bg); color: var(--success-solid); }
	.compose-banner--draft { background: var(--accent-subtle); color: var(--accent); }
	.compose-banner--error { background: var(--danger-bg); color: var(--danger-solid); }
	.compose-shared-lease { display:flex; align-items:center; justify-content:space-between; gap:var(--space-2); }
	.compose-draft-handoff { display:grid; gap:var(--space-2); padding:var(--space-2); margin-bottom:var(--space-2); border:1px solid var(--border-default); border-radius:var(--radius-md); background:var(--surface-card); }
	.compose-draft-handoff input { min-height:36px; padding:0 var(--space-2); border:1px solid var(--border-default); border-radius:var(--radius-sm); background:var(--surface-card); color:var(--text-primary); }
	.compose-draft-handoff > button { display:grid; gap:var(--space-1); padding:var(--space-2); text-align:left; border:1px solid var(--border-default); border-radius:var(--radius-sm); background:var(--surface-card); color:var(--text-primary); }
	.compose-draft-handoff > button.selected { border-color:var(--border-accent); background:var(--surface-selected); }
	.compose-draft-handoff > button span { color:var(--text-secondary); font-size:var(--text-xs); }
	.compose-draft-handoff__error { color:var(--danger-solid); }
	.compose-error-text { color: var(--danger-solid); font-size: var(--text-sm); margin: 0; }

	.gal-wrap { position: relative; }
	.gal-dropdown { position: absolute; top: 100%; left: 0; right: 0; background: var(--surface-card); border: 1px solid var(--border-default); border-radius: var(--radius-md); box-shadow: var(--shadow-md); z-index: 10; max-height: 200px; overflow-y: auto; }
	.gal-item { display: flex; flex-direction: column; padding: 8px 12px; background: none; border: none; border-bottom: 1px solid var(--border-subtle); cursor: pointer; width: 100%; text-align: left; }
	.gal-item:hover, .gal-item--active { background: var(--surface-hover); }
	.gal-item:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.gal-item strong { font-size: var(--text-sm); color: var(--text-primary); }
	.gal-item span { font-size: var(--text-xs); color: var(--text-secondary); }
	.gal-item-error { padding: 8px 12px; color: var(--text-secondary); font-style: italic; font-size: var(--text-sm); cursor: default; }
	.gal-item--group { flex-direction: row; align-items: center; gap: 6px; }
	.gal-item--group strong { flex: 1; min-width: 0; }
	.gal-group-mark { display: inline-flex; color: var(--text-tertiary); }
	.gal-item--cache { flex-direction: row; align-items: center; gap: 4px; padding: 0; }
	.gal-cache-pick { flex: 1; min-width: 0; display: flex; flex-direction: column; align-items: flex-start; background: none; border: none; padding: 8px 4px 8px 12px; cursor: pointer; text-align: left; }
	.gal-cache-pick strong { font-size: var(--text-sm); color: var(--text-primary); }
	.gal-cache-pick span { font-size: var(--text-xs); color: var(--text-secondary); }
	.gal-cache-x { display: inline-flex; align-items: center; justify-content: center; width: 26px; height: 26px; margin-right: 6px; background: none; border: none; border-radius: var(--radius-sm); color: var(--text-tertiary); cursor: pointer; flex: none; }
	.gal-cache-x:hover { background: var(--surface-hover); color: var(--text-primary); }
	.gal-cache-x:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.mailtips { display: flex; flex-wrap: wrap; gap: 4px; padding: 4px 0; }
	.mailtip-badge { font-size: var(--text-xs); padding: 2px 8px; border-radius: var(--radius-sm); line-height: 1.3; }
	.mailtip-warn { background: var(--warning-bg); color: var(--warning-fg); }
	.mailtip-ext { background: var(--info-bg); color: var(--info-fg); }
	.mailtip-err { background: var(--danger-bg); color: var(--danger-solid); }

	.attachments-list { display: flex; flex-wrap: wrap; gap: 4px; padding: 4px 0; }
	.att-item { display: inline-flex; flex-direction: column; gap: 2px; padding: 3px 8px; background: var(--surface-sidebar); border-radius: var(--radius-md); font-size: var(--text-xs); min-width: 140px; }
	.att-item--failed { border: 1px solid var(--danger-solid); }
	.att-item__row { display: inline-flex; align-items: center; gap: 4px; }
	.att-name { color: var(--text-primary); max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.att-size { color: var(--text-secondary); }
	.att-failed-label { color: var(--danger-fg); }
	.att-retry { background: none; border: none; cursor: pointer; color: var(--accent); font-size: var(--text-xs); border-radius: var(--radius-sm); padding: 0 2px; }
	.att-retry:hover { text-decoration: underline; }
	.att-retry:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.send-upload-gate { font-size: var(--text-xs); color: var(--text-caption); }
	.att-remove { background: none; border: none; cursor: pointer; color: var(--text-secondary); font-size: var(--text-xs); border-radius: var(--radius-sm); }
	.att-remove:hover { color: var(--danger-solid); }
	.att-remove:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.attach-total { display: block; font-size: var(--text-xs); color: var(--text-caption); padding: 0 0 2px; }
	.attach-total--over { color: var(--danger-solid); }

	.drop-zone { padding: 6px; border: 2px dashed var(--border-default); border-radius: var(--radius-md); text-align: center; font-size: var(--text-sm); color: var(--text-secondary); cursor: pointer; margin: 4px 0; }
	.drop-zone:hover { border-color: var(--accent); background: var(--accent-subtle); }
	.drop-zone-label { display: inline-flex; align-items: center; gap: 6px; }
	.drop-zone:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.editor-container { flex: 1; display: flex; flex-direction: column; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); overflow: hidden; min-height: 200px; margin-top: 4px; }
	.reply-context-indicator { color: var(--text-secondary); font-size: var(--text-xs); font-style: italic; padding: 4px 8px; display: block; }

	.sj-send-bar { display: flex; align-items: center; gap: 8px; padding-top: 10px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; flex: none; }
	.send-bar-spacer { flex: 1; }

	.cp-sig-anchor { position: relative; display: inline-flex; }
	.cp-sig-menu { position: absolute; bottom: 100%; left: 0; margin-bottom: 4px; min-width: 180px; display: flex; flex-direction: column; padding: 4px; background: var(--surface-card); border: 1px solid var(--border-default); border-radius: var(--radius-md); box-shadow: var(--shadow-md); z-index: 20; }
	.cp-sig-item { display: block; width: 100%; text-align: left; padding: 6px 10px; border: none; background: none; cursor: pointer; font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-primary); border-radius: var(--radius-sm); }
	.cp-sig-item:hover { background: var(--surface-hover); }
	.cp-sig-item:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.cp-sig-empty { padding: 6px 10px; font-size: var(--text-xs); color: var(--text-tertiary); }
	.cp-undo-hint { font-size: var(--text-2xs); color: var(--text-caption); }
	.cp-smime-hint { font-size: var(--text-2xs); color: var(--text-caption); margin: 2px 0 0; }
	.draft-save-error { color: var(--danger-solid); font-size: var(--text-xs); font-weight: 500; cursor: pointer; text-decoration: underline; text-decoration-style: dotted; }

	.undo-toast { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: var(--surface-card); border: 1px solid var(--border-default); border-radius: var(--radius-md); box-shadow: var(--shadow-md); font-size: var(--text-sm); margin-top: 8px; }
	.undo-btn { border: none; background: none; color: var(--text-accent); font-size: var(--text-sm); font-weight: 500; cursor: pointer; }

	/* ─── Options sidebar styles ─── */
	.cp-section-head { font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-caption); font-weight: 600; padding: 0 0 8px; margin: 0; }
	.cp-opt-row { display: flex; align-items: center; gap: 8px; font-size: var(--text-sm); }
	.cp-opt-cap { width: 80px; color: var(--text-secondary); }

	.cp-custom-picker { margin-top: 8px; }
	.cp-meeting-fields { display: flex; gap: 6px; margin-top: 10px; }
	.sel-style { height: 28px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font-family: var(--font-sans); font-size: var(--text-xs); padding: 0 6px; }

	.cp-tag-chips { display: flex; flex-wrap: wrap; gap: 6px; }
	.cp-tag-chip-btn { border: none; background: none; padding: 0; cursor: pointer; border-radius: var(--radius-sm); }
		.cp-tag-chip-btn:hover { opacity: 0.85; }
		.cp-tag-chip-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.cp-disclosure { display: flex; align-items: center; gap: 6px; border: none; background: none; cursor: pointer; font-size: var(--text-sm); color: var(--text-secondary); padding: 2px 0; width: 100%; font-family: var(--font-sans); border-radius: var(--radius-sm); }
	.cp-disclosure:hover { color: var(--text-primary); }
	.cp-disclosure:focus-visible { outline: none; box-shadow: var(--focus-ring); }

	.cp-more-panel { display: flex; flex-direction: column; gap: 12px; }
	.cp-categories { display: flex; flex-direction: column; gap: 4px; }
	.cp-cat-label { font-size: var(--text-sm); color: var(--text-caption); display: block; margin-bottom: 4px; }
	.cp-cat-list { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
	.cp-cat-pill { display: inline-flex; align-items: center; gap: 2px; padding: 2px 8px; background: var(--accent-subtle); color: var(--accent); border-radius: var(--radius-full); font-size: var(--text-xs); font-weight: 500; }
	.cp-cat-pill button { background: none; border: none; cursor: pointer; color: inherit; font-size: var(--text-xs); padding: 0; border-radius: var(--radius-sm); }
	.cp-cat-pill button:focus-visible { outline: none; box-shadow: var(--focus-ring); }

		.cp-voting { display: flex; flex-direction: column; gap: 6px; }
		.cp-vote-row { display: flex; align-items: center; gap: 6px; }

	.cp-assist-section { border-top: 1px solid var(--border-subtle); padding-top: 16px; }
	.cp-assist-btns { display: flex; flex-wrap: wrap; gap: 6px; }
	.cp-assist-hint { font-size: var(--text-2xs); color: var(--text-caption); margin-top: 8px; line-height: 1.5; }

	/* QoL #7: consolidated out-of-office advisory banner. */
	.ooo-advisory { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; padding: 6px 10px; margin: 4px 0; background: var(--info-bg); color: var(--info-fg); border-radius: var(--radius-md); font-size: var(--text-sm); }
	.ooo-advisory__head { display: inline-flex; align-items: center; gap: 6px; flex: 1; min-width: 0; border: none; background: none; cursor: pointer; color: inherit; font-family: var(--font-sans); font-size: var(--text-sm); text-align: left; padding: 0; border-radius: var(--radius-sm); }
	.ooo-advisory__head:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.ooo-advisory__list { flex-basis: 100%; margin: 4px 0 0; padding: 0 0 0 20px; display: flex; flex-direction: column; gap: 2px; font-size: var(--text-sm); }

	.dlp-tip { display: flex; align-items: center; gap: 6px; padding: 6px 10px; margin: 4px 0; background: var(--info-bg); color: var(--info-fg); border-radius: var(--radius-md); font-size: var(--text-sm); }
	.dlp-tip span { flex: 1; min-width: 0; }
	.dlp-tip--block { background: var(--danger-bg); color: var(--danger-fg); }
</style>
