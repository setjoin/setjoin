<svelte:options runes={true} />
<script lang="ts">
	import { IconButton, Tag, Button, Textarea, Input, Menu } from '$lib/components/ui';
	import type { MenuItem } from '$lib/components/ui/Menu.svelte';
	import MessageCard from './MessageCard.svelte';
	import type { TagColor } from '$lib/components/ui/tag';
	import Icon from '$lib/components/Icon.svelte';
	import SnoozePicker from '$lib/components/SnoozePicker.svelte';
	import FollowUpPicker, { type FollowUpSelection } from '$lib/components/FollowUpPicker.svelte';
	import QuickStepsBar from '$lib/components/QuickStepsBar.svelte';
	import { LOCATION_ROLES } from '$lib/stores/tagHelpers';
	import { resolveReceiptAction, type ReceiptPolicy } from '$lib/mail/readReceipt';
	import { printMessage } from '$lib/mail/printMessage';
	import { t, locale } from '$lib/i18n';
	import { assistComplete } from '$lib/jmap/client';
	import { effectiveCaps } from '$lib/stores/session';
	import type { Email, Mailbox, QuickStep } from '$lib/types/jmap';
	import WatermarkOverlay from '$lib/components/WatermarkOverlay.svelte';
	import { isNative } from '$lib/native';
	import { offline } from '$lib/offline/state.svelte';
	import SenderControlPanel from './SenderControlPanel.svelte';
	import MailWorkRail from './MailWorkRail.svelte';

	/**
	 * The reading-pane action facade (candidate 7 — EmailActionStore seam). The
	 * coordinator passes ONE `actions` object; each member maps to a member of the
	 * typed `EmailAction` union the store dispatches. This is the sole dispatch
	 * mechanism — required members are guaranteed by the type; optional members
	 * gate their button's rendering by presence.
	 */
	export interface ReadingPaneActions {
		onArchive: () => void;
		onSnooze: (date: Date) => void;
		onTrash: () => void;
		onMute: () => void;
		onStar: () => void;
		onReply: () => void;
		onReplyAll?: () => void;
		onForward: () => void;
		/** Resend after NDR/bounce — a fresh compose (DeliveryPanel shows it only when bounced>0). */
		onResend?: () => void;
		onToggleRead?: (read: boolean) => void;
		onFollowUp?: (sel: FollowUpSelection) => void;
		onCreateTask?: () => void;
		onBlockSender?: () => void;
		/** Create a mail rule/filter pre-filled from this message (#4). */
		onCreateRule?: () => void;
		onApplyQuickStep?: (id: string) => void;
		onRemoveTag: (tagId: string) => void;
		onAddTag: (tagId: string) => void;
		onCreateTag: (name: string) => void;
		onSendReply: (text: string) => void;
		onScheduleReply: (text: string) => void;
		onNotSpam?: () => void;
		onVoteResponse?: (option: string) => void;
		onRecall?: () => void;
		onReadReceipt?: (consent: boolean) => void;
		/**
		 * Read-on-expand (WAVE-5 #6): fired with an UNREAD message when its card
		 * becomes visible — the auto-expanded newest on thread open, or a collapsed
		 * older card the user expands. Collapsed cards are never marked.
		 */
		onMarkSeen?: (email: Email) => void;
		onSenderControlChanged?: () => void;
	}

	interface Props {
		/**
		 * The context message — drives the toolbar, subject, tag chips, follow-up,
		 * read-receipt, and reply box (what the coordinator's mutations act on). In the
		 * normal flow this is the newest message of the open thread (the row clicked).
		 */
		email: Email;
		/**
		 * The full conversation, oldest→newest, rendered as stacked collapsible cards
		 * (conversation-view depth). Falls back to `[email]` when omitted/empty, so a
		 * single message renders exactly one card.
		 */
		emails?: Email[];
		/** All mailboxes (system + user tags) for tag resolution. */
		mailboxes: Mailbox[];
		/** Selected mailbox role — controls Not-Spam / Delete branching. */
		currentRole: string | null;
		/** Mobile back button intent (Back button only shown when provided). */
		onBack?: () => void;
		/** The action facade (candidate 7) — the sole mutation/intent dispatch. */
		actions: ReadingPaneActions;
		/** User-defined quick-step macros to render above the reply box. */
		quickSteps?: QuickStep[];
		/** Id of the quick step currently running (disables its button). */
		applyingQuickStep?: string | null;
		/** Effective read-receipt policy for the current user (Track A privacy). Default 'ask'. */
		readReceiptPolicy?: ReceiptPolicy;
		/**
		 * Authenticated user's email — passed to the MAM watermark overlay.
		 * The coordinator supplies this from the session user store.
		 */
		userEmail?: string;
		/** JMAP account id — builds attachment download URLs. Coordinator-supplied. */
		accountId?: string;
		/**
		 * #13 shared-mailbox use-surface DANGER STATE: true when the caller holds
		 * only a read-only grant on the currently-open shared mailbox (no
		 * send_as/send_on_behalf/full_access). Compose/Reply/Reply-all/Forward
		 * render DISABLED with a tooltip explaining why — never hidden (the
		 * design pin: a disabled-with-reason affordance beats a vanished one).
		 */
		composeDisabled?: boolean;
		/** Tooltip/caption copy shown alongside the disabled compose affordances. */
		composeDisabledReason?: string;
		senderControlEnabled?: boolean;
		mailWorkEnabled?: boolean;
		mailWorkCanCollaborate?: boolean;
	}

	let {
		email,
		emails,
		mailboxes = [],
		currentRole = null,
		onBack,
		actions,
		quickSteps = [],
		applyingQuickStep = null,
		readReceiptPolicy = 'ask',
		userEmail = '',
		accountId = '',
		composeDisabled = false,
		composeDisabledReason = '',
		senderControlEnabled = false,
		mailWorkEnabled = false,
		mailWorkCanCollaborate = false,
	}: Props = $props();
	let showSenderControl = $state(false);
	let showMailWork = $state(false);

	// The conversation to stack — the full thread when supplied, else the single
	// context message (so a one-message thread renders exactly one card).
	const cards = $derived(emails && emails.length ? emails : [email]);

	// Expanded cards. Seed to the newest message; reset whenever the newest changes
	// (thread switch, or the thread finishing its cross-folder fetch). Uses the same
	// track-last-id pattern as the read-receipt $effect below.
	let expandedIds = $state<Set<string>>(new Set());
	let lastNewestId: string | null = null;
	$effect(() => {
		const newest = cards[cards.length - 1];
		const newestId = newest?.id ?? null;
		if (newestId === lastNewestId) return;
		lastNewestId = newestId;
		expandedIds = new Set(newestId ? [newestId] : []);
		// Read-on-expand (WAVE-5 #6): opening a thread marks ONLY the auto-expanded
		// message $seen; collapsed older messages stay unread until expanded.
		if (newest && !newest.keywords?.['$seen']) onMarkSeen?.(newest);
	});

	function toggleCard(id: string) {
		const next = new Set(expandedIds);
		if (next.has(id)) next.delete(id);
		else {
			next.add(id);
			// Read-on-expand: an individually expanded unread card becomes read.
			const m = cards.find((c) => c.id === id);
			if (m && !m.keywords?.['$seen']) onMarkSeen?.(m);
		}
		expandedIds = next;
	}

	// MAM watermark: show iff the native shell is present AND the policy requires it.
	const watermarkOn = $derived(isNative() && offline.watermarkEnabled);

	// ── Copilot assist (feature.assist): ONE Sparkles menu — Summarize + Translate ──
	// Gated on the per-user effective capability, same source as compose's assist panel.
	const featureAssist = $derived($effectiveCaps?.assist ?? false);
	type AssistMode = 'summary' | 'translation';
	let assistMode = $state<AssistMode>('summary');
	let assistResult = $state('');
	let assistLoading = $state(false);
	let assistError = $state<'' | 'failed' | 'too_long'>('');

	// Mirrors shared/assist MaxRequestBytes (512 KiB — the server 422s above it).
	// Pre-checking client-side turns the inevitable rejection into the specific
	// size-cap copy instead of a generic failure; the server stays the gate.
	const ASSIST_MAX_BYTES = 512 * 1024;

	const assistMenuItems = $derived<MenuItem[]>([
		{ id: 'summarize', label: t('mail.summarize') },
		{ id: 'translate', label: t('mail.translate') },
	]);

	// Target language = the current UI locale (no picker in v1).
	const LOCALE_LANGUAGE: Record<string, string> = {
		en: 'English',
		de: 'German',
		zh: 'Simplified Chinese',
	};

	async function runAssist(mode: AssistMode) {
		if (assistLoading) return;
		assistMode = mode;
		assistLoading = true;
		assistError = '';
		assistResult = '';
		const text = email.bodyText || email.preview || '';
		if (text.length > ASSIST_MAX_BYTES) {
			assistError = 'too_long';
			assistLoading = false;
			return;
		}
		const prompt =
			mode === 'summary'
				? `Summarize this email in 3-5 concise bullet points, plain text only:\n\n${text}`
				: `Translate this email into ${LOCALE_LANGUAGE[$locale] ?? 'English'}. Output only the translation, plain text only:\n\n${text}`;
		try {
			// SECURITY: the result is rendered as PLAIN TEXT ({assistResult} binding,
			// never {@html}). LLM output is attacker-influenceable (the email body
			// feeds the prompt), so treating it as HTML would be an XSS vector.
			assistResult = await assistComplete([{ role: 'user', content: prompt }], $locale);
		} catch {
			assistError = 'failed';
		} finally {
			assistLoading = false;
		}
	}

	// "Show original" (translation) and the X (both modes) drop the panel — the
	// original body is always rendered below, untouched.
	function dismissAssist() {
		assistResult = '';
		assistError = '';
	}

	// ── Action resolution ──
	// One mechanism: every intent comes from the `actions` facade. Required members
	// are guaranteed by the type; optional members are `undefined` when absent and
	// gate their button's rendering by presence.
	const onArchive = $derived(actions.onArchive);
	const onSnooze = $derived(actions.onSnooze);
	const onTrash = $derived(actions.onTrash);
	const onMute = $derived(actions.onMute);
	const onStar = $derived(actions.onStar);
	const onReply = $derived(actions.onReply);
	const onReplyAll = $derived(actions.onReplyAll);
	const onForward = $derived(actions.onForward);
	const onResend = $derived(actions.onResend);
	const onToggleRead = $derived(actions.onToggleRead);
	const onFollowUp = $derived(actions.onFollowUp);
	const onCreateTask = $derived(actions.onCreateTask);
	const onBlockSender = $derived(actions.onBlockSender);
	const onCreateRule = $derived(actions.onCreateRule);
	const onApplyQuickStep = $derived(actions.onApplyQuickStep);
	const onRemoveTag = $derived(actions.onRemoveTag);
	const onAddTag = $derived(actions.onAddTag);
	const onCreateTag = $derived(actions.onCreateTag);
	const onSendReply = $derived(actions.onSendReply);
	const onScheduleReply = $derived(actions.onScheduleReply);
	const onNotSpam = $derived(actions.onNotSpam);
	const onVoteResponse = $derived(actions.onVoteResponse);
	const onRecall = $derived(actions.onRecall);
	const onReadReceipt = $derived(actions.onReadReceipt);
	const onMarkSeen = $derived(actions.onMarkSeen);

	let showSnoozePicker = $state(false);
	let showFollowUpPicker = $state(false);
	let showTagPicker = $state(false);
	let tagSearch = $state('');
	let newTagName = $state('');
	let replyText = $state('');

	// Smart-reply quick-response chips (#14): 1-tap short replies suggested from
	// the message content via the existing assist provider. Cached per message so
	// re-opening doesn't re-call the model; loaded lazily on first reply focus to
	// bound provider cost. Silent-degrade — never an error UI (nice-to-have).
	let replySuggestions = $state<string[]>([]);
	const suggestionCache = new Map<string, string[]>();

	async function loadReplySuggestions() {
		if (!featureAssist || isSent || replyText.trim()) return;
		const id = email.id;
		const cached = suggestionCache.get(id);
		if (cached) {
			replySuggestions = cached;
			return;
		}
		const text = email.bodyText || email.preview || '';
		if (!text || text.length > ASSIST_MAX_BYTES) return;
		const prompt =
			`Suggest exactly 3 short (max 6 words each) reply options to this email. ` +
			`One per line, no numbering, no quotes, plain text only:\n\n${text}`;
		try {
			// SECURITY: chips render as PLAIN TEXT (button label binding, never
			// {@html}); clicking only fills the reply box for review (never auto-sends).
			const raw = await assistComplete([{ role: 'user', content: prompt }], $locale);
			const parsed = raw
				.split('\n')
				.map((l) => l.replace(/^[\s\-*\d.)"']+/, '').replace(/["']+$/, '').trim())
				.filter(Boolean)
				.slice(0, 3);
			suggestionCache.set(id, parsed);
			replySuggestions = parsed;
		} catch {
			replySuggestions = [];
		}
	}

	// Reset suggestions when the open message changes (cache still keyed by id).
	$effect(() => {
		void email.id;
		replySuggestions = [];
	});

	// Read-receipt prompt (Track A privacy). When an opened message requested a receipt,
	// resolveReceiptAction decides: 'never' → nothing; 'always' → auto-send consent;
	// 'ask' → show the consent banner. We track the email we last acted on so opening,
	// switching, and reopening behave correctly and we never double-fire.
	let receiptPromptEmailId = $state<string | null>(null);
	let lastReceiptEmailId: string | null = null;

	$effect(() => {
		const id = email.id;
		if (id === lastReceiptEmailId) return;
		lastReceiptEmailId = id;
		receiptPromptEmailId = null;
		const action = resolveReceiptAction(readReceiptPolicy, email.readReceiptRequested === true);
		if (action.send) {
			onReadReceipt?.(action.consent === true);
		} else if (action.prompt) {
			receiptPromptEmailId = id;
		}
	});

	function answerReceipt(consent: boolean) {
		receiptPromptEmailId = null;
		onReadReceipt?.(consent);
	}

	const senderName = $derived(
		email.from && email.from.length > 0
			? (email.from[0].name || email.from[0].email || 'Unknown')
			: 'Unknown',
	);

	const isStarred = $derived(!!email.keywords?.['$flagged']);
	const isRead = $derived(!!email.keywords?.['$seen']);

	/** Due-date chip near the subject when the follow-up flag carries a due instant. */
	const followUpDueLabel = $derived(
		email.flagDueAt ? new Date(email.flagDueAt).toLocaleString() : '',
	);

	const isSpam = $derived(currentRole === 'spam' || currentRole === 'junk');
	const isTrash = $derived(currentRole === 'trash');
	const isSent = $derived(currentRole === 'sent');

	const replyPlaceholder = $derived(`Reply to ${senderName}...`);


	/** Resolve mailboxIds to user-tag mailboxes for chip rendering (exclude location roles). */
	const tagMailboxes = $derived(
		Object.keys(email.mailboxIds ?? {})
			.map((id) => mailboxes.find((m) => m.id === id))
			.filter((m): m is Mailbox => !!m)
			.filter((m) => !m.role || !(LOCATION_ROLES as ReadonlyArray<string>).includes(m.role)),
	);

	/** Filter user-tag mailboxes for the tag picker (exclude system roles). */
	const userTagMailboxes = $derived(
		mailboxes.filter((m) => !m.role || !(LOCATION_ROLES as ReadonlyArray<string>).includes(m.role)),
	);

	const filteredPickerTags = $derived(
		tagSearch
			? userTagMailboxes.filter((t) => t.name.toLowerCase().includes(tagSearch.toLowerCase()))
			: userTagMailboxes,
	);

	/** Breadcrumb label for nested tags. */
	function getTagLabel(mb: Mailbox): string {
		if (!mb.parentId) return mb.name;
		const parent = mailboxes.find((m) => m.id === mb.parentId);
		if (parent) return `${parent.name}/${mb.name}`;
		return mb.name;
	}

	function closeSnoozePicker() {
		showSnoozePicker = false;
	}

	function handleSnoozeSelect(date: Date) {
		onSnooze(date);
		showSnoozePicker = false;
	}

	function closeFollowUpPicker() {
		showFollowUpPicker = false;
	}

	function handleFollowUpSelect(sel: FollowUpSelection) {
		onFollowUp?.(sel);
		showFollowUpPicker = false;
	}

	function toggleTagPicker() {
		showTagPicker = !showTagPicker;
		tagSearch = '';
		newTagName = '';
	}

	function closeTagPicker() {
		showTagPicker = false;
		tagSearch = '';
		newTagName = '';
	}

	function handleAddTag(tagId: string) {
		onAddTag(tagId);
	}

	async function handleCreateTag() {
		const name = newTagName.trim();
		if (!name) return;
		onCreateTag(name);
		newTagName = '';
	}

	function handleSendReply() {
		replySuggestions = [];
		const text = replyText.trim();
		if (!text) return;
		onSendReply(text);
		replyText = '';
	}

	function handleScheduleReply() {
		replySuggestions = [];
		onScheduleReply(replyText.trim());
		replyText = '';
	}
</script>

<div class="sj-reading-pane">
	<!-- Toolbar -->
	<div class="sj-reading-pane__toolbar">
		{#if onBack}
			<IconButton label="Back" size="sm" onclick={onBack}>
				<Icon name="ArrowLeft" size={17} strokeWidth={1.75} />
			</IconButton>
		{/if}
		<IconButton label="Archive" size="sm" onclick={onArchive}>
			<Icon name="Archive" size={16} strokeWidth={1.75} />
		</IconButton>
		<span class="sj-reading-pane__snooze-anchor">
			<IconButton label="Snooze" size="sm" onclick={() => (showSnoozePicker = !showSnoozePicker)}>
				<Icon name="Clock" size={16} strokeWidth={1.75} />
			</IconButton>
			{#if showSnoozePicker}
				<div
					class="sj-reading-pane__snooze-dropdown"
					role="dialog"
					aria-modal="false"
					aria-label="Snooze options"
				>
					<SnoozePicker onSelect={handleSnoozeSelect} onClose={closeSnoozePicker} />
				</div>
			{/if}
		</span>
		{#if isSpam}
			<IconButton label="Not Spam" size="sm" onclick={onNotSpam}>
				<Icon name="Mail" size={16} strokeWidth={1.75} />
			</IconButton>
		{:else if isTrash}
			<IconButton label="Delete permanently" size="sm" onclick={onTrash}>
				<Icon name="Trash2" size={16} strokeWidth={1.75} />
			</IconButton>
		{:else}
			<IconButton label="Trash" size="sm" onclick={onTrash}>
				<Icon name="Trash2" size={16} strokeWidth={1.75} />
			</IconButton>
		{/if}
		<IconButton label="Mute" size="sm" onclick={onMute}>
			<Icon name="BellOff" size={16} strokeWidth={1.75} />
		</IconButton>
		{#if onToggleRead}
			<IconButton
				label={isRead ? t('triage.mark_unread') : t('triage.mark_read')}
				size="sm"
				onclick={() => onToggleRead?.(!isRead)}
			>
				<Icon name={isRead ? 'MailOpen' : 'Mail'} size={16} strokeWidth={1.75} />
			</IconButton>
		{/if}
		{#if onFollowUp}
			<span class="sj-reading-pane__snooze-anchor">
				<IconButton
					label={t('triage.follow_up')}
					size="sm"
					active={!!email.flagDueAt}
					onclick={() => (showFollowUpPicker = !showFollowUpPicker)}
				>
					<Icon name="Flag" size={16} strokeWidth={1.75} />
				</IconButton>
				{#if showFollowUpPicker}
					<div
						class="sj-reading-pane__snooze-dropdown"
						role="dialog"
						aria-modal="false"
						aria-label={t('triage.followup.title')}
					>
						<FollowUpPicker onSelect={handleFollowUpSelect} onClose={closeFollowUpPicker} />
					</div>
				{/if}
			</span>
		{/if}
		{#if onCreateTask}
			<IconButton label={t('triage.create_task')} size="sm" onclick={onCreateTask}>
				<Icon name="SquareCheck" size={16} strokeWidth={1.75} />
			</IconButton>
		{/if}
		{#if mailWorkEnabled && $effectiveCaps.sharedMailWork && accountId && email.threadId}
			<span class="sj-reading-pane__sender-control-anchor">
				<IconButton label={t('inbox.work.title')} size="sm" active={showMailWork} onclick={() => (showMailWork = !showMailWork)}>
					<Icon name="ListChecks" size={16} strokeWidth={1.75} />
				</IconButton>
				{#if showMailWork}
					<MailWorkRail accountId={accountId} threadId={email.threadId} canCollaborate={mailWorkCanCollaborate}
						commentsEnabled={$effectiveCaps.sharedMailComments}
						notificationsEnabled={$effectiveCaps.sharedMailNotifications}
						analyticsEnabled={$effectiveCaps.sharedMailAnalytics}
						integrationsEnabled={$effectiveCaps.sharedMailIntegrations}
						onClose={() => (showMailWork = false)} />
				{/if}
			</span>
		{/if}
		{#if senderControlEnabled && $effectiveCaps.senderControlCenter && accountId && email.receivedAt}
			<span class="sj-reading-pane__sender-control-anchor">
				<IconButton label={t('inbox.sender_control.title')} size="sm" active={showSenderControl} onclick={() => (showSenderControl = !showSenderControl)}>
					<Icon name="ShieldCheck" size={16} strokeWidth={1.75} />
				</IconButton>
				{#if showSenderControl}
					<SenderControlPanel
						target={{ mailboxId: accountId, messageId: email.id, receivedAt: email.receivedAt }}
						onClose={() => (showSenderControl = false)}
						onChanged={actions.onSenderControlChanged}
					/>
				{/if}
			</span>
		{:else if onBlockSender}
			<IconButton label={t('triage.block_sender')} size="sm" onclick={onBlockSender}>
				<Icon name="ShieldBan" size={16} strokeWidth={1.75} />
			</IconButton>
		{/if}
		{#if onCreateRule}
			<IconButton label={t('triage.create_rule')} size="sm" onclick={onCreateRule}>
				<Icon name="ListFilter" size={16} strokeWidth={1.75} />
			</IconButton>
		{/if}
		{#if isSent && onRecall}
			<IconButton label="Recall" size="sm" onclick={onRecall}>
				<Icon name="Undo2" size={16} strokeWidth={1.75} />
			</IconButton>
		{/if}
		{#if featureAssist}
			<!-- ONE Sparkles assist menu (WAVE-5 #7): Summarize + Translate share the
			     trigger instead of sprawling sibling toolbar icons. -->
			<Menu
				items={assistMenuItems}
				onSelect={(id) => runAssist(id === 'translate' ? 'translation' : 'summary')}
				label={t('mail.assist')}
				align="end"
			>
				{#snippet children()}
					<Icon name="Sparkles" size={16} strokeWidth={1.75} />
				{/snippet}
			</Menu>
		{/if}
		<div class="sj-reading-pane__toolbar-spacer"></div>
		<IconButton label={t('triage.print')} size="sm" onclick={() => printMessage(email)}>
			<Icon name="Printer" size={16} strokeWidth={1.75} />
		</IconButton>
		<IconButton
			label={isStarred ? 'Unstar' : 'Star'}
			size="sm"
			active={isStarred}
			onclick={onStar}
		>
			<Icon name="Star" size={16} strokeWidth={1.75} />
		</IconButton>
	</div>

	<!-- Body scroll area -->
	<div class="sj-reading-body">
		<!-- ponytail: inner wrapper is position:relative so WatermarkOverlay inset:0
		     resolves against content height (not the scroll container's visible height).
		     Without this, bottom:0 on an absolute child inside overflow-y:auto anchors
		     to the viewport height, leaving below-fold content un-watermarked. -->
		<div class="sj-reading-body__inner">
		<!-- Read-receipt consent prompt (Track A privacy, policy 'ask') -->
		{#if receiptPromptEmailId === email.id}
			<div class="sj-receipt-prompt" role="region" aria-label={t('privacy.send_receipt_prompt')}>
				<span class="sj-receipt-prompt__text">{t('privacy.send_receipt_prompt')}</span>
				<div class="sj-receipt-prompt__actions">
					<Button size="sm" variant="primary" onclick={() => answerReceipt(true)}>
						{t('privacy.send_receipt')}
					</Button>
					<Button size="sm" variant="ghost" onclick={() => answerReceipt(false)}>
						{t('privacy.dont_send_receipt')}
					</Button>
				</div>
			</div>
		{/if}

		<!-- Copilot assist panel (feature.assist): summary OR translation.
		     PLAIN TEXT only — never {@html}. -->
		{#if featureAssist && (assistLoading || assistResult || assistError)}
			{@const panelTitle = assistMode === 'translation' ? t('mail.translate_title') : t('mail.summarize_title')}
			<div class="sj-reading-body__summary" role="region" aria-label={panelTitle}>
				<div class="sj-reading-body__summary-head">
					<Icon name="Sparkles" size={14} strokeWidth={1.75} />
					<span class="sj-reading-body__summary-title">{panelTitle}</span>
					<span class="sj-reading-body__summary-spacer"></span>
					<IconButton label={t('mail.summarize_dismiss')} size="sm" onclick={dismissAssist}>
						<Icon name="X" size={14} strokeWidth={1.75} />
					</IconButton>
				</div>
				{#if assistLoading}
					<p class="sj-reading-body__summary-text sj-reading-body__summary-text--muted">
						{assistMode === 'translation' ? t('mail.translate_loading') : t('mail.summarize_loading')}
					</p>
				{:else if assistError === 'too_long'}
					<p class="sj-reading-body__summary-text sj-reading-body__summary-text--muted">
						{t('mail.assist_too_long')}
					</p>
				{:else if assistError}
					<p class="sj-reading-body__summary-text sj-reading-body__summary-text--muted">
						{assistMode === 'translation' ? t('mail.translate_error') : t('mail.summarize_error')}
					</p>
				{:else}
					<p class="sj-reading-body__summary-text">{assistResult}</p>
					{#if assistMode === 'translation'}
						<button type="button" class="sj-reading-body__summary-original" onclick={dismissAssist}>
							{t('mail.show_original')}
						</button>
					{/if}
				{/if}
			</div>
		{/if}

		<!-- Subject -->
		<h1 class="sj-reading-body__subject">{email.subject || '(no subject)'}</h1>

		<!-- Follow-up due chip (A2) -->
		{#if followUpDueLabel}
			<div class="sj-reading-body__followup-chip">
				<Icon name="Flag" size={13} strokeWidth={1.75} />
				<span>{t('triage.followup.due_chip', { date: followUpDueLabel })}</span>
			</div>
		{/if}

		<!-- Tag chips with breadcrumbs. The row (and its "+ tag" opener) renders even
		     with zero chips — it is the only surface that applies a tag, so hiding it
		     on untagged messages made the FIRST tag unreachable. -->
		<div class="sj-reading-body__tags">
			{#each tagMailboxes as mb (mb.id)}
				{@const color = (mb.color as TagColor) ?? 'gray'}
				<Tag label={getTagLabel(mb)} color={color} onremove={() => onRemoveTag(mb.id)} />
			{/each}
			<button class="sj-reading-body__add-tag" onclick={toggleTagPicker}>+ tag</button>
		</div>

		<!-- Tag picker popover -->
		{#if showTagPicker}
			<div class="sj-reading-pane__tag-picker" role="region" aria-label="Tags">
				<Input
					label="Filter tags"
					placeholder="Filter tags..."
					bind:value={tagSearch}
				/>
				<div class="sj-reading-pane__tag-picker-list">
					{#each filteredPickerTags as t (t.id)}
						{@const isOnEmail = !!email.mailboxIds?.[t.id]}
						<button
							class="sj-reading-pane__tag-picker-item"
							class:sj-reading-pane__tag-picker-item--on={isOnEmail}
							onclick={() => { handleAddTag(t.id); closeTagPicker(); }}
						>
							<span class="sj-reading-pane__tag-picker-dot" style="background: var(--tag-{(t.color ?? 'gray')}-dot)"></span>
							{t.name}
							{#if isOnEmail}
								<span class="sj-reading-pane__tag-picker-icon">&check;</span>
							{/if}
						</button>
					{/each}
				</div>
				<div class="sj-reading-pane__tag-picker-create">
					<Input
						label="New tag name"
						placeholder="Create new tag..."
						bind:value={newTagName}
						onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') handleCreateTag(); }}
					/>
				</div>
			</div>
		{/if}

		<!-- Conversation-view depth: the thread as stacked collapsible cards
		     (oldest→newest). A single-message thread renders exactly one card.
		     Reply/Forward act on the pane's context message (per-message reply is
		     out of scope); delivery inspection is per-card. -->
		<div class="sj-reading-pane__cards">
			{#each cards as m (m.id)}
				<MessageCard
					email={m}
					expanded={expandedIds.has(m.id)}
					onToggle={() => toggleCard(m.id)}
					accountId={accountId}
					onReply={onReply}
					onReplyAll={onReplyAll}
					onForward={onForward}
					onResend={onResend}
					onVoteResponse={onVoteResponse}
					composeDisabled={composeDisabled}
					composeDisabledReason={composeDisabledReason}
				/>
			{/each}
		</div>

		<!-- Quick Steps (A2) -->
		{#if quickSteps.length > 0 && onApplyQuickStep}
			<div class="sj-reading-body__quicksteps">
				<QuickStepsBar
					quickSteps={quickSteps}
					applying={applyingQuickStep}
					onApply={(id) => onApplyQuickStep?.(id)}
				/>
			</div>
		{/if}

		<!-- Inline reply — #13 danger state: DISABLED (not hidden) with a tooltip/
		     caption when the caller only holds read-only access to this shared
		     mailbox (see MessageCard for the per-card Reply/Reply-all/Forward
		     buttons, gated the same way). -->
		<div class="sj-reading-body__reply">
			{#if replySuggestions.length}
				<div class="sj-reading-body__reply-chips">
					{#each replySuggestions as suggestion (suggestion)}
						<button
							type="button"
							class="sj-reading-body__reply-chip"
							aria-label={t('mail.reply_suggestion_use', { text: suggestion })}
							onclick={() => (replyText = suggestion)}
						>
							{suggestion}
						</button>
					{/each}
				</div>
			{/if}
			<Textarea
				placeholder={replyPlaceholder}
				bind:value={replyText}
				rows={3}
				disabled={composeDisabled}
				onfocus={loadReplySuggestions}
			/>
			<div class="sj-reading-body__reply-footer">
				<div class="sj-reading-body__reply-actions-left">
					<IconButton
						label={composeDisabled ? composeDisabledReason : 'Attach'}
						size="sm"
						disabled={composeDisabled}
						onclick={() => { /* coordinator handles attach */ }}
					>
						<Icon name="Paperclip" size={14} strokeWidth={1.75} />
					</IconButton>
					<IconButton
						label={composeDisabled ? composeDisabledReason : 'Schedule send'}
						size="sm"
						disabled={composeDisabled}
						onclick={handleScheduleReply}
					>
						<Icon name="CalendarClock" size={14} strokeWidth={1.75} />
					</IconButton>
				</div>
				<Button
					size="sm"
					variant="primary"
					disabled={composeDisabled || !replyText.trim()}
					title={composeDisabled ? composeDisabledReason : undefined}
					onclick={handleSendReply}
					aria-label="Send"
				>
					<Icon name="Send" size={13} strokeWidth={1.75} />
					Send
				</Button>
			</div>
			{#if composeDisabled && composeDisabledReason}
				<p class="sj-reading-body__reply-disabled-note">{composeDisabledReason}</p>
			{/if}
		</div>

		<!-- MAM watermark: tiled identity/timestamp over the full reading pane scroll height.
		     pointer-events:none so it never blocks reading, selection, or clicks. -->
		<WatermarkOverlay enabled={watermarkOn} userEmail={userEmail} />
		</div><!-- /.sj-reading-body__inner -->
	</div>
</div>

<style>
	.sj-reading-pane__sender-control-anchor { position:relative; display:inline-flex; }
	.sj-reading-pane {
		display: flex;
		flex-direction: column;
		flex: 1;
		min-width: 0;
		background: var(--surface-card);
		height: 100%;
	}

	.sj-reading-pane__toolbar {
		display: flex;
		align-items: center;
		gap: 4px;
		padding: 10px 16px;
		border-bottom: 1px solid var(--border-subtle);
		flex: none;
	}

	.sj-reading-pane__toolbar-spacer {
		flex: 1;
	}

	.sj-reading-pane__snooze-anchor {
		position: relative;
		display: inline-flex;
	}

	/* Positioning context only — the picker inside owns its box. The picker is
	   in-flow so this wrapper sizes to it and drops it below-left of the button,
	   opening rightward into the reading pane (not leftward over the clipped list). */
	.sj-reading-pane__snooze-dropdown {
		position: absolute;
		top: 100%;
		left: 0;
		z-index: 50;
		margin-top: 4px;
	}

	/* — Body container — */
	.sj-reading-body {
		flex: 1;
		overflow-y: auto;
		padding: clamp(14px, 4vw, 28px);
	}

	/* Inner wrapper: position:relative so the WatermarkOverlay absolute inset:0
	   fills the full content height, not just the scroll container's visible height. */
	.sj-reading-body__inner {
		position: relative;
	}

	.sj-receipt-prompt {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 10px 14px;
		margin: 0 0 16px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-sunken);
	}

	.sj-receipt-prompt__text {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.sj-receipt-prompt__actions {
		display: flex;
		gap: 8px;
	}

	/* — Copilot summary panel — */
	.sj-reading-body__summary {
		margin: 0 0 16px;
		padding: 10px 14px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-sunken);
	}

	.sj-reading-body__summary-head {
		display: flex;
		align-items: center;
		gap: 6px;
		margin-bottom: 6px;
	}

	.sj-reading-body__summary-head :global(svg) {
		color: var(--accent);
	}

	.sj-reading-body__summary-title {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}

	.sj-reading-body__summary-spacer {
		flex: 1;
	}

	.sj-reading-body__summary-text {
		margin: 0;
		font-size: var(--text-sm);
		line-height: 1.6;
		color: var(--text-primary);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}

	.sj-reading-body__summary-text--muted {
		color: var(--text-caption);
	}

	.sj-reading-body__summary-original {
		margin-top: 6px;
		padding: 3px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-full);
		background: none;
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		cursor: pointer;
	}

	.sj-reading-body__summary-original:hover {
		border-color: var(--accent);
		color: var(--text-primary);
	}

	.sj-reading-body__summary-original:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-reading-body__subject {
		font-size: clamp(17px, 1rem + 1vw, 20px);
		font-weight: 600;
		letter-spacing: var(--tracking-heading);
		margin: 0 0 6px;
		overflow-wrap: anywhere;
		color: var(--text-primary);
	}

	.sj-reading-body__followup-chip {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		margin: 0 0 10px;
		padding: 3px 10px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-sunken);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.sj-reading-body__followup-chip :global(svg) {
		color: var(--accent);
	}

	.sj-reading-body__quicksteps {
		margin-top: 20px;
	}

	/* — Tag chips — */
	.sj-reading-body__tags {
		display: flex;
		gap: 6px;
		margin-bottom: 18px;
		flex-wrap: wrap;
		align-items: center;
	}

	.sj-reading-body__add-tag {
		border: 1px dashed var(--border-strong);
		background: none;
		cursor: pointer;
		border-radius: var(--radius-sm);
		height: 22px;
		padding: 0 8px;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		font-family: var(--font-sans);
	}

	.sj-reading-body__add-tag:hover {
		border-color: var(--accent);
		color: var(--accent);
	}

	.sj-reading-body__add-tag:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	/* — Tag picker — */
	.sj-reading-pane__tag-picker {
		position: relative;
		margin-bottom: 16px;
		padding: 8px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		box-shadow: var(--shadow-sm);
		max-height: 260px;
		overflow-y: auto;
	}

	.sj-reading-pane__tag-picker-list {
		margin: 6px 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
		max-height: 160px;
		overflow-y: auto;
	}

	.sj-reading-pane__tag-picker-item {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 4px 8px;
		border: none;
		background: none;
		cursor: pointer;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		border-radius: var(--radius-sm);
		width: 100%;
		text-align: left;
	}

	.sj-reading-pane__tag-picker-item:hover {
		background: var(--surface-hover);
	}

	.sj-reading-pane__tag-picker-item:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-reading-pane__tag-picker-item--on {
		font-weight: 500;
	}

	.sj-reading-pane__tag-picker-dot {
		width: 7px;
		height: 7px;
		border-radius: 999px;
		flex: none;
	}

	.sj-reading-pane__tag-picker-icon {
		margin-left: auto;
		color: var(--accent);
		font-size: var(--text-sm);
	}

	.sj-reading-pane__tag-picker-create {
		padding-top: 4px;
		border-top: 1px solid var(--border-subtle);
		margin-top: 4px;
	}

	/* — Conversation-view card stack — */
	.sj-reading-pane__cards {
		margin-bottom: 12px;
	}

	/* — Inline reply — */
	.sj-reading-body__reply {
		margin-top: 28px;
		max-width: 640px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-xs);
	}

	.sj-reading-body__reply-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		padding: 8px 8px 0;
	}

	.sj-reading-body__reply-chip {
		font: inherit;
		font-size: var(--text-xs);
		line-height: 1.4;
		padding: 4px 10px;
		border-radius: var(--radius-full);
		border: 1px solid var(--border-default);
		background: var(--surface-sunken);
		color: var(--text-secondary);
		cursor: pointer;
	}

	.sj-reading-body__reply-chip:hover {
		background: var(--accent-subtle);
		border-color: var(--accent);
		color: var(--accent-fg-on-subtle);
	}

	.sj-reading-body__reply-chip:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-reading-body__reply-footer {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 8px;
		border-top: 1px solid var(--border-subtle);
	}

	.sj-reading-body__reply-actions-left {
		display: flex;
		gap: 2px;
	}

	/* #13 danger state: caption under the disabled inline-reply box (read-only
	   shared-mailbox grant). */
	.sj-reading-body__reply-disabled-note {
		padding: 0 10px 8px;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
